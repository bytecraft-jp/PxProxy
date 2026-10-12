//! 1 クライアント接続上のリクエスト / レスポンスの中継（ダミーサーバ・Intercept・記録・Upgrade）。

use std::io;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use px_store::{FlowSink, FlowSource, NewFlow, classify, content_type};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use super::stream::Prefixed;
use super::target::{Route, Target, route_request};
use super::upstream::{Upstream, connect, read_final_head};
use crate::http1::{BodyKind, Conn, RelayError, RequestHead, ResponseHead, rebuild_message};
use crate::intercept::{Decision, Direction, Held};
use crate::mock::{MockRequest, MockServer};
use crate::rules::CompiledRules;
use crate::ws::{self, Deflate, Recorder};
use crate::{ProxyContext, ProxyError, Result};

const DROPPED_REQUEST: &str = "Intercept でリクエストを破棄しました";
const DROPPED_RESPONSE: &str = "Intercept でレスポンスを破棄しました";
/// これより大きいリクエスト Body は（Intercept で止めないなら）溜めずに流す
const STREAM_REQUEST_OVER: u64 = 1024 * 1024;

pub(crate) fn now_us() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_micros() as i64).unwrap_or(0)
}

/// 段階ごとの結果。`Done` なら記録とクライアントへの応答（または切断）は済んでいて、この接続を終える。
enum Step<T> {
    Next(T),
    Done,
}

/// 処理中のリクエスト 1 件。Intercept で編集されたら `head`・`path`・`wire_head` を差し替える。
struct Exchange {
    target: Target,
    head: RequestHead,
    /// 記録するパス（origin-form）
    path: String,
    /// 上流に送るリクエストヘッド
    wire_head: Vec<u8>,
    started_at_us: i64,
    started: Instant,
    /// このリクエストを受け取った時点の設定
    rules: Arc<CompiledRules>,
    /// Body の記録の上限
    keep: usize,
}

impl Exchange {
    /// このリクエストの記録を作る。
    fn flow(&self, req_head: Vec<u8>, req_body: Vec<u8>) -> NewFlow {
        new_flow(&self.target, self.started_at_us, &self.head.method, self.path.clone(), req_head, req_body)
    }
}

/// Intercept の対象か調べるために溜めたリクエスト。
struct BufferedRequest {
    flow: NewFlow,
    /// 上流へ送る Body（転送時のエンコードのまま）
    body: Vec<u8>,
    /// Intercept で「レスポンスも止める」が選ばれた
    intercept_response: bool,
}

/// クライアントへ返したレスポンス。
struct Delivered {
    flow: NewFlow,
    /// クライアントへ返したヘッド（Intercept で編集されていれば編集後）
    head: ResponseHead,
    kind: BodyKind,
    /// クライアントへの送信の結果
    written: Result<()>,
}

/// 1 クライアント接続上のリクエストを順に処理する（keep-alive 対応）。
pub(super) async fn serve<S>(
    mut client: Conn<S>,
    route: Route,
    mut pending: Option<RequestHead>,
    ctx: &ProxyContext,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut upstream: Option<(Target, Upstream)> = None;
    loop {
        let head = match pending.take() {
            Some(h) => h,
            None => match read_next_request(&mut client, &mut upstream, ctx).await? {
                Some(h) => h,
                None => return Ok(()),
            },
        };
        let started_at_us = now_us();
        let started = Instant::now();

        // 宛先と、上流に送るリクエストヘッドを決める
        let Some((target, wire_head, path)) = route_request(&route, &head) else {
            client.io.write_all(&simple_response(400, "Bad Request", "missing Host")).await?;
            return Ok(());
        };
        let rules = ctx.interceptor.rules();
        let keep = rules.max_record_body();
        let mut ex = Exchange { target, head, path, wire_head, started_at_us, started, rules, keep };

        // ---- ダミーサーバ: 上流へは送らずに設定した応答を返す（Intercept の対象外）
        if let Some(mock) = ex.rules.mock_for(&ex.target.host) {
            let flow = ex.flow(ex.wire_head.clone(), Vec::new());
            if serve_mock(&mut client, ctx, mock, &ex.head, flow, started, keep).await? {
                continue;
            }
            let _ = client.io.shutdown().await;
            return Ok(());
        }

        let req_kind = BodyKind::for_request(&ex.head)?;
        let hold_request = ctx.interceptor.is_enabled() && {
            let kind = classify(&ex.path, &ex.wire_head, None);
            let url = format!("{}://{}:{}{}", ex.target.scheme.as_str(), ex.target.host, ex.target.port, ex.path);
            ex.rules.request_matches(&url, &ex.target.host, &ex.path, kind)
        };
        // 大きな Body は溜めずに流す（止めて編集するなら全体が要るので溜める）
        let stream_request = !hold_request
            && match req_kind {
                BodyKind::Chunked => true,
                BodyKind::Length(n) => n > STREAM_REQUEST_OVER,
                _ => false,
            };

        let mut intercept_response = false;
        let sent = if stream_request {
            send_streaming_request(&mut client, &mut upstream, ctx, &ex, req_kind).await?
        } else {
            let Step::Next(req) = buffer_request(&mut client, ctx, &mut ex, req_kind, hold_request).await? else {
                return Ok(());
            };
            intercept_response = req.intercept_response;
            send_buffered_request(&mut client, &mut upstream, ctx, &ex, req.flow, &req.body).await?
        };
        let Step::Next((flow, res_head)) = sent else { return Ok(()) };

        let up = &mut upstream.as_mut().expect("connected").1;
        let res_kind = BodyKind::for_response(&res_head, &ex.head.method)?;
        let upstream_close = res_kind == BodyKind::UntilClose
            || res_head.headers.has_token("connection", "close")
            || (res_head.minor_version == 0 && !res_head.headers.has_token("connection", "keep-alive"));

        // ---- Intercept (レスポンス)。101 (Upgrade) は対象外。止めるときだけ Body 全体を溜める
        let ct = content_type(Some(&res_head.raw));
        let hold_response = ctx.interceptor.is_enabled()
            && res_head.status != 101
            && (intercept_response
                || ex.rules.response_matches(
                    &ex.target.host,
                    &ex.path,
                    classify(&ex.path, &ex.wire_head, ct.as_deref()),
                    ct.as_deref(),
                ));
        let delivered = if hold_response {
            send_held_response(&mut client, up, ctx, &ex, flow, res_head, res_kind).await?
        } else {
            relay_response(&mut client, up, ctx, &ex, flow, res_head, res_kind).await?
        };
        let Step::Next(Delivered { mut flow, head: client_res, kind: client_res_kind, written }) = delivered else {
            return Ok(());
        };

        // クライアントが先に切断していても（Intercept で待たせた場合など）記録は残す
        flow.duration_us = started.elapsed().as_micros() as i64;
        flow.status = Some(client_res.status);
        flow.res_head = Some(client_res.raw.clone());
        if let Err(e) = &written {
            flow.error = Some(format!("クライアントへの送信に失敗: {e}"));
        }
        let upgrade = client_res.status == 101 && written.is_ok();
        let recorded = if upgrade {
            ctx.submit_with_sink(flow)
        } else {
            ctx.submit(flow);
            None
        };
        written?;

        if upgrade {
            let (_, up) = upstream.take().expect("connected");
            return relay_upgrade(client, up, &client_res, recorded, keep).await;
        }
        if upstream_close {
            upstream = None;
        }
        if client_wants_close(&ex.head) || client_res_kind == BodyKind::UntilClose {
            let _ = client.io.shutdown().await;
            return Ok(());
        }
    }
}

/// 大きなリクエスト: 新しい接続に、読んだそばから流す（失敗しても送り直せないので張り直す）。
async fn send_streaming_request<S>(
    client: &mut Conn<S>,
    upstream: &mut Option<(Target, Upstream)>,
    ctx: &ProxyContext,
    ex: &Exchange,
    req_kind: BodyKind,
) -> Result<Step<(NewFlow, ResponseHead)>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut flow = ex.flow(ex.wire_head.clone(), Vec::new());
    drop(upstream.take());
    let mut up = match connect(ctx, &ex.target).await {
        Ok(c) => c,
        Err(e) => return fail(client, ctx, flow, ex.started, e).await,
    };
    let wire = up.request_head(&ex.wire_head).into_owned();
    if let Err(e) = up.io.write_all(&wire).await {
        return fail(client, ctx, flow, ex.started, e.into()).await;
    }
    let relayed = client.relay_body(req_kind, &mut up.conn.io, ex.keep).await;
    flow.req_body_total = relayed.truncated().then_some(relayed.total);
    flow.req_body = relayed.data;
    match relayed.error {
        None => {}
        Some(RelayError::Write(e)) => return fail(client, ctx, flow, ex.started, e.into()).await,
        Some(RelayError::Read(e)) => {
            // クライアントが送りきらずに切断した
            flow.duration_us = ex.started.elapsed().as_micros() as i64;
            flow.error = Some(format!("リクエストの受信に失敗: {e}"));
            ctx.submit(flow);
            return Ok(Step::Done);
        }
    }
    let res = read_final_head(&mut up, &mut client.io).await;
    *upstream = Some((ex.target.clone(), up));
    match res {
        Ok(Some(h)) => Ok(Step::Next((flow, h))),
        Ok(None) => {
            let e = ProxyError::Upstream("connection closed before response".into());
            fail(client, ctx, flow, ex.started, e).await
        }
        Err(e) => fail(client, ctx, flow, ex.started, e).await,
    }
}

/// リクエスト Body を読み切る。`hold` なら Intercept で止め、編集されたら `ex` を編集後の内容に差し替える。
async fn buffer_request<S>(
    client: &mut Conn<S>,
    ctx: &ProxyContext,
    ex: &mut Exchange,
    req_kind: BodyKind,
    hold: bool,
) -> Result<Step<BufferedRequest>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let req_body = client.read_body(req_kind).await?;
    let mut req_wire_body = req_body.raw;
    let mut req_decoded = req_body.decoded.unwrap_or_else(|| req_wire_body.clone());
    let mut orig_request = None;
    let mut intercept_response = false;

    // ---- Intercept (リクエスト)
    if hold {
        let held = Held {
            id: 0,
            direction: Direction::Request,
            scheme: ex.target.scheme.as_str(),
            host: ex.target.host.clone(),
            port: ex.target.port,
            method: ex.head.method.clone(),
            target: ex.path.clone(),
            status: None,
            head: ex.wire_head.clone(),
            body: req_decoded.clone(),
        };
        match ctx.interceptor.hold(held).await {
            Decision::Drop => {
                let flow = ex.flow(ex.wire_head.clone(), req_decoded);
                let err = ProxyError::Dropped(DROPPED_REQUEST);
                return fail(client, ctx, flow, ex.started, err).await;
            }
            Decision::Forward { edited, intercept_response: r } => {
                intercept_response = r;
                if let Some((h, b)) = edited {
                    let changed = b != req_decoded;
                    let rb = rebuild_message(&h, &b, changed, ex.rules.fix_content_length());
                    if changed || rb.head != ex.wire_head {
                        let parsed = match parse_edited_request(&rb.head).await {
                            Ok(p) => p,
                            Err(e) => {
                                // 壊れた編集は送らず、編集前と一緒に記録して 502 を返す
                                let mut flow = ex.flow(rb.head, b);
                                flow.orig_request = Some((std::mem::take(&mut ex.wire_head), req_decoded));
                                return fail(client, ctx, flow, ex.started, e).await;
                            }
                        };
                        orig_request = Some((std::mem::take(&mut ex.wire_head), std::mem::take(&mut req_decoded)));
                        ex.path = parsed.target.clone();
                        ex.head = parsed;
                        ex.wire_head = rb.head;
                        req_wire_body = rb.body_wire;
                        req_decoded = b;
                    }
                }
            }
        }
    }

    let mut flow = ex.flow(ex.wire_head.clone(), req_decoded);
    flow.orig_request = orig_request;
    Ok(Step::Next(BufferedRequest { flow, body: req_wire_body, intercept_response }))
}

/// 溜めたリクエストを送って最終レスポンスのヘッドを受け取る。再利用した接続が切れていたら 1 回だけ張り直す。
async fn send_buffered_request<S>(
    client: &mut Conn<S>,
    upstream: &mut Option<(Target, Upstream)>,
    ctx: &ProxyContext,
    ex: &Exchange,
    flow: NewFlow,
    body: &[u8],
) -> Result<Step<(NewFlow, ResponseHead)>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut retried = false;
    loop {
        let reused = upstream.as_ref().is_some_and(|(t, _)| *t == ex.target);
        if !reused {
            // 別の宛先への接続は先に閉じる（同時接続数の上限に自分で掛からないように）
            drop(upstream.take());
            match connect(ctx, &ex.target).await {
                Ok(c) => *upstream = Some((ex.target.clone(), c)),
                Err(e) => return fail(client, ctx, flow, ex.started, e).await,
            }
        }
        let up = &mut upstream.as_mut().expect("connected").1;
        let result: Result<_> = async {
            let wire = up.request_head(&ex.wire_head).into_owned();
            up.io.write_all(&wire).await?;
            up.io.write_all(body).await?;
            up.io.flush().await?;
            read_final_head(up, &mut client.io).await
        }
        .await;
        match result {
            Ok(Some(h)) => return Ok(Step::Next((flow, h))),
            Ok(None) | Err(_) if reused && !retried => {
                retried = true;
                *upstream = None;
            }
            Ok(None) => {
                let e = ProxyError::Upstream("connection closed before response".into());
                return fail(client, ctx, flow, ex.started, e).await;
            }
            Err(e) => return fail(client, ctx, flow, ex.started, e).await,
        }
    }
}

/// レスポンスを Body まで溜めて Intercept で止め、編集を反映してクライアントへ返す。
async fn send_held_response<S>(
    client: &mut Conn<S>,
    up: &mut Upstream,
    ctx: &ProxyContext,
    ex: &Exchange,
    mut flow: NewFlow,
    res_head: ResponseHead,
    res_kind: BodyKind,
) -> Result<Step<Delivered>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let res_body = match up.read_body(res_kind).await {
        Ok(b) => b,
        Err(e) => {
            flow.status = Some(res_head.status);
            flow.res_head = Some(res_head.raw);
            return fail(client, ctx, flow, ex.started, e).await;
        }
    };
    let mut res_wire_body = res_body.raw;
    let mut res_decoded = res_body.decoded.unwrap_or_else(|| res_wire_body.clone());
    let mut client_res = res_head;
    let mut client_res_kind = res_kind;
    let held = Held {
        id: 0,
        direction: Direction::Response,
        scheme: ex.target.scheme.as_str(),
        host: ex.target.host.clone(),
        port: ex.target.port,
        method: ex.head.method.clone(),
        target: ex.path.clone(),
        status: Some(client_res.status),
        head: client_res.raw.clone(),
        body: res_decoded.clone(),
    };
    match ctx.interceptor.hold(held).await {
        Decision::Drop => {
            flow.status = Some(client_res.status);
            flow.res_head = Some(client_res.raw);
            flow.res_body = res_decoded;
            return fail(client, ctx, flow, ex.started, ProxyError::Dropped(DROPPED_RESPONSE)).await;
        }
        Decision::Forward { edited: Some((h, b)), .. } => {
            let changed = b != res_decoded;
            let rb = rebuild_message(&h, &b, changed, ex.rules.fix_content_length());
            if changed || rb.head != client_res.raw {
                let parsed = match Conn::new(&rb.head[..]).read_response_head().await {
                    Ok(Some(p)) => p,
                    other => {
                        let e = other.err().unwrap_or(ProxyError::Parse("empty".into()));
                        flow.status = Some(client_res.status);
                        flow.orig_response = Some((client_res.raw, res_decoded));
                        flow.res_head = Some(rb.head);
                        flow.res_body = b;
                        let e = ProxyError::Parse(format!("編集後のレスポンスを解析できません: {e}"));
                        return fail(client, ctx, flow, ex.started, e).await;
                    }
                };
                let original = std::mem::replace(&mut client_res, parsed);
                flow.orig_response = Some((original.raw, res_decoded));
                client_res_kind = BodyKind::for_response(&client_res, &ex.head.method)?;
                res_wire_body = rb.body_wire;
                res_decoded = b;
            }
        }
        Decision::Forward { edited: None, .. } => {}
    }
    flow.res_body = res_decoded;
    let written = async {
        client.io.write_all(&client_res.raw).await?;
        client.io.write_all(&res_wire_body).await?;
        client.io.flush().await?;
        Ok(())
    }
    .await;
    Ok(Step::Next(Delivered { flow, head: client_res, kind: client_res_kind, written }))
}

/// 止めないレスポンスは、読んだそばからクライアントへ流す（大きなダウンロードや SSE を溜めない）。
async fn relay_response<S>(
    client: &mut Conn<S>,
    up: &mut Upstream,
    ctx: &ProxyContext,
    ex: &Exchange,
    mut flow: NewFlow,
    res_head: ResponseHead,
    res_kind: BodyKind,
) -> Result<Step<Delivered>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let written = if let Err(e) = client.io.write_all(&res_head.raw).await {
        Err(e.into())
    } else {
        let relayed = up.relay_body(res_kind, &mut client.io, ex.keep).await;
        flow.res_body_total = relayed.truncated().then_some(relayed.total);
        flow.res_body = relayed.data;
        match relayed.error {
            None => Ok(()),
            Some(RelayError::Write(e)) => Err(e.into()),
            Some(RelayError::Read(e)) => {
                // ヘッドは送ってしまったので 502 は返せない。記録して接続を閉じる
                flow.duration_us = ex.started.elapsed().as_micros() as i64;
                flow.status = Some(res_head.status);
                flow.res_head = Some(res_head.raw);
                flow.error = Some(format!("レスポンスの受信に失敗: {e}"));
                ctx.submit(flow);
                let _ = client.io.shutdown().await;
                return Ok(Step::Done);
            }
        }
    };
    Ok(Step::Next(Delivered { flow, head: res_head, kind: res_kind, written }))
}

/// Upgrade（101）後の中継。WebSocket ならフレームを解析して記録しながら、それ以外（h2c 等）はそのまま中継する。
async fn relay_upgrade<S>(
    client: Conn<S>,
    up: Upstream,
    res: &ResponseHead,
    recorded: Option<(FlowSink, i64)>,
    keep: usize,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let Conn { io: up_io, buf: up_buf } = up.conn;
    let Conn { io: client_io, buf: client_buf } = client;
    let websocket = res.headers.has_token("upgrade", "websocket");
    let rec = recorded.filter(|_| websocket).map(|(sink, flow_id)| Recorder { sink, flow_id, keep });
    if websocket {
        let deflate = Deflate::negotiated(&res.headers);
        ws::relay(client_io, client_buf, up_io, up_buf, rec, deflate).await?;
    } else {
        let mut client_io = Prefixed { prefix: client_buf, inner: client_io };
        let mut up_io = Prefixed { prefix: up_buf, inner: up_io };
        // 先読みした分は Prefixed が読み出し側に返すので、ここで反対側へ流れる
        tokio::io::copy_bidirectional(&mut client_io, &mut up_io).await?;
    }
    Ok(())
}

/// クライアントがこのリクエストで接続を閉じるつもりか。
fn client_wants_close(head: &RequestHead) -> bool {
    head.headers.has_token("connection", "close")
        || head.headers.has_token("proxy-connection", "close")
        || (head.minor_version == 0 && !head.headers.has_token("connection", "keep-alive"))
}

/// ダミーサーバの応答を返して記録する。続けて同じ接続で次のリクエストを読めるなら true。
async fn serve_mock<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut Conn<S>,
    ctx: &ProxyContext,
    mock: &MockServer,
    head: &RequestHead,
    mut flow: NewFlow,
    started: Instant,
    keep: usize,
) -> Result<bool> {
    flow.source = FlowSource::Mock;
    // Body は読み捨てる（記録は上限まで）
    let relayed = client.relay_body(BodyKind::for_request(head)?, &mut tokio::io::sink(), keep).await;
    flow.req_body_total = relayed.truncated().then_some(relayed.total);
    flow.req_body = relayed.data;
    if let Some(e) = relayed.error {
        let e = match e {
            RelayError::Read(e) => e,
            RelayError::Write(e) => e.into(),
        };
        flow.duration_us = started.elapsed().as_micros() as i64;
        flow.error = Some(format!("リクエストの受信に失敗: {e}"));
        ctx.submit(flow);
        return Ok(false);
    }
    let res = mock.respond(&MockRequest {
        method: &head.method,
        target: &flow.target,
        headers: &head.headers.0,
        body: &flow.req_body,
    });
    let written: io::Result<()> = async {
        client.io.write_all(&res.head).await?;
        client.io.write_all(&res.body).await?;
        client.io.flush().await
    }
    .await;
    flow.duration_us = started.elapsed().as_micros() as i64;
    flow.status = Some(res.status);
    flow.res_head = Some(res.head);
    flow.res_body = res.body;
    if let Err(e) = &written {
        flow.error = Some(format!("クライアントへの送信に失敗: {e}"));
    }
    ctx.submit(flow);
    written?;
    Ok(!client_wants_close(head))
}

/// クライアントの次のリクエストを待つ。その間に接続の空き待ちが出たら、
/// 使っていない上流接続を閉じて枠を譲る。
async fn read_next_request<S: AsyncRead + Unpin>(
    client: &mut Conn<S>,
    upstream: &mut Option<(Target, Upstream)>,
    ctx: &ProxyContext,
) -> Result<Option<RequestHead>> {
    if upstream.is_some() {
        // read_request_head は読んだ分を client.buf に残すので、途中で打ち切っても取りこぼさない
        tokio::select! {
            head = client.read_request_head() => return head,
            _ = ctx.limiter.idle_wanted() => *upstream = None,
        }
    }
    client.read_request_head().await
}

pub(crate) fn new_flow(
    target: &Target,
    started_at_us: i64,
    method: &str,
    path: String,
    req_head: Vec<u8>,
    req_body: Vec<u8>,
) -> NewFlow {
    NewFlow {
        source: FlowSource::Proxy,
        started_at_us,
        duration_us: 0,
        scheme: target.scheme.as_str().into(),
        host: target.host.clone(),
        port: target.port,
        method: method.to_string(),
        target: path,
        status: None,
        req_head,
        req_body,
        res_head: None,
        res_body: Vec::new(),
        error: None,
        orig_request: None,
        orig_response: None,
        req_body_total: None,
        res_body_total: None,
    }
}

pub(crate) async fn parse_edited_request(head: &[u8]) -> Result<RequestHead> {
    match Conn::new(head).read_request_head().await {
        Ok(Some(p)) => Ok(p),
        Ok(None) => Err(ProxyError::Parse("編集後のリクエストが空です".into())),
        Err(e) => Err(ProxyError::Parse(format!("編集後のリクエストを解析できません: {e}"))),
    }
}

/// 上流エラー時: 502 を返し、エラー付きでフローを記録して接続を閉じる。
async fn fail<S: AsyncWrite + Unpin, T>(
    client: &mut Conn<S>,
    ctx: &ProxyContext,
    mut flow: NewFlow,
    started: Instant,
    err: ProxyError,
) -> Result<Step<T>> {
    flow.duration_us = started.elapsed().as_micros() as i64;
    flow.error = Some(err.to_string());
    ctx.submit(flow);
    if client.io.write_all(&simple_response(502, "Bad Gateway", &err.to_string())).await.is_ok() {
        let _ = client.io.shutdown().await;
    }
    Ok(Step::Done)
}

fn simple_response(status: u16, reason: &str, body: &str) -> Vec<u8> {
    let body = format!("pxproxy: {body}\n");
    format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}
