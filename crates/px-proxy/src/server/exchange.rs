//! 1 クライアント接続上のリクエスト / レスポンスの中継（ダミーサーバ・Intercept・記録・Upgrade）。

use std::io;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use px_store::{FlowSource, NewFlow, classify, content_type};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use super::stream::Prefixed;
use super::target::{Route, Target, route_request};
use super::upstream::{Upstream, connect, read_final_head};
use crate::http1::{BodyKind, Conn, RelayError, RequestHead, rebuild_message};
use crate::intercept::{Decision, Direction, Held};
use crate::mock::{MockRequest, MockServer};
use crate::ws::{self, Deflate, Recorder};
use crate::{ProxyContext, ProxyError, Result};

const DROPPED_REQUEST: &str = "Intercept でリクエストを破棄しました";
const DROPPED_RESPONSE: &str = "Intercept でレスポンスを破棄しました";
/// これより大きいリクエスト Body は（Intercept で止めないなら）溜めずに流す
const STREAM_REQUEST_OVER: u64 = 1024 * 1024;

pub(crate) fn now_us() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_micros() as i64).unwrap_or(0)
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

        let interceptor = &ctx.interceptor;
        let rules = interceptor.rules();
        let keep = rules.max_record_body();

        // ---- ダミーサーバ: 上流へは送らずに設定した応答を返す（Intercept の対象外）
        if let Some(mock) = rules.mock_for(&target.host) {
            let flow = new_flow(&target, started_at_us, &head.method, path, wire_head, Vec::new());
            if serve_mock(&mut client, ctx, mock, &head, flow, started, keep).await? {
                continue;
            }
            let _ = client.io.shutdown().await;
            return Ok(());
        }

        let req_kind = BodyKind::for_request(&head)?;
        let hold_request = interceptor.is_enabled() && {
            let kind = classify(&path, &wire_head, None);
            let url = format!("{}://{}:{}{}", target.scheme.as_str(), target.host, target.port, path);
            rules.request_matches(&url, &target.host, &path, kind)
        };
        // 大きな Body は溜めずに流す（止めて編集するなら全体が要るので溜める）
        let stream_request = !hold_request
            && match req_kind {
                BodyKind::Chunked => true,
                BodyKind::Length(n) => n > STREAM_REQUEST_OVER,
                _ => false,
            };

        let mut head = head;
        let mut path = path;
        let mut wire_head = wire_head;
        let mut intercept_response = false;
        let mut flow;

        let res_head = if stream_request {
            // ---- 大きなリクエスト: 新しい接続に、読んだそばから流す（失敗しても送り直せないので張り直す）
            flow = new_flow(&target, started_at_us, &head.method, path.clone(), wire_head.clone(), Vec::new());
            drop(upstream.take());
            let mut up = match connect(ctx, &target).await {
                Ok(c) => c,
                Err(e) => return fail(&mut client, ctx, flow, started, e).await,
            };
            let wire = up.request_head(&wire_head).into_owned();
            if let Err(e) = up.io.write_all(&wire).await {
                return fail(&mut client, ctx, flow, started, e.into()).await;
            }
            let relayed = client.relay_body(req_kind, &mut up.conn.io, keep).await;
            flow.req_body_total = relayed.truncated().then_some(relayed.total);
            flow.req_body = relayed.data;
            match relayed.error {
                None => {}
                Some(RelayError::Write(e)) => return fail(&mut client, ctx, flow, started, e.into()).await,
                Some(RelayError::Read(e)) => {
                    // クライアントが送りきらずに切断した
                    flow.duration_us = started.elapsed().as_micros() as i64;
                    flow.error = Some(format!("リクエストの受信に失敗: {e}"));
                    ctx.submit(flow);
                    return Ok(());
                }
            }
            let res = read_final_head(&mut up, &mut client.io).await;
            upstream = Some((target.clone(), up));
            match res {
                Ok(Some(h)) => h,
                Ok(None) => {
                    let e = ProxyError::Upstream("connection closed before response".into());
                    return fail(&mut client, ctx, flow, started, e).await;
                }
                Err(e) => return fail(&mut client, ctx, flow, started, e).await,
            }
        } else {
            let req_body = client.read_body(req_kind).await?;
            let mut req_wire_body = req_body.raw;
            let mut req_decoded = req_body.decoded.unwrap_or_else(|| req_wire_body.clone());
            let mut orig_request = None;

            // ---- Intercept (リクエスト)
            if hold_request {
                let held = Held {
                    id: 0,
                    direction: Direction::Request,
                    scheme: target.scheme.as_str(),
                    host: target.host.clone(),
                    port: target.port,
                    method: head.method.clone(),
                    target: path.clone(),
                    status: None,
                    head: wire_head.clone(),
                    body: req_decoded.clone(),
                };
                match interceptor.hold(held).await {
                    Decision::Drop => {
                        let flow = new_flow(&target, started_at_us, &head.method, path, wire_head, req_decoded);
                        let err = ProxyError::Dropped(DROPPED_REQUEST);
                        return fail(&mut client, ctx, flow, started, err).await;
                    }
                    Decision::Forward { edited, intercept_response: r } => {
                        intercept_response = r;
                        if let Some((h, b)) = edited {
                            let changed = b != req_decoded;
                            let rb = rebuild_message(&h, &b, changed, rules.fix_content_length());
                            if changed || rb.head != wire_head {
                                let parsed = match parse_edited_request(&rb.head).await {
                                    Ok(p) => p,
                                    Err(e) => {
                                        // 壊れた編集は送らず、編集前と一緒に記録して 502 を返す
                                        let mut flow = new_flow(&target, started_at_us, &head.method, path, rb.head, b);
                                        flow.orig_request = Some((wire_head, req_decoded));
                                        return fail(&mut client, ctx, flow, started, e).await;
                                    }
                                };
                                orig_request = Some((std::mem::take(&mut wire_head), std::mem::take(&mut req_decoded)));
                                path = parsed.target.clone();
                                head = parsed;
                                wire_head = rb.head;
                                req_wire_body = rb.body_wire;
                                req_decoded = b;
                            }
                        }
                    }
                }
            }

            flow = new_flow(&target, started_at_us, &head.method, path.clone(), wire_head.clone(), req_decoded);
            flow.orig_request = orig_request;

            // 送信して最終レスポンスのヘッドを受け取る。再利用した接続が切れていたら 1 回だけ張り直す。
            let mut retried = false;
            loop {
                let reused = matches!(&upstream, Some((t, _)) if *t == target);
                if !reused {
                    // 別の宛先への接続は先に閉じる（同時接続数の上限に自分で掛からないように）
                    drop(upstream.take());
                    match connect(ctx, &target).await {
                        Ok(c) => upstream = Some((target.clone(), c)),
                        Err(e) => {
                            return fail(&mut client, ctx, flow, started, e).await;
                        }
                    }
                }
                let up = &mut upstream.as_mut().expect("connected").1;
                let result: Result<_> = async {
                    let wire = up.request_head(&wire_head).into_owned();
                    up.io.write_all(&wire).await?;
                    up.io.write_all(&req_wire_body).await?;
                    up.io.flush().await?;
                    read_final_head(up, &mut client.io).await
                }
                .await;
                match result {
                    Ok(Some(h)) => break h,
                    Ok(None) | Err(_) if reused && !retried => {
                        retried = true;
                        upstream = None;
                    }
                    Ok(None) => {
                        let e = ProxyError::Upstream("connection closed before response".into());
                        return fail(&mut client, ctx, flow, started, e).await;
                    }
                    Err(e) => return fail(&mut client, ctx, flow, started, e).await,
                }
            }
        };

        let up = &mut upstream.as_mut().expect("connected").1;
        let res_kind = BodyKind::for_response(&res_head, &head.method)?;
        let upstream_close = res_kind == BodyKind::UntilClose
            || res_head.headers.has_token("connection", "close")
            || (res_head.minor_version == 0 && !res_head.headers.has_token("connection", "keep-alive"));

        let mut client_res = res_head;
        let mut client_res_kind = res_kind;

        // ---- Intercept (レスポンス)。101 (Upgrade) は対象外。止めるときだけ Body 全体を溜める
        let ct = content_type(Some(&client_res.raw));
        let hold_response = interceptor.is_enabled()
            && client_res.status != 101
            && (intercept_response
                || rules.response_matches(&target.host, &path, classify(&path, &wire_head, ct.as_deref()), ct.as_deref()));

        let written: Result<()> = if hold_response {
            let res_body = match up.read_body(res_kind).await {
                Ok(b) => b,
                Err(e) => {
                    flow.status = Some(client_res.status);
                    flow.res_head = Some(client_res.raw);
                    return fail(&mut client, ctx, flow, started, e).await;
                }
            };
            let mut res_wire_body = res_body.raw;
            let mut res_decoded = res_body.decoded.unwrap_or_else(|| res_wire_body.clone());
            let held = Held {
                id: 0,
                direction: Direction::Response,
                scheme: target.scheme.as_str(),
                host: target.host.clone(),
                port: target.port,
                method: head.method.clone(),
                target: path.clone(),
                status: Some(client_res.status),
                head: client_res.raw.clone(),
                body: res_decoded.clone(),
            };
            match interceptor.hold(held).await {
                Decision::Drop => {
                    flow.status = Some(client_res.status);
                    flow.res_head = Some(client_res.raw);
                    flow.res_body = res_decoded;
                    return fail(&mut client, ctx, flow, started, ProxyError::Dropped(DROPPED_RESPONSE)).await;
                }
                Decision::Forward { edited: Some((h, b)), .. } => {
                    let changed = b != res_decoded;
                    let rb = rebuild_message(&h, &b, changed, rules.fix_content_length());
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
                                return fail(&mut client, ctx, flow, started, e).await;
                            }
                        };
                        let original = std::mem::replace(&mut client_res, parsed);
                        flow.orig_response = Some((original.raw, res_decoded));
                        client_res_kind = BodyKind::for_response(&client_res, &head.method)?;
                        res_wire_body = rb.body_wire;
                        res_decoded = b;
                    }
                }
                Decision::Forward { edited: None, .. } => {}
            }
            flow.res_body = res_decoded;
            async {
                client.io.write_all(&client_res.raw).await?;
                client.io.write_all(&res_wire_body).await?;
                client.io.flush().await?;
                Ok(())
            }
            .await
        } else {
            // ---- 止めないなら、読んだそばからクライアントへ流す（大きなダウンロードや SSE を溜めない）
            if let Err(e) = client.io.write_all(&client_res.raw).await {
                Err(e.into())
            } else {
                let relayed = up.relay_body(res_kind, &mut client.io, keep).await;
                flow.res_body_total = relayed.truncated().then_some(relayed.total);
                flow.res_body = relayed.data;
                match relayed.error {
                    None => Ok(()),
                    Some(RelayError::Write(e)) => Err(e.into()),
                    Some(RelayError::Read(e)) => {
                        // ヘッドは送ってしまったので 502 は返せない。記録して接続を閉じる
                        flow.duration_us = started.elapsed().as_micros() as i64;
                        flow.status = Some(client_res.status);
                        flow.res_head = Some(client_res.raw);
                        flow.error = Some(format!("レスポンスの受信に失敗: {e}"));
                        ctx.submit(flow);
                        let _ = client.io.shutdown().await;
                        return Ok(());
                    }
                }
            }
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
            // WebSocket ならフレームを解析して記録しながら、それ以外（h2c 等）はそのまま中継する
            let (_, up) = upstream.take().expect("connected");
            let Conn { io: up_io, buf: up_buf } = up.conn;
            let Conn { io: client_io, buf: client_buf } = client;
            let websocket = client_res.headers.has_token("upgrade", "websocket");
            let rec = recorded.filter(|_| websocket).map(|(sink, flow_id)| Recorder { sink, flow_id, keep });
            if websocket {
                let deflate = Deflate::negotiated(&client_res.headers);
                ws::relay(client_io, client_buf, up_io, up_buf, rec, deflate).await?;
            } else {
                let mut client_io = Prefixed { prefix: client_buf, inner: client_io };
                let mut up_io = Prefixed { prefix: up_buf, inner: up_io };
                // 先読みした分は Prefixed が読み出し側に返すので、ここで反対側へ流れる
                tokio::io::copy_bidirectional(&mut client_io, &mut up_io).await?;
            }
            return Ok(());
        }

        if upstream_close {
            upstream = None;
        }
        if client_wants_close(&head) || client_res_kind == BodyKind::UntilClose {
            let _ = client.io.shutdown().await;
            return Ok(());
        }
    }
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
async fn fail<S: AsyncWrite + Unpin>(
    client: &mut Conn<S>,
    ctx: &ProxyContext,
    mut flow: NewFlow,
    started: Instant,
    err: ProxyError,
) -> Result<()> {
    flow.duration_us = started.elapsed().as_micros() as i64;
    flow.error = Some(err.to_string());
    ctx.submit(flow);
    if client.io.write_all(&simple_response(502, "Bad Gateway", &err.to_string())).await.is_ok() {
        let _ = client.io.shutdown().await;
    }
    Ok(())
}

fn simple_response(status: u16, reason: &str, body: &str) -> Vec<u8> {
    let body = format!("pxproxy: {body}\n");
    format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}
