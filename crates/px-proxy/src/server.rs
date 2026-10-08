use std::borrow::Cow;
use std::io;
use std::net::SocketAddr;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::BytesMut;
use px_store::{FlowSource, NewFlow, classify, content_type};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};
use tokio_rustls::{LazyConfigAcceptor, TlsConnector};

use crate::http1::{BodyKind, Conn, RelayError, RequestHead, ResponseHead, rebuild_message, rewrite_target};
use crate::intercept::{Decision, Direction, Held};
use crate::limit::{Limited, Limiter};
use crate::ws::{self, Deflate, Recorder};
use crate::{ProxyContext, ProxyError, Result};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DROPPED_REQUEST: &str = "Intercept でリクエストを破棄しました";
const DROPPED_RESPONSE: &str = "Intercept でレスポンスを破棄しました";
/// これより大きいリクエスト Body は（Intercept で止めないなら）溜めずに流す
const STREAM_REQUEST_OVER: u64 = 1024 * 1024;
/// SNI を読むために溜める ClientHello の上限
const MAX_CLIENT_HELLO: usize = 16 * 1024 + 5;

/// 待ち受け中のプロキシ。`stop`/drop で待ち受けと全コネクションを止める。
///
/// CONNECT・absolute-form の通常のプロキシ要求に加えて、透過プロキシ
/// （iptables・portproxy 等でこちらへ向けた、CONNECT 無しの HTTP / TLS）も同じ待受で受け付ける。
pub struct ProxyServer {
    local_addr: SocketAddr,
    task: JoinHandle<()>,
    ctx: Arc<ProxyContext>,
}

impl ProxyServer {
    pub async fn bind(addr: SocketAddr, ctx: Arc<ProxyContext>) -> io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        let local_addr = listener.local_addr()?;
        ctx.listeners.write().push(local_addr);
        let task = tokio::spawn(accept_loop(listener, ctx.clone()));
        Ok(Self { local_addr, task, ctx })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn stop(self) {}
}

impl Drop for ProxyServer {
    fn drop(&mut self) {
        self.task.abort();
        let mut registered = self.ctx.listeners.write();
        if let Some(i) = registered.iter().position(|a| *a == self.local_addr) {
            registered.remove(i);
        }
    }
}

async fn accept_loop(listener: TcpListener, ctx: Arc<ProxyContext>) {
    // JoinSet ごと drop されると配下のコネクションも abort される。
    let mut conns = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, peer)) => {
                    let ctx = ctx.clone();
                    conns.spawn(async move {
                        let _ = stream.set_nodelay(true);
                        if let Err(e) = handle_client(stream, ctx).await {
                            tracing::debug!(%peer, "connection ended: {e}");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!("accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            },
            Some(_) = conns.join_next(), if !conns.is_empty() => {}
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scheme {
    Http,
    Https,
}

impl Scheme {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Target {
    pub(crate) scheme: Scheme,
    pub(crate) host: String,
    pub(crate) port: u16,
}

/// `host:port` / `[v6]:port` / `host` を分解する。
pub(crate) fn parse_authority(auth: &str, default_port: u16) -> Option<(String, u16)> {
    if let Some(rest) = auth.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None => default_port,
        };
        return Some((host.to_string(), port));
    }
    match auth.rsplit_once(':') {
        Some((h, p)) => Some((h.to_string(), p.parse().ok()?)),
        None => Some((auth.to_string(), default_port)),
    }
}

/// `host:port`（IPv6 は角括弧で囲む）。
fn authority(host: &str, port: u16) -> String {
    if host.contains(':') { format!("[{host}]:{port}") } else { format!("{host}:{port}") }
}

/// absolute-form (`http://host/path`) を (Target, origin-form) に分解する。
pub(crate) fn parse_absolute(target: &str) -> Option<(Target, String)> {
    let (scheme, rest) = if let Some(r) = target.strip_prefix("http://") {
        (Scheme::Http, r)
    } else {
        (Scheme::Https, target.strip_prefix("https://")?)
    };
    let split = rest.find(['/', '?']).unwrap_or(rest.len());
    let (auth, path) = rest.split_at(split);
    let default_port = if scheme == Scheme::Https { 443 } else { 80 };
    let (host, port) = parse_authority(auth, default_port)?;
    let path = if path.is_empty() {
        "/".to_string()
    } else if path.starts_with('?') {
        format!("/{path}")
    } else {
        path.to_string()
    };
    Some((Target { scheme, host, port }, path))
}

/// TLS レコードの先頭バイト（Handshake）
const TLS_HANDSHAKE: u8 = 0x16;

/// 上流の宛先の決め方。
#[derive(Debug, Clone)]
enum Route {
    /// CONNECT で宛先が決まっている
    Fixed(Target),
    /// absolute-form ならその URL、それ以外は Host ヘッダ（無ければ SNI）から決める。
    /// 通常の平文プロキシ要求と、透過プロキシ（CONNECT 無し）の接続で使う。
    ByHost { scheme: Scheme, sni: Option<String> },
}

async fn handle_client(stream: TcpStream, ctx: Arc<ProxyContext>) -> Result<()> {
    let mut client = Conn::new(stream);
    if client.fill().await? == 0 {
        return Ok(());
    }
    if client.buf[0] == TLS_HANDSHAKE {
        // 透過プロキシ: CONNECT 無しでいきなり TLS。宛先は SNI / Host ヘッダから決める
        if ctx.interceptor.rules().has_passthrough()
            && let Some(sni) = peek_sni(&mut client).await?
            && ctx.interceptor.rules().passthrough(&[&sni])
        {
            // Host ヘッダは暗号化されていて読めないので、ポートは 443 とみなす
            return tunnel(client, Target { scheme: Scheme::Https, host: sni, port: 443 }, false, &ctx).await;
        }
        let prefixed = Prefixed { prefix: client.buf, inner: client.io };
        return mitm_tls(prefixed, None, &ctx).await;
    }
    let Some(head) = client.read_request_head().await? else {
        return Ok(());
    };
    if !head.method.eq_ignore_ascii_case("CONNECT") {
        // 通常の平文プロキシ要求（absolute-form）か、透過プロキシの平文 HTTP（origin-form + Host）
        return serve(client, Route::ByHost { scheme: Scheme::Http, sni: None }, Some(head), &ctx).await;
    }

    let (host, port) =
        parse_authority(&head.target, 443).ok_or_else(|| ProxyError::Parse(format!("CONNECT {}", head.target)))?;
    client.io.write_all(CONNECT_ESTABLISHED).await?;
    if client.buf.is_empty() && client.fill().await? == 0 {
        return Ok(());
    }
    let is_tls = client.buf[0] == TLS_HANDSHAKE;
    if is_tls && ctx.interceptor.rules().has_passthrough() {
        let sni = peek_sni(&mut client).await?;
        if ctx.interceptor.rules().passthrough(&[&host, sni.as_deref().unwrap_or("")]) {
            return tunnel(client, Target { scheme: Scheme::Https, host: sni.unwrap_or(host), port }, true, &ctx).await;
        }
    }
    let prefixed = Prefixed { prefix: client.buf, inner: client.io };
    if !is_tls {
        let target = Target { scheme: Scheme::Http, host, port };
        return serve(Conn::new(prefixed), Route::Fixed(target), None, &ctx).await;
    }
    mitm_tls(prefixed, Some((host, port)), &ctx).await
}

const CONNECT_ESTABLISHED: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";

/// クライアントとの TLS を CA の証明書で終端して中継する。
/// `connect_to` は CONNECT で指定された宛先。None なら透過プロキシで、宛先は SNI / Host ヘッダから決める。
async fn mitm_tls<S>(io: S, connect_to: Option<(String, u16)>, ctx: &ProxyContext) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let start = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), io).await?;
    // 証明書は SNI を優先（CONNECT が IP 指定でも正しいホスト名で発行する）。
    let sni = start.client_hello().server_name().map(str::to_string);
    let cert_host = match (&sni, &connect_to) {
        (Some(s), _) => s.clone(),
        (None, Some((host, _))) => host.clone(),
        (None, None) => {
            return Err(ProxyError::Parse("透過プロキシ: SNI の無い TLS 接続は宛先が分からないため中継できません".into()));
        }
    };
    let cfg = ctx.ca.server_config(&cert_host)?;
    let tls = start.into_stream(cfg).await?;
    let route = match connect_to {
        Some((host, port)) => Route::Fixed(Target { scheme: Scheme::Https, host: sni.unwrap_or(host), port }),
        None => Route::ByHost { scheme: Scheme::Https, sni },
    };
    serve(Conn::new(tls), route, None, ctx).await
}

/// ClientHello が揃うまで読み足して SNI を返す（クライアントからは何も消費しない）。
async fn peek_sni(client: &mut Conn<TcpStream>) -> Result<Option<String>> {
    loop {
        match client_hello_sni(&client.buf) {
            Sni::Found(name) => return Ok(Some(name)),
            Sni::Absent => return Ok(None),
            Sni::Incomplete if client.buf.len() >= MAX_CLIENT_HELLO => return Ok(None),
            Sni::Incomplete => {
                if client.fill().await? == 0 {
                    return Ok(None);
                }
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Sni {
    Found(String),
    /// SNI が無い・解析できない
    Absent,
    /// まだ ClientHello の途中
    Incomplete,
}

/// TLS レコードの先頭にある ClientHello から server_name を取り出す。
fn client_hello_sni(buf: &[u8]) -> Sni {
    if buf.len() < 5 {
        return Sni::Incomplete;
    }
    if buf[0] != TLS_HANDSHAKE {
        return Sni::Absent;
    }
    let record_len = usize::from(u16::from_be_bytes([buf[3], buf[4]]));
    if buf.len() < 5 + record_len {
        return Sni::Incomplete;
    }
    parse_client_hello(&buf[5..5 + record_len]).map_or(Sni::Absent, Sni::Found)
}

fn parse_client_hello(hs: &[u8]) -> Option<String> {
    struct Reader<'a>(&'a [u8]);
    impl<'a> Reader<'a> {
        fn take(&mut self, n: usize) -> Option<&'a [u8]> {
            let (a, b) = (self.0.get(..n)?, self.0.get(n..)?);
            self.0 = b;
            Some(a)
        }
        fn u8(&mut self) -> Option<usize> {
            self.take(1).map(|b| usize::from(b[0]))
        }
        fn u16(&mut self) -> Option<usize> {
            self.take(2).map(|b| usize::from(u16::from_be_bytes([b[0], b[1]])))
        }
    }
    let mut r = Reader(hs);
    // ClientHello、長さ 3 バイト、バージョン、乱数
    if r.u8()? != 1 {
        return None;
    }
    r.take(3 + 2 + 32)?;
    let n = r.u8()?;
    r.take(n)?; // session id
    let n = r.u16()?;
    r.take(n)?; // cipher suites
    let n = r.u8()?;
    r.take(n)?; // compression
    let n = r.u16()?;
    let mut ext = Reader(r.take(n)?);
    while !ext.0.is_empty() {
        let (kind, len) = (ext.u16()?, ext.u16()?);
        let data = ext.take(len)?;
        if kind != 0 {
            continue;
        }
        let mut list = Reader(data);
        let n = list.u16()?;
        let mut names = Reader(list.take(n)?);
        while !names.0.is_empty() {
            let (name_type, len) = (names.u8()?, names.u16()?);
            let name = names.take(len)?;
            if name_type == 0 {
                return std::str::from_utf8(name).ok().map(str::to_string);
            }
        }
    }
    None
}

/// TLS パススルー: 復号せずにバイト列をそのまま中継する。接続できたかどうかを記録する。
/// `connected` は CONNECT に 200 を返した後か（透過プロキシなら false）。
async fn tunnel(client: Conn<TcpStream>, target: Target, connected: bool, ctx: &ProxyContext) -> Result<()> {
    let started_at_us = now_us();
    let started = Instant::now();
    let auth = authority(&target.host, target.port);
    let req_head = format!("CONNECT {auth} HTTP/1.1\r\nHost: {auth}\r\n\r\n").into_bytes();
    let mut flow = new_flow(&target, started_at_us, "CONNECT", auth, req_head, Vec::new());
    flow.source = FlowSource::Tunnel;
    if connected {
        flow.status = Some(200);
        flow.res_head = Some(CONNECT_ESTABLISHED.to_vec());
    }
    let mut up = match open(ctx, &target, true).await {
        Ok((up, _)) => up,
        Err(e) => {
            flow.duration_us = started.elapsed().as_micros() as i64;
            flow.error = Some(e.to_string());
            ctx.submit(flow);
            return Ok(());
        }
    };
    flow.duration_us = started.elapsed().as_micros() as i64;
    ctx.submit(flow);
    let Conn { io: mut client, buf } = client;
    up.write_all(&buf).await?;
    tokio::io::copy_bidirectional(&mut client, &mut up).await?;
    Ok(())
}

/// リクエストの宛先と、上流に送るヘッド・パスを決める。決められなければ None。
fn route_request(route: &Route, head: &RequestHead) -> Option<(Target, Vec<u8>, String)> {
    let forced_scheme = match route {
        Route::Fixed(t) => Some(t.scheme),
        // TLS の内側で absolute-form が来ても https のまま
        Route::ByHost { scheme: Scheme::Https, .. } => Some(Scheme::Https),
        Route::ByHost { scheme: Scheme::Http, .. } => None,
    };
    if let Some((t, path)) = parse_absolute(&head.target) {
        let t = Target { scheme: forced_scheme.unwrap_or(t.scheme), ..t };
        let wire = rewrite_target(&head.raw, &head.method, &path);
        return Some((t, wire, path));
    }
    let target = match route {
        Route::Fixed(t) => t.clone(),
        Route::ByHost { scheme, sni } => {
            let default_port = if *scheme == Scheme::Https { 443 } else { 80 };
            let host = head.headers.get("host").map(|h| String::from_utf8_lossy(h).trim().to_owned());
            let (host, port) = match host.filter(|h| !h.is_empty()) {
                Some(h) => parse_authority(&h, default_port)?,
                None => (sni.clone()?, default_port),
            };
            Target { scheme: *scheme, host, port }
        }
    };
    Some((target, head.raw.clone(), head.target.clone()))
}

pub(crate) trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

/// 上流への接続。
pub(crate) struct Upstream {
    conn: Conn<Box<dyn Io>>,
    /// 平文 HTTP を上流プロキシへ送るとき: absolute-form にして送る
    forward: Option<Forward>,
}

/// 平文 HTTP を上流プロキシへ送るときの書き換え。
struct Forward {
    /// absolute-form に入れる `host:port`（hosts で上書きしていればその IP）
    authority: String,
    /// Proxy-Authorization の値
    auth: Option<String>,
}

impl Deref for Upstream {
    type Target = Conn<Box<dyn Io>>;

    fn deref(&self) -> &Self::Target {
        &self.conn
    }
}

impl DerefMut for Upstream {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.conn
    }
}

impl Upstream {
    /// 上流へ送るリクエストヘッド。上流プロキシへ平文 HTTP を送るときは absolute-form にして認証を付ける。
    /// 記録には元のヘッドを残す（オリジンサーバへのリクエストとして見せる）。
    pub(crate) fn request_head<'a>(&self, head: &'a [u8]) -> Cow<'a, [u8]> {
        let Some(fwd) = &self.forward else { return Cow::Borrowed(head) };
        let line_end = head.iter().position(|b| *b == b'\n').map_or(head.len(), |p| p + 1);
        let line = String::from_utf8_lossy(&head[..line_end]);
        let mut parts = line.trim_end().splitn(3, ' ');
        let (method, target, version) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""), parts.next().unwrap_or("HTTP/1.1"));
        let target = if target.starts_with('/') { format!("http://{}{target}", fwd.authority) } else { target.to_string() };
        let mut out = format!("{method} {target} {version}\r\n").into_bytes();
        if let Some(a) = &fwd.auth {
            out.extend_from_slice(format!("Proxy-Authorization: {a}\r\n").as_bytes());
        }
        out.extend_from_slice(&head[line_end..]);
        Cow::Owned(out)
    }
}

/// TCP で接続する。接続先は hosts の設定で差し替える（SNI・証明書の検証は元のホスト名で行う）。
async fn dial(ctx: &ProxyContext, host: &str, port: u16) -> Result<TcpStream> {
    let pinned = ctx.interceptor.rules().resolve(host);
    let via = pinned.map(|ip| format!(" (hosts: {ip})")).unwrap_or_default();
    let dial = async {
        let addrs: Vec<SocketAddr> = match pinned {
            Some(ip) => vec![SocketAddr::new(ip, port)],
            None => tokio::net::lookup_host((host, port)).await?.collect(),
        };
        // 透過プロキシで OS の hosts ファイルを 127.0.0.1 に向けていると、上流への接続も自分に戻ってきて無限ループになる
        let (own, others): (Vec<_>, Vec<_>) = addrs.into_iter().partition(|a| ctx.is_own_listener(*a));
        if others.is_empty() && !own.is_empty() {
            return Err(ProxyError::Upstream(format!(
                "{host}:{port} は pxproxy 自身（{}）に解決されるため転送できません。透過プロキシで OS の hosts ファイルを書き換えている場合は、\
                 「診断対象 / ルール」の hosts に本来の IP を指定してください",
                own[0]
            )));
        }
        let mut last = None;
        for a in others {
            match TcpStream::connect(a).await {
                Ok(s) => return Ok(s),
                Err(e) => last = Some(e),
            }
        }
        Err(last.map_or_else(|| ProxyError::Upstream(format!("{host} を名前解決できません")), ProxyError::Io))
    };
    let tcp = tokio::time::timeout(CONNECT_TIMEOUT, dial)
        .await
        .map_err(|_| ProxyError::Upstream(format!("connect timeout {host}:{port}{via}")))??;
    let _ = tcp.set_nodelay(true);
    Ok(tcp)
}

/// 宛先へのバイト列の通り道を開く（TLS はまだ張らない）。上流プロキシを使う設定ならそれを経由する。
/// `tunnel` なら平文 HTTP でも上流プロキシに CONNECT する（TLS パススルー用）。
/// 接続の制限（同時接続数・頻度）に掛かる間はここで待つ。
async fn open(ctx: &ProxyContext, t: &Target, tunnel: bool) -> Result<(Box<dyn Io>, Option<Forward>)> {
    // 待っている間に設定が変わることがあるので、毎回読み直す
    let permit = Limiter::acquire(&ctx.limiter, || ctx.interceptor.rules().settings.limits).await;
    let rules = ctx.interceptor.rules();
    let Some(proxy) = rules.upstream_for(&t.host) else {
        let tcp = dial(ctx, &t.host, t.port).await?;
        // 接続を閉じるまで同時接続数の枠を持つ
        return Ok((Box::new(Limited { inner: tcp, _permit: permit }), None));
    };
    let tcp = dial(ctx, &proxy.host, proxy.port)
        .await
        .map_err(|e| ProxyError::Upstream(format!("上流プロキシ {}:{} に接続できません: {e}", proxy.host, proxy.port)))?;
    let io = Limited { inner: tcp, _permit: permit };
    // hosts で上書きしていれば、その IP を上流プロキシに伝える
    let host = rules.resolve(&t.host).map_or_else(|| t.host.clone(), |ip| ip.to_string());
    let dest = authority(&host, t.port);
    if t.scheme == Scheme::Http && !tunnel {
        // absolute-form では既定のポートを省く
        let authority = match (t.port, host.contains(':')) {
            (80, true) => format!("[{host}]"),
            (80, false) => host,
            _ => dest,
        };
        return Ok((Box::new(io), Some(Forward { authority, auth: proxy.auth.clone() })));
    }
    let mut req = format!("CONNECT {dest} HTTP/1.1\r\nHost: {dest}\r\n");
    if let Some(a) = &proxy.auth {
        req.push_str(&format!("Proxy-Authorization: {a}\r\n"));
    }
    req.push_str("\r\n");
    let mut conn = Conn::new(io);
    let res = tokio::time::timeout(CONNECT_TIMEOUT, async {
        conn.io.write_all(req.as_bytes()).await?;
        conn.read_response_head().await
    })
    .await
    .map_err(|_| ProxyError::Upstream(format!("上流プロキシ {}:{} が CONNECT に応答しません", proxy.host, proxy.port)))??;
    match res {
        Some(h) if (200..300).contains(&h.status) => {}
        Some(h) => {
            let line = String::from_utf8_lossy(&h.raw).lines().next().unwrap_or_default().to_string();
            return Err(ProxyError::Upstream(format!("上流プロキシが {dest} への CONNECT を拒否しました: {line}")));
        }
        None => return Err(ProxyError::Upstream("上流プロキシが CONNECT の途中で切断しました".into())),
    }
    let Conn { io, buf } = conn;
    let io: Box<dyn Io> = if buf.is_empty() { Box::new(io) } else { Box::new(Prefixed { prefix: buf, inner: io }) };
    Ok((io, None))
}

/// 上流へ接続する（HTTPS なら TLS まで張る）。
pub(crate) async fn connect(ctx: &ProxyContext, t: &Target) -> Result<Upstream> {
    let (io, forward) = open(ctx, t, false).await?;
    let io: Box<dyn Io> = match t.scheme {
        Scheme::Http => io,
        Scheme::Https => {
            let name = ServerName::try_from(t.host.clone())?;
            Box::new(TlsConnector::from(ctx.client_tls.clone()).connect(name, io).await?)
        }
    };
    Ok(Upstream { conn: Conn::new(io), forward })
}

pub(crate) fn now_us() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_micros() as i64).unwrap_or(0)
}

/// 上流の最終レスポンスのヘッドを読む。1xx（101 以外）はクライアントへ中継して読み飛ばす。
async fn read_final_head<S: AsyncWrite + Unpin>(up: &mut Upstream, client: &mut S) -> Result<Option<ResponseHead>> {
    loop {
        match up.read_response_head().await? {
            Some(h) if (100..200).contains(&h.status) && h.status != 101 => client.write_all(&h.raw).await?,
            other => return Ok(other),
        }
    }
}

/// 1 クライアント接続上のリクエストを順に処理する（keep-alive 対応）。
async fn serve<S>(
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
        let client_close = head.headers.has_token("connection", "close")
            || head.headers.has_token("proxy-connection", "close")
            || (head.minor_version == 0 && !head.headers.has_token("connection", "keep-alive"))
            || client_res_kind == BodyKind::UntilClose;
        if client_close {
            let _ = client.io.shutdown().await;
            return Ok(());
        }
    }
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

/// 先読みしたバイト列を先に返すストリーム（CONNECT 後の TLS 判定用）。
struct Prefixed<S> {
    prefix: BytesMut,
    inner: S,
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if !self.prefix.is_empty() {
            let n = self.prefix.len().min(buf.remaining());
            let chunk = self.prefix.split_to(n);
            buf.put_slice(&chunk);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absolute_form() {
        let (t, p) = parse_absolute("http://example.com:8080?q=1").unwrap();
        assert_eq!((t.host.as_str(), t.port, p.as_str()), ("example.com", 8080, "/?q=1"));
        let (t, p) = parse_absolute("http://[::1]/a/b").unwrap();
        assert_eq!((t.host.as_str(), t.port, p.as_str()), ("::1", 80, "/a/b"));
    }

    async fn head(raw: &str) -> RequestHead {
        Conn::new(raw.as_bytes()).read_request_head().await.unwrap().unwrap()
    }

    fn routed(route: &Route, h: &RequestHead) -> Option<(Scheme, String, u16, String)> {
        route_request(route, h).map(|(t, _, path)| (t.scheme, t.host, t.port, path))
    }

    #[tokio::test]
    async fn transparent_routing() {
        let https = |sni: Option<&str>| Route::ByHost { scheme: Scheme::Https, sni: sni.map(Into::into) };
        let http = Route::ByHost { scheme: Scheme::Http, sni: None };
        let h = head("GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n").await;
        // ポート省略時は scheme の既定ポート
        assert_eq!(routed(&https(None), &h), Some((Scheme::Https, "example.com".into(), 443, "/a".into())));
        assert_eq!(routed(&http, &h), Some((Scheme::Http, "example.com".into(), 80, "/a".into())));
        let h = head("GET /a HTTP/1.1\r\nHost: example.com:8443\r\n\r\n").await;
        assert_eq!(routed(&https(Some("other")), &h).unwrap().2, 8443, "Host のポートを使う");
        // Host が無ければ SNI。どちらも無ければ決められない
        let h = head("GET /a HTTP/1.0\r\n\r\n").await;
        assert_eq!(routed(&https(Some("sni.test")), &h), Some((Scheme::Https, "sni.test".into(), 443, "/a".into())));
        assert_eq!(routed(&https(None), &h), None);
        assert_eq!(routed(&http, &h), None);
        // TLS の内側の absolute-form は https のまま
        let h = head("GET http://example.com/x HTTP/1.1\r\nHost: example.com\r\n\r\n").await;
        assert_eq!(routed(&https(None), &h).unwrap().0, Scheme::Https);
        assert_eq!(routed(&http, &h).unwrap().0, Scheme::Http);
    }

    #[test]
    fn sni_from_client_hello() {
        // rustls で実際の ClientHello を作って読む
        let cfg = crate::tls::client_config().unwrap();
        let name = ServerName::try_from("pass.example.com").unwrap();
        let mut conn = rustls::ClientConnection::new(Arc::new(cfg), name).unwrap();
        let mut hello = Vec::new();
        conn.write_tls(&mut hello).unwrap();
        assert_eq!(client_hello_sni(&hello), Sni::Found("pass.example.com".into()));
        assert_eq!(client_hello_sni(&hello[..hello.len() - 1]), Sni::Incomplete);
        assert_eq!(client_hello_sni(&hello[..3]), Sni::Incomplete);
        assert_eq!(client_hello_sni(b"GET / HTTP/1.1\r\n"), Sni::Absent);
    }

    #[test]
    fn forward_head_for_upstream_proxy() {
        let io = || Box::new(tokio::io::duplex(1).0) as Box<dyn Io>;
        let up = Upstream {
            conn: Conn::new(io()),
            forward: Some(Forward { authority: "example.com:8080".into(), auth: Some("Basic dTpw".into()) }),
        };
        let out = up.request_head(b"GET /a?b HTTP/1.1\r\nHost: example.com:8080\r\n\r\n");
        assert_eq!(
            &out[..],
            b"GET http://example.com:8080/a?b HTTP/1.1\r\nProxy-Authorization: Basic dTpw\r\nHost: example.com:8080\r\n\r\n"
        );
        let direct = Upstream { conn: Conn::new(io()), forward: None };
        assert!(matches!(direct.request_head(b"GET / HTTP/1.1\r\n\r\n"), Cow::Borrowed(_)));
    }
}
