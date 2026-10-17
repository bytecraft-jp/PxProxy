//! 待ち受けと、接続ごとの振り分け（CONNECT・透過プロキシ・TLS の終端 / パススルー）。
//! 1 接続上のリクエストの中継は `exchange`、上流への接続は `upstream` が受け持つ。

mod exchange;
mod sni;
mod stream;
mod target;
mod upstream;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use px_store::FlowSource;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};
use tokio_rustls::LazyConfigAcceptor;

pub(crate) use exchange::{new_flow, now_us, parse_edited_request};
pub(crate) use target::{Scheme, Target, parse_absolute, parse_authority};
pub(crate) use upstream::connect;

use exchange::serve;
use sni::{TLS_HANDSHAKE, peek_sni};
use stream::Prefixed;
use target::{Route, authority};
use upstream::open;
use crate::http1::Conn;
use crate::{ProxyContext, ProxyError, Result};

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
