//! 上流への接続（hosts の差し替え・上流プロキシ経由・接続の制限・TLS）。

use std::borrow::Cow;
use std::net::SocketAddr;
use std::ops::{Deref, DerefMut};
use std::time::Duration;

use rustls::pki_types::ServerName;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use super::stream::{Io, Prefixed};
use super::target::{Scheme, Target, authority};
use crate::http1::{Conn, ResponseHead};
use crate::limit::{Limited, Limiter};
use crate::{ProxyContext, ProxyError, Result};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// 上流への接続。
pub(crate) struct Upstream {
    pub(super) conn: Conn<Box<dyn Io>>,
    /// 平文 HTTP を上流プロキシへ送るとき: absolute-form にして送る
    forward: Option<Forward>,
}

/// 平文 HTTP を上流プロキシへ送るときの書き換え。
pub(super) struct Forward {
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
pub(super) async fn open(ctx: &ProxyContext, t: &Target, tunnel: bool) -> Result<(Box<dyn Io>, Option<Forward>)> {
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

/// 上流の最終レスポンスのヘッドを読む。1xx（101 以外）はクライアントへ中継して読み飛ばす。
pub(super) async fn read_final_head<S: AsyncWrite + Unpin>(up: &mut Upstream, client: &mut S) -> Result<Option<ResponseHead>> {
    loop {
        match up.read_response_head().await? {
            Some(h) if (100..200).contains(&h.status) && h.status != 101 => client.write_all(&h.raw).await?,
            other => return Ok(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
