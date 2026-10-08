//! Repeater: 手で編集したリクエストを 1 回だけ送り、結果を History に記録して返す。
//! Intercept は通さない。接続は毎回張り直す（前の送信の状態を持ち越さない）。

use std::fmt;
use std::time::{Duration, Instant};

use px_store::{FlowSource, NewFlow};
use tokio::io::AsyncWriteExt;

use crate::http1::{BodyKind, rebuild_message};
use crate::server::{Scheme, Target, connect, new_flow, now_us, parse_absolute, parse_authority, parse_edited_request};
use crate::{ProxyContext, ProxyError, Result};

/// 接続から応答の読み終わりまでの上限
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(60);

/// 送信先。`https://example.com:8443` / `http://[::1]` / `example.com`（https とみなす）の形で書く。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    pub https: bool,
    pub host: String,
    pub port: u16,
}

impl Origin {
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim().trim_end_matches('/');
        let (https, auth) = match s.split_once("://") {
            Some((scheme, rest)) if scheme.eq_ignore_ascii_case("https") => (true, rest),
            Some((scheme, rest)) if scheme.eq_ignore_ascii_case("http") => (false, rest),
            Some(_) => return None,
            None => (true, s),
        };
        let (host, port) = parse_authority(auth, if https { 443 } else { 80 })?;
        (!host.is_empty() && !host.contains(['/', ' '])).then_some(Self { https, host, port })
    }

    fn target(&self) -> Target {
        Target { scheme: if self.https { Scheme::Https } else { Scheme::Http }, host: self.host.clone(), port: self.port }
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let scheme = if self.https { "https" } else { "http" };
        let host = if self.host.contains(':') { format!("[{}]", self.host) } else { self.host.clone() };
        let default_port = if self.https { 443 } else { 80 };
        if self.port == default_port {
            write!(f, "{scheme}://{host}")
        } else {
            write!(f, "{scheme}://{host}:{}", self.port)
        }
    }
}

pub struct RepeatRequest {
    pub origin: Origin,
    /// UI で編集したヘッド（改行は LF でもよい）
    pub head: Vec<u8>,
    /// Transfer-Encoding を外した Body
    pub body: Vec<u8>,
    /// Content-Length を Body に合わせる
    pub fix_content_length: bool,
}

impl ProxyContext {
    /// リクエストを送って結果のフローを返す。送れたもの（失敗含む）は History にも記録する。
    /// ヘッドが解析できず送らなかった場合だけ Err。
    pub async fn repeat(&self, req: RepeatRequest) -> Result<NewFlow> {
        let rb = rebuild_message(&req.head, &req.body, true, req.fix_content_length);
        let head = parse_edited_request(&rb.head).await?;
        let target = req.origin.target();
        let path = parse_absolute(&head.target).map_or_else(|| head.target.clone(), |(_, p)| p);
        let mut flow = new_flow(&target, now_us(), &head.method, path, rb.head.clone(), req.body);
        flow.source = FlowSource::Repeater;

        let started = Instant::now();
        let result = tokio::time::timeout(EXCHANGE_TIMEOUT, async {
            let mut up = connect(self, &target).await?;
            let wire = up.request_head(&rb.head).into_owned();
            up.io.write_all(&wire).await?;
            up.io.write_all(&rb.body_wire).await?;
            up.io.flush().await?;
            // 1xx（101 以外）は読み飛ばす
            let res_head = loop {
                match up.read_response_head().await? {
                    Some(h) if (100..200).contains(&h.status) && h.status != 101 => {}
                    Some(h) => break h,
                    None => return Err(ProxyError::Upstream("connection closed before response".into())),
                }
            };
            flow.status = Some(res_head.status);
            flow.res_head = Some(res_head.raw.clone());
            let body = up.read_body(BodyKind::for_response(&res_head, &head.method)?).await?;
            flow.res_body = body.decoded.unwrap_or(body.raw);
            Ok(())
        })
        .await
        .unwrap_or_else(|_| Err(ProxyError::Upstream(format!("timeout ({}s)", EXCHANGE_TIMEOUT.as_secs()))));

        flow.duration_us = started.elapsed().as_micros() as i64;
        if let Err(e) = result {
            flow.error = Some(e.to_string());
        }
        self.submit(flow.clone());
        Ok(flow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_parse_and_display() {
        let o = Origin::parse("https://example.com:8443/").unwrap();
        assert_eq!((o.https, o.host.as_str(), o.port), (true, "example.com", 8443));
        assert_eq!(o.to_string(), "https://example.com:8443");
        let o = Origin::parse("http://[::1]").unwrap();
        assert_eq!((o.https, o.host.as_str(), o.port), (false, "::1", 80));
        assert_eq!(o.to_string(), "http://[::1]");
        assert_eq!(Origin::parse("example.com").unwrap().to_string(), "https://example.com");
        assert!(Origin::parse("ftp://x").is_none());
        assert!(Origin::parse("http://x:notaport").is_none());
        assert!(Origin::parse("https://x/path").is_none());
    }
}
