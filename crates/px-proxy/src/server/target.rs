//! 上流の宛先（scheme・ホスト・ポート）の解釈と、リクエストごとの宛先の決定。

use crate::http1::{RequestHead, rewrite_target};

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
pub(super) fn authority(host: &str, port: u16) -> String {
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

/// 上流の宛先の決め方。
#[derive(Debug, Clone)]
pub(super) enum Route {
    /// CONNECT で宛先が決まっている
    Fixed(Target),
    /// absolute-form ならその URL、それ以外は Host ヘッダ（無ければ SNI）から決める。
    /// 通常の平文プロキシ要求と、透過プロキシ（CONNECT 無し）の接続で使う。
    ByHost { scheme: Scheme, sni: Option<String> },
}

/// リクエストの宛先と、上流に送るヘッド・パスを決める。決められなければ None。
pub(super) fn route_request(route: &Route, head: &RequestHead) -> Option<(Target, Vec<u8>, String)> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http1::Conn;

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
}
