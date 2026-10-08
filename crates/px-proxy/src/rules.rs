//! 案件ごとの設定（Scope / Intercept ルール / hosts / 接続の制限 / 上流プロキシ / TLS パススルー）とその判定。
//! 設定は案件フォルダの settings.toml に保存される（保存は UI 側）。

use std::net::IpAddr;

use px_store::FlowKind;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// Scope の 1 行。`host` は `*` / `?` のワイルドカード（例: `*.example.com`）、
/// `path` は前方一致（`*` 可、空なら全パス）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ScopeRule {
    pub enabled: bool,
    pub host: String,
    pub path: String,
}

impl Default for ScopeRule {
    fn default() -> Self {
        Self { enabled: true, host: String::new(), path: String::new() }
    }
}

impl ScopeRule {
    fn is_active(&self) -> bool {
        self.enabled && !self.host.trim().is_empty()
    }

    fn matches(&self, host: &str, path: &str) -> bool {
        if !self.is_active() || !glob(&self.host.trim().to_ascii_lowercase(), &host.to_ascii_lowercase()) {
            return false;
        }
        let p = self.path.trim();
        p.is_empty() || glob(&format!("{p}*"), path)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Scope {
    pub include: Vec<ScopeRule>,
    pub exclude: Vec<ScopeRule>,
}

impl Scope {
    /// 有効な include が 1 つも無ければ全ホストが Scope 内。exclude は常に優先。
    pub fn contains(&self, host: &str, path: &str) -> bool {
        let included = !self.has_include() || self.include.iter().any(|r| r.matches(host, path));
        included && !self.exclude.iter().any(|r| r.matches(host, path))
    }

    pub fn has_include(&self) -> bool {
        self.include.iter().any(ScopeRule::is_active)
    }
}

/// Intercept の条件。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct InterceptRules {
    /// Scope 内のものだけ止める
    pub only_in_scope: bool,
    /// 止めない種類（FlowKind のビット和）
    pub skip_kinds: u32,
    /// URL（scheme://host:port/path）がこの正規表現に一致するものだけ止める。空なら全て。
    pub url_regex: String,
    /// レスポンスもルールで止める（個別指定とは別）
    pub responses: bool,
    /// レスポンスの Content-Type に含まれる文字列（カンマ区切り、空なら全て）
    pub response_content_types: String,
    /// Body を編集したら Content-Length / chunked を付け直す
    pub fix_content_length: bool,
    /// 止めたときに Intercept タブへ切り替える（UI 用）
    pub switch_to_tab: bool,
}

impl Default for InterceptRules {
    fn default() -> Self {
        Self {
            only_in_scope: true,
            skip_kinds: FlowKind::Css.bit() | FlowKind::Image.bit() | FlowKind::Font.bit() | FlowKind::Media.bit(),
            url_regex: String::new(),
            responses: false,
            response_content_types: String::new(),
            fix_content_length: true,
            switch_to_tab: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ProjectSettings {
    pub scope: Scope,
    pub intercept: InterceptRules,
    /// hosts ファイルと同じ書式の名前解決の上書き（`IP ホスト名…`、`#` 以降はコメント）
    pub hosts: String,
    pub limits: ConnectionLimits,
    pub upstream: UpstreamProxy,
    /// TLS を復号せずにそのまま中継するホスト（空白・改行区切りのワイルドカード、`#` 以降はコメント）
    pub tls_passthrough: String,
    /// 記録する Body の上限（MB）。超えた分は記録せずに転送だけする
    pub max_record_body_mb: u32,
}

impl Default for ProjectSettings {
    fn default() -> Self {
        Self {
            scope: Scope::default(),
            intercept: InterceptRules::default(),
            hosts: String::new(),
            limits: ConnectionLimits::default(),
            upstream: UpstreamProxy::default(),
            tls_passthrough: String::new(),
            max_record_body_mb: DEFAULT_MAX_RECORD_BODY_MB,
        }
    }
}

pub const DEFAULT_MAX_RECORD_BODY_MB: u32 = 32;

/// 上流プロキシ（社内プロキシなど）。HTTPS は CONNECT で、平文 HTTP は absolute-form で送る。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UpstreamProxy {
    pub enabled: bool,
    /// `host:port`（`http://` は付けても付けなくてもよい）
    pub address: String,
    /// Basic 認証。空なら認証しない
    pub username: String,
    pub password: String,
    /// 上流プロキシを通さず直接つなぐホスト（空白・改行区切りのワイルドカード、`#` 以降はコメント）
    pub bypass: String,
}

impl Default for UpstreamProxy {
    fn default() -> Self {
        Self {
            enabled: false,
            address: String::new(),
            username: String::new(),
            password: String::new(),
            bypass: "localhost 127.0.0.1 ::1".into(),
        }
    }
}

/// 解析済みの上流プロキシ。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyAddr {
    pub host: String,
    pub port: u16,
    /// `Proxy-Authorization` の値（`Basic …`）
    pub auth: Option<String>,
}

impl UpstreamProxy {
    /// 有効なら解析した宛先。無効なら Ok(None)、書式が不正なら Err。
    pub fn parse(&self) -> Result<Option<ProxyAddr>, String> {
        if !self.enabled {
            return Ok(None);
        }
        let addr = self.address.trim();
        let addr = addr.strip_prefix("http://").unwrap_or(addr).trim_end_matches('/');
        if addr.is_empty() {
            return Err("上流プロキシのアドレスを入力してください".into());
        }
        let (host, port) = match crate::server::parse_authority(addr, 0) {
            Some((h, p)) if !h.is_empty() && p != 0 && !h.contains(['/', ' ', '@']) => (h, p),
            _ => return Err(format!("上流プロキシのアドレスは host:port の形で指定してください: {addr}")),
        };
        let auth = (!self.username.is_empty())
            .then(|| format!("Basic {}", base64(format!("{}:{}", self.username, self.password).as_bytes())));
        Ok(Some(ProxyAddr { host, port, auth }))
    }
}

/// 空白・改行・カンマ区切りのホストのワイルドカード一覧（`#` 以降はコメント、小文字化）。
pub fn parse_host_list(text: &str) -> Vec<String> {
    text.lines()
        .flat_map(|l| l.split('#').next().unwrap_or("").split([' ', '\t', ',']))
        .map(|w| w.trim().to_ascii_lowercase())
        .filter(|w| !w.is_empty())
        .collect()
}

fn base64(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |acc, (i, b)| acc | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(TABLE[(n >> (18 - 6 * i)) as usize & 63] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// 上流への接続の制限（ルータの IP フラッド検出などに引っ掛からないようにする）。0 は無制限。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ConnectionLimits {
    /// 同時に開いておく上流接続の上限
    pub max_connections: u32,
    /// 1 秒あたりに新しく張る上流接続の上限（等間隔に出す）
    pub max_new_per_sec: u32,
}

/// hosts の 1 エントリ。`host` は小文字化したワイルドカード（`*` / `?`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostEntry {
    pub host: String,
    pub addr: IpAddr,
}

/// hosts の書式を解析する。不正な行は飛ばし、行番号付きのメッセージを返す。
pub fn parse_hosts(text: &str) -> (Vec<HostEntry>, Vec<String>) {
    let mut entries = Vec::new();
    let mut errors = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("");
        let mut words = line.split_whitespace();
        let Some(addr) = words.next() else { continue };
        let Ok(addr) = addr.trim_start_matches('[').trim_end_matches(']').parse::<IpAddr>() else {
            errors.push(format!("{} 行目: IP アドレスではありません: {addr}", i + 1));
            continue;
        };
        let before = entries.len();
        entries.extend(words.map(|h| HostEntry { host: h.to_ascii_lowercase(), addr }));
        if entries.len() == before {
            errors.push(format!("{} 行目: ホスト名がありません", i + 1));
        }
    }
    (entries, errors)
}

/// 判定用にコンパイル済みの設定。
#[derive(Debug, Default)]
pub struct CompiledRules {
    pub settings: ProjectSettings,
    url_regex: Option<Regex>,
    hosts: Vec<HostEntry>,
    upstream: Option<ProxyAddr>,
    bypass: Vec<String>,
    passthrough: Vec<String>,
}

impl CompiledRules {
    /// 正規表現が不正ならエラーメッセージも返す（その条件は無視される）。
    /// 上流プロキシの指定が不正なら上流プロキシは使わない（`UpstreamProxy::parse` で理由が分かる）。
    pub fn compile(settings: ProjectSettings) -> (Self, Option<String>) {
        let pattern = settings.intercept.url_regex.trim();
        let (url_regex, err) = if pattern.is_empty() {
            (None, None)
        } else {
            match Regex::new(pattern) {
                Ok(r) => (Some(r), None),
                Err(e) => (None, Some(format!("URL 正規表現が不正です: {e}"))),
            }
        };
        let hosts = parse_hosts(&settings.hosts).0;
        let upstream = settings.upstream.parse().ok().flatten();
        let bypass = parse_host_list(&settings.upstream.bypass);
        let passthrough = parse_host_list(&settings.tls_passthrough);
        (Self { settings, url_regex, hosts, upstream, bypass, passthrough }, err)
    }

    /// `host` へつなぐときに通す上流プロキシ。使わないなら None。
    pub fn upstream_for(&self, host: &str) -> Option<&ProxyAddr> {
        let host = host.to_ascii_lowercase();
        self.upstream.as_ref().filter(|_| !self.bypass.iter().any(|b| glob(b, &host)))
    }

    /// TLS を復号せずに中継するホストか（CONNECT のホストか SNI のどちらかが一致すれば）。
    pub fn passthrough(&self, hosts: &[&str]) -> bool {
        hosts.iter().any(|h| {
            let h = h.to_ascii_lowercase();
            self.passthrough.iter().any(|p| glob(p, &h))
        })
    }

    pub fn has_passthrough(&self) -> bool {
        !self.passthrough.is_empty()
    }

    /// 記録する Body の上限（バイト）。
    pub fn max_record_body(&self) -> usize {
        (self.settings.max_record_body_mb.max(1) as usize).saturating_mul(1024 * 1024)
    }

    /// hosts で上書きした接続先。最初に一致した行が優先（hosts ファイルと同じ）。
    pub fn resolve(&self, host: &str) -> Option<IpAddr> {
        let host = host.to_ascii_lowercase();
        self.hosts.iter().find(|e| glob(&e.host, &host)).map(|e| e.addr)
    }

    pub fn in_scope(&self, host: &str, path: &str) -> bool {
        self.settings.scope.contains(host, path)
    }

    fn scoped(&self, host: &str, path: &str) -> bool {
        !self.settings.intercept.only_in_scope || self.in_scope(host, path)
    }

    pub fn request_matches(&self, url: &str, host: &str, path: &str, kind: FlowKind) -> bool {
        let r = &self.settings.intercept;
        self.scoped(host, path)
            && r.skip_kinds & kind.bit() == 0
            && self.url_regex.as_ref().is_none_or(|re| re.is_match(url))
    }

    pub fn response_matches(&self, host: &str, path: &str, kind: FlowKind, content_type: Option<&str>) -> bool {
        let r = &self.settings.intercept;
        if !r.responses || !self.scoped(host, path) || r.skip_kinds & kind.bit() != 0 {
            return false;
        }
        let wanted: Vec<String> = r
            .response_content_types
            .split(',')
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        wanted.is_empty() || content_type.is_some_and(|ct| wanted.iter().any(|w| ct.contains(w.as_str())))
    }

    pub fn fix_content_length(&self) -> bool {
        self.settings.intercept.fix_content_length
    }
}

/// `*`（任意の文字列）と `?`（任意の 1 文字）のワイルドカード一致。
pub fn glob(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some((pi, ti));
            pi += 1;
        } else if let Some((sp, st)) = star {
            pi = sp + 1;
            ti = st + 1;
            star = Some((sp, st + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|c| *c == '*')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(host: &str, path: &str) -> ScopeRule {
        ScopeRule { enabled: true, host: host.into(), path: path.into() }
    }

    #[test]
    fn glob_matches() {
        assert!(glob("*.example.com", "api.example.com"));
        assert!(!glob("*.example.com", "example.com"));
        assert!(glob("ex?mple.*", "example.org"));
        assert!(glob("/api/*", "/api/v1/users"));
        assert!(!glob("/api/*", "/static/a.js"));
    }

    #[test]
    fn scope_include_exclude() {
        let mut s = Scope::default();
        assert!(s.contains("anything", "/"), "empty include = everything");
        s.include.push(rule("*.example.com", ""));
        s.include.push(rule("example.org", "/api"));
        s.exclude.push(rule("cdn.example.com", ""));
        assert!(s.contains("API.Example.com", "/x"));
        assert!(!s.contains("cdn.example.com", "/x"));
        assert!(s.contains("example.org", "/api/v1"));
        assert!(!s.contains("example.org", "/static"));
        assert!(!s.contains("other.net", "/"));
    }

    #[test]
    fn intercept_conditions() {
        let mut settings = ProjectSettings::default();
        settings.scope.include.push(rule("target.test", ""));
        settings.intercept.url_regex = "/api/".into();
        let (r, err) = CompiledRules::compile(settings.clone());
        assert!(err.is_none());
        assert!(r.request_matches("https://target.test:443/api/x", "target.test", "/api/x", FlowKind::Xhr));
        assert!(!r.request_matches("https://target.test:443/page", "target.test", "/page", FlowKind::Html));
        assert!(!r.request_matches("https://other.test:443/api/x", "other.test", "/api/x", FlowKind::Xhr));
        assert!(!r.request_matches("https://target.test:443/api/a.png", "target.test", "/api/a.png", FlowKind::Image));

        settings.intercept.responses = true;
        settings.intercept.response_content_types = "html, json".into();
        let (r, _) = CompiledRules::compile(settings.clone());
        assert!(r.response_matches("target.test", "/", FlowKind::Html, Some("text/html")));
        assert!(!r.response_matches("target.test", "/", FlowKind::Script, Some("text/javascript")));

        settings.intercept.url_regex = "(".into();
        assert!(CompiledRules::compile(settings).1.is_some());
    }

    #[test]
    fn upstream_and_passthrough() {
        let mut settings = ProjectSettings::default();
        settings.upstream.enabled = true;
        settings.upstream.address = "http://proxy.corp:3128/".into();
        settings.upstream.username = "user".into();
        settings.upstream.password = "pa:ss".into();
        settings.upstream.bypass.push_str("\n*.internal  # 社内");
        settings.tls_passthrough = "*.apple.com\nupdate.example.com, # コメント".into();
        let (r, err) = CompiledRules::compile(settings.clone());
        assert!(err.is_none(), "{err:?}");
        let up = r.upstream_for("example.com").unwrap();
        assert_eq!((up.host.as_str(), up.port), ("proxy.corp", 3128));
        assert_eq!(up.auth.as_deref(), Some("Basic dXNlcjpwYTpzcw=="));
        assert!(r.upstream_for("LOCALHOST").is_none() && r.upstream_for("a.internal").is_none());
        assert!(r.passthrough(&["x.apple.com"]) && r.passthrough(&["10.0.0.1", "Update.Example.com"]));
        assert!(!r.passthrough(&["apple.com"]));

        settings.upstream.address = "proxy.corp".into();
        assert!(settings.upstream.parse().is_err());
        let (r, _) = CompiledRules::compile(settings);
        assert!(r.upstream_for("example.com").is_none(), "ポートが無ければ使わない");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b""), "");
    }

    #[test]
    fn hosts_override() {
        let text = "# comment\n127.0.0.1  a.test B.test  # trailing\n\n::1 *.v6.test\n10.0.0.1 a.test\nbad x.test\n192.0.2.1\n";
        let (entries, errors) = parse_hosts(text);
        assert_eq!(entries.len(), 4);
        assert_eq!(errors.len(), 2, "{errors:?}");
        assert!(errors[0].starts_with("6 行目") && errors[1].starts_with("7 行目"));

        let settings = ProjectSettings { hosts: text.into(), ..Default::default() };
        let (r, _) = CompiledRules::compile(settings);
        let ip = |s: &str| Some(s.parse::<IpAddr>().unwrap());
        assert_eq!(r.resolve("A.test"), ip("127.0.0.1"), "first match wins");
        assert_eq!(r.resolve("b.test"), ip("127.0.0.1"));
        assert_eq!(r.resolve("api.v6.test"), ip("::1"));
        assert_eq!(r.resolve("other.test"), None);
    }
}
