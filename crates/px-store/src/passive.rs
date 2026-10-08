//! パッシブチェック: 記録した通信を眺めるだけで分かる問題（ヘッダの欠落・Cookie の属性・
//! エラーメッセージの露出など）を印付けする。通信は送らない。
//! writer スレッドで実行するので、プロキシの転送は待たせない。

use std::net::Ipv4Addr;
use std::sync::LazyLock;

use regex::Regex;

use crate::classify::content_type;
use crate::decode::{decode_content, header, headers};

/// 重要度。値は DB に保存するので変更しないこと（大きいほど重い）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Severity {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
}

impl Severity {
    pub const ALL: [Severity; 4] = [Self::High, Self::Medium, Self::Low, Self::Info];

    pub fn from_i64(v: i64) -> Self {
        match v {
            3 => Self::High,
            2 => Self::Medium,
            1 => Self::Low,
            _ => Self::Info,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::High => "高",
            Self::Medium => "中",
            Self::Low => "低",
            Self::Info => "情報",
        }
    }
}

/// チェックの種類。`id` は DB に保存する。
#[derive(Debug, PartialEq, Eq)]
pub struct Check {
    pub id: &'static str,
    pub title: &'static str,
    pub severity: Severity,
    pub description: &'static str,
}

macro_rules! checks {
    ($($name:ident = ($id:literal, $sev:ident, $title:literal, $desc:literal);)*) => {
        $(const $name: &Check = &Check { id: $id, title: $title, severity: Severity::$sev, description: $desc };)*
        /// すべてのチェック
        pub const CHECKS: &[&Check] = &[$($name),*];
    };
}

checks! {
    SQL_ERROR = ("sql-error", Medium, "SQL のエラーメッセージ",
        "レスポンスにデータベースのエラーメッセージが含まれています。SQL インジェクションの手掛かりになります。");
    PASSWORD_OVER_HTTP = ("password-over-http", Medium, "パスワードを平文 HTTP で送受信",
        "パスワード入力欄のあるページ、またはパスワードらしきパラメータを HTTPS を使わずにやり取りしています。");
    BASIC_AUTH_HTTP = ("basic-auth-http", Medium, "Basic 認証を平文 HTTP で送信",
        "Authorization: Basic ヘッダを HTTPS を使わずに送っています。資格情報が盗聴されます。");
    CORS_REFLECT = ("cors-reflect-credentials", Medium, "CORS: 任意のオリジンを資格情報付きで許可",
        "Access-Control-Allow-Origin がリクエストの Origin（別オリジン）をそのまま返し、Access-Control-Allow-Credentials: true です。");
    ERROR_MESSAGE = ("error-message", Low, "エラーメッセージ・スタックトレースの露出",
        "レスポンスに例外やスタックトレース、言語処理系のエラーが含まれています。内部構成の手掛かりになります。");
    COOKIE_NO_SECURE = ("cookie-no-secure", Low, "Cookie に Secure 属性がない",
        "HTTPS で発行した Cookie に Secure 属性がなく、平文 HTTP の通信でも送られます。");
    COOKIE_NO_HTTPONLY = ("cookie-no-httponly", Low, "Cookie に HttpOnly 属性がない",
        "JavaScript から読める Cookie です。セッション Cookie なら XSS で盗まれます。");
    HSTS_MISSING = ("hsts-missing", Low, "Strict-Transport-Security がない",
        "HTTPS の HTML レスポンスに HSTS ヘッダがありません。");
    CLICKJACKING = ("clickjacking", Low, "フレーム埋め込みの制限がない",
        "HTML レスポンスに X-Frame-Options も CSP の frame-ancestors もありません（クリックジャッキング）。");
    SENSITIVE_QUERY = ("sensitive-query", Low, "URL に機密らしきパラメータ",
        "パスワードやトークンらしきパラメータが URL のクエリに含まれています。ログや Referer に残ります。");
    DIRECTORY_LISTING = ("directory-listing", Low, "ディレクトリ一覧",
        "Web サーバのディレクトリ一覧が表示されています。");
    COOKIE_NO_SAMESITE = ("cookie-no-samesite", Info, "Cookie に SameSite 属性がない",
        "SameSite 属性のない Cookie です（ブラウザの既定は Lax）。");
    CSP_MISSING = ("csp-missing", Info, "Content-Security-Policy がない",
        "HTML レスポンスに CSP がありません。");
    NOSNIFF_MISSING = ("nosniff-missing", Info, "X-Content-Type-Options: nosniff がない",
        "Content-Type の推測（MIME スニッフィング）を止めていません。");
    SERVER_VERSION = ("server-version", Info, "ソフトウェアのバージョンを開示",
        "Server / X-Powered-By などのヘッダにバージョン番号が含まれています。");
    CORS_WILDCARD = ("cors-wildcard", Info, "CORS: すべてのオリジンを許可",
        "Access-Control-Allow-Origin: * です。公開してよいデータか確認してください。");
    PRIVATE_IP = ("private-ip", Info, "プライベート IP アドレスの露出",
        "レスポンスに内部ネットワークの IP アドレスが含まれています。");
}

pub fn check(id: &str) -> Option<&'static Check> {
    CHECKS.iter().copied().find(|c| c.id == id)
}

/// 1 件の検出結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub check: &'static Check,
    /// 何が見つかったか（Cookie 名・一致した文字列など）
    pub detail: String,
}

/// チェックに渡す 1 往復分。Body は Transfer-Encoding を外したもの（Content-Encoding はそのまま）。
pub struct Exchange<'a> {
    pub scheme: &'a str,
    pub host: &'a str,
    pub method: &'a str,
    pub target: &'a str,
    pub req_head: &'a [u8],
    pub req_body: &'a [u8],
    pub res_head: Option<&'a [u8]>,
    pub res_body: &'a [u8],
}

/// 本文を調べる上限（展開後）
const MAX_SCAN_BODY: usize = 2 * 1024 * 1024;
/// detail に入れる一致箇所の長さの上限
const MAX_SNIPPET: usize = 160;

static SQL_ERROR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i)(you have an error in your sql syntax|warning: mysqli?_|mysql_fetch_|valid mysql result",
        r"|unclosed quotation mark after the character string|microsoft ole db provider for (?:sql server|odbc)",
        r"|\[odbc [^\]]*driver|odbc (?:sql server )?driver|sqlstate\[\w+\]|pg_query\(\)|psql: error|postgresql query failed",
        r"|syntax error at or near|ora-\d{5}|quoted string not properly terminated|sqlite3?::|sqlite_error",
        r"|near \x22[^\x22]{1,40}\x22: syntax error|db2 sql error|sybase message|jdbc\.\w+exception|org\.hibernate\.\w+exception)"
    ))
    .expect("valid regex")
});

static ERROR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(Traceback \(most recent call last\)|Exception in thread \x22|\bat (?:java|javax|org\.springframework|org\.apache)\.[\w$.]+\([\w$]+\.java:\d+\)",
        r"|(?:PHP )?(?:Fatal error|Parse error|Warning|Notice): .{1,200}? in .{1,200}? on line \d+",
        r"|System\.\w+Exception: |   at System\.[\w.`]+\(|Server Error in '[^']*' Application",
        r"|\bat [\w$.]+ \((?:/|[A-Za-z]:\\)[^)]+\.js:\d+:\d+\)|Whoops, looks like something went wrong",
        r"|ActionController::\w+|\(most recent call last\)|java\.lang\.\w+(?:Exception|Error)",
        r"|Microsoft \.NET Framework Version:|<b>Warning</b>:  .{1,200}? in <b>)"
    ))
    .expect("valid regex")
});

static PRIVATE_IP_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:10|172|192)\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").expect("valid regex")
});

static LISTING_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(<title>\s*Index of /|<h1>\s*Index of /|<title>\s*Directory Listing For|\[To Parent Directory\])")
        .expect("valid regex")
});

static PASSWORD_INPUT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)<input[^>]+type\s*=\s*["']?password"#).expect("valid regex"));

/// クエリ・フォームのパラメータ名で機密らしいもの
const SENSITIVE_PARAMS: &[&str] = &[
    "password", "passwd", "pwd", "pass", "passphrase", "secret", "client_secret", "token", "access_token",
    "refresh_token", "id_token", "api_key", "apikey", "auth", "session", "sessionid", "sid", "jsessionid",
    "phpsessid",
];

/// 1 往復を調べる。同じチェックでも detail が違えば別の Hit になる。
pub fn scan(x: &Exchange<'_>) -> Vec<Hit> {
    let mut hits = Vec::new();
    let mut hit = |check: &'static Check, detail: String| {
        let detail = truncate(&detail, MAX_SNIPPET);
        if !hits.iter().any(|h: &Hit| std::ptr::eq(h.check, check) && h.detail == detail) {
            hits.push(Hit { check, detail });
        }
    };
    let https = x.scheme.eq_ignore_ascii_case("https");
    let req = String::from_utf8_lossy(x.req_head);

    // ---- リクエスト
    if let Some(query) = x.target.split_once('?').map(|(_, q)| q.split('#').next().unwrap_or("")) {
        for name in param_names(query) {
            if is_sensitive_param(&name) {
                hit(SENSITIVE_QUERY, name);
            }
        }
    }
    if !https {
        if header(&req, "authorization").is_some_and(|v| v.len() > 6 && v[..6].eq_ignore_ascii_case("basic ")) {
            hit(BASIC_AUTH_HTTP, "Authorization: Basic".into());
        }
        let form = header(&req, "content-type").is_some_and(|c| c.to_ascii_lowercase().contains("x-www-form-urlencoded"));
        if form && !x.req_body.is_empty() {
            let body = String::from_utf8_lossy(&x.req_body[..x.req_body.len().min(64 * 1024)]);
            if let Some(name) = param_names(&body).find(|n| matches!(n.to_ascii_lowercase().as_str(), "password" | "passwd" | "pwd" | "pass")) {
                hit(PASSWORD_OVER_HTTP, format!("{} {} のパラメータ {name}", x.method, path_of(x.target)));
            }
        }
    }

    // ---- レスポンス
    let Some(res_head) = x.res_head else { return hits };
    let res = String::from_utf8_lossy(res_head);
    let status: u16 = res.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let ct = content_type(Some(res_head)).unwrap_or_default();
    let html = ct == "text/html" || ct == "application/xhtml+xml";

    for (name, value) in ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"]
        .iter()
        .flat_map(|n| headers(&res, n).map(move |v| (*n, v)))
    {
        if value.bytes().any(|b| b.is_ascii_digit()) {
            hit(SERVER_VERSION, format!("{name}: {value}"));
        }
    }

    for cookie in headers(&res, "set-cookie") {
        let mut parts = cookie.split(';');
        let name = parts.next().and_then(|p| p.split_once('=')).map(|(n, _)| n.trim()).unwrap_or("").to_string();
        if name.is_empty() {
            continue;
        }
        let attrs: Vec<String> =
            parts.map(|a| a.split('=').next().unwrap_or("").trim().to_ascii_lowercase()).collect();
        let has = |a: &str| attrs.iter().any(|x| x == a);
        // 削除用（過去の有効期限）の Cookie は対象外
        if cookie.to_ascii_lowercase().contains("expires=thu, 01 jan 1970") || cookie.to_ascii_lowercase().contains("max-age=0") {
            continue;
        }
        if https && !has("secure") {
            hit(COOKIE_NO_SECURE, name.clone());
        }
        if !has("httponly") {
            hit(COOKIE_NO_HTTPONLY, name.clone());
        }
        if !has("samesite") {
            hit(COOKIE_NO_SAMESITE, name);
        }
    }

    match header(&res, "access-control-allow-origin") {
        Some("*") => hit(CORS_WILDCARD, "Access-Control-Allow-Origin: *".into()),
        Some(allowed) => {
            let creds = header(&res, "access-control-allow-credentials").is_some_and(|v| v.eq_ignore_ascii_case("true"));
            let origin = header(&req, "origin");
            if creds
                && origin.is_some_and(|o| o == allowed && !o.eq_ignore_ascii_case(&format!("{}://{}", x.scheme, x.host)))
            {
                hit(CORS_REFLECT, format!("Origin: {allowed}"));
            } else if creds && allowed.eq_ignore_ascii_case("null") {
                hit(CORS_REFLECT, "Access-Control-Allow-Origin: null".into());
            }
        }
        None => {}
    }

    let ok = (200..400).contains(&status);
    if html && ok {
        let csp = headers(&res, "content-security-policy").collect::<Vec<_>>().join(";").to_ascii_lowercase();
        if https && header(&res, "strict-transport-security").is_none() {
            hit(HSTS_MISSING, path_of(x.target).into());
        }
        if csp.is_empty() {
            hit(CSP_MISSING, path_of(x.target).into());
        }
        if header(&res, "x-frame-options").is_none() && !csp.contains("frame-ancestors") {
            hit(CLICKJACKING, path_of(x.target).into());
        }
    }
    if ok && !x.res_body.is_empty() && !header(&res, "x-content-type-options").is_some_and(|v| v.eq_ignore_ascii_case("nosniff")) {
        hit(NOSNIFF_MISSING, if ct.is_empty() { "Content-Type なし".into() } else { ct.clone() });
    }

    // ---- Body（テキストだけ）
    if x.res_body.is_empty() || !is_text_type(&ct) {
        return hits;
    }
    let encoding = header(&res, "content-encoding").unwrap_or_default().to_ascii_lowercase();
    let decoded = match decode_content(&encoding, x.res_body) {
        Ok(Some(d)) => std::borrow::Cow::Owned(d),
        Ok(None) => std::borrow::Cow::Borrowed(x.res_body),
        Err(_) => return hits,
    };
    let body = String::from_utf8_lossy(&decoded[..decoded.len().min(MAX_SCAN_BODY)]);

    if let Some(m) = SQL_ERROR_RE.find(&body) {
        hit(SQL_ERROR, snippet(&body, m.start(), m.end()));
    }
    if let Some(m) = ERROR_RE.find(&body) {
        hit(ERROR_MESSAGE, snippet(&body, m.start(), m.end()));
    }
    if html && LISTING_RE.is_match(&body) {
        hit(DIRECTORY_LISTING, path_of(x.target).into());
    }
    if html && !https && PASSWORD_INPUT_RE.is_match(&body) {
        hit(PASSWORD_OVER_HTTP, format!("{} のパスワード入力欄", path_of(x.target)));
    }
    // 接続先自体が内部アドレスなら、本文に内部アドレスが出るのは当たり前なので見ない
    if !x.host.parse::<Ipv4Addr>().is_ok_and(|ip| ip.is_private()) {
        let mut seen = 0;
        for m in PRIVATE_IP_RE.find_iter(&body) {
            // 前後が数字・ドットならバージョン番号などの一部
            let before = body[..m.start()].chars().next_back();
            let after = body[m.end()..].chars().next();
            if before.is_some_and(|c| c == '.' || c.is_ascii_digit()) || after.is_some_and(|c| c == '.' && body[m.end() + 1..].starts_with(|d: char| d.is_ascii_digit())) {
                continue;
            }
            if m.as_str().parse::<Ipv4Addr>().is_ok_and(|ip| ip.is_private()) {
                hit(PRIVATE_IP, m.as_str().into());
                seen += 1;
                if seen >= 5 {
                    break;
                }
            }
        }
    }
    hits
}

fn is_text_type(ct: &str) -> bool {
    ct.is_empty()
        || ct.starts_with("text/")
        || ct.contains("json")
        || ct.contains("xml")
        || ct.contains("javascript")
        || ct.contains("x-www-form-urlencoded")
}

fn is_sensitive_param(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    SENSITIVE_PARAMS.contains(&n.as_str())
}

/// `a=1&b&c=3` のパラメータ名（URL デコードしない）。
fn param_names(query: &str) -> impl Iterator<Item = String> + '_ {
    query.split('&').filter_map(|kv| {
        let name = kv.split('=').next().unwrap_or("").trim();
        (!name.is_empty()).then(|| name.to_string())
    })
}

fn path_of(target: &str) -> &str {
    target.split(['?', '#']).next().unwrap_or(target)
}

/// 一致箇所の前後を少し含めた 1 行の抜粋。
fn snippet(body: &str, start: usize, end: usize) -> String {
    let mut s = start.saturating_sub(20);
    while !body.is_char_boundary(s) {
        s -= 1;
    }
    let mut e = (end + 40).min(body.len());
    while !body.is_char_boundary(e) {
        e += 1;
    }
    body[s..e].split_whitespace().collect::<Vec<_>>().join(" ")
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exchange<'a>(scheme: &'a str, target: &'a str, req: &'a [u8], res: &'a [u8], body: &'a [u8]) -> Exchange<'a> {
        Exchange {
            scheme,
            host: "example.com",
            method: "GET",
            target,
            req_head: req,
            req_body: b"",
            res_head: Some(res),
            res_body: body,
        }
    }

    fn ids(hits: &[Hit]) -> Vec<&'static str> {
        let mut v: Vec<_> = hits.iter().map(|h| h.check.id).collect();
        v.sort();
        v.dedup();
        v
    }

    #[test]
    fn html_without_security_headers() {
        let res = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nServer: Apache/2.4.1\r\n\
                    Set-Cookie: SID=abc; Path=/\r\nSet-Cookie: old=; Expires=Thu, 01 Jan 1970 00:00:00 GMT\r\n\r\n";
        let hits = scan(&exchange("https", "/?token=x&q=1", b"GET / HTTP/1.1\r\n\r\n", res, b"<html></html>"));
        assert_eq!(
            ids(&hits),
            [
                "clickjacking", "cookie-no-httponly", "cookie-no-samesite", "cookie-no-secure", "csp-missing",
                "hsts-missing", "nosniff-missing", "sensitive-query", "server-version"
            ]
        );
        assert!(hits.iter().all(|h| h.detail != "old"), "削除用の Cookie は対象外");
        assert!(hits.iter().any(|h| h.check.id == "sensitive-query" && h.detail == "token"));
    }

    #[test]
    fn well_configured_response_is_quiet() {
        let res = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nStrict-Transport-Security: max-age=1\r\n\
                    Content-Security-Policy: default-src 'self'; frame-ancestors 'none'\r\nX-Content-Type-Options: nosniff\r\n\
                    Set-Cookie: SID=abc; Secure; HttpOnly; SameSite=Lax\r\nServer: nginx\r\n\r\n";
        assert!(scan(&exchange("https", "/", b"GET / HTTP/1.1\r\n\r\n", res, b"<p>ok 1.2.3.4 192.168.1.10.5</p>")).is_empty());
    }

    #[test]
    fn body_patterns() {
        let res = b"HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/html\r\n\r\n";
        let body = b"<b>Warning</b>: mysql_fetch_array() expects ... You have an error in your SQL syntax near '1'\n\
                     Traceback (most recent call last):\n internal 10.0.0.12 and 8.8.8.8";
        let hits = scan(&exchange("http", "/", b"GET / HTTP/1.1\r\n\r\n", res, body));
        assert_eq!(ids(&hits), ["error-message", "private-ip", "sql-error"]);
        assert!(hits.iter().any(|h| h.check.id == "private-ip" && h.detail == "10.0.0.12"));
    }

    #[test]
    fn gzip_body_is_decoded() {
        use std::io::Write;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        enc.write_all(b"ORA-00933: SQL command not properly ended").unwrap();
        let body = enc.finish().unwrap();
        let res = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nX-Content-Type-Options: nosniff\r\n\r\n";
        let hits = scan(&exchange("https", "/", b"GET / HTTP/1.1\r\n\r\n", res, &body));
        assert_eq!(ids(&hits), ["sql-error"]);
    }

    #[test]
    fn cors_and_plain_http_credentials() {
        let req = b"GET / HTTP/1.1\r\nOrigin: https://evil.test\r\nAuthorization: Basic dTpw\r\n\r\n";
        let res = b"HTTP/1.1 204 No Content\r\nAccess-Control-Allow-Origin: https://evil.test\r\nAccess-Control-Allow-Credentials: true\r\n\r\n";
        assert_eq!(ids(&scan(&exchange("http", "/", req, res, b""))), ["basic-auth-http", "cors-reflect-credentials"]);
        let mut x = exchange("http", "/login", b"POST /login HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n", b"HTTP/1.1 302 Found\r\n\r\n", b"");
        x.req_body = b"user=a&password=b";
        assert_eq!(ids(&scan(&x)), ["password-over-http"]);
    }
}
