//! ダミーサーバ（仮想 Web サーバ）: 指定したホスト宛てのリクエストを上流へ送らず、パスごとに設定した応答を返す。
//! 待受は増やさず、プロキシに届いた通信をホスト名で振り分ける（HTTP / HTTPS・ポートは問わない）。

use serde::{Deserialize, Serialize};

use crate::rules::glob;

/// 必ず用意するパス
pub const ROOT_PATH: &str = "/";

/// 選べる Content-Type（表示名, 値, Body をファイルから読むか）。
/// テキストの種類は Body を手書きし、画像・バイナリはファイルを選ぶ。
pub const CONTENT_TYPES: &[(&str, &str, bool)] = &[
    ("HTML", "text/html; charset=utf-8", false),
    ("JSON", "application/json", false),
    ("CSS", "text/css; charset=utf-8", false),
    ("JavaScript", "text/javascript; charset=utf-8", false),
    ("XML", "application/xml", false),
    ("テキスト", "text/plain; charset=utf-8", false),
    ("画像 PNG", "image/png", true),
    ("画像 JPEG", "image/jpeg", true),
    ("画像 GIF", "image/gif", true),
    ("画像 WebP", "image/webp", true),
    ("画像 SVG", "image/svg+xml", true),
    ("画像 ICO", "image/x-icon", true),
    ("PDF", "application/pdf", true),
    ("バイナリ", "application/octet-stream", true),
    ("指定しない", "", false),
];

/// 1 つのダミーサーバ。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MockServer {
    pub enabled: bool,
    /// ホスト名（`*` / `?` のワイルドカード可）。ポートは問わない
    pub host: String,
    /// パスごとの応答（`/` は必須）。上から順に調べ、最初に一致したものを返す
    pub routes: Vec<MockRoute>,
}

impl Default for MockServer {
    fn default() -> Self {
        Self { enabled: true, host: String::new(), routes: vec![MockRoute::default()] }
    }
}

/// パスごとの応答。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MockRoute {
    /// パス。クエリを除いて比較する（完全一致、`*` / `?` のワイルドカード可）
    pub path: String,
    /// 受け付けるメソッド（空白・カンマ区切り、空なら全て）
    pub methods: String,
    pub status: u16,
    /// Content-Type（空なら付けない）。ヘッダに Content-Type があればそちらを優先する。
    /// 項目が無い古い設定はヘッダで指定していたので空にする
    #[serde(default)]
    pub content_type: String,
    /// レスポンスヘッダ（1 行に `名前: 値`）。Content-Length は Body から付ける
    pub headers: String,
    /// 手書きの Body（テキストの Content-Type のとき）
    pub body: String,
    /// Body にするファイルのパス（画像・バイナリの Content-Type のとき）。応答のたびに読む
    pub file: String,
}

impl Default for MockRoute {
    fn default() -> Self {
        Self {
            path: ROOT_PATH.into(),
            methods: String::new(),
            status: 200,
            content_type: CONTENT_TYPES[0].1.into(),
            headers: String::new(),
            body: String::new(),
            file: String::new(),
        }
    }
}

impl MockRoute {
    /// 受け付けるメソッド（大文字）。空なら全て。
    pub fn method_list(&self) -> Vec<String> {
        self.methods
            .split([' ', '\t', '\n', ','])
            .map(|m| m.trim().to_ascii_uppercase())
            .filter(|m| !m.is_empty())
            .collect()
    }

    /// Body をファイルから読むか（画像・音声・動画・フォントや、テキストでない application/*）。
    pub fn uses_file(&self) -> bool {
        let mime = self.content_type.split(';').next().unwrap_or_default().trim().to_ascii_lowercase();
        if mime.is_empty() {
            return false;
        }
        if let Some(&(_, _, file)) = CONTENT_TYPES.iter().find(|(_, v, _)| v.split(';').next() == Some(mime.as_str())) {
            return file;
        }
        let text = mime.starts_with("text/")
            || mime.ends_with("/json")
            || mime.ends_with("+json")
            || mime.ends_with("/xml")
            || mime.ends_with("javascript")
            || mime == "application/x-www-form-urlencoded";
        !text
    }

    /// ファイルの拡張子に合う Content-Type（ファイルから読む種類のうち）。
    pub fn content_type_for_file(path: &str) -> Option<&'static str> {
        let ext = path.rsplit_once('.')?.1.to_ascii_lowercase();
        Some(match ext.as_str() {
            "png" => "image/png",
            "jpg" | "jpeg" => "image/jpeg",
            "gif" => "image/gif",
            "webp" => "image/webp",
            "svg" => "image/svg+xml",
            "ico" => "image/x-icon",
            "pdf" => "application/pdf",
            _ => return None,
        })
    }

    fn accepts(&self, method: &str) -> bool {
        let list = self.method_list();
        list.is_empty() || list.iter().any(|m| m.eq_ignore_ascii_case(method))
    }

    fn matches_path(&self, path: &str) -> bool {
        let p = self.path.trim();
        !p.is_empty() && glob(p, path)
    }
}

/// 組み立てた応答。`body` はクライアントへ送る分（HEAD や 204 / 304 なら空）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MockResponse {
    pub(crate) status: u16,
    pub(crate) head: Vec<u8>,
    pub(crate) body: Vec<u8>,
}

impl MockServer {
    pub fn matches_host(&self, host: &str) -> bool {
        let pattern = self.host.trim();
        self.enabled && !pattern.is_empty() && glob(&pattern.to_ascii_lowercase(), &host.to_ascii_lowercase())
    }

    /// 設定の誤り（UI・CLI に出す）。
    pub fn problems(&self) -> Vec<String> {
        let mut out = Vec::new();
        let host = self.host.trim();
        if host.is_empty() {
            out.push("ホスト名を入力してください".to_string());
        } else if host.contains(['/', ' ', '\t']) {
            out.push(format!("ホスト名だけを書いてください（スキーム・パスは不要）: {host}"));
        }
        if !self.routes.iter().any(|r| r.path.trim() == ROOT_PATH) {
            out.push("パス / の応答がありません".to_string());
        }
        for r in &self.routes {
            let path = r.path.trim();
            if !path.starts_with('/') {
                out.push(format!("パスは / で始めてください: {path}"));
            }
            if !(200..=599).contains(&r.status) {
                out.push(format!("{path}: ステータスは 200〜599 で指定してください: {}", r.status));
            }
            for line in header_lines(&r.headers) {
                if !line.split_once(':').is_some_and(|(name, _)| !name.trim().is_empty()) {
                    out.push(format!("{path}: ヘッダは「名前: 値」の形で書いてください: {line}"));
                }
            }
            if r.uses_file() {
                let file = r.file.trim();
                if file.is_empty() {
                    out.push(format!("{path}: Body のファイルを選択してください"));
                } else if !std::path::Path::new(file).is_file() {
                    out.push(format!("{path}: Body のファイルがありません: {file}"));
                }
            }
        }
        out
    }

    /// リクエストへの応答を作る。一致するパスが無ければ 404、パスはあるがメソッドが違えば 405。
    /// ヘッダと Body の `{{…}}` はリクエストの内容で置き換える。
    pub(crate) fn respond(&self, req: &MockRequest<'_>) -> MockResponse {
        const TEXT: &str = "Content-Type: text/plain; charset=utf-8";
        let (method, path) = (req.method, req.path());
        let mut allowed: Vec<String> = Vec::new();
        for r in self.routes.iter().filter(|r| r.matches_path(path)) {
            if r.accepts(method) {
                let mut headers = String::new();
                let content_type = r.content_type.trim();
                if !content_type.is_empty() && !header_lines(&r.headers).any(|l| header_name(l).eq_ignore_ascii_case("content-type")) {
                    headers = format!("Content-Type: {content_type}\n");
                }
                // 置き換えた値に改行があってもヘッダの枠を壊さないよう、行ごとに置き換えて改行を除く
                headers.extend(header_lines(&r.headers).map(|l| String::from_utf8_lossy(&render(l, req)).replace(['\r', '\n'], "") + "\n"));
                // ファイルはバイト列のまま返す（プレースホルダは置き換えない）
                let body = if r.uses_file() {
                    let file = r.file.trim();
                    match std::fs::read(file) {
                        Ok(b) => b,
                        Err(e) => {
                            let body = format!("pxproxy ダミーサーバ: {path} の Body のファイルを読めません: {file}: {e}\n");
                            return MockResponse::build(method, 500, TEXT, body.as_bytes());
                        }
                    }
                } else {
                    render(&r.body, req)
                };
                return MockResponse::build(method, r.status, &headers, &body);
            }
            allowed.extend(r.method_list());
        }
        if allowed.is_empty() {
            let body = format!("pxproxy ダミーサーバ: {path} はありません\n");
            return MockResponse::build(method, 404, TEXT, body.as_bytes());
        }
        allowed.sort();
        allowed.dedup();
        let body = format!("pxproxy ダミーサーバ: {path} は {method} を受け付けません\n");
        MockResponse::build(method, 405, &format!("{TEXT}\nAllow: {}", allowed.join(", ")), body.as_bytes())
    }
}

impl MockResponse {
    fn build(method: &str, status: u16, headers: &str, body: &[u8]) -> Self {
        let mut head = format!("HTTP/1.1 {status} {}\r\n", reason(status));
        for line in header_lines(headers) {
            let Some((name, _)) = line.split_once(':') else { continue };
            let name = name.trim();
            // 長さは Body から付け直す（食い違うとクライアントとの接続が壊れる）
            if name.is_empty() || name.eq_ignore_ascii_case("content-length") || name.eq_ignore_ascii_case("transfer-encoding") {
                continue;
            }
            head.push_str(line);
            head.push_str("\r\n");
        }
        let no_body = status == 204 || status == 304;
        if !no_body {
            head.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        head.push_str("\r\n");
        let body = if no_body || method.eq_ignore_ascii_case("HEAD") { Vec::new() } else { body.to_vec() };
        Self { status, head: head.into_bytes(), body }
    }
}

/// 応答を作るときに参照するリクエストの内容。
pub(crate) struct MockRequest<'a> {
    pub(crate) method: &'a str,
    /// origin-form（パスとクエリ）
    pub(crate) target: &'a str,
    pub(crate) headers: &'a [(String, Vec<u8>)],
    /// Transfer-Encoding を外した Body
    pub(crate) body: &'a [u8],
}

impl MockRequest<'_> {
    fn path(&self) -> &str {
        self.target.split(['?', '#']).next().unwrap_or_default()
    }

    fn query(&self) -> &str {
        self.target.split('#').next().unwrap_or_default().split_once('?').map_or("", |(_, q)| q)
    }

    /// プレースホルダの値。名前を解釈できなければ None（値が無いだけなら空）。
    fn value(&self, key: &str) -> Option<Vec<u8>> {
        Some(match key {
            "method" => self.method.as_bytes().to_vec(),
            "path" => self.path().as_bytes().to_vec(),
            "query" => self.query().as_bytes().to_vec(),
            "body" => self.body.to_vec(),
            _ => {
                let (kind, name) = key.split_once('.')?;
                match kind {
                    "query" => form_value(self.query().as_bytes(), name),
                    "form" => form_value(self.body, name),
                    "json" => json_value(self.body, name),
                    "header" => self.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.clone()),
                    _ => return None,
                }
                .unwrap_or_default()
            }
        })
    }
}

/// `{{名前}}` / `{{エスケープ:名前}}` をリクエストの内容で置き換える。解釈できないものはそのまま残す。
fn render(template: &str, req: &MockRequest<'_>) -> Vec<u8> {
    let mut out = Vec::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        out.extend_from_slice(&rest.as_bytes()[..start]);
        let after = &rest[start + 2..];
        let replaced = after.find("}}").and_then(|end| Some((placeholder(after[..end].trim(), req)?, &after[end + 2..])));
        match replaced {
            Some((value, next)) => {
                out.extend_from_slice(&value);
                rest = next;
            }
            None => {
                out.extend_from_slice(b"{{");
                rest = after;
            }
        }
    }
    out.extend_from_slice(rest.as_bytes());
    out
}

fn placeholder(expr: &str, req: &MockRequest<'_>) -> Option<Vec<u8>> {
    let (escape, key) = match expr.split_once(':') {
        Some((e, k)) => (Some(e.trim()), k.trim()),
        None => (None, expr),
    };
    let value = req.value(key)?;
    let text = || String::from_utf8_lossy(&value).into_owned();
    Some(match escape {
        None => value.clone(),
        Some("html") => html_escape(&text()).into_bytes(),
        Some("url") => url_encode(&value).into_bytes(),
        // 引用符の内側に埋め込む形（前後の " は付けない）
        Some("json") => {
            let quoted = serde_json::Value::String(text()).to_string();
            quoted.as_bytes()[1..quoted.len() - 1].to_vec()
        }
        Some(_) => return None,
    })
}

/// `a=1&b=2` 形式から `name` の最初の値を取り出す（URL デコード後）。
fn form_value(data: &[u8], name: &str) -> Option<Vec<u8>> {
    data.split(|b| *b == b'&').find_map(|pair| {
        let (k, v) = match pair.iter().position(|b| *b == b'=') {
            Some(i) => (&pair[..i], &pair[i + 1..]),
            None => (pair, &b""[..]),
        };
        (url_decode(k) == name.as_bytes()).then(|| url_decode(v))
    })
}

/// JSON の Body から `a.b.0` のようなパスで値を取り出す。文字列は中身、それ以外は JSON の表記。
fn json_value(body: &[u8], path: &str) -> Option<Vec<u8>> {
    let root: serde_json::Value = serde_json::from_slice(body).ok()?;
    let mut v = &root;
    for seg in path.split('.') {
        v = match v {
            serde_json::Value::Object(o) => o.get(seg)?,
            serde_json::Value::Array(a) => a.get(seg.parse::<usize>().ok()?)?,
            _ => return None,
        };
    }
    Some(match v {
        serde_json::Value::String(s) => s.clone().into_bytes(),
        other => other.to_string().into_bytes(),
    })
}

fn url_decode(s: &[u8]) -> Vec<u8> {
    let hex = |b: u8| (b as char).to_digit(16).map(|d| d as u8);
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        match s[i] {
            b'+' => out.push(b' '),
            b'%' => match (s.get(i + 1).and_then(|b| hex(*b)), s.get(i + 2).and_then(|b| hex(*b))) {
                (Some(h), Some(l)) => {
                    out.push(h << 4 | l);
                    i += 2;
                }
                _ => out.push(b'%'),
            },
            b => out.push(b),
        }
        i += 1;
    }
    out
}

fn url_encode(s: &[u8]) -> String {
    s.iter()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => (*b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

fn header_lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines().map(str::trim).filter(|l| !l.is_empty())
}

fn header_name(line: &str) -> &str {
    line.split_once(':').map_or("", |(name, _)| name.trim())
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        413 => "Content Too Large",
        415 => "Unsupported Media Type",
        422 => "Unprocessable Content",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(path: &str, methods: &str, status: u16, body: &str) -> MockRoute {
        MockRoute {
            path: path.into(),
            methods: methods.into(),
            status,
            content_type: String::new(),
            headers: "X-Mock: 1".into(),
            body: body.into(),
            file: String::new(),
        }
    }

    fn server() -> MockServer {
        MockServer {
            enabled: true,
            host: "*.Mock.test".into(),
            routes: vec![
                route("/", "", 200, "top"),
                route("/login", "POST", 302, "post"),
                route("/login", "get, head", 200, "form"),
                route("/api/*", "GET", 500, "err"),
            ],
        }
    }

    fn call(s: &MockServer, method: &str, target: &str) -> MockResponse {
        s.respond(&MockRequest { method, target, headers: &[], body: b"" })
    }

    fn text(r: &MockResponse) -> (u16, String, String) {
        (r.status, String::from_utf8_lossy(&r.head).into_owned(), String::from_utf8_lossy(&r.body).into_owned())
    }

    #[test]
    fn routes_by_path_and_method() {
        let s = server();
        assert!(s.matches_host("www.mock.test") && !s.matches_host("mock.test"));
        let (st, head, body) = text(&call(&s, "GET", "/?q=1"));
        assert_eq!((st, body.as_str()), (200, "top"));
        assert_eq!(head, "HTTP/1.1 200 OK\r\nX-Mock: 1\r\nContent-Length: 3\r\n\r\n");
        assert_eq!(text(&call(&s, "POST", "/login")).0, 302);
        assert_eq!(text(&call(&s, "get", "/login")).2, "form");
        assert_eq!(text(&call(&s, "GET", "/api/v1/x")).0, 500);

        // HEAD は長さだけ返す
        let (_, head, body) = text(&call(&s, "HEAD", "/login"));
        assert!(head.contains("Content-Length: 4\r\n") && body.is_empty());
        // パスが無ければ 404、メソッドが違えば 405 と Allow
        assert_eq!(text(&call(&s, "GET", "/nothing")).0, 404);
        let (st, head, _) = text(&call(&s, "DELETE", "/login"));
        assert_eq!(st, 405);
        assert!(head.contains("Allow: GET, HEAD, POST\r\n"), "{head}");

        let off = MockServer { enabled: false, ..server() };
        assert!(!off.matches_host("www.mock.test"));
    }

    #[test]
    fn placeholders_are_replaced_by_request() {
        let mut route = route("/echo", "", 200, "");
        route.headers = "X-Q: {{query.q}}\nX-Bad: {{header.X-Multi}}\nContent-Type: text/html".into();
        route.body = [
            "{{method}} {{path}} [{{query}}] q={{query.q}} h={{html:query.q}} u={{url:form.name}}",
            "j={{json:json.user.name}} n={{json.items.1}} f={{form.name}} ua={{header.user-agent}}",
            "none=[{{query.none}}] keep={{unknown.x}} {{nope:body}} {{ open",
        ]
        .join(" ");
        let s = MockServer { routes: vec![route], ..server() };
        let headers = [("User-Agent".to_string(), b"ua/1".to_vec()), ("X-Multi".to_string(), b"a\r\nInjected: 1".to_vec())];
        let req = MockRequest { method: "POST", target: "/echo?q=%3Cb%3E+x&z", headers: &headers, body: b"name=a%26b+c" };
        let (_, head, body) = text(&s.respond(&req));
        assert!(head.contains("X-Q: <b> x\r\nX-Bad: aInjected: 1\r\n"), "ヘッダ値の改行は除く: {head}");
        assert_eq!(
            body,
            "POST /echo [q=%3Cb%3E+x&z] q=<b> x h=&lt;b&gt; x u=a%26b%20c j= n= f=a&b c ua=ua/1 none=[] keep={{unknown.x}} {{nope:body}} {{ open"
        );

        let json = br#"{"user":{"name":"say \"hi\""},"items":[1,{"id":2}]}"#;
        let req = MockRequest { method: "POST", target: "/echo", headers: &[], body: json };
        let body = text(&s.respond(&req)).2;
        assert!(body.contains(r#"j=say \"hi\" n={"id":2}"#), "{body}");
        let echo = MockServer { routes: vec![MockRoute { body: "{{body}}".into(), ..Default::default() }], ..server() };
        let req = MockRequest { method: "POST", target: "/", headers: &[], body: &[0xff, 0x00] };
        assert_eq!(echo.respond(&req).body, [0xff, 0x00], "Body はバイト列のまま返す");
    }

    #[test]
    fn content_type_and_file_body() {
        let dir = tempfile::tempdir().unwrap();
        let png = dir.path().join("a.png");
        std::fs::write(&png, [0x89, b'P', b'N', b'G', 0x00, 0xff]).unwrap();

        let json = MockRoute { content_type: "application/json".into(), body: "{\"q\":\"{{query.q}}\"}".into(), ..Default::default() };
        let s = MockServer { routes: vec![json], ..server() };
        let (_, head, body) = text(&call(&s, "GET", "/?q=1"));
        assert!(head.starts_with("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"), "{head}");
        assert_eq!(body, "{\"q\":\"1\"}");

        // ヘッダの Content-Type が優先（古い設定はヘッダで指定している）
        let old = MockRoute { headers: "content-type: text/plain".into(), body: "x".into(), ..Default::default() };
        let (_, head, _) = text(&call(&MockServer { routes: vec![old], ..server() }, "GET", "/"));
        assert_eq!(head, "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\nContent-Length: 1\r\n\r\n");

        // 画像はファイルをバイト列のまま返す（手書きの Body は使わない）
        let image = MockRoute { content_type: "image/png".into(), body: "unused".into(), file: png.display().to_string(), ..Default::default() };
        assert!(image.uses_file());
        let s = MockServer { routes: vec![image.clone()], ..server() };
        assert!(s.problems().is_empty(), "{:?}", s.problems());
        let r = call(&s, "GET", "/");
        assert!(String::from_utf8_lossy(&r.head).contains("Content-Type: image/png\r\nContent-Length: 6\r\n"));
        assert_eq!(r.body, [0x89, b'P', b'N', b'G', 0x00, 0xff]);

        // ファイルが無ければ設定の誤りとして出し、応答は 500
        let missing = MockRoute { content_type: "application/octet-stream".into(), file: dir.path().join("none.bin").display().to_string(), ..image };
        let s = MockServer { routes: vec![missing], ..server() };
        assert_eq!(s.problems().len(), 1, "{:?}", s.problems());
        assert_eq!(call(&s, "GET", "/").status, 500);

        let kind = |ct: &str| MockRoute { content_type: ct.into(), ..Default::default() }.uses_file();
        assert!(!kind("") && !kind("text/csv") && !kind("application/problem+json") && !kind("application/json; charset=utf-8"));
        assert!(kind("image/avif") && kind("font/woff2") && kind("application/zip") && kind("image/svg+xml"));
        assert_eq!(MockRoute::content_type_for_file(r"C:\x\Logo.JPG"), Some("image/jpeg"));
    }

    #[test]
    fn old_settings_keep_content_type_in_headers() {
        let r: MockRoute = serde_json::from_str(r#"{"path": "/", "headers": "Content-Type: application/json"}"#).unwrap();
        assert_eq!((r.content_type.as_str(), r.status), ("", 200), "項目が無ければ Content-Type は付けない");
    }

    #[test]
    fn length_headers_are_recomputed() {
        let r = MockResponse::build("GET", 200, "Content-Length: 99\nTransfer-Encoding: chunked\nX-A: b", b"abc");
        assert_eq!(r.head, b"HTTP/1.1 200 OK\r\nX-A: b\r\nContent-Length: 3\r\n\r\n");
        let r = MockResponse::build("GET", 204, "", b"ignored");
        assert_eq!((r.head.as_slice(), r.body.len()), (&b"HTTP/1.1 204 No Content\r\n\r\n"[..], 0));
    }

    #[test]
    fn problems_are_reported() {
        assert!(server().problems().is_empty(), "{:?}", server().problems());
        assert_eq!(MockServer::default().problems(), ["ホスト名を入力してください"]);
        let bad = MockServer {
            enabled: true,
            host: "https://x.test/".into(),
            routes: vec![MockRoute { path: "api".into(), status: 99, headers: "broken".into(), ..Default::default() }],
        };
        assert_eq!(bad.problems().len(), 5, "{:?}", bad.problems());
    }
}
