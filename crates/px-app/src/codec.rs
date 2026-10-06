//! エンコード / デコード（Base64・URL・HTML エンティティ・Hex・Unicode エスケープ・JWT）。

use crate::view;

/// 変換結果。UTF-8 として読めないものは Binary。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    Text(String),
    Binary(Vec<u8>),
}

impl Output {
    fn from_bytes(bytes: Vec<u8>) -> Self {
        String::from_utf8(bytes).map_or_else(|e| Self::Binary(e.into_bytes()), Self::Text)
    }
}

/// 表示用の上限
const MAX_BINARY_SHOWN: usize = 4096;

impl std::fmt::Display for Output {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Text(s) => f.write_str(s),
            Self::Binary(b) => {
                let mut s = format!("[バイナリ {} bytes]\n", b.len());
                view::hexdump(&mut s, &b[..b.len().min(MAX_BINARY_SHOWN)]);
                f.write_str(&s)
            }
        }
    }
}

/// 各方式でデコードした結果。その方式で解釈できない・変化しないものは None。
pub fn decode_all(input: &str) -> Vec<(&'static str, Option<Output>)> {
    let changed = |o: Output| (o != Output::Text(input.to_string())).then_some(o);
    vec![
        ("URL", (input.contains(['%', '+'])).then(|| Output::from_bytes(url_decode(input))).and_then(changed)),
        ("Base64", base64_decode(input).map(Output::from_bytes)),
        ("HTML エンティティ", input.contains('&').then(|| Output::Text(html_decode(input))).and_then(changed)),
        ("Hex", hex_decode(input).map(Output::from_bytes)),
        ("Unicode エスケープ", input.contains('\\').then(|| unicode_unescape(input)).flatten().map(Output::Text).and_then(changed)),
        ("JWT", jwt_decode(input).map(Output::Text)),
    ]
}

pub fn encode_all(input: &str) -> Vec<(&'static str, String)> {
    vec![
        ("URL", url_encode(input, false)),
        ("URL（全文字）", url_encode(input, true)),
        ("Base64", base64_encode(input.as_bytes(), false)),
        ("Base64URL", base64_encode(input.as_bytes(), true)),
        ("HTML エンティティ", html_encode(input)),
        ("Hex", input.bytes().map(|b| format!("{b:02x}")).collect()),
        ("Unicode エスケープ", unicode_escape(input)),
    ]
}

// ---- URL ------------------------------------------------------------------

/// `%XX` と `+`（空白）を戻す。不正な `%` はそのまま残す。
pub fn url_decode(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => match (hex_val(b[i + 1]), hex_val(b[i + 2])) {
                (Some(h), Some(l)) => {
                    out.push(h << 4 | l);
                    i += 3;
                    continue;
                }
                _ => out.push(b'%'),
            },
            b'+' => out.push(b' '),
            c => out.push(c),
        }
        i += 1;
    }
    out
}

/// `all` が false なら RFC 3986 の非予約文字以外を、true なら全バイトを `%XX` にする。
pub fn url_encode(s: &str, all: bool) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        if !all && (b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~')) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

// ---- Base64 ---------------------------------------------------------------

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub fn base64_encode(data: &[u8], url: bool) -> String {
    let table = if url { B64URL } else { B64 };
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = (chunk[0] as u32) << 16 | (*chunk.get(1).unwrap_or(&0) as u32) << 8 | *chunk.get(2).unwrap_or(&0) as u32;
        for k in 0..=chunk.len() {
            out.push(table[(n >> (18 - 6 * k) & 63) as usize] as char);
        }
        if !url {
            out.extend(std::iter::repeat_n('=', 3 - chunk.len()));
        }
    }
    out
}

/// 標準・URL セーフのどちらのアルファベットも受け付ける。空白は無視し、末尾の `=` は省略可。
pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let chars: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    let body = chars.strip_suffix(b"==").or_else(|| chars.strip_suffix(b"=")).unwrap_or(&chars);
    if body.is_empty() || body.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(body.len() * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0;
    for &c in body {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        };
        acc = acc << 6 | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

// ---- HTML -----------------------------------------------------------------

const NAMED_ENTITIES: &[(&str, char)] = &[
    ("amp", '&'),
    ("lt", '<'),
    ("gt", '>'),
    ("quot", '"'),
    ("apos", '\''),
    ("nbsp", '\u{a0}'),
    ("copy", '©'),
    ("reg", '®'),
    ("yen", '¥'),
    ("times", '×'),
    ("divide", '÷'),
    ("hellip", '…'),
    ("ndash", '–'),
    ("mdash", '—'),
    ("laquo", '«'),
    ("raquo", '»'),
];

/// `&name;` `&#NN;` `&#xHH;` を戻す。知らない名前はそのまま残す。
pub fn html_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(p) = rest.find('&') {
        out.push_str(&rest[..p]);
        rest = &rest[p..];
        let decoded = rest[1..].find(';').filter(|&e| e <= 10).and_then(|e| {
            let name = &rest[1..1 + e];
            let c = if let Some(num) = name.strip_prefix('#') {
                let n = match num.strip_prefix(['x', 'X']) {
                    Some(hex) => u32::from_str_radix(hex, 16).ok()?,
                    None => num.parse().ok()?,
                };
                char::from_u32(n)?
            } else {
                NAMED_ENTITIES.iter().find(|(n, _)| *n == name)?.1
            };
            Some((c, e + 2))
        });
        match decoded {
            Some((c, len)) => {
                out.push(c);
                rest = &rest[len..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

pub fn html_encode(s: &str) -> String {
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

// ---- Hex ------------------------------------------------------------------

fn hex_val(b: u8) -> Option<u8> {
    (b as char).to_digit(16).map(|d| d as u8)
}

/// 空白・`:`・`-` 区切りや `0x` / `\x` 接頭辞を許す。
pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    let digits: Vec<u8> = s
        .replace("\\x", "")
        .bytes()
        .filter(|b| !(b.is_ascii_whitespace() || matches!(b, b':' | b'-')))
        .collect();
    if digits.is_empty() || !digits.len().is_multiple_of(2) {
        return None;
    }
    digits.chunks(2).map(|p| Some(hex_val(p[0])? << 4 | hex_val(p[1])?)).collect()
}

// ---- Unicode エスケープ ----------------------------------------------------

/// JavaScript / JSON 形式のエスケープ（`\uXXXX`、`\u{...}`、`\xHH`、`\n` 等）を戻す。
pub fn unicode_unescape(s: &str) -> Option<String> {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    // 上位サロゲートを持ち越す
    let mut high: Option<u32> = None;
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let code = match chars.next() {
            Some('u') if chars.peek() == Some(&'{') => {
                chars.next();
                let hex: String = chars.by_ref().take_while(|&c| c != '}').collect();
                u32::from_str_radix(&hex, 16).ok()?
            }
            Some('u') => u32::from_str_radix(&chars.by_ref().take(4).collect::<String>(), 16).ok()?,
            Some('x') => u32::from_str_radix(&chars.by_ref().take(2).collect::<String>(), 16).ok()?,
            Some('n') => '\n' as u32,
            Some('r') => '\r' as u32,
            Some('t') => '\t' as u32,
            Some('0') => 0,
            Some(other) => other as u32,
            None => '\\' as u32,
        };
        match (high.take(), code) {
            (None, 0xD800..=0xDBFF) => high = Some(code),
            (Some(h), 0xDC00..=0xDFFF) => out.push(char::from_u32(0x10000 + ((h - 0xD800) << 10) + (code - 0xDC00))?),
            (Some(_), _) => return None,
            (None, _) => out.push(char::from_u32(code)?),
        }
    }
    high.is_none().then_some(out)
}

/// ASCII 以外を `\uXXXX`（BMP 外はサロゲートペア）にする。
pub fn unicode_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii() {
            out.push(c);
        } else {
            let mut buf = [0u16; 2];
            for u in c.encode_utf16(&mut buf) {
                out.push_str(&format!("\\u{u:04x}"));
            }
        }
    }
    out
}

// ---- JWT ------------------------------------------------------------------

/// `header.payload.signature` のヘッダとペイロードを整形して返す。
pub fn jwt_decode(s: &str) -> Option<String> {
    let parts: Vec<&str> = s.trim().split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let json = |p: &str| {
        let text = String::from_utf8(base64_decode(p)?).ok()?;
        text.trim_start().starts_with('{').then(|| view::pretty_json(&text).unwrap_or(text))
    };
    let (header, payload) = (json(parts[0])?, json(parts[1])?);
    Some(format!("// header\n{header}\n// payload\n{payload}\n// signature: {} bytes", base64_decode(parts[2]).map_or(0, |b| b.len())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_roundtrip_and_lenient_decode() {
        for data in [&b""[..], b"f", b"fo", b"foo", b"foob", b"\xff\xfe\x00"] {
            assert_eq!(base64_decode(&base64_encode(data, false)).unwrap_or_default(), data);
            assert_eq!(base64_decode(&base64_encode(data, true)).unwrap_or_default(), data);
        }
        assert_eq!(base64_encode(b"fo", false), "Zm8=");
        assert_eq!(base64_encode(b"\xfb\xff", true), "-_8");
        assert_eq!(base64_decode("Zm9v\nYmFy").unwrap(), b"foobar");
        assert_eq!(base64_decode("Zm8").unwrap(), b"fo", "padding is optional");
        assert!(base64_decode("hello").is_none(), "length % 4 == 1");
        assert!(base64_decode("a=bc").is_none());
    }

    #[test]
    fn url_codec() {
        assert_eq!(url_decode("a%20b+c%e3%81%82%zz%"), "a b cあ%zz%".as_bytes());
        assert_eq!(url_encode("a b/あ~", false), "a%20b%2F%E3%81%82~");
        assert_eq!(url_encode("ab", true), "%61%62");
    }

    #[test]
    fn html_codec() {
        assert_eq!(html_decode("&lt;a&gt; &amp;amp; &#39;&#x3042;&unknown; & x"), "<a> &amp; 'あ&unknown; & x");
        assert_eq!(html_encode("<a href=\"x\">'&"), "&lt;a href=&quot;x&quot;&gt;&#39;&amp;");
    }

    #[test]
    fn hex_and_unicode() {
        assert_eq!(hex_decode("0x48 65:6c-6c 6f").unwrap(), b"Hello");
        assert_eq!(hex_decode("\\x41\\x42").unwrap(), b"AB");
        assert!(hex_decode("abc").is_none());
        assert_eq!(unicode_unescape(r"\u3042\ud83d\ude00\x41\n\u{1F600}").unwrap(), "\u{3042}\u{1F600}A\n\u{1F600}");
        assert!(unicode_unescape(r"\ud83d").is_none(), "lone surrogate");
        assert_eq!(unicode_escape("a\u{3042}\u{1F600}"), r"a\u3042\ud83d\ude00");
    }

    #[test]
    fn decode_all_skips_inapplicable() {
        let rows = decode_all("plain text");
        assert!(rows.iter().all(|(_, o)| o.is_none()), "{rows:?}");
        let jwt = format!("{}.{}.sig", base64_encode(br#"{"alg":"HS256"}"#, true), base64_encode(br#"{"sub":"1"}"#, true));
        let rows = decode_all(&jwt);
        let out = rows.iter().find(|(n, _)| *n == "JWT").unwrap().1.clone().unwrap();
        assert!(out.to_string().contains("\"alg\": \"HS256\"") && out.to_string().contains("\"sub\": \"1\""), "{out}");
    }
}
