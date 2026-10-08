//! メッセージ表示用の整形（Content-Encoding の展開、画像プレビュー、バイナリの hexdump、巨大 Body の切り詰め、
//! JSON / HTML / XML の整形）。

use std::fmt::Write;
use std::sync::{Arc, OnceLock};

pub(crate) use px_store::decode_content;
use time::{OffsetDateTime, UtcOffset};

const MAX_TEXT: usize = 512 * 1024;
const MAX_HEX: usize = 64 * 1024;
/// これより大きい Body は整形しない
const MAX_PRETTY_INPUT: usize = 8 * 1024 * 1024;
/// 整形結果の表示上限
const MAX_PRETTY: usize = 2 * 1024 * 1024;

/// 画像プレビュー用のデータ。`uri` は egui の画像キャッシュのキー（拡張子でデコーダが選ばれる）。
pub struct ImagePreview {
    pub uri: String,
    pub bytes: Arc<[u8]>,
    pub mime: &'static str,
    /// SVG 以外は (幅, 高さ)
    pub size: Option<(u32, u32)>,
}

/// Body のハイライト・整形の種類。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Syntax {
    Plain,
    Json,
    Html,
    Xml,
}

/// 整形済みメッセージ。`text` は Raw 表示（ヘッダ + 本文テキスト or hexdump）。
pub struct Rendered {
    pub head: String,
    pub text: String,
    /// `text` / `pretty` で Body の表示が始まるバイト位置（ヘッダと注記の後）
    pub body_start: usize,
    /// Body のハイライト種別。hexdump は Plain
    pub syntax: Syntax,
    /// 整形表示（ヘッダ + 整形した Body）。整形できない・変化しないなら None
    pub pretty: Option<String>,
    pub image: Option<ImagePreview>,
}

impl Rendered {
    /// ヘッダも Body も無い、メッセージだけの表示（接続エラー等）。
    pub fn plain(text: String) -> Self {
        Self { head: String::new(), text, body_start: 0, syntax: Syntax::Plain, pretty: None, image: None }
    }
}

/// `uri_key` は画像キャッシュのキーに使う一意な文字列（例: "12/res"）。
pub fn render_message(head: &[u8], body: &[u8], uri_key: &str) -> Rendered {
    let head_text = String::from_utf8_lossy(head).into_owned();
    let mut text = head_text.clone();
    if body.is_empty() {
        let body_start = text.len();
        return Rendered { head: head_text, text, body_start, syntax: Syntax::Plain, pretty: None, image: None };
    }

    let encoding = header_value(&head_text, "content-encoding").unwrap_or_default().to_ascii_lowercase();
    let (body, note) = match decode_content(&encoding, body) {
        Ok(Some(d)) => {
            let note = format!("[Content-Encoding: {encoding} を展開して表示: {} → {} bytes]\n", body.len(), d.len());
            (std::borrow::Cow::Owned(d), Some(note))
        }
        Ok(None) => (std::borrow::Cow::Borrowed(body), None),
        Err(e) => (std::borrow::Cow::Borrowed(body), Some(format!("[{e}。生データを表示]\n"))),
    };
    if let Some(note) = &note {
        text.push_str(note);
    }

    let content_type = header_value(&head_text, "content-type")
        .map(|v| v.split(';').next().unwrap_or("").trim().to_ascii_lowercase())
        .unwrap_or_default();
    let image = image_preview(&content_type, &body, uri_key);
    let body_start = text.len();

    if image.as_ref().is_some_and(|i| i.mime != "image/svg+xml") || !looks_like_text(&body) {
        hexdump(&mut text, &body[..body.len().min(MAX_HEX)]);
        if body.len() > MAX_HEX {
            let _ = write!(text, "[... {} bytes 省略 ...]", body.len() - MAX_HEX);
        }
        return Rendered { head: head_text, text, body_start, syntax: Syntax::Plain, pretty: None, image };
    }

    text.push_str(&String::from_utf8_lossy(&body[..body.len().min(MAX_TEXT)]));
    if body.len() > MAX_TEXT {
        let _ = write!(text, "\n\n[... {} bytes 省略 ...]", body.len() - MAX_TEXT);
    }
    let syntax = detect_syntax(&content_type, &body);
    let pretty = (body.len() <= MAX_PRETTY_INPUT)
        .then(|| std::str::from_utf8(&body).ok())
        .flatten()
        .and_then(|b| prettify(syntax, b).filter(|p| p != b))
        .map(|p| {
            let mut out = text[..body_start].to_string();
            out.push_str(truncate_str(&p, MAX_PRETTY));
            if p.len() > MAX_PRETTY {
                let _ = write!(out, "\n\n[... 整形結果の残り {} bytes 省略 ...]", p.len() - MAX_PRETTY);
            }
            out
        });
    Rendered { head: head_text, text, body_start, syntax, pretty, image }
}

/// Content-Type（無ければ先頭バイト）から Body の種類を決める。
fn detect_syntax(content_type: &str, body: &[u8]) -> Syntax {
    if content_type.contains("json") {
        return Syntax::Json;
    }
    if content_type.contains("html") {
        return Syntax::Html;
    }
    if content_type.contains("xml") {
        return Syntax::Xml;
    }
    if content_type.contains("javascript") || content_type.contains("css") {
        return Syntax::Plain;
    }
    let start = body.iter().position(|b| !b.is_ascii_whitespace()).unwrap_or(body.len());
    let head = &body[start..body.len().min(start + 5)];
    match head.first() {
        Some(b'{' | b'[') => Syntax::Json,
        Some(b'<') if head.eq_ignore_ascii_case(b"<?xml") => Syntax::Xml,
        Some(b'<') => Syntax::Html,
        _ => Syntax::Plain,
    }
}

fn prettify(syntax: Syntax, body: &str) -> Option<String> {
    match syntax {
        Syntax::Json => pretty_json(body),
        Syntax::Html => pretty_markup(body, true),
        Syntax::Xml => pretty_markup(body, false),
        Syntax::Plain => None,
    }
}

/// `max` バイト以下に、文字の途中で切らないように切り詰める。
pub(crate) fn truncate_str(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// JSON をインデントし直す。値は一切解釈せず空白だけを入れ替えるので、数値の桁やキー順はそのまま。
/// 改行区切りで複数の値が並ぶもの（NDJSON）も扱う。JSON でなければ None。
pub(crate) fn pretty_json(src: &str) -> Option<String> {
    let b = src.trim().as_bytes();
    if !matches!(b.first(), Some(b'{' | b'[')) {
        return None;
    }
    let mut out = Vec::with_capacity(b.len() + b.len() / 2);
    let mut stack = Vec::new();
    let newline = |out: &mut Vec<u8>, depth: usize| {
        out.push(b'\n');
        out.extend(std::iter::repeat_n(b' ', depth * 2));
    };
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        i += 1;
        match c {
            b'"' => {
                let start = i - 1;
                let mut escaped = false;
                loop {
                    let &d = b.get(i)?;
                    i += 1;
                    if escaped {
                        escaped = false;
                    } else if d == b'\\' {
                        escaped = true;
                    } else if d == b'"' {
                        break;
                    }
                }
                out.extend_from_slice(&b[start..i]);
            }
            b'{' | b'[' => {
                if stack.is_empty() && !out.is_empty() {
                    out.push(b'\n');
                }
                let close = if c == b'{' { b'}' } else { b']' };
                let next = i + b[i..].iter().take_while(|b| b.is_ascii_whitespace()).count();
                if b.get(next) == Some(&close) {
                    out.extend_from_slice(&[c, close]);
                    i = next + 1;
                    continue;
                }
                stack.push(close);
                out.push(c);
                newline(&mut out, stack.len());
            }
            b'}' | b']' => {
                if stack.pop() != Some(c) {
                    return None;
                }
                newline(&mut out, stack.len());
                out.push(c);
            }
            b',' if !stack.is_empty() => {
                out.push(c);
                newline(&mut out, stack.len());
            }
            b':' if !stack.is_empty() => out.extend_from_slice(b": "),
            c if c.is_ascii_whitespace() => {}
            _ if !stack.is_empty() => out.push(c),
            _ => return None,
        }
    }
    if !stack.is_empty() {
        return None;
    }
    String::from_utf8(out).ok()
}

const VOID_ELEMENTS: &[&str] =
    &["area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"];
/// 中身をタグとして解釈しない要素
pub(crate) const RAW_TEXT_ELEMENTS: &[&str] = &["script", "style", "textarea", "pre"];
/// 子がこの長さ以下のテキストだけなら 1 行にまとめる
const INLINE_TEXT_MAX: usize = 120;

#[derive(Clone, Copy)]
enum MarkupToken<'a> {
    Text(&'a str),
    /// コメント・DOCTYPE・処理命令・CDATA
    Other(&'a str),
    /// `empty` は void 要素か `/>` で閉じたもの
    Open { name: &'a str, raw: &'a str, empty: bool },
    Close { name: &'a str, raw: &'a str },
    /// script / style 等の中身
    RawText(&'a str),
}

/// HTML / XML を 1 タグ 1 行でインデントする。閲覧用なので、閉じタグの省略などは厳密に扱わない。
pub(crate) fn pretty_markup(src: &str, html: bool) -> Option<String> {
    let tokens = tokenize_markup(src, html);
    if !tokens.iter().any(|t| matches!(t, MarkupToken::Open { .. } | MarkupToken::Close { .. })) {
        return None;
    }
    let same = |a: &str, b: &str| if html { a.eq_ignore_ascii_case(b) } else { a == b };
    let short = |t: &str| !t.trim().contains('\n') && t.trim().len() <= INLINE_TEXT_MAX;
    let mut out = String::with_capacity(src.len() * 3 / 2);
    let mut line = |depth: usize, s: &str| {
        if !out.is_empty() {
            out.push('\n');
        }
        for _ in 0..depth {
            out.push_str("  ");
        }
        out.push_str(s);
    };
    let mut depth = 0usize;
    let mut k = 0;
    while k < tokens.len() {
        match tokens[k] {
            MarkupToken::Text(t) => t.lines().map(str::trim).filter(|l| !l.is_empty()).for_each(|l| line(depth, l)),
            MarkupToken::RawText(t) => t.trim().lines().for_each(|l| line(depth, l.trim_end())),
            MarkupToken::Other(s) => line(depth, s.trim()),
            MarkupToken::Open { raw, empty: true, .. } => line(depth, raw),
            MarkupToken::Open { name, raw, empty: false } => match (tokens.get(k + 1), tokens.get(k + 2)) {
                // 空要素や短いテキストだけの要素は 1 行にまとめる
                (Some(MarkupToken::Close { name: n, raw: close }), _) if same(n, name) => {
                    line(depth, &format!("{raw}{close}"));
                    k += 1;
                }
                (
                    Some(MarkupToken::Text(t) | MarkupToken::RawText(t)),
                    Some(MarkupToken::Close { name: n, raw: close }),
                ) if same(n, name) && short(t) => {
                    line(depth, &format!("{raw}{}{close}", t.trim()));
                    k += 2;
                }
                _ => {
                    line(depth, raw);
                    depth += 1;
                }
            },
            MarkupToken::Close { raw, .. } => {
                depth = depth.saturating_sub(1);
                line(depth, raw);
            }
        }
        k += 1;
    }
    Some(out)
}

fn tokenize_markup(src: &str, html: bool) -> Vec<MarkupToken<'_>> {
    let mut tokens = Vec::new();
    let mut text_start = 0;
    let mut i = 0;
    while i < src.len() {
        if src.as_bytes()[i] != b'<' {
            i += 1;
            continue;
        }
        let Some((token, end)) = markup_tag_at(src, i, html) else {
            i += 1;
            continue;
        };
        if text_start < i {
            tokens.push(MarkupToken::Text(&src[text_start..i]));
        }
        tokens.push(token);
        i = end;
        if let MarkupToken::Open { name, empty: false, .. } = token
            && html
            && RAW_TEXT_ELEMENTS.iter().any(|r| r.eq_ignore_ascii_case(name))
        {
            let close = find_ascii_ci(&src.as_bytes()[end..], format!("</{name}").as_bytes()).map_or(src.len(), |p| end + p);
            tokens.push(MarkupToken::RawText(&src[end..close]));
            i = close;
        }
        text_start = i;
    }
    if text_start < src.len() {
        tokens.push(MarkupToken::Text(&src[text_start..]));
    }
    tokens
}

/// `src[i]` が `<` のとき、そこから始まるタグ等を読む。タグでなければ None（`<` は文字として扱う）。
fn markup_tag_at(src: &str, i: usize, html: bool) -> Option<(MarkupToken<'_>, usize)> {
    let rest = &src[i..];
    let until = |open: usize, close: &str| rest[open..].find(close).map_or(src.len(), |p| i + open + p + close.len());
    if rest.starts_with("<!--") {
        let end = until(4, "-->");
        return Some((MarkupToken::Other(&src[i..end]), end));
    }
    if rest.starts_with("<![CDATA[") {
        let end = until(9, "]]>");
        return Some((MarkupToken::Other(&src[i..end]), end));
    }
    if rest.starts_with("<!") || rest.starts_with("<?") {
        let end = until(2, ">");
        return Some((MarkupToken::Other(&src[i..end]), end));
    }
    let closing = rest.starts_with("</");
    let name_start = i + if closing { 2 } else { 1 };
    if !src.as_bytes().get(name_start)?.is_ascii_alphabetic() {
        return None;
    }
    let end = tag_end(src.as_bytes(), name_start)?;
    let name_end = src[name_start..end]
        .find(|c: char| c.is_ascii_whitespace() || c == '/' || c == '>')
        .map_or(end, |p| name_start + p);
    let name = &src[name_start..name_end];
    let raw = &src[i..end];
    let token = if closing {
        MarkupToken::Close { name, raw }
    } else {
        let empty = raw.ends_with("/>") || (html && VOID_ELEMENTS.iter().any(|v| v.eq_ignore_ascii_case(name)));
        MarkupToken::Open { name, raw, empty }
    };
    Some((token, end))
}

/// タグを閉じる `>` の次の位置。属性値の引用符の中の `>` は飛ばす。閉じていなければ None。
pub(crate) fn tag_end(b: &[u8], from: usize) -> Option<usize> {
    let mut quote = None;
    let mut j = from;
    loop {
        match (quote, *b.get(j)?) {
            (None, q @ (b'"' | b'\'')) => quote = Some(q),
            (Some(q), c) if c == q => quote = None,
            (None, b'>') => return Some(j + 1),
            _ => {}
        }
        j += 1;
    }
}

/// ASCII の大文字小文字を無視して `needle` を探す。
pub(crate) fn find_ascii_ci(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w.eq_ignore_ascii_case(needle))
}

/// Content-Type とマジックバイトから画像を判定する。
fn image_preview(content_type: &str, body: &[u8], uri_key: &str) -> Option<ImagePreview> {
    let sniffed = image::guess_format(body).ok().and_then(|f| match f {
        image::ImageFormat::Png => Some(("png", "image/png")),
        image::ImageFormat::Jpeg => Some(("jpg", "image/jpeg")),
        image::ImageFormat::Gif => Some(("gif", "image/gif")),
        image::ImageFormat::WebP => Some(("webp", "image/webp")),
        image::ImageFormat::Bmp => Some(("bmp", "image/bmp")),
        image::ImageFormat::Ico => Some(("ico", "image/x-icon")),
        _ => None,
    });
    let (ext, mime) = match sniffed {
        Some(s) => s,
        None if content_type == "image/svg+xml" || (content_type.is_empty() && looks_like_svg(body)) => {
            ("svg", "image/svg+xml")
        }
        None => return None,
    };
    let size = (ext != "svg")
        .then(|| image::ImageReader::new(std::io::Cursor::new(body)).with_guessed_format().ok()?.into_dimensions().ok())
        .flatten();
    Some(ImagePreview { uri: format!("bytes://pxproxy/{uri_key}.{ext}"), bytes: Arc::from(body), mime, size })
}

fn looks_like_svg(body: &[u8]) -> bool {
    let head = String::from_utf8_lossy(&body[..body.len().min(512)]).to_ascii_lowercase();
    head.contains("<svg")
}

pub(crate) fn header_value<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().skip(1).find_map(|line| {
        let (n, v) = line.split_once(':')?;
        n.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

fn looks_like_text(body: &[u8]) -> bool {
    let sample = &body[..body.len().min(4096)];
    match std::str::from_utf8(sample) {
        Ok(s) => !s.chars().any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t')),
        // サンプル末尾でマルチバイト文字が切れただけなら text とみなす
        Err(e) => e.error_len().is_none() && e.valid_up_to() + 4 >= sample.len(),
    }
}

pub(crate) fn hexdump(out: &mut String, data: &[u8]) {
    for (i, chunk) in data.chunks(16).enumerate() {
        let _ = write!(out, "{:08x}  ", i * 16);
        for j in 0..16 {
            match chunk.get(j) {
                Some(b) => {
                    let _ = write!(out, "{b:02x} ");
                }
                None => out.push_str("   "),
            }
            if j == 7 {
                out.push(' ');
            }
        }
        out.push_str(" |");
        out.extend(chunk.iter().map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' }));
        out.push_str("|\n");
    }
}

static LOCAL_OFFSET: OnceLock<UtcOffset> = OnceLock::new();

/// ローカルのタイムゾーンを読んでおく。OS によっては複数スレッドになる前でないと読めないので、起動直後に呼ぶ。
pub fn init_local_offset() {
    let _ = LOCAL_OFFSET.set(UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC));
}

fn local(us: i64) -> OffsetDateTime {
    let offset = *LOCAL_OFFSET.get_or_init(|| UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC));
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(us) * 1000)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH)
        .to_offset(offset)
}

/// `2026-10-08 12:34:56.789`（ローカル時刻）
pub fn format_datetime(us: i64) -> String {
    let t = local(us);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
        t.year(),
        t.month() as u8,
        t.day(),
        t.hour(),
        t.minute(),
        t.second(),
        t.millisecond()
    )
}

/// 一覧用の短い表記 `10-08 12:34:56`
pub fn format_time_short(us: i64) -> String {
    let t = local(us);
    format!("{:02}-{:02} {:02}:{:02}:{:02}", t.month() as u8, t.day(), t.hour(), t.minute(), t.second())
}

/// 時刻だけ `12:34:56.789`
pub fn format_clock(us: i64) -> String {
    let t = local(us);
    format!("{:02}:{:02}:{:02}.{:03}", t.hour(), t.minute(), t.second(), t.millisecond())
}

pub fn human_size(n: i64) -> String {
    match n {
        n if n < 1024 => format!("{n}"),
        n if n < 1024 * 1024 => format!("{:.1}K", n as f64 / 1024.0),
        n => format!("{:.1}M", n as f64 / (1024.0 * 1024.0)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    fn brotli(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        {
            let mut w = brotli::CompressorWriter::new(&mut out, 4096, 5, 22);
            w.write_all(data).unwrap();
        }
        out
    }

    #[test]
    fn gzip_body_is_expanded() {
        let r = render_message(b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n", &gzip("こんにちは".as_bytes()), "t");
        assert!(r.text.ends_with("こんにちは"), "{}", r.text);
    }

    #[test]
    fn brotli_and_stacked_encodings() {
        let r = render_message(b"HTTP/1.1 200 OK\r\ncontent-encoding: br\r\n\r\n", &brotli(b"{\"a\":1}"), "t");
        assert!(r.text.ends_with("{\"a\":1}"), "{}", r.text);
        // gzip → br の順に適用されたもの
        let both = brotli(&gzip(b"hello"));
        let r = render_message(b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip, br\r\n\r\n", &both, "t");
        assert!(r.text.ends_with("hello"), "{}", r.text);
    }

    #[test]
    fn unknown_encoding_is_reported() {
        let r = render_message(b"HTTP/1.1 200 OK\r\nContent-Encoding: compress\r\n\r\n", b"xyz", "t");
        assert!(r.text.contains("compress は未対応"), "{}", r.text);
    }

    #[test]
    fn png_is_previewed() {
        let mut png = Vec::new();
        image::RgbaImage::new(3, 2)
            .write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)
            .unwrap();
        // Content-Type が無くてもマジックバイトで判定する
        let r = render_message(b"HTTP/1.1 200 OK\r\n\r\n", &png, "7/res");
        let img = r.image.expect("image preview");
        assert_eq!((img.mime, img.size, img.uri.as_str()), ("image/png", Some((3, 2)), "bytes://pxproxy/7/res.png"));
        assert!(r.text.contains("00000000  89 50 4e 47"), "raw view is hexdump");
    }

    #[test]
    fn svg_is_previewed_and_shown_as_text() {
        let svg = b"<svg xmlns=\"http://www.w3.org/2000/svg\"/>";
        let r = render_message(b"HTTP/1.1 200 OK\r\nContent-Type: image/svg+xml\r\n\r\n", svg, "1/res");
        assert_eq!(r.image.unwrap().mime, "image/svg+xml");
        assert!(r.text.ends_with("<svg xmlns=\"http://www.w3.org/2000/svg\"/>"));
    }

    #[test]
    fn json_is_prettified_without_touching_values() {
        let src = r#"{"a":[1,2.50,{}],"b\"":"x, y: {z}","c":{"d":null}}"#;
        let p = pretty_json(src).unwrap();
        assert_eq!(
            p,
            "{\n  \"a\": [\n    1,\n    2.50,\n    {}\n  ],\n  \"b\\\"\": \"x, y: {z}\",\n  \"c\": {\n    \"d\": null\n  }\n}"
        );
        assert_eq!(pretty_json("{\"a\":1}\n{\"b\":2}").unwrap(), "{\n  \"a\": 1\n}\n{\n  \"b\": 2\n}");
        assert!(pretty_json("{\"a\":1").is_none(), "unbalanced");
        assert!(pretty_json("[1]]").is_none());
        assert!(pretty_json("{\"a\":\"x}").is_none(), "unterminated string");
        assert!(pretty_json("callback({})").is_none());
    }

    #[test]
    fn html_is_indented() {
        let src = "<!DOCTYPE html><html><head><meta charset=utf-8><title>t</title>\
                   <script>if (a<b) { x(\"</div>\") }</script></head>\
                   <body><div class=\"a>b\"><p>hi</p><br><img src=x /></div></body></html>";
        let p = pretty_markup(src, true).unwrap();
        let want = "<!DOCTYPE html>\n<html>\n  <head>\n    <meta charset=utf-8>\n    <title>t</title>\n    \
                    <script>if (a<b) { x(\"</div>\") }</script>\n  </head>\n  <body>\n    <div class=\"a>b\">\n      \
                    <p>hi</p>\n      <br>\n      <img src=x />\n    </div>\n  </body>\n</html>";
        assert_eq!(p, want);
        assert!(pretty_markup("a < b", true).is_none());
    }

    #[test]
    fn pretty_view_keeps_head_and_detects_syntax() {
        let r = render_message(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n", b"{\"a\":1}", "t");
        assert_eq!(r.syntax, Syntax::Json);
        assert_eq!(&r.text[r.body_start..], "{\"a\":1}");
        let pretty = r.pretty.unwrap();
        assert_eq!(&pretty[..r.body_start], &r.text[..r.body_start]);
        assert_eq!(&pretty[r.body_start..], "{\n  \"a\": 1\n}");
        // Content-Type が無くても先頭で判定する
        let r = render_message(b"HTTP/1.1 200 OK\r\n\r\n", b"  <?xml version=\"1.0\"?><a><b/></a>", "t");
        assert_eq!((r.syntax, r.pretty.is_some()), (Syntax::Xml, true));
        // 既に整形済みなら整形表示は出さない
        let r = render_message(b"HTTP/1.1 200 OK\r\n\r\n", b"[]", "t");
        assert!(r.pretty.is_none());
    }

    #[test]
    fn datetime_format() {
        let _ = LOCAL_OFFSET.set(UtcOffset::UTC);
        let us = 1_791_455_696_789_000; // 2026-10-08 10:34:56.789 UTC
        assert_eq!(format_datetime(us), "2026-10-08 10:34:56.789");
        assert_eq!(format_time_short(us), "10-08 10:34:56");
        assert_eq!(format_clock(us), "10:34:56.789");
    }

    #[test]
    fn binary_is_hexdumped() {
        let r = render_message(b"HTTP/1.1 200 OK\r\n\r\n", &[0, 1, 2, 0xff], "t");
        assert!(r.text.contains("00000000  00 01 02 ff"), "{}", r.text);
        assert!(r.image.is_none());
    }
}
