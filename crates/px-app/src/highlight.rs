//! Request / Response 表示のシンタックスハイライトと検索一致の強調。

use std::ops::Range;

use egui::text::{ByteIndex, LayoutJob, LayoutSection, TextFormat};
use egui::{Color32, FontId};

use crate::view::{self, Syntax};

/// 一致箇所の上限（これ以上は数えない）
pub const MAX_MATCHES: usize = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tok {
    Plain,
    /// リクエスト行 / ステータス行
    StartLine,
    HeaderName,
    /// `[...]` の注記
    Note,
    Key,
    Str,
    Num,
    Literal,
    Punct,
    Tag,
    Attr,
    AttrValue,
    Comment,
}

fn color(tok: Tok, dark: bool, plain: Color32) -> Color32 {
    let rgb = |d: (u8, u8, u8), l: (u8, u8, u8)| {
        let (r, g, b) = if dark { d } else { l };
        Color32::from_rgb(r, g, b)
    };
    match tok {
        Tok::Plain | Tok::Punct => plain,
        Tok::StartLine => rgb((230, 200, 120), (150, 90, 0)),
        Tok::HeaderName | Tok::Key | Tok::Attr => rgb((130, 180, 240), (20, 90, 180)),
        Tok::Note | Tok::Comment => rgb((120, 130, 120), (120, 130, 120)),
        Tok::Str | Tok::AttrValue => rgb((150, 200, 120), (40, 120, 40)),
        Tok::Num | Tok::Literal => rgb((220, 150, 220), (150, 40, 150)),
        Tok::Tag => rgb((230, 130, 110), (170, 50, 30)),
    }
}

/// 連続した (範囲, 種類) の列。範囲は昇順に積み、隙間は Plain で埋める。
#[derive(Default)]
struct Spans(Vec<(Range<usize>, Tok)>);

impl Spans {
    fn mark(&mut self, range: Range<usize>, tok: Tok) {
        let end = self.0.last().map_or(0, |(r, _)| r.end);
        debug_assert!(range.start >= end);
        if range.start > end {
            self.push(end..range.start, Tok::Plain);
        }
        if !range.is_empty() {
            self.push(range, tok);
        }
    }

    fn push(&mut self, range: Range<usize>, tok: Tok) {
        match self.0.last_mut() {
            Some((r, t)) if *t == tok && r.end == range.start => r.end = range.end,
            _ => self.0.push((range, tok)),
        }
    }
}

/// 色とフォント。
#[derive(Debug, Clone, PartialEq)]
pub struct Theme {
    pub font: FontId,
    pub dark: bool,
    /// 色を付けない部分の文字色
    pub plain: Color32,
}

/// `text` 全体の LayoutJob を作る。`body_start` より前はヘッダ、後ろは `syntax` でハイライトし、
/// `matches`（バイト範囲・昇順）を背景色で強調する。`current` は強調を変える一致の番号。
pub fn layout_job(
    text: &str,
    body_start: usize,
    syntax: Syntax,
    matches: &[Range<usize>],
    current: Option<usize>,
    theme: &Theme,
) -> LayoutJob {
    let Theme { font, dark, plain } = theme.clone();
    let mut spans = Spans::default();
    head(&mut spans, &text[..body_start.min(text.len())]);
    let body = &text[body_start.min(text.len())..];
    match syntax {
        Syntax::Json => json(&mut spans, body, body_start),
        Syntax::Html => markup(&mut spans, body, body_start, true),
        Syntax::Xml => markup(&mut spans, body, body_start, false),
        Syntax::Plain => {}
    }
    spans.mark(text.len()..text.len(), Tok::Plain);

    let (hit_bg, current_bg) = if dark {
        (Color32::from_rgb(110, 95, 30), Color32::from_rgb(230, 140, 30))
    } else {
        (Color32::from_rgb(255, 235, 140), Color32::from_rgb(255, 160, 50))
    };
    let mut job = LayoutJob { text: text.to_owned(), ..Default::default() };
    job.wrap.max_width = f32::INFINITY;
    let mut push = |range: Range<usize>, tok: Tok, hit: Option<usize>| {
        let mut format = TextFormat::simple(font.clone(), color(tok, dark, plain));
        if let Some(m) = hit {
            format.background = if Some(m) == current { current_bg } else { hit_bg };
            if Some(m) == current {
                format.color = Color32::BLACK;
            }
        }
        let byte_range = ByteIndex(range.start)..ByteIndex(range.end);
        job.sections.push(LayoutSection { leading_space: 0.0, byte_range, format });
    };
    // 各 span を一致範囲の境界で分割する
    let mut m = 0;
    for (r, tok) in spans.0 {
        let mut pos = r.start;
        while pos < r.end {
            while m < matches.len() && matches[m].end <= pos {
                m += 1;
            }
            match matches.get(m) {
                Some(hit) if hit.start <= pos => {
                    let end = r.end.min(hit.end);
                    push(pos..end, tok, Some(m));
                    pos = end;
                }
                next => {
                    let end = r.end.min(next.map_or(r.end, |h| h.start));
                    push(pos..end, tok, None);
                    pos = end;
                }
            }
        }
    }
    job
}

/// ASCII の大文字小文字を無視した、重ならない一致のバイト範囲。
pub fn find_matches(text: &str, query: &str) -> Vec<Range<usize>> {
    let needle = query.as_bytes();
    let hay = text.as_bytes();
    let mut out = Vec::new();
    let mut from = 0;
    while out.len() < MAX_MATCHES
        && let Some(p) = view::find_ascii_ci(&hay[from..], needle)
    {
        let start = from + p;
        out.push(start..start + needle.len());
        from = start + needle.len();
    }
    out
}

fn head(spans: &mut Spans, head: &str) {
    let mut offset = 0;
    for (i, line) in head.split_inclusive('\n').enumerate() {
        let content = line.trim_end_matches(['\r', '\n']);
        if i == 0 && !content.starts_with('[') {
            spans.mark(offset..offset + content.len(), Tok::StartLine);
        } else if content.starts_with('[') {
            spans.mark(offset..offset + content.len(), Tok::Note);
        } else if let Some(colon) = content.find(':') {
            spans.mark(offset..offset + colon, Tok::HeaderName);
        }
        offset += line.len();
    }
}

/// 切り詰められた JSON でも壊れないよう、トークン単位で色を付けるだけにする。
fn json(spans: &mut Spans, body: &str, base: usize) {
    let b = body.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let start = i;
        match b[i] {
            b'"' => {
                i += 1;
                let mut escaped = false;
                while i < b.len() {
                    let c = b[i];
                    i += 1;
                    if escaped {
                        escaped = false;
                    } else if c == b'\\' {
                        escaped = true;
                    } else if c == b'"' {
                        break;
                    }
                }
                let next = b[i..].iter().find(|c| !c.is_ascii_whitespace());
                let tok = if next == Some(&b':') { Tok::Key } else { Tok::Str };
                spans.mark(base + start..base + i, tok);
            }
            b'-' | b'0'..=b'9' => {
                i += b[i..].iter().take_while(|c| c.is_ascii_digit() || matches!(c, b'-' | b'+' | b'.' | b'e' | b'E')).count();
                spans.mark(base + start..base + i, Tok::Num);
            }
            c if c.is_ascii_alphabetic() => {
                i += b[i..].iter().take_while(|c| c.is_ascii_alphabetic()).count();
                if matches!(&body[start..i], "true" | "false" | "null") {
                    spans.mark(base + start..base + i, Tok::Literal);
                }
            }
            b'{' | b'}' | b'[' | b']' | b',' | b':' => {
                i += 1;
                spans.mark(base + start..base + i, Tok::Punct);
            }
            _ => i += 1,
        }
    }
}

fn markup(spans: &mut Spans, body: &str, base: usize, html: bool) {
    let b = body.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'<' {
            i += 1;
            continue;
        }
        let rest = &body[i..];
        if rest.starts_with("<!--") || rest.starts_with("<!") || rest.starts_with("<?") {
            let close = if rest.starts_with("<!--") { "-->" } else { ">" };
            let end = rest[2..].find(close).map_or(b.len(), |p| i + 2 + p + close.len());
            spans.mark(base + i..base + end, Tok::Comment);
            i = end;
            continue;
        }
        let closing = rest.starts_with("</");
        let name_start = i + if closing { 2 } else { 1 };
        if !b.get(name_start).is_some_and(u8::is_ascii_alphabetic) {
            i += 1;
            continue;
        }
        let Some(end) = view::tag_end(b, name_start) else {
            i += 1;
            continue;
        };
        let name_end = name_start
            + b[name_start..end].iter().take_while(|c| !(c.is_ascii_whitespace() || matches!(c, b'/' | b'>'))).count();
        spans.mark(base + i..base + name_end, Tok::Tag);
        attributes(spans, body, name_end, end, base);
        i = end;
        // script / style の中身はタグとして読まない
        let name = &body[name_start..name_end];
        if html
            && !closing
            && !body[..end].ends_with("/>")
            && view::RAW_TEXT_ELEMENTS.iter().any(|r| r.eq_ignore_ascii_case(name))
        {
            i = view::find_ascii_ci(&b[end..], format!("</{name}").as_bytes()).map_or(b.len(), |p| end + p);
        }
    }
}

/// タグ内 `[from, end)` の属性に色を付ける。最後の `>` / `/>` は Tag。
fn attributes(spans: &mut Spans, body: &str, from: usize, end: usize, base: usize) {
    let b = body.as_bytes();
    let close_len = if body[..end].ends_with("/>") { 2 } else { 1 };
    let attrs_end = end - close_len;
    let mut i = from;
    while i < attrs_end {
        let c = b[i];
        if c.is_ascii_whitespace() || c == b'=' || c == b'/' {
            i += 1;
        } else if c == b'"' || c == b'\'' {
            let close = b[i + 1..attrs_end].iter().position(|&x| x == c).map_or(attrs_end, |p| i + 2 + p);
            spans.mark(base + i..base + close, Tok::AttrValue);
            i = close;
        } else {
            let start = i;
            i += b[i..attrs_end].iter().take_while(|x| !(x.is_ascii_whitespace() || matches!(x, b'=' | b'"' | b'\''))).count();
            // `=` の直後なら引用符なしの値
            let after_eq = b[from..start].iter().rev().find(|x| !x.is_ascii_whitespace()) == Some(&b'=');
            spans.mark(base + start..base + i, if after_eq { Tok::AttrValue } else { Tok::Attr });
        }
    }
    spans.mark(base + attrs_end..base + end, Tok::Tag);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tokens(text: &str, body_start: usize, syntax: Syntax) -> Vec<(String, Tok)> {
        let mut spans = Spans::default();
        head(&mut spans, &text[..body_start]);
        match syntax {
            Syntax::Json => json(&mut spans, &text[body_start..], body_start),
            Syntax::Html => markup(&mut spans, &text[body_start..], body_start, true),
            _ => {}
        }
        spans.0.into_iter().filter(|(_, t)| *t != Tok::Plain).map(|(r, t)| (text[r].to_string(), t)).collect()
    }

    #[test]
    fn head_and_json_tokens() {
        let text = "HTTP/1.1 200 OK\r\nContent-Type: json\r\n\r\n{\"k\": [\"v\", -1.5e3, true]}";
        let body_start = text.find('{').unwrap();
        let t = tokens(text, body_start, Syntax::Json);
        let want = [
            ("HTTP/1.1 200 OK", Tok::StartLine),
            ("Content-Type", Tok::HeaderName),
            ("{", Tok::Punct),
            ("\"k\"", Tok::Key),
            (":", Tok::Punct),
            ("[", Tok::Punct),
            ("\"v\"", Tok::Str),
            (",", Tok::Punct),
            ("-1.5e3", Tok::Num),
            (",", Tok::Punct),
            ("true", Tok::Literal),
            ("]}", Tok::Punct),
        ];
        assert_eq!(t, want.map(|(s, k)| (s.to_string(), k)));
    }

    #[test]
    fn markup_tokens() {
        let t = tokens("<a href=\"x>y\" b=c disabled><!-- c --><script>a<b</script>", 0, Syntax::Html);
        let want = [
            ("<a", Tok::Tag),
            ("href", Tok::Attr),
            ("\"x>y\"", Tok::AttrValue),
            ("b", Tok::Attr),
            ("c", Tok::AttrValue),
            ("disabled", Tok::Attr),
            (">", Tok::Tag),
            ("<!-- c -->", Tok::Comment),
            ("<script>", Tok::Tag),
            ("</script>", Tok::Tag),
        ];
        assert_eq!(t, want.map(|(s, k)| (s.to_string(), k)));
    }

    #[test]
    fn matches_split_sections() {
        assert_eq!(find_matches("aXa xa", "XA"), vec![1..3, 4..6]);
        assert!(find_matches("abc", "").is_empty());
        let theme = Theme { font: FontId::monospace(12.0), dark: true, plain: Color32::WHITE };
        let job = layout_job("abcabc", 0, Syntax::Plain, &[1..2, 4..6], Some(1), &theme);
        let ranges: Vec<_> = job.sections.iter().map(|s| s.byte_range.start.0..s.byte_range.end.0).collect();
        assert_eq!(ranges, vec![0..1, 1..2, 2..4, 4..6]);
        assert_eq!(job.sections[3].format.color, Color32::BLACK, "current match");
    }
}
