//! Comparer 用の行単位の差分。変更された行の組は、さらに単語単位で違う箇所を求める。

use std::ops::Range;
use std::time::Duration;

use similar::{ChangeTag, DiffOp, TextDiff};

/// 差分の計算をあきらめて近似にする時間
const TIMEOUT: Duration = Duration::from_secs(2);
/// これより長い行は単語単位の差分を取らない
const MAX_INLINE_LINE: usize = 4096;

/// 片側の 1 行。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    /// 1 始まりの行番号
    pub no: usize,
    /// 改行を除いた内容
    pub text: String,
    /// 行内で違う箇所（バイト範囲）
    pub spans: Vec<Range<usize>>,
}

/// 左右に並べる 1 行。片側だけの行は反対側が None。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub left: Option<Line>,
    pub right: Option<Line>,
    pub changed: bool,
}

#[derive(Debug, Default)]
pub struct Diff {
    pub rows: Vec<Row>,
    /// 変更のかたまりの先頭の行（`rows` の位置）
    pub hunks: Vec<usize>,
}

pub fn diff(a: &str, b: &str) -> Diff {
    let la: Vec<&str> = a.split_inclusive('\n').collect();
    let lb: Vec<&str> = b.split_inclusive('\n').collect();
    let d = TextDiff::configure().timeout(TIMEOUT).diff_lines(a, b);
    let line = |lines: &[&str], i: usize| Line { no: i + 1, text: trim_newline(lines[i]).to_string(), spans: Vec::new() };
    let mut out = Diff::default();
    for op in d.ops() {
        if !matches!(op, DiffOp::Equal { .. }) {
            out.hunks.push(out.rows.len());
        }
        match *op {
            DiffOp::Equal { old_index, new_index, len } => {
                for k in 0..len {
                    out.rows.push(Row {
                        left: Some(line(&la, old_index + k)),
                        right: Some(line(&lb, new_index + k)),
                        changed: false,
                    });
                }
            }
            DiffOp::Delete { old_index, old_len, .. } => {
                for k in 0..old_len {
                    out.rows.push(Row { left: Some(line(&la, old_index + k)), right: None, changed: true });
                }
            }
            DiffOp::Insert { new_index, new_len, .. } => {
                for k in 0..new_len {
                    out.rows.push(Row { left: None, right: Some(line(&lb, new_index + k)), changed: true });
                }
            }
            DiffOp::Replace { old_index, old_len, new_index, new_len } => {
                for k in 0..old_len.max(new_len) {
                    let mut left = (k < old_len).then(|| line(&la, old_index + k));
                    let mut right = (k < new_len).then(|| line(&lb, new_index + k));
                    if let (Some(l), Some(r)) = (&mut left, &mut right) {
                        inline_spans(l, r);
                    }
                    out.rows.push(Row { left, right, changed: true });
                }
            }
        }
    }
    out
}

fn trim_newline(s: &str) -> &str {
    let s = s.strip_suffix('\n').unwrap_or(s);
    s.strip_suffix('\r').unwrap_or(s)
}

/// 対応する 2 行の、単語単位で違う箇所を求める。
fn inline_spans(l: &mut Line, r: &mut Line) {
    if l.text.len() > MAX_INLINE_LINE || r.text.len() > MAX_INLINE_LINE {
        return;
    }
    let d = TextDiff::configure().timeout(TIMEOUT).diff_words(l.text.as_str(), r.text.as_str());
    let (mut li, mut ri) = (0, 0);
    for c in d.iter_all_changes() {
        let n = c.value().len();
        match c.tag() {
            ChangeTag::Equal => {
                li += n;
                ri += n;
            }
            ChangeTag::Delete => {
                push_span(&mut l.spans, li..li + n);
                li += n;
            }
            ChangeTag::Insert => {
                push_span(&mut r.spans, ri..ri + n);
                ri += n;
            }
        }
    }
}

/// 隣り合う範囲はつなげる。
fn push_span(spans: &mut Vec<Range<usize>>, r: Range<usize>) {
    match spans.last_mut() {
        Some(last) if last.end == r.start => last.end = r.end,
        _ => spans.push(r),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn side_by_side_rows() {
        let a = "GET /a HTTP/1.1\r\nHost: x\r\nCookie: s=1\r\nX-Old: 1\r\n";
        let b = "GET /a HTTP/1.1\r\nHost: x\r\nCookie: s=2\r\nX-New: 2\r\nX-Add: 3\r\n";
        let d = diff(a, b);
        let shape: Vec<(Option<usize>, Option<usize>, bool)> =
            d.rows.iter().map(|r| (r.left.as_ref().map(|l| l.no), r.right.as_ref().map(|l| l.no), r.changed)).collect();
        assert_eq!(
            shape,
            [(Some(1), Some(1), false), (Some(2), Some(2), false), (Some(3), Some(3), true), (Some(4), Some(4), true), (None, Some(5), true)]
        );
        assert_eq!(d.hunks, [2]);
        let row = &d.rows[2];
        let (l, r) = (row.left.as_ref().unwrap(), row.right.as_ref().unwrap());
        assert_eq!(l.text, "Cookie: s=1", "改行は含めない");
        assert_eq!(l.spans.iter().map(|s| &l.text[s.clone()]).collect::<Vec<_>>(), ["s=1"]);
        assert_eq!(r.spans.iter().map(|s| &r.text[s.clone()]).collect::<Vec<_>>(), ["s=2"]);
    }

    #[test]
    fn identical_and_empty() {
        assert!(diff("a\nb", "a\nb").hunks.is_empty());
        let d = diff("", "x");
        assert_eq!(d.rows.len(), 1);
        assert_eq!(d.hunks, [0]);
    }
}
