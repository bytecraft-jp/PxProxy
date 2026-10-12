//! GraphQL のリクエストを読みやすく整形する（クエリのインデントと variables の分離）。

use crate::view::pretty_json;

/// GraphQL のリクエスト Body なら整形したテキストを返す。
/// `{"query": "...", "variables": {...}}`（バッチの配列も可）と、`application/graphql` の生のクエリを扱う。
pub fn pretty_request(content_type: &str, body: &str) -> Option<String> {
    if content_type.contains("graphql") && !content_type.contains("json") {
        return pretty_query(body);
    }
    if !content_type.is_empty() && !content_type.contains("json") {
        return None;
    }
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    let ops: Vec<&serde_json::Map<String, serde_json::Value>> = match &value {
        serde_json::Value::Object(o) => vec![o],
        serde_json::Value::Array(items) if !items.is_empty() => items.iter().map(|v| v.as_object()).collect::<Option<_>>()?,
        _ => return None,
    };
    let mut out = String::new();
    for (i, op) in ops.iter().enumerate() {
        let query = op.get("query")?.as_str()?;
        let pretty = pretty_query(query)?;
        if i > 0 {
            out.push_str("\n\n");
        }
        if ops.len() > 1 {
            out.push_str(&format!("# [{}]\n", i + 1));
        }
        if let Some(name) = op.get("operationName").and_then(|n| n.as_str()) {
            out.push_str(&format!("# operationName: {name}\n"));
        }
        out.push_str(&pretty);
        for key in ["variables", "extensions"] {
            if let Some(v) = op.get(key).filter(|v| !v.is_null()) {
                let raw = v.to_string();
                out.push_str(&format!("\n\n# {key}\n{}", pretty_json(&raw).unwrap_or(raw)));
            }
        }
    }
    Some(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tok<'a> {
    Name(&'a str),
    /// 数値・文字列（ブロック文字列を含む）
    Value(&'a str),
    Punct(&'a str),
    Comment(&'a str),
}

/// GraphQL の字句に分ける。知らない文字があれば None（GraphQL ではない）。
fn tokenize(src: &str) -> Option<Vec<Tok<'_>>> {
    let b = src.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let start = i;
        let c = b[i];
        match c {
            // カンマは空白と同じ扱い（引数の中では出力時に補う）
            b' ' | b'\t' | b'\r' | b'\n' | b',' => {
                i += 1;
                if c == b',' {
                    out.push(Tok::Punct(","));
                }
            }
            b'#' => {
                i += b[i..].iter().position(|&x| x == b'\n').unwrap_or(b.len() - i);
                out.push(Tok::Comment(src[start..i].trim_end()));
            }
            b'"' if src[i..].starts_with("\"\"\"") => {
                let end = src[i + 3..].find("\"\"\"")?;
                i += 3 + end + 3;
                out.push(Tok::Value(&src[start..i]));
            }
            b'"' => {
                i += 1;
                let mut escaped = false;
                loop {
                    let &d = b.get(i)?;
                    i += 1;
                    match d {
                        _ if escaped => escaped = false,
                        b'\\' => escaped = true,
                        b'"' => break,
                        b'\n' => return None,
                        _ => {}
                    }
                }
                out.push(Tok::Value(&src[start..i]));
            }
            b'.' if src[i..].starts_with("...") => {
                i += 3;
                out.push(Tok::Punct("..."));
            }
            b'-' | b'0'..=b'9' => {
                i += 1;
                i += b[i..].iter().take_while(|x| x.is_ascii_alphanumeric() || matches!(x, b'.' | b'+' | b'-')).count();
                out.push(Tok::Value(&src[start..i]));
            }
            b'_' | b'a'..=b'z' | b'A'..=b'Z' => {
                i += b[i..].iter().take_while(|x| x.is_ascii_alphanumeric() || **x == b'_').count();
                out.push(Tok::Name(&src[start..i]));
            }
            b'{' | b'}' | b'(' | b')' | b'[' | b']' | b':' | b'!' | b'$' | b'@' | b'=' | b'|' | b'&' => {
                i += 1;
                out.push(Tok::Punct(&src[start..i]));
            }
            _ => return None,
        }
    }
    Some(out)
}

/// クエリをインデントし直す。選択セット（`{ }`）の中は 1 フィールド 1 行、引数（`( )`）の中は 1 行にまとめる。
/// GraphQL として読めなければ None。
pub fn pretty_query(src: &str) -> Option<String> {
    let tokens = tokenize(src.trim())?;
    if !tokens.contains(&Tok::Punct("{")) {
        return None;
    }
    let mut out = String::new();
    let mut depth = 0usize;
    // 引数・変数定義の ( ) と、その中の入力オブジェクト・リストの深さ
    let mut paren = 0usize;
    let mut prev: Option<Tok<'_>> = None;
    let mut prev2: Option<Tok<'_>> = None;
    let newline = |out: &mut String, depth: usize| {
        while out.ends_with(' ') {
            out.pop();
        }
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(&"  ".repeat(depth));
    };
    for t in tokens {
        match t {
            Tok::Comment(c) => {
                newline(&mut out, depth);
                out.push_str(c);
                out.push('\n');
                out.push_str(&"  ".repeat(depth));
                // コメントの後は行頭として扱う
                prev = Some(Tok::Punct("{"));
                prev2 = None;
                continue;
            }
            Tok::Punct("{") if paren == 0 => {
                while out.ends_with(' ') || out.ends_with('\n') {
                    out.pop();
                }
                if !out.is_empty() {
                    out.push(' ');
                }
                out.push('{');
                depth += 1;
                newline(&mut out, depth);
            }
            Tok::Punct("}") if paren == 0 => {
                depth = depth.saturating_sub(1);
                newline(&mut out, depth);
                out.push('}');
                if depth == 0 {
                    // 次の定義（fragment など）との間は 1 行空ける
                    out.push_str("\n\n");
                }
            }
            Tok::Punct(",") if paren == 0 => continue,
            Tok::Punct(",") => out.push_str(", "),
            Tok::Punct(p @ ("(" | "[" | "{")) => {
                out.push_str(p);
                paren += 1;
            }
            Tok::Punct(p @ (")" | "]" | "}")) => {
                out.push_str(p);
                paren = paren.saturating_sub(1);
            }
            Tok::Punct(":") => out.push_str(": "),
            Tok::Punct("=") => out.push_str(" = "),
            Tok::Punct(p @ ("|" | "&")) => {
                out.push(' ');
                out.push_str(p);
                out.push(' ');
            }
            Tok::Punct("@") => {
                space(&mut out, prev);
                out.push('@');
            }
            Tok::Punct(p) => {
                // `$`・`!`・`...`
                if p == "..." && starts_field(prev, prev2, depth, paren) {
                    newline(&mut out, depth);
                } else if p == "$" {
                    space(&mut out, prev);
                }
                out.push_str(p);
            }
            Tok::Name(n) => {
                if starts_field(prev, prev2, depth, paren) {
                    newline(&mut out, depth);
                } else if prev == Some(Tok::Punct("...")) && n == "on" {
                    out.push(' ');
                } else {
                    space(&mut out, prev);
                }
                out.push_str(n);
            }
            Tok::Value(v) => {
                space(&mut out, prev);
                out.push_str(v);
            }
        }
        prev2 = prev;
        prev = Some(t);
    }
    Some(out.trim_end().to_string())
}

/// 選択セットの中で、新しいフィールド（または `...` の展開）が始まるか。
fn starts_field(prev: Option<Tok<'_>>, prev2: Option<Tok<'_>>, depth: usize, paren: usize) -> bool {
    if depth == 0 || paren > 0 {
        return false;
    }
    match prev {
        Some(Tok::Punct("{" | "}" | ")")) | Some(Tok::Value(_)) => true,
        // `... on Type` の Type は続き
        Some(Tok::Name("on")) => prev2 != Some(Tok::Punct("...")),
        // 前のフィールド名・引数なしのディレクティブ名・`...Fragment` の後
        Some(Tok::Name(_)) => true,
        _ => false,
    }
}

/// 直前の字句との間に空白が要れば入れる（行頭には入れない）。
fn space(out: &mut String, prev: Option<Tok<'_>>) {
    if matches!(prev, Some(Tok::Name(_) | Tok::Value(_) | Tok::Punct(")" | "]" | "}" | "!"))) && !out.ends_with('\n') {
        out.push(' ');
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_is_indented() {
        let q = "query Get($id: ID!, $n: Int = 10) { user(id: $id) { name, friends(first: $n) @include(if: true) { edges { node { id } } } ...F ... on Admin { level } } } fragment F on User { email }";
        let want = "query Get($id: ID!, $n: Int = 10) {\n  user(id: $id) {\n    name\n    friends(first: $n) @include(if: true) {\n      edges {\n        node {\n          id\n        }\n      }\n    }\n    ...F\n    ... on Admin {\n      level\n    }\n  }\n}\n\nfragment F on User {\n  email\n}";
        assert_eq!(pretty_query(q).unwrap(), want);
    }

    #[test]
    fn shorthand_alias_input_objects_and_comments() {
        let q = "{ a: user(filter: {name: \"x y\", tags: [\"a\", \"b\"]}) { id } # 末尾\n me { id } }";
        let want = "{\n  a: user(filter: {name: \"x y\", tags: [\"a\", \"b\"]}) {\n    id\n  }\n  # 末尾\n  me {\n    id\n  }\n}";
        assert_eq!(pretty_query(q).unwrap(), want);
        assert!(pretty_query("not graphql; at all").is_none());
        assert!(pretty_query("hello world").is_none(), "選択セットが無い");
    }

    #[test]
    fn json_request_shows_query_and_variables() {
        let body = r#"{"operationName":"Get","query":"query Get($id: ID!) { user(id: $id) { name } }","variables":{"id":"1"}}"#;
        let want = "# operationName: Get\nquery Get($id: ID!) {\n  user(id: $id) {\n    name\n  }\n}\n\n# variables\n{\n  \"id\": \"1\"\n}";
        assert_eq!(pretty_request("application/json", body).unwrap(), want);
        let batch = format!("[{body},{body}]");
        let p = pretty_request("application/json", &batch).unwrap();
        assert!(p.starts_with("# [1]\n# operationName: Get") && p.contains("\n\n# [2]\n"), "{p}");
        assert!(pretty_request("application/json", r#"{"a":1}"#).is_none(), "GraphQL ではない JSON");
        assert!(pretty_request("text/html", body).is_none());
        assert_eq!(pretty_request("application/graphql", "{ me { id } }").unwrap(), "{\n  me {\n    id\n  }\n}");
    }
}
