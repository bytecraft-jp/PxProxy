//! Protocol Buffers をスキーマなしでデコードして表示する（`protoc --decode_raw` と同じ形式）。
//! gRPC / gRPC-Web の Body は 5 バイトの枠（圧縮フラグ + 長さ）で区切られているので、枠ごとにデコードする。

use std::fmt::Write;

use crate::view::{decode_content, header_value};

/// 入れ子の深さの上限（壊れたデータで深く潜りすぎないように）
const MAX_DEPTH: usize = 32;
/// 表示する bytes の長さの上限
const MAX_BYTES_SHOWN: usize = 256;

/// Protobuf として扱う Content-Type か（gRPC-Web のテキスト形式 = Base64 は除く）。
pub fn is_protobuf(content_type: &str) -> bool {
    !content_type.contains("grpc-web-text")
        && (content_type.contains("protobuf")
            || content_type.starts_with("application/grpc")
            || content_type == "application/x-google-protobuf")
}

/// Body をデコードして表示用のテキストにする。デコードできなければ None。
pub fn decode_body(head: &str, content_type: &str, body: &[u8]) -> Option<String> {
    if content_type.starts_with("application/grpc") {
        return decode_grpc(head, body);
    }
    let mut out = String::new();
    message(&mut out, body, 0).ok()?;
    Some(out)
}

/// gRPC の枠を順に読む。gRPC-Web のトレーラー（フラグの最上位ビット）はテキストとして出す。
fn decode_grpc(head: &str, mut body: &[u8]) -> Option<String> {
    let encoding = header_value(head, "grpc-encoding").unwrap_or("identity").to_ascii_lowercase();
    let mut out = String::new();
    let mut n = 0;
    while !body.is_empty() {
        let (&flags, rest) = body.split_first()?;
        let len = u32::from_be_bytes(rest.get(..4)?.try_into().ok()?) as usize;
        let data = rest.get(4..4 + len)?;
        body = &rest[4 + len..];
        n += 1;
        if n > 1 {
            out.push('\n');
        }
        if flags & 0x80 != 0 {
            let _ = writeln!(out, "# トレーラー ({len} bytes)");
            out.push_str(String::from_utf8_lossy(data).trim_end());
            out.push('\n');
            continue;
        }
        let compressed = flags & 1 != 0;
        let _ = writeln!(out, "# メッセージ {n} ({len} bytes{})", if compressed { format!(", {encoding} で圧縮") } else { String::new() });
        let decoded;
        let data = if compressed {
            match decode_content(&encoding, data) {
                Ok(Some(d)) => {
                    decoded = d;
                    &decoded[..]
                }
                _ => {
                    out.push_str("[展開できません]\n");
                    continue;
                }
            }
        } else {
            data
        };
        if message(&mut out, data, 0).is_err() {
            out.push_str("[Protobuf としてデコードできません]\n");
        }
    }
    (n > 0).then_some(out)
}

fn varint(buf: &[u8], pos: &mut usize) -> Result<u64, ()> {
    let mut v: u64 = 0;
    for shift in (0..64).step_by(7) {
        let &b = buf.get(*pos).ok_or(())?;
        *pos += 1;
        v |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Ok(v);
        }
    }
    Err(())
}

/// 1 メッセージを `out` に書く。最後まで正しく読めなければ Err（`out` は途中まで書かれている）。
fn message(out: &mut String, buf: &[u8], depth: usize) -> Result<(), ()> {
    if depth > MAX_DEPTH {
        return Err(());
    }
    let indent = "  ".repeat(depth);
    let mut pos = 0;
    while pos < buf.len() {
        let key = varint(buf, &mut pos)?;
        let (field, wire) = (key >> 3, key & 7);
        if field == 0 || field > (1 << 29) {
            return Err(());
        }
        match wire {
            0 => {
                let v = varint(buf, &mut pos)?;
                // 負の int32 / int64 は 10 バイトの大きな値になるので、符号付きでも出す
                if v > i64::MAX as u64 {
                    let _ = writeln!(out, "{indent}{field}: {v}  # {}", v as i64);
                } else {
                    let _ = writeln!(out, "{indent}{field}: {v}");
                }
            }
            1 => {
                let b: [u8; 8] = buf.get(pos..pos + 8).ok_or(())?.try_into().map_err(|_| ())?;
                pos += 8;
                let _ = writeln!(out, "{indent}{field}: 0x{:016x}  # {}", u64::from_le_bytes(b), f64::from_le_bytes(b));
            }
            5 => {
                let b: [u8; 4] = buf.get(pos..pos + 4).ok_or(())?.try_into().map_err(|_| ())?;
                pos += 4;
                let _ = writeln!(out, "{indent}{field}: 0x{:08x}  # {}", u32::from_le_bytes(b), f32::from_le_bytes(b));
            }
            2 => {
                let len = usize::try_from(varint(buf, &mut pos)?).map_err(|_| ())?;
                let data = buf.get(pos..pos.checked_add(len).ok_or(())?).ok_or(())?;
                pos += len;
                length_delimited(out, field, data, depth);
            }
            // グループ（非推奨）とその他は扱わない
            _ => return Err(()),
        }
    }
    Ok(())
}

/// 長さ付きの値: 読める文字列ならそのまま、メッセージとして読めれば入れ子、どちらでもなければ bytes。
fn length_delimited(out: &mut String, field: u64, data: &[u8], depth: usize) {
    let indent = "  ".repeat(depth);
    if let Ok(s) = std::str::from_utf8(data)
        && !s.chars().any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
    {
        let _ = writeln!(out, "{indent}{field}: {s:?}");
        return;
    }
    if !data.is_empty() {
        let mut nested = String::new();
        if message(&mut nested, data, depth + 1).is_ok() {
            let _ = writeln!(out, "{indent}{field} {{");
            out.push_str(&nested);
            let _ = writeln!(out, "{indent}}}");
            return;
        }
    }
    let shown: String = data.iter().take(MAX_BYTES_SHOWN).map(|b| format!("{b:02x}")).collect();
    let more = if data.len() > MAX_BYTES_SHOWN { format!("…（全 {} bytes）", data.len()) } else { String::new() };
    let _ = writeln!(out, "{indent}{field}: <{shown}{more}>");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// field 1 = 150, field 2 = "hi", field 3 = { 1: -1 (int64) }, field 4 = fixed32 1.5f, field 5 = bytes ff 00
    fn sample() -> Vec<u8> {
        let mut m = vec![0x08, 0x96, 0x01, 0x12, 0x02, b'h', b'i'];
        let neg: [u8; 10] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01];
        m.extend([0x1a, 11, 0x08]);
        m.extend(neg);
        m.push(0x25);
        m.extend(1.5f32.to_le_bytes());
        m.extend([0x2a, 0x02, 0xff, 0x00]);
        m
    }

    #[test]
    fn raw_message() {
        let want = "1: 150\n2: \"hi\"\n3 {\n  1: 18446744073709551615  # -1\n}\n4: 0x3fc00000  # 1.5\n5: <ff00>\n";
        assert_eq!(decode_body("", "application/x-protobuf", &sample()).unwrap(), want);
        assert!(decode_body("", "application/x-protobuf", &[0x08]).is_none(), "途中で切れている");
        assert!(decode_body("", "application/x-protobuf", &[0x00, 0x01]).is_none(), "field 0 は無い");
    }

    #[test]
    fn grpc_frames_and_trailers() {
        let msg = sample();
        let mut body = vec![0];
        body.extend((msg.len() as u32).to_be_bytes());
        body.extend(&msg);
        let trailer = b"grpc-status: 0\r\n";
        body.push(0x80);
        body.extend((trailer.len() as u32).to_be_bytes());
        body.extend(trailer);
        let out = decode_body("HTTP/1.1 200 OK\r\n\r\n", "application/grpc-web+proto", &body).unwrap();
        assert!(out.starts_with(&format!("# メッセージ 1 ({} bytes)\n1: 150\n", msg.len())), "{out}");
        assert!(out.ends_with("# トレーラー (16 bytes)\ngrpc-status: 0\n"), "{out}");
        assert!(decode_body("", "application/grpc", &[0, 0, 0, 0, 9, 1]).is_none(), "枠が足りない");
        assert!(is_protobuf("application/grpc-web+proto") && is_protobuf("application/x-protobuf"));
        assert!(!is_protobuf("application/grpc-web-text") && !is_protobuf("application/json"));
    }
}
