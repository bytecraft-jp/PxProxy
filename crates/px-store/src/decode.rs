//! Content-Encoding の展開。表示（px-app）とパッシブチェックで共用する。

use std::io::Read;

/// 展開後の上限（圧縮爆弾でメモリを使い切らないように）
const MAX_DECOMPRESSED: u64 = 32 * 1024 * 1024;

/// `Content-Encoding: gzip, br` のような複数指定は適用の逆順に展開する。
/// 何もしなければ Ok(None)。
pub fn decode_content(encoding: &str, body: &[u8]) -> Result<Option<Vec<u8>>, String> {
    let codings: Vec<&str> =
        encoding.split(',').map(str::trim).filter(|c| !c.is_empty() && *c != "identity").collect();
    if codings.is_empty() {
        return Ok(None);
    }
    let mut data = body.to_vec();
    for coding in codings.iter().rev() {
        let src = data.as_slice();
        data = match *coding {
            "gzip" | "x-gzip" => decompress(flate2::read::MultiGzDecoder::new(src)),
            "deflate" => decompress(flate2::read::ZlibDecoder::new(src))
                .or_else(|_| decompress(flate2::read::DeflateDecoder::new(src))),
            "br" => decompress(brotli_decompressor::Decompressor::new(src, 64 * 1024)),
            "zstd" => zstd::stream::read::Decoder::new(src).map_err(|e| e.to_string()).and_then(decompress),
            other => return Err(format!("Content-Encoding: {other} は未対応")),
        }
        .map_err(|e| format!("Content-Encoding: {coding} の展開に失敗 ({e})"))?;
    }
    Ok(Some(data))
}

fn decompress(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    reader.take(MAX_DECOMPRESSED).read_to_end(&mut out).map_err(|e| e.to_string())?;
    Ok(out)
}

/// ヘッド（ステータス行 / リクエスト行の後のヘッダ）から最初に一致したヘッダの値を返す。
pub(crate) fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().skip(1).find_map(|line| {
        let (n, v) = line.split_once(':')?;
        n.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

/// 同名のヘッダの値をすべて返す（Set-Cookie など）。
pub(crate) fn headers<'a>(head: &'a str, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
    head.lines().skip(1).filter_map(move |line| {
        let (n, v) = line.split_once(':')?;
        n.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}
