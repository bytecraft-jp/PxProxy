//! 生バイトを保持する HTTP/1.x のメッセージ読み取り。
//! ヘッダの大文字小文字・順序・重複を変えずにそのまま転送するため hyper は使わない。

use std::io;

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{ProxyError, Result};

const MAX_HEADERS: usize = 256;
const MAX_HEAD_BYTES: usize = 256 * 1024;
const READ_CHUNK: usize = 16 * 1024;

#[derive(Debug, Clone)]
pub struct Headers(pub Vec<(String, Vec<u8>)>);

impl Headers {
    fn from_httparse(h: &[httparse::Header<'_>]) -> Self {
        Self(h.iter().map(|h| (h.name.to_string(), h.value.to_vec())).collect())
    }

    pub fn get(&self, name: &str) -> Option<&[u8]> {
        self.0.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_slice())
    }

    /// `Connection: keep-alive, Upgrade` のようなカンマ区切りトークンを含むか。
    pub fn has_token(&self, name: &str, token: &str) -> bool {
        self.0
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .flat_map(|(_, v)| v.split(|b| *b == b','))
            .any(|t| t.trim_ascii().eq_ignore_ascii_case(token.as_bytes()))
    }

    pub fn content_length(&self) -> Result<Option<u64>> {
        match self.get("content-length") {
            None => Ok(None),
            Some(v) => std::str::from_utf8(v)
                .ok()
                .and_then(|s| s.trim().parse().ok())
                .map(Some)
                .ok_or_else(|| ProxyError::Parse("invalid Content-Length".into())),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RequestHead {
    pub raw: Vec<u8>,
    pub method: String,
    pub target: String,
    pub minor_version: u8,
    pub headers: Headers,
}

#[derive(Debug, Clone)]
pub struct ResponseHead {
    pub raw: Vec<u8>,
    pub status: u16,
    pub minor_version: u8,
    pub headers: Headers,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyKind {
    Empty,
    Length(u64),
    Chunked,
    UntilClose,
}

impl BodyKind {
    pub fn for_request(h: &RequestHead) -> Result<Self> {
        if h.headers.has_token("transfer-encoding", "chunked") {
            return Ok(Self::Chunked);
        }
        Ok(match h.headers.content_length()? {
            Some(0) | None => Self::Empty,
            Some(n) => Self::Length(n),
        })
    }

    pub fn for_response(h: &ResponseHead, request_method: &str) -> Result<Self> {
        if request_method.eq_ignore_ascii_case("HEAD")
            || (100..200).contains(&h.status)
            || h.status == 204
            || h.status == 304
        {
            return Ok(Self::Empty);
        }
        if h.headers.has_token("transfer-encoding", "chunked") {
            return Ok(Self::Chunked);
        }
        Ok(match h.headers.content_length()? {
            Some(0) => Self::Empty,
            Some(n) => Self::Length(n),
            None => Self::UntilClose,
        })
    }
}

/// 読み取ったボディ。`raw` は回線上のバイト列（チャンク枠含む）、`decoded` は枠を外したもの。
pub struct Body {
    pub raw: Vec<u8>,
    pub decoded: Option<Vec<u8>>,
}

impl Body {
    pub fn decoded(&self) -> &[u8] {
        self.decoded.as_deref().unwrap_or(&self.raw)
    }
}

/// `relay_body` の結果。途中で失敗しても、それまでに読んだ分は残る。
#[derive(Debug)]
pub struct Relayed {
    /// 枠を外した Body の先頭（記録の上限まで）
    pub data: Vec<u8>,
    /// 枠を外した Body の実際の長さ
    pub total: u64,
    pub error: Option<RelayError>,
}

impl Relayed {
    /// 上限で切り詰めたか
    pub fn truncated(&self) -> bool {
        self.total > self.data.len() as u64
    }
}

#[derive(Debug)]
pub enum RelayError {
    /// 読み取り側（送り元）の失敗
    Read(ProxyError),
    /// 書き込み側（送り先）の失敗
    Write(io::Error),
}

/// 読んだ分を送り先に流しつつ、記録用に先頭だけ残す。
struct Relay<'a, W> {
    out: &'a mut W,
    /// まだ送り先に書いていないバイト列。読み取りで待つ前に書き出す（チャンクの枠を小分けに書かない）
    pending: Vec<u8>,
    data: Vec<u8>,
    keep: usize,
    total: u64,
}

impl<W: AsyncWrite + Unpin> Relay<'_, W> {
    /// 回線上のバイト列（チャンクの枠など）をそのまま送る。
    fn pass(&mut self, wire: &[u8]) {
        self.pending.extend_from_slice(wire);
    }

    /// Body の中身を送り、記録用に残す。
    fn body(&mut self, data: &[u8]) {
        self.pending.extend_from_slice(data);
        self.total += data.len() as u64;
        let room = self.keep.saturating_sub(self.data.len());
        self.data.extend_from_slice(&data[..data.len().min(room)]);
    }

    async fn flush(&mut self) -> io::Result<()> {
        if !self.pending.is_empty() {
            self.out.write_all(&self.pending).await?;
            self.pending.clear();
            self.out.flush().await?;
        }
        Ok(())
    }
}

/// 読み取りバッファ付きの接続。
pub struct Conn<S> {
    pub io: S,
    pub buf: BytesMut,
}

impl<S: AsyncRead + Unpin> Conn<S> {
    pub fn new(io: S) -> Self {
        Self::with_buf(io, BytesMut::new())
    }

    pub fn with_buf(io: S, buf: BytesMut) -> Self {
        Self { io, buf }
    }

    pub async fn fill(&mut self) -> io::Result<usize> {
        self.buf.reserve(READ_CHUNK);
        self.io.read_buf(&mut self.buf).await
    }

    /// 接続が閉じられていれば None。
    pub async fn read_request_head(&mut self) -> Result<Option<RequestHead>> {
        loop {
            if !self.buf.is_empty() {
                let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
                let mut req = httparse::Request::new(&mut headers);
                match req.parse(&self.buf) {
                    Ok(httparse::Status::Complete(n)) => {
                        let method = req.method.unwrap_or_default().to_string();
                        let target = req.path.unwrap_or_default().to_string();
                        let minor_version = req.version.unwrap_or(1);
                        let headers = Headers::from_httparse(req.headers);
                        let raw = self.buf.split_to(n).to_vec();
                        return Ok(Some(RequestHead { raw, method, target, minor_version, headers }));
                    }
                    Ok(httparse::Status::Partial) => {}
                    Err(e) => return Err(ProxyError::Parse(format!("request: {e}"))),
                }
                if self.buf.len() > MAX_HEAD_BYTES {
                    return Err(ProxyError::Parse("request head too large".into()));
                }
            }
            if self.fill().await? == 0 {
                return if self.buf.is_empty() { Ok(None) } else { Err(eof("request head")) };
            }
        }
    }

    pub async fn read_response_head(&mut self) -> Result<Option<ResponseHead>> {
        loop {
            if !self.buf.is_empty() {
                let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
                let mut res = httparse::Response::new(&mut headers);
                match res.parse(&self.buf) {
                    Ok(httparse::Status::Complete(n)) => {
                        let status = res.code.unwrap_or(0);
                        let minor_version = res.version.unwrap_or(1);
                        let headers = Headers::from_httparse(res.headers);
                        let raw = self.buf.split_to(n).to_vec();
                        return Ok(Some(ResponseHead { raw, status, minor_version, headers }));
                    }
                    Ok(httparse::Status::Partial) => {}
                    Err(e) => return Err(ProxyError::Parse(format!("response: {e}"))),
                }
                if self.buf.len() > MAX_HEAD_BYTES {
                    return Err(ProxyError::Parse("response head too large".into()));
                }
            }
            if self.fill().await? == 0 {
                return if self.buf.is_empty() { Ok(None) } else { Err(eof("response head")) };
            }
        }
    }

    pub async fn read_body(&mut self, kind: BodyKind) -> Result<Body> {
        match kind {
            BodyKind::Empty => Ok(Body { raw: Vec::new(), decoded: None }),
            BodyKind::Length(n) => {
                let n = usize::try_from(n).map_err(|_| ProxyError::Parse("body too large".into()))?;
                Ok(Body { raw: self.read_exact_vec(n).await?, decoded: None })
            }
            BodyKind::UntilClose => {
                while self.fill().await? > 0 {}
                Ok(Body { raw: self.buf.split().to_vec(), decoded: None })
            }
            BodyKind::Chunked => self.read_chunked().await,
        }
    }

    async fn read_chunked(&mut self) -> Result<Body> {
        let mut raw = Vec::new();
        let mut decoded = Vec::new();
        loop {
            let line = self.read_line().await?;
            raw.extend_from_slice(&line);
            let size_str = std::str::from_utf8(&line)
                .map_err(|_| ProxyError::Parse("chunk size".into()))?
                .split(';')
                .next()
                .unwrap_or("")
                .trim();
            let size = usize::from_str_radix(size_str, 16)
                .map_err(|_| ProxyError::Parse(format!("chunk size {size_str:?}")))?;
            if size == 0 {
                // trailer セクション: 空行まで
                loop {
                    let t = self.read_line().await?;
                    raw.extend_from_slice(&t);
                    if t == b"\r\n" || t == b"\n" {
                        break;
                    }
                }
                break;
            }
            let data = self.read_exact_vec(size).await?;
            raw.extend_from_slice(&data);
            decoded.extend_from_slice(&data);
            let crlf = self.read_line().await?;
            raw.extend_from_slice(&crlf);
        }
        Ok(Body { raw, decoded: Some(decoded) })
    }

    /// 改行（LF）までを改行込みで返す。
    async fn read_line(&mut self) -> Result<Vec<u8>> {
        loop {
            if let Some(pos) = self.buf.iter().position(|b| *b == b'\n') {
                return Ok(self.buf.split_to(pos + 1).to_vec());
            }
            if self.buf.len() > MAX_HEAD_BYTES {
                return Err(ProxyError::Parse("line too long".into()));
            }
            if self.fill().await? == 0 {
                return Err(eof("line"));
            }
        }
    }

    /// Body を読んだそばから `out` へ流す（全体をメモリに溜めない）。記録用に枠を外した先頭 `keep` バイトを返す。
    /// 送り元は止まらずに読み続けるので、SSE のような終わらない応答もそのまま届く。
    pub async fn relay_body<W: AsyncWrite + Unpin>(&mut self, kind: BodyKind, out: &mut W, keep: usize) -> Relayed {
        let mut r = Relay { out, pending: Vec::new(), data: Vec::new(), keep, total: 0 };
        let error = match self.relay_inner(kind, &mut r).await {
            Ok(()) => r.flush().await.err().map(RelayError::Write),
            Err(e) => Some(e),
        };
        Relayed { data: r.data, total: r.total, error }
    }

    async fn relay_inner<W: AsyncWrite + Unpin>(&mut self, kind: BodyKind, r: &mut Relay<'_, W>) -> std::result::Result<(), RelayError> {
        match kind {
            BodyKind::Empty => Ok(()),
            BodyKind::Length(mut remaining) => {
                while remaining > 0 {
                    self.more(r, "body").await?;
                    let n = (self.buf.len() as u64).min(remaining) as usize;
                    let chunk = self.buf.split_to(n);
                    r.body(&chunk);
                    remaining -= n as u64;
                }
                Ok(())
            }
            BodyKind::UntilClose => loop {
                if self.buf.is_empty() {
                    r.flush().await.map_err(RelayError::Write)?;
                    if self.fill().await.map_err(|e| RelayError::Read(e.into()))? == 0 {
                        return Ok(());
                    }
                }
                let chunk = self.buf.split();
                r.body(&chunk);
            },
            BodyKind::Chunked => loop {
                let line = self.relay_line(r).await?;
                r.pass(&line);
                let size_str = std::str::from_utf8(&line).unwrap_or("").split(';').next().unwrap_or("").trim();
                let size = u64::from_str_radix(size_str, 16)
                    .map_err(|_| RelayError::Read(ProxyError::Parse(format!("chunk size {size_str:?}"))))?;
                if size == 0 {
                    // trailer セクション: 空行まで
                    loop {
                        let t = self.relay_line(r).await?;
                        r.pass(&t);
                        if t == b"\r\n" || t == b"\n" {
                            return Ok(());
                        }
                    }
                }
                let mut remaining = size;
                while remaining > 0 {
                    self.more(r, "chunk").await?;
                    let n = (self.buf.len() as u64).min(remaining) as usize;
                    let chunk = self.buf.split_to(n);
                    r.body(&chunk);
                    remaining -= n as u64;
                }
                let crlf = self.relay_line(r).await?;
                r.pass(&crlf);
            },
        }
    }

    /// バッファが空なら、送り先へ書き出してから読み足す。読めなければ EOF のエラー。
    async fn more<W: AsyncWrite + Unpin>(&mut self, r: &mut Relay<'_, W>, what: &str) -> std::result::Result<(), RelayError> {
        if self.buf.is_empty() {
            r.flush().await.map_err(RelayError::Write)?;
            if self.fill().await.map_err(|e| RelayError::Read(e.into()))? == 0 {
                return Err(RelayError::Read(eof(what)));
            }
        }
        Ok(())
    }

    /// 改行（LF）までを改行込みで返す。待つ前に送り先へ書き出す。
    async fn relay_line<W: AsyncWrite + Unpin>(&mut self, r: &mut Relay<'_, W>) -> std::result::Result<Vec<u8>, RelayError> {
        loop {
            if let Some(pos) = self.buf.iter().position(|b| *b == b'\n') {
                return Ok(self.buf.split_to(pos + 1).to_vec());
            }
            if self.buf.len() > MAX_HEAD_BYTES {
                return Err(RelayError::Read(ProxyError::Parse("line too long".into())));
            }
            r.flush().await.map_err(RelayError::Write)?;
            if self.fill().await.map_err(|e| RelayError::Read(e.into()))? == 0 {
                return Err(RelayError::Read(eof("line")));
            }
        }
    }

    async fn read_exact_vec(&mut self, n: usize) -> Result<Vec<u8>> {
        while self.buf.len() < n {
            self.buf.reserve((n - self.buf.len()).min(4 * 1024 * 1024));
            if self.io.read_buf(&mut self.buf).await? == 0 {
                return Err(eof("body"));
            }
        }
        Ok(self.buf.split_to(n).to_vec())
    }
}

fn eof(what: &str) -> ProxyError {
    ProxyError::Io(io::Error::new(io::ErrorKind::UnexpectedEof, format!("connection closed while reading {what}")))
}

/// リクエストラインの request-target だけを差し替える（ヘッダ部分はバイト列そのまま）。
pub fn rewrite_target(raw: &[u8], method: &str, new_target: &str) -> Vec<u8> {
    let line_end = raw.iter().position(|b| *b == b'\n').unwrap_or(raw.len());
    let line = &raw[..line_end];
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let version = line.rsplit(|b| *b == b' ').next().unwrap_or(b"HTTP/1.1");
    let mut out = Vec::with_capacity(raw.len());
    out.extend_from_slice(method.as_bytes());
    out.push(b' ');
    out.extend_from_slice(new_target.as_bytes());
    out.push(b' ');
    out.extend_from_slice(version);
    out.extend_from_slice(&raw[line.len()..]);
    out
}

/// 編集後のメッセージを送信用に組み立て直した結果。
pub struct Rebuilt {
    /// 末尾の空行（CRLF CRLF）まで含むヘッド
    pub head: Vec<u8>,
    /// 回線に流す Body（chunked なら枠付き）
    pub body_wire: Vec<u8>,
}

/// UI で編集されたヘッドと Body（Transfer-Encoding を外した状態）から送信用バイト列を作る。
/// - 改行は CRLF に正規化する（エディタは LF を入れるため）
/// - `Transfer-Encoding: chunked` なら 1 チャンクに包み直す
/// - それ以外で `fix_content_length` かつ Body が変わったなら Content-Length を合わせる
pub fn rebuild_message(head: &[u8], body: &[u8], body_changed: bool, fix_content_length: bool) -> Rebuilt {
    let text = String::from_utf8_lossy(head);
    let mut lines: Vec<String> = text.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l).to_string()).collect();
    while lines.last().is_some_and(|l| l.is_empty()) {
        lines.pop();
    }
    let is_header = |l: &str, name: &str| l.split_once(':').is_some_and(|(n, _)| n.trim().eq_ignore_ascii_case(name));
    let chunked = lines.iter().skip(1).any(|l| {
        is_header(l, "transfer-encoding") && l.split_once(':').is_some_and(|(_, v)| v.to_ascii_lowercase().contains("chunked"))
    });

    let body_wire = if chunked {
        let mut w = Vec::with_capacity(body.len() + 16);
        if !body.is_empty() {
            w.extend_from_slice(format!("{:x}\r\n", body.len()).as_bytes());
            w.extend_from_slice(body);
            w.extend_from_slice(b"\r\n");
        }
        w.extend_from_slice(b"0\r\n\r\n");
        w
    } else {
        if fix_content_length && body_changed {
            let value = body.len().to_string();
            let mut found = false;
            for l in lines.iter_mut().skip(1) {
                if is_header(l, "content-length") {
                    let name = l.split_once(':').map(|(n, _)| n.to_string()).unwrap_or_default();
                    *l = format!("{name}: {value}");
                    found = true;
                }
            }
            if !found && !body.is_empty() {
                lines.push(format!("Content-Length: {value}"));
            }
        }
        body.to_vec()
    };

    let mut out = lines.join("\r\n").into_bytes();
    out.extend_from_slice(b"\r\n\r\n");
    Rebuilt { head: out, body_wire }
}

/// 編集後のヘッドが HTTP として解析できるか（Forward 前の検証用）。
pub fn validate_head(head: &[u8], is_request: bool) -> std::result::Result<(), String> {
    let normalized = rebuild_message(head, b"", false, false).head;
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let status = if is_request {
        httparse::Request::new(&mut headers).parse(&normalized)
    } else {
        httparse::Response::new(&mut headers).parse(&normalized)
    };
    match status {
        Ok(httparse::Status::Complete(_)) => Ok(()),
        Ok(httparse::Status::Partial) => Err("ヘッダが途中で終わっています".into()),
        Err(e) => {
            let what = if is_request { "リクエストライン/ヘッダ" } else { "ステータスライン/ヘッダ" };
            Err(format!("{what}を解析できません: {e}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_detects_broken_status_line() {
        assert!(validate_head(b"HTTP/1.1 403 Forbidden\nX: 1\n", false).is_ok());
        assert!(validate_head(b"HTTP/1.1 2403 Forbidden\n", false).is_err());
        assert!(validate_head(b"GET / HTTP/1.1\nHost: a\n", true).is_ok());
        assert!(validate_head(b"GET /\n", true).is_err());
    }

    #[test]
    fn rebuild_fixes_length_and_line_endings() {
        let r = rebuild_message(b"POST /a HTTP/1.1\nHost: x\ncontent-length: 3\n", b"hello", true, true);
        assert_eq!(r.head, b"POST /a HTTP/1.1\r\nHost: x\r\ncontent-length: 5\r\n\r\n");
        assert_eq!(r.body_wire, b"hello");
        // Body 不変なら Content-Length は触らない（HEAD/304 等を壊さない）
        let r = rebuild_message(b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\n", b"", false, true);
        assert_eq!(r.head, b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\n");
        // 無ければ追加
        let r = rebuild_message(b"POST / HTTP/1.1\r\n\r\n", b"ab", true, true);
        assert_eq!(r.head, b"POST / HTTP/1.1\r\nContent-Length: 2\r\n\r\n");
        // fix 無効なら変更しない
        let r = rebuild_message(b"POST / HTTP/1.1\r\nContent-Length: 1\r\n\r\n", b"ab", true, false);
        assert_eq!(r.head, b"POST / HTTP/1.1\r\nContent-Length: 1\r\n\r\n");
    }

    #[test]
    fn rebuild_rechunks() {
        let r = rebuild_message(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", b"abc", true, true);
        assert_eq!(r.body_wire, b"3\r\nabc\r\n0\r\n\r\n");
    }

    #[test]
    fn rewrite_keeps_headers() {
        let raw = b"GET http://a.example/x?y HTTP/1.1\r\nHoSt: a.example\r\n\r\n";
        let out = rewrite_target(raw, "GET", "/x?y");
        assert_eq!(out, b"GET /x?y HTTP/1.1\r\nHoSt: a.example\r\n\r\n");
    }

    #[tokio::test]
    async fn relay_keeps_wire_bytes_and_records_head() {
        let data: &[u8] = b"4;ext=1\r\nWiki\r\n5\r\npedia\r\n0\r\nX-T: 1\r\n\r\nNEXT";
        let mut c = Conn::new(data);
        let mut out = Vec::new();
        let r = c.relay_body(BodyKind::Chunked, &mut out, 6).await;
        assert!(r.error.is_none(), "{:?}", r.error);
        assert_eq!(out, &data[..data.len() - 4], "枠ごとそのまま流す");
        assert_eq!((r.data.as_slice(), r.total, r.truncated()), (&b"Wikipe"[..], 9, true));
        assert_eq!(&c.buf[..], b"NEXT");

        let mut c = Conn::new(&b"abcdefXYZ"[..]);
        let mut out = Vec::new();
        let r = c.relay_body(BodyKind::Length(6), &mut out, 100).await;
        assert_eq!((out.as_slice(), r.data.as_slice(), r.truncated()), (&b"abcdef"[..], &b"abcdef"[..], false));

        // 途中で切れたら、それまでの分は送って Read エラー
        let mut c = Conn::new(&b"abc"[..]);
        let mut out = Vec::new();
        let r = c.relay_body(BodyKind::Length(6), &mut out, 100).await;
        assert!(matches!(r.error, Some(RelayError::Read(_))));
        assert_eq!((out.as_slice(), r.total), (&b"abc"[..], 3));

        let mut c = Conn::new(&b"until close"[..]);
        let mut out = Vec::new();
        let r = c.relay_body(BodyKind::UntilClose, &mut out, 5).await;
        assert!(r.error.is_none());
        assert_eq!((out.as_slice(), r.data.as_slice(), r.total), (&b"until close"[..], &b"until"[..], 11));
    }

    #[tokio::test]
    async fn chunked_body() {
        let data: &[u8] = b"4;ext=1\r\nWiki\r\n5\r\npedia\r\n0\r\nX-T: 1\r\n\r\nNEXT";
        let mut c = Conn::new(data);
        let body = c.read_body(BodyKind::Chunked).await.unwrap();
        assert_eq!(body.decoded(), b"Wikipedia");
        assert_eq!(body.raw, &data[..data.len() - 4]);
        assert_eq!(&c.buf[..], b"NEXT");
    }
}
