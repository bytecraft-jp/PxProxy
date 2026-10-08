//! WebSocket の中継と記録。バイト列は読んだそばからそのまま転送し（フレームを組み直さない）、
//! 並行してフレームを解析してメッセージ単位で記録する。
//! permessage-deflate で圧縮されたメッセージは展開して記録する。

use std::io;

use bytes::BytesMut;
use flate2::{Decompress, FlushDecompress, Status};
use px_store::{FlowSink, WsMessage};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::http1::Headers;
use crate::server::now_us;

const READ_CHUNK: usize = 16 * 1024;
/// permessage-deflate のメッセージ末尾に補う 4 バイト（RFC 7692 7.2.2）
const DEFLATE_TAIL: [u8; 4] = [0, 0, 0xff, 0xff];

/// 101 のレスポンスヘッダから決まる圧縮の設定。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Deflate {
    pub(crate) client_no_context_takeover: bool,
    pub(crate) server_no_context_takeover: bool,
}

impl Deflate {
    /// `Sec-WebSocket-Extensions` で permessage-deflate が合意されていれば Some。
    pub(crate) fn negotiated(res: &Headers) -> Option<Self> {
        let ext = res
            .0
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case("sec-websocket-extensions"))
            .map(|(_, v)| String::from_utf8_lossy(v).to_ascii_lowercase())
            .collect::<Vec<_>>()
            .join(",");
        let params = ext.split(',').find(|e| e.trim().starts_with("permessage-deflate"))?;
        let has = |p: &str| params.split(';').any(|x| x.trim().starts_with(p));
        Some(Self {
            client_no_context_takeover: has("client_no_context_takeover"),
            server_no_context_takeover: has("server_no_context_takeover"),
        })
    }
}

/// 記録先。
#[derive(Clone)]
pub(crate) struct Recorder {
    pub(crate) sink: FlowSink,
    pub(crate) flow_id: i64,
    /// 1 メッセージあたりの記録の上限
    pub(crate) keep: usize,
}

/// 101 の後の接続を双方向に中継する。`client_buf` / `up_buf` は 101 までに読み過ぎた分（既にフレーム）。
#[allow(clippy::too_many_arguments)]
pub(crate) async fn relay<C, U>(
    client: C,
    client_buf: BytesMut,
    up: U,
    up_buf: BytesMut,
    rec: Option<Recorder>,
    deflate: Option<Deflate>,
) -> io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    let (cr, cw) = tokio::io::split(client);
    let (ur, uw) = tokio::io::split(up);
    let keep = rec.as_ref().map_or(0, |r| r.keep);
    let to_server = Parser::new(true, deflate.map(|d| d.client_no_context_takeover), keep);
    let to_client = Parser::new(false, deflate.map(|d| d.server_no_context_takeover), keep);
    let a = pump(client_buf, cr, uw, to_server, rec.clone());
    let b = pump(up_buf, ur, cw, to_client, rec);
    tokio::pin!(a, b);
    // 片方が正常に閉じたら、もう片方が閉じるのを待つ。エラーなら両方やめる
    tokio::select! {
        r = &mut a => { r?; b.await }
        r = &mut b => { r?; a.await }
    }
}

async fn pump<R, W>(prefix: BytesMut, mut r: R, mut w: W, mut parser: Parser, rec: Option<Recorder>) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let emit = |parser: &mut Parser, data: &[u8]| {
        if let Some(rec) = &rec {
            for mut m in parser.feed(data) {
                m.flow_id = rec.flow_id;
                rec.sink.submit_ws(m);
            }
        }
    };
    if !prefix.is_empty() {
        w.write_all(&prefix).await?;
        w.flush().await?;
        emit(&mut parser, &prefix);
    }
    let mut buf = vec![0u8; READ_CHUNK];
    loop {
        let n = r.read(&mut buf).await?;
        if n == 0 {
            let _ = w.shutdown().await;
            return Ok(());
        }
        // 先に転送してから解析する（記録で遅らせない）
        w.write_all(&buf[..n]).await?;
        w.flush().await?;
        emit(&mut parser, &buf[..n]);
    }
}

/// 解析中のフレーム。
enum Frame {
    /// ヘッダを読んでいる途中（最大 14 バイト）
    Header(Vec<u8>),
    Payload { fin: bool, opcode: u8, mask: Option<[u8; 4]>, remaining: u64, offset: u64 },
}

/// 組み立て中のメッセージ。
struct Message {
    opcode: u8,
    at_us: i64,
    compressed: bool,
    data: Vec<u8>,
    len: u64,
}

/// 片方向のフレームの解析器。
pub(crate) struct Parser {
    from_client: bool,
    frame: Frame,
    /// 分割されたデータメッセージ
    message: Option<Message>,
    /// 制御フレーム（分割されないが、データメッセージの途中に挟まる）
    control: Option<Message>,
    /// permessage-deflate の展開器と、メッセージごとにリセットするか
    inflate: Option<(Decompress, bool)>,
    /// 展開に失敗したら以降は圧縮のまま記録する
    inflate_broken: bool,
    keep: usize,
}

impl Parser {
    /// `deflate` は permessage-deflate が合意されていれば Some(no_context_takeover)。
    pub(crate) fn new(from_client: bool, deflate: Option<bool>, keep: usize) -> Self {
        Self {
            from_client,
            frame: Frame::Header(Vec::with_capacity(14)),
            message: None,
            control: None,
            inflate: deflate.map(|reset| (Decompress::new(false), reset)),
            inflate_broken: false,
            keep,
        }
    }

    /// 届いたバイト列を解析し、完成したメッセージを返す。
    pub(crate) fn feed(&mut self, mut data: &[u8]) -> Vec<WsMessage> {
        let mut out = Vec::new();
        while !data.is_empty() {
            match &mut self.frame {
                Frame::Header(h) => {
                    let need = header_len(h);
                    let take = (need - h.len()).min(data.len());
                    h.extend_from_slice(&data[..take]);
                    data = &data[take..];
                    if h.len() < header_len(h) {
                        continue;
                    }
                    let h = std::mem::take(h);
                    self.start_frame(&h, &mut out);
                }
                Frame::Payload { remaining, mask, offset, .. } => {
                    let n = (*remaining).min(data.len() as u64) as usize;
                    let mut chunk = data[..n].to_vec();
                    if let Some(key) = mask {
                        for (i, b) in chunk.iter_mut().enumerate() {
                            *b ^= key[((*offset + i as u64) % 4) as usize];
                        }
                    }
                    *offset += n as u64;
                    *remaining -= n as u64;
                    data = &data[n..];
                    let done = *remaining == 0;
                    self.payload(&chunk);
                    if done {
                        self.end_frame(&mut out);
                    }
                }
            }
        }
        out
    }

    fn start_frame(&mut self, h: &[u8], out: &mut Vec<WsMessage>) {
        let fin = h[0] & 0x80 != 0;
        let rsv1 = h[0] & 0x40 != 0;
        let opcode = h[0] & 0x0f;
        let masked = h[1] & 0x80 != 0;
        let (len, at) = match h[1] & 0x7f {
            126 => (u64::from(u16::from_be_bytes([h[2], h[3]])), 4),
            127 => (u64::from_be_bytes(h[2..10].try_into().expect("8 bytes")), 10),
            n => (u64::from(n), 2),
        };
        let mask = masked.then(|| [h[at], h[at + 1], h[at + 2], h[at + 3]]);
        let msg = || Message { opcode, at_us: now_us(), compressed: false, data: Vec::new(), len: 0 };
        if opcode >= 8 {
            self.control = Some(msg());
        } else if opcode != 0 || self.message.is_none() {
            // 新しいデータメッセージ（前のメッセージが終わっていなければ、それは捨てる）
            let mut m = msg();
            m.compressed = rsv1 && self.inflate.is_some() && !self.inflate_broken;
            if m.compressed
                && let Some((z, true)) = &mut self.inflate
            {
                z.reset(false);
            }
            self.message = Some(m);
        }
        self.frame = Frame::Payload { fin, opcode, mask, remaining: len, offset: 0 };
        if len == 0 {
            self.end_frame(out);
        }
    }

    fn payload(&mut self, chunk: &[u8]) {
        let Frame::Payload { opcode, .. } = self.frame else { return };
        let keep = self.keep;
        if opcode >= 8 {
            if let Some(c) = &mut self.control {
                append(c, chunk, keep);
            }
            return;
        }
        let Some(m) = &mut self.message else { return };
        if m.compressed {
            if let Some((z, _)) = &mut self.inflate
                && inflate(z, chunk, m, keep).is_err()
            {
                self.inflate_broken = true;
                m.compressed = false;
            }
        } else {
            append(m, chunk, keep);
        }
    }

    fn end_frame(&mut self, out: &mut Vec<WsMessage>) {
        let Frame::Payload { fin, opcode, .. } = std::mem::replace(&mut self.frame, Frame::Header(Vec::with_capacity(14))) else {
            return;
        };
        let done = if opcode >= 8 {
            self.control.take()
        } else if fin {
            let mut m = self.message.take();
            if let Some(m) = &mut m
                && m.compressed
                && let Some((z, _)) = &mut self.inflate
                && inflate(z, &DEFLATE_TAIL, m, self.keep).is_err()
            {
                self.inflate_broken = true;
            }
            m
        } else {
            None
        };
        if let Some(m) = done {
            out.push(WsMessage {
                id: 0,
                flow_id: 0,
                at_us: m.at_us,
                from_client: self.from_client,
                opcode: m.opcode,
                len: m.len,
                data: m.data,
            });
        }
    }
}

/// 2 バイト目までで決まるヘッダ全体の長さ（足りなければ 2）。
fn header_len(h: &[u8]) -> usize {
    if h.len() < 2 {
        return 2;
    }
    let ext = match h[1] & 0x7f {
        126 => 2,
        127 => 8,
        _ => 0,
    };
    2 + ext + if h[1] & 0x80 != 0 { 4 } else { 0 }
}

fn append(m: &mut Message, chunk: &[u8], keep: usize) {
    m.len += chunk.len() as u64;
    let room = keep.saturating_sub(m.data.len());
    m.data.extend_from_slice(&chunk[..chunk.len().min(room)]);
}

/// 圧縮されたペイロードを展開して追記する。上限を超えた分も展開は続ける（文脈を保つため）。
fn inflate(z: &mut Decompress, mut input: &[u8], m: &mut Message, keep: usize) -> Result<(), flate2::DecompressError> {
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        let (before_in, before_out) = (z.total_in(), z.total_out());
        let status = z.decompress(input, &mut buf, FlushDecompress::Sync)?;
        let used = (z.total_in() - before_in) as usize;
        let produced = (z.total_out() - before_out) as usize;
        input = &input[used..];
        append(m, &buf[..produced], keep);
        // 出力が満杯なら続きがある。入力を使い切り、出力も余ったら終わり
        if status == Status::StreamEnd || (input.is_empty() && produced < buf.len()) || (used == 0 && produced == 0) {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(fin: bool, rsv1: bool, opcode: u8, mask: Option<[u8; 4]>, payload: &[u8]) -> Vec<u8> {
        let mut f = vec![(fin as u8) << 7 | (rsv1 as u8) << 6 | opcode];
        let m = if mask.is_some() { 0x80 } else { 0 };
        match payload.len() {
            n if n < 126 => f.push(m | n as u8),
            n if n < 65536 => {
                f.push(m | 126);
                f.extend_from_slice(&(n as u16).to_be_bytes());
            }
            n => {
                f.push(m | 127);
                f.extend_from_slice(&(n as u64).to_be_bytes());
            }
        }
        match mask {
            Some(k) => {
                f.extend_from_slice(&k);
                f.extend(payload.iter().enumerate().map(|(i, b)| b ^ k[i % 4]));
            }
            None => f.extend_from_slice(payload),
        }
        f
    }

    fn texts(msgs: &[WsMessage]) -> Vec<(u8, String)> {
        msgs.iter().map(|m| (m.opcode, String::from_utf8_lossy(&m.data).into_owned())).collect()
    }

    #[test]
    fn masked_fragmented_with_interleaved_ping() {
        let key = Some([1, 2, 3, 4]);
        let mut wire = frame(false, false, 1, key, b"hel");
        wire.extend(frame(true, false, 9, key, b"p"));
        wire.extend(frame(true, false, 0, key, b"lo"));
        wire.extend(frame(true, false, 2, key, &[0u8; 300]));
        let mut p = Parser::new(true, None, 1024);
        // 1 バイトずつ届いても組み立てられる
        let mut msgs = Vec::new();
        for b in &wire {
            msgs.extend(p.feed(std::slice::from_ref(b)));
        }
        assert_eq!(texts(&msgs)[..2], [(9, "p".into()), (1, "hello".into())]);
        assert_eq!((msgs[2].opcode, msgs[2].len, msgs[2].data.len()), (2, 300, 300));
        assert!(msgs.iter().all(|m| m.from_client));
    }

    #[test]
    fn large_message_is_truncated_but_counted() {
        let payload = vec![b'x'; 70_000];
        let mut p = Parser::new(false, None, 100);
        let msgs = p.feed(&frame(true, false, 1, None, &payload));
        assert_eq!((msgs[0].len, msgs[0].data.len()), (70_000, 100));
    }

    #[test]
    fn permessage_deflate_with_context_takeover() {
        use flate2::{Compress, Compression, FlushCompress};
        let mut c = Compress::new(Compression::fast(), false);
        let mut compress = |text: &[u8]| {
            let mut out = Vec::with_capacity(256);
            c.compress_vec(text, &mut out, FlushCompress::Sync).unwrap();
            assert!(out.ends_with(&DEFLATE_TAIL));
            out.truncate(out.len() - 4);
            out
        };
        let a = compress(b"hello hello hello");
        let b = compress(b"hello hello hello"); // 前のメッセージを参照して短くなる
        let mut p = Parser::new(false, Some(false), 1024);
        let mut wire = frame(true, true, 1, None, &a);
        wire.extend(frame(true, true, 1, None, &b));
        wire.extend(frame(true, false, 1, None, b"plain"));
        let msgs = p.feed(&wire);
        assert_eq!(
            texts(&msgs),
            [(1, "hello hello hello".into()), (1, "hello hello hello".into()), (1, "plain".into())]
        );
    }

    #[test]
    fn negotiation() {
        let h = Headers(vec![("Sec-WebSocket-Extensions".into(), b"permessage-deflate; server_no_context_takeover".to_vec())]);
        assert_eq!(
            Deflate::negotiated(&h),
            Some(Deflate { client_no_context_takeover: false, server_no_context_takeover: true })
        );
        assert_eq!(Deflate::negotiated(&Headers(Vec::new())), None);
    }
}
