//! TLS の ClientHello から SNI を読む（TLS パススルーと透過プロキシの判定用）。

use tokio::net::TcpStream;

use crate::Result;
use crate::http1::Conn;

/// TLS レコードの先頭バイト（Handshake）
pub(super) const TLS_HANDSHAKE: u8 = 0x16;
/// SNI を読むために溜める ClientHello の上限
const MAX_CLIENT_HELLO: usize = 16 * 1024 + 5;

/// ClientHello が揃うまで読み足して SNI を返す（クライアントからは何も消費しない）。
pub(super) async fn peek_sni(client: &mut Conn<TcpStream>) -> Result<Option<String>> {
    loop {
        match client_hello_sni(&client.buf) {
            Sni::Found(name) => return Ok(Some(name)),
            Sni::Absent => return Ok(None),
            Sni::Incomplete if client.buf.len() >= MAX_CLIENT_HELLO => return Ok(None),
            Sni::Incomplete => {
                if client.fill().await? == 0 {
                    return Ok(None);
                }
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Sni {
    Found(String),
    /// SNI が無い・解析できない
    Absent,
    /// まだ ClientHello の途中
    Incomplete,
}

/// TLS レコードの先頭にある ClientHello から server_name を取り出す。
fn client_hello_sni(buf: &[u8]) -> Sni {
    if buf.len() < 5 {
        return Sni::Incomplete;
    }
    if buf[0] != TLS_HANDSHAKE {
        return Sni::Absent;
    }
    let record_len = usize::from(u16::from_be_bytes([buf[3], buf[4]]));
    if buf.len() < 5 + record_len {
        return Sni::Incomplete;
    }
    parse_client_hello(&buf[5..5 + record_len]).map_or(Sni::Absent, Sni::Found)
}

fn parse_client_hello(hs: &[u8]) -> Option<String> {
    struct Reader<'a>(&'a [u8]);
    impl<'a> Reader<'a> {
        fn take(&mut self, n: usize) -> Option<&'a [u8]> {
            let (a, b) = (self.0.get(..n)?, self.0.get(n..)?);
            self.0 = b;
            Some(a)
        }
        fn u8(&mut self) -> Option<usize> {
            self.take(1).map(|b| usize::from(b[0]))
        }
        fn u16(&mut self) -> Option<usize> {
            self.take(2).map(|b| usize::from(u16::from_be_bytes([b[0], b[1]])))
        }
    }
    let mut r = Reader(hs);
    // ClientHello、長さ 3 バイト、バージョン、乱数
    if r.u8()? != 1 {
        return None;
    }
    r.take(3 + 2 + 32)?;
    let n = r.u8()?;
    r.take(n)?; // session id
    let n = r.u16()?;
    r.take(n)?; // cipher suites
    let n = r.u8()?;
    r.take(n)?; // compression
    let n = r.u16()?;
    let mut ext = Reader(r.take(n)?);
    while !ext.0.is_empty() {
        let (kind, len) = (ext.u16()?, ext.u16()?);
        let data = ext.take(len)?;
        if kind != 0 {
            continue;
        }
        let mut list = Reader(data);
        let n = list.u16()?;
        let mut names = Reader(list.take(n)?);
        while !names.0.is_empty() {
            let (name_type, len) = (names.u8()?, names.u16()?);
            let name = names.take(len)?;
            if name_type == 0 {
                return std::str::from_utf8(name).ok().map(str::to_string);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rustls::pki_types::ServerName;

    use super::*;

    #[test]
    fn sni_from_client_hello() {
        // rustls で実際の ClientHello を作って読む
        let cfg = crate::tls::client_config().unwrap();
        let name = ServerName::try_from("pass.example.com").unwrap();
        let mut conn = rustls::ClientConnection::new(Arc::new(cfg), name).unwrap();
        let mut hello = Vec::new();
        conn.write_tls(&mut hello).unwrap();
        assert_eq!(client_hello_sni(&hello), Sni::Found("pass.example.com".into()));
        assert_eq!(client_hello_sni(&hello[..hello.len() - 1]), Sni::Incomplete);
        assert_eq!(client_hello_sni(&hello[..3]), Sni::Incomplete);
        assert_eq!(client_hello_sni(b"GET / HTTP/1.1\r\n"), Sni::Absent);
    }
}
