use std::sync::Arc;
use std::time::Duration;

use px_proxy::http1::{BodyKind, Conn};
use px_proxy::{CertAuthority, ProxyContext, ProxyServer};
use px_store::{Filter, Project};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// chunked で応答する keep-alive な上流サーバ。`tls` があれば HTTPS。
async fn upstream(tls: Option<Arc<rustls::ServerConfig>>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (s, _) = listener.accept().await.unwrap();
            let tls = tls.clone();
            tokio::spawn(async move {
                match tls {
                    Some(cfg) => echo(tokio_rustls::TlsAcceptor::from(cfg).accept(s).await.unwrap()).await,
                    None => echo(s).await,
                }
            });
        }
    });
    port
}

async fn echo<S: AsyncRead + AsyncWrite + Unpin>(s: S) {
    let mut c = Conn::new(s);
    while let Ok(Some(h)) = c.read_request_head().await {
        let body = c.read_body(BodyKind::for_request(&h).unwrap()).await.unwrap();
        let msg = format!("{} {} body={}", h.method, h.target, String::from_utf8_lossy(body.decoded()));
        let res = format!("HTTP/1.1 200 OK\r\nX-Up: 1\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{msg}\r\n0\r\n\r\n", msg.len());
        c.io.write_all(res.as_bytes()).await.unwrap();
    }
}

async fn roundtrip<S: AsyncRead + AsyncWrite + Unpin>(c: &mut Conn<S>, req: &str) -> (u16, Vec<u8>) {
    c.io.write_all(req.as_bytes()).await.unwrap();
    let h = c.read_response_head().await.unwrap().unwrap();
    let body = c.read_body(BodyKind::for_response(&h, "GET").unwrap()).await.unwrap();
    (h.status, body.decoded().to_vec())
}

async fn wait_count(project: &Project, n: i64) -> px_store::Reader {
    let reader = project.reader().unwrap();
    for _ in 0..100 {
        if reader.count().unwrap() >= n {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    reader
}

#[tokio::test(flavor = "multi_thread")]
async fn http_and_https_are_proxied_and_recorded() {
    let tmp = tempfile::tempdir().unwrap();
    let ca = Arc::new(CertAuthority::load_or_create(tmp.path().join("ca")).unwrap());
    let project = Project::create(tmp.path().join("t.pxproj"), None).unwrap();
    let ctx = ProxyContext::new(ca.clone()).unwrap();
    ctx.set_sink(Some(project.sink()));
    let proxy = ProxyServer::bind("127.0.0.1:0".parse().unwrap(), ctx.clone()).await.unwrap();

    // --- 平文 HTTP (absolute-form) を keep-alive で 2 回
    let http_port = upstream(None).await;
    let mut c = Conn::new(TcpStream::connect(proxy.local_addr()).await.unwrap());
    let (st, body) =
        roundtrip(&mut c, &format!("GET http://127.0.0.1:{http_port}/a?x=1 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")).await;
    assert_eq!(st, 200);
    assert_eq!(body, b"GET /a?x=1 body=");
    let (_, body) = roundtrip(
        &mut c,
        &format!("POST http://127.0.0.1:{http_port}/b HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 3\r\n\r\nabc"),
    )
    .await;
    assert_eq!(body, b"POST /b body=abc");

    // --- CONNECT + TLS (MITM)
    let https_port = upstream(Some(ca.server_config("localhost").unwrap())).await;
    let mut tcp = Conn::new(TcpStream::connect(proxy.local_addr()).await.unwrap());
    tcp.io.write_all(format!("CONNECT localhost:{https_port} HTTP/1.1\r\n\r\n").as_bytes()).await.unwrap();
    let h = tcp.read_response_head().await.unwrap().unwrap();
    assert_eq!(h.status, 200);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from_pem_slice(ca.ca_pem().as_bytes()).unwrap()).unwrap();
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let tls = tokio_rustls::TlsConnector::from(Arc::new(cfg))
        .connect(ServerName::try_from("localhost").unwrap(), tcp.io)
        .await
        .expect("client must trust MITM cert issued by our CA");
    let mut c = Conn::new(tls);
    let (st, body) = roundtrip(&mut c, "GET /secure HTTP/1.1\r\nHost: localhost\r\n\r\n").await;
    assert_eq!(st, 200);
    assert_eq!(body, b"GET /secure body=");

    // --- 記録内容
    let reader = wait_count(&project, 3).await;
    let ids = reader.ids_after(0, &Filter::default()).unwrap();
    assert_eq!(ids.len(), 3);
    let d = reader.detail(ids[1]).unwrap().unwrap();
    assert_eq!(d.summary.method, "POST");
    assert_eq!(d.req_body, b"abc");
    assert!(d.req_head.starts_with(b"POST /b HTTP/1.1\r\n"), "absolute-form rewritten to origin-form");
    assert_eq!(d.res_body, b"POST /b body=abc", "chunked framing removed");
    let s = reader.detail(ids[2]).unwrap().unwrap();
    assert_eq!((s.summary.scheme.as_str(), s.summary.host.as_str()), ("https", "localhost"));
    assert_eq!(s.summary.status, Some(200));
}

#[tokio::test(flavor = "multi_thread")]
async fn hosts_override_connects_to_given_address() {
    let tmp = tempfile::tempdir().unwrap();
    let ca = Arc::new(CertAuthority::load_or_create(tmp.path().join("ca")).unwrap());
    let ctx = ProxyContext::new(ca).unwrap();
    // .invalid は DNS で引けないので、hosts が効かなければ接続に失敗する
    let settings = px_proxy::ProjectSettings { hosts: "127.0.0.1 *.pinned.invalid".into(), ..Default::default() };
    ctx.interceptor().set_settings(settings);
    let proxy = ProxyServer::bind("127.0.0.1:0".parse().unwrap(), ctx).await.unwrap();

    let port = upstream(None).await;
    let mut c = Conn::new(TcpStream::connect(proxy.local_addr()).await.unwrap());
    let req = format!("GET http://www.pinned.invalid:{port}/h HTTP/1.1\r\nHost: www.pinned.invalid\r\n\r\n");
    let (st, body) = roundtrip(&mut c, &req).await;
    assert_eq!(st, 200);
    assert_eq!(body, b"GET /h body=");
}

async fn wait_pending(ctx: &ProxyContext, n: usize) -> Vec<Arc<px_proxy::Held>> {
    for _ in 0..200 {
        let p = ctx.interceptor().pending();
        if p.len() >= n {
            return p;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("intercept did not hold {n} item(s)");
}

#[tokio::test(flavor = "multi_thread")]
async fn intercept_edit_drop_and_disable() {
    use px_proxy::{Decision, Direction};

    let tmp = tempfile::tempdir().unwrap();
    let ca = Arc::new(CertAuthority::load_or_create(tmp.path().join("ca")).unwrap());
    let project = Project::create(tmp.path().join("i.pxproj"), None).unwrap();
    let ctx = ProxyContext::new(ca).unwrap();
    ctx.set_sink(Some(project.sink()));
    ctx.interceptor().set_enabled(true);
    let proxy = ProxyServer::bind("127.0.0.1:0".parse().unwrap(), ctx.clone()).await.unwrap();
    let port = upstream(None).await;

    // --- 1. リクエストを編集し、レスポンスも止めて編集する
    let addr = proxy.local_addr();
    let client = tokio::spawn(async move {
        let mut c = Conn::new(TcpStream::connect(addr).await.unwrap());
        roundtrip(
            &mut c,
            &format!("POST http://127.0.0.1:{port}/orig HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\nabc"),
        )
        .await
    });
    let held = wait_pending(&ctx, 1).await;
    assert_eq!(held[0].direction, Direction::Request);
    assert_eq!(held[0].body, b"abc");
    // エディタは LF 改行・Content-Length 未修正の状態で返してくる
    let edited_head = b"POST /edited HTTP/1.1\nHost: x\nContent-Length: 3\n".to_vec();
    assert!(ctx.interceptor().resolve(
        held[0].id,
        Decision::Forward { edited: Some((edited_head, b"hello world".to_vec())), intercept_response: true },
    ));
    let held = wait_pending(&ctx, 1).await;
    assert_eq!(held[0].direction, Direction::Response);
    assert_eq!(held[0].body, b"POST /edited body=hello world", "upstream saw edited request");
    let res_head = String::from_utf8(held[0].head.clone()).unwrap().replace("200 OK", "201 Created");
    ctx.interceptor().resolve(
        held[0].id,
        Decision::Forward { edited: Some((res_head.into_bytes(), b"patched".to_vec())), intercept_response: false },
    );
    let (status, body) = client.await.unwrap();
    assert_eq!((status, body.as_slice()), (201, &b"patched"[..]), "chunked response re-framed");

    // --- 2. Drop
    let client = tokio::spawn(async move {
        let mut c = Conn::new(TcpStream::connect(addr).await.unwrap());
        roundtrip(&mut c, &format!("GET http://127.0.0.1:{port}/drop HTTP/1.1\r\nHost: x\r\n\r\n")).await
    });
    let held = wait_pending(&ctx, 1).await;
    ctx.interceptor().resolve(held[0].id, Decision::Drop);
    assert_eq!(client.await.unwrap().0, 502);

    // --- 3. 停止中に OFF → そのまま転送される
    let client = tokio::spawn(async move {
        let mut c = Conn::new(TcpStream::connect(addr).await.unwrap());
        roundtrip(&mut c, &format!("GET http://127.0.0.1:{port}/pass HTTP/1.1\r\nHost: x\r\n\r\n")).await
    });
    wait_pending(&ctx, 1).await;
    ctx.interceptor().set_enabled(false);
    assert_eq!(client.await.unwrap(), (200, b"GET /pass body=".to_vec()));

    // --- 記録
    let reader = wait_count(&project, 3).await;
    let ids = reader.ids_after(0, &Filter::default()).unwrap();
    let d = reader.detail(ids[0]).unwrap().unwrap();
    assert_eq!(d.summary.edited, px_store::EDITED_REQUEST | px_store::EDITED_RESPONSE);
    assert_eq!(d.summary.target, "/edited");
    assert_eq!(d.summary.status, Some(201));
    assert!(d.req_head.starts_with(b"POST /edited HTTP/1.1\r\nHost: x\r\nContent-Length: 11\r\n\r\n"));
    let (orig_head, orig_body) = d.orig_request.unwrap();
    assert!(orig_head.starts_with(b"POST /orig HTTP/1.1\r\n"));
    assert_eq!(orig_body, b"abc");
    assert_eq!(d.orig_response.unwrap().1, b"POST /edited body=hello world");
    let dropped = reader.detail(ids[1]).unwrap().unwrap();
    assert!(dropped.summary.error.unwrap().contains("破棄"));
}

#[tokio::test(flavor = "multi_thread")]
async fn flow_is_recorded_even_if_client_left_while_held() {
    let tmp = tempfile::tempdir().unwrap();
    let ca = Arc::new(CertAuthority::load_or_create(tmp.path().join("ca")).unwrap());
    let project = Project::create(tmp.path().join("g.pxproj"), None).unwrap();
    let ctx = ProxyContext::new(ca).unwrap();
    ctx.set_sink(Some(project.sink()));
    ctx.interceptor().set_enabled(true);
    let proxy = ProxyServer::bind("127.0.0.1:0".parse().unwrap(), ctx.clone()).await.unwrap();
    let port = upstream(None).await;

    let mut s = TcpStream::connect(proxy.local_addr()).await.unwrap();
    s.write_all(format!("GET http://127.0.0.1:{port}/gone HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes()).await.unwrap();
    let held = wait_pending(&ctx, 1).await;
    drop(s); // クライアントが待ちきれずに切断
    // 同一ホストの別リクエストで切断を確実に検知させるのではなく、そのまま Forward する
    ctx.interceptor().resolve(held[0].id, px_proxy::Decision::FORWARD);

    let reader = wait_count(&project, 1).await;
    let d = reader.detail(reader.ids_after(0, &Filter::default()).unwrap()[0]).unwrap().unwrap();
    assert_eq!(d.summary.target, "/gone");
    assert_eq!(d.summary.status, Some(200), "response from upstream is recorded");
}

#[tokio::test(flavor = "multi_thread")]
async fn intercept_over_https_records_flow() {
    let tmp = tempfile::tempdir().unwrap();
    let ca = Arc::new(CertAuthority::load_or_create(tmp.path().join("ca")).unwrap());
    let project = Project::create(tmp.path().join("h.pxproj"), None).unwrap();
    let ctx = ProxyContext::new(ca.clone()).unwrap();
    ctx.set_sink(Some(project.sink()));
    ctx.interceptor().set_enabled(true);
    let proxy = ProxyServer::bind("127.0.0.1:0".parse().unwrap(), ctx.clone()).await.unwrap();
    let https_port = upstream(Some(ca.server_config("localhost").unwrap())).await;

    let addr = proxy.local_addr();
    let ca2 = ca.clone();
    let client = tokio::spawn(async move {
        let mut tcp = Conn::new(TcpStream::connect(addr).await.unwrap());
        tcp.io.write_all(format!("CONNECT localhost:{https_port} HTTP/1.1\r\n\r\n").as_bytes()).await.unwrap();
        tcp.read_response_head().await.unwrap().unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(CertificateDer::from_pem_slice(ca2.ca_pem().as_bytes()).unwrap()).unwrap();
        let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let tls = tokio_rustls::TlsConnector::from(Arc::new(cfg))
            .connect(ServerName::try_from("localhost").unwrap(), tcp.io)
            .await
            .unwrap();
        let mut c = Conn::new(tls);
        roundtrip(&mut c, "POST /post HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\nuser").await
    });
    let held = wait_pending(&ctx, 1).await;
    let text = String::from_utf8(held[0].head.clone()).unwrap();
    ctx.interceptor().resolve(
        held[0].id,
        px_proxy::Decision::Forward { edited: Some((text.into_bytes(), b"admin".to_vec())), intercept_response: true },
    );
    let held = wait_pending(&ctx, 1).await;
    ctx.interceptor().resolve(held[0].id, px_proxy::Decision::FORWARD);
    assert_eq!(client.await.unwrap(), (200, b"POST /post body=admin".to_vec()));
    let reader = wait_count(&project, 1).await;
    assert_eq!(reader.count().unwrap(), 1, "intercepted flow must be recorded");
}

#[tokio::test(flavor = "multi_thread")]
async fn broken_edit_is_recorded_with_error() {
    let tmp = tempfile::tempdir().unwrap();
    let ca = Arc::new(CertAuthority::load_or_create(tmp.path().join("ca")).unwrap());
    let project = Project::create(tmp.path().join("b.pxproj"), None).unwrap();
    let ctx = ProxyContext::new(ca).unwrap();
    ctx.set_sink(Some(project.sink()));
    ctx.interceptor().set_enabled(true);
    let proxy = ProxyServer::bind("127.0.0.1:0".parse().unwrap(), ctx.clone()).await.unwrap();
    let port = upstream(None).await;

    let addr = proxy.local_addr();
    let client = tokio::spawn(async move {
        let mut c = Conn::new(TcpStream::connect(addr).await.unwrap());
        roundtrip(&mut c, &format!("GET http://127.0.0.1:{port}/x HTTP/1.1\r\nHost: x\r\n\r\n")).await
    });
    let held = wait_pending(&ctx, 1).await;
    ctx.interceptor().resolve(
        held[0].id,
        px_proxy::Decision::Forward { edited: Some((b"GET /x\n".to_vec(), Vec::new())), intercept_response: false },
    );
    assert_eq!(client.await.unwrap().0, 502);
    let reader = wait_count(&project, 1).await;
    let d = reader.detail(1).unwrap().unwrap();
    assert!(d.summary.error.unwrap().contains("解析できません"));
    assert!(d.orig_request.is_some(), "original request kept");
}

#[tokio::test(flavor = "multi_thread")]
async fn repeater_sends_edited_request_and_records_it() {
    let tmp = tempfile::tempdir().unwrap();
    let ca = Arc::new(CertAuthority::load_or_create(tmp.path().join("ca")).unwrap());
    let project = Project::create(tmp.path().join("r.pxproj"), None).unwrap();
    let ctx = ProxyContext::new(ca.clone()).unwrap();
    ctx.set_sink(Some(project.sink()));
    let port = upstream(None).await;
    let origin = px_proxy::Origin::parse(&format!("http://127.0.0.1:{port}")).unwrap();

    // LF 改行・古い Content-Length のままでも直して送る
    let req = px_proxy::RepeatRequest {
        origin: origin.clone(),
        head: b"POST /r?q=1 HTTP/1.1\nHost: 127.0.0.1\nContent-Length: 1\n\n".to_vec(),
        body: b"edited".to_vec(),
        fix_content_length: true,
    };
    let flow = ctx.repeat(req).await.unwrap();
    assert_eq!(flow.error, None);
    assert_eq!(flow.status, Some(200));
    assert_eq!(flow.res_body, b"POST /r?q=1 body=edited");
    assert!(flow.req_head.ends_with(b"Content-Length: 6\r\n\r\n"), "{}", String::from_utf8_lossy(&flow.req_head));

    // 解析できないヘッドは送らない
    let bad = px_proxy::RepeatRequest { origin: origin.clone(), head: b"\x01\n\n".to_vec(), body: Vec::new(), fix_content_length: true };
    assert!(ctx.repeat(bad).await.is_err());

    // 接続できなければエラー付きで記録する
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead = px_proxy::Origin::parse(&format!("http://127.0.0.1:{}", closed.local_addr().unwrap().port())).unwrap();
    drop(closed);
    let req = px_proxy::RepeatRequest { origin: dead, head: b"GET / HTTP/1.1\r\n\r\n".to_vec(), body: Vec::new(), fix_content_length: true };
    assert!(ctx.repeat(req).await.unwrap().error.is_some());

    let reader = wait_count(&project, 2).await;
    let ids = reader.ids_after(0, &Filter::default()).unwrap();
    assert_eq!(ids.len(), 2);
    let d = reader.detail(ids[0]).unwrap().unwrap();
    assert_eq!(d.summary.source, px_store::FlowSource::Repeater);
    assert_eq!((d.summary.target.as_str(), d.req_body.as_slice()), ("/r?q=1", &b"edited"[..]));
}

fn trusting(ca: &CertAuthority) -> tokio_rustls::TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from_pem_slice(ca.ca_pem().as_bytes()).unwrap()).unwrap();
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tokio_rustls::TlsConnector::from(Arc::new(cfg))
}

#[tokio::test(flavor = "multi_thread")]
async fn transparent_http_and_https_are_routed_by_host_and_sni() {
    let tmp = tempfile::tempdir().unwrap();
    let ca = Arc::new(CertAuthority::load_or_create(tmp.path().join("ca")).unwrap());
    let project = Project::create(tmp.path().join("t.pxproj"), None).unwrap();
    let ctx = ProxyContext::new(ca.clone()).unwrap();
    ctx.set_sink(Some(project.sink()));
    // 通常のプロキシと同じ待受で、透過の接続も受け付ける
    let proxy = ProxyServer::bind("127.0.0.1:0".parse().unwrap(), ctx.clone()).await.unwrap();
    let addr = proxy.local_addr();

    // --- 平文 HTTP: CONNECT も absolute-form も無く、Host ヘッダだけで宛先が決まる
    let http_port = upstream(None).await;
    let mut c = Conn::new(TcpStream::connect(addr).await.unwrap());
    let (st, body) = roundtrip(&mut c, &format!("GET /plain HTTP/1.1\r\nHost: 127.0.0.1:{http_port}\r\n\r\n")).await;
    assert_eq!((st, body.as_slice()), (200, &b"GET /plain body="[..]));

    // --- HTTPS: CONNECT 無しでいきなり TLS。SNI で証明書を発行し、Host ヘッダのポートへ転送する
    let https_port = upstream(Some(ca.server_config("localhost").unwrap())).await;
    let tcp = TcpStream::connect(addr).await.unwrap();
    let tls = trusting(&ca)
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .expect("client must trust the certificate issued for SNI");
    let mut c = Conn::new(tls);
    let req = format!("POST /tls HTTP/1.1\r\nHost: localhost:{https_port}\r\nContent-Length: 2\r\n\r\nhi");
    let (st, body) = roundtrip(&mut c, &req).await;
    assert_eq!((st, body.as_slice()), (200, &b"POST /tls body=hi"[..]));
    // keep-alive で続けて送れる
    let (st, _) = roundtrip(&mut c, &format!("GET /again HTTP/1.1\r\nHost: localhost:{https_port}\r\n\r\n")).await;
    assert_eq!(st, 200);

    let reader = wait_count(&project, 3).await;
    let ids = reader.ids_after(0, &Filter::default()).unwrap();
    let d = reader.detail(ids[1]).unwrap().unwrap();
    assert_eq!((d.summary.scheme.as_str(), d.summary.host.as_str(), d.summary.port), ("https", "localhost", https_port));
    assert_eq!(d.summary.target, "/tls");
}

#[tokio::test(flavor = "multi_thread")]
async fn upstream_pointing_back_to_proxy_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let ca = Arc::new(CertAuthority::load_or_create(tmp.path().join("ca")).unwrap());
    let ctx = ProxyContext::new(ca).unwrap();
    // OS の hosts ファイルで 127.0.0.1 に向けた状態を、案件の hosts で再現する
    ctx.interceptor().set_settings(px_proxy::ProjectSettings { hosts: "127.0.0.1 loop.invalid".into(), ..Default::default() });
    let proxy = ProxyServer::bind("127.0.0.1:0".parse().unwrap(), ctx).await.unwrap();
    let port = proxy.local_addr().port();

    for host in [format!("127.0.0.1:{port}"), format!("loop.invalid:{port}"), format!("localhost:{port}")] {
        let mut c = Conn::new(TcpStream::connect(proxy.local_addr()).await.unwrap());
        let (st, body) = roundtrip(&mut c, &format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n")).await;
        let body = String::from_utf8_lossy(&body);
        assert_eq!(st, 502, "{host}");
        assert!(body.contains("pxproxy 自身"), "{host}: {body}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn connection_limit_reclaims_idle_upstream() {
    let tmp = tempfile::tempdir().unwrap();
    let ca = Arc::new(CertAuthority::load_or_create(tmp.path().join("ca")).unwrap());
    let ctx = ProxyContext::new(ca).unwrap();
    let limits = px_proxy::ConnectionLimits { max_connections: 1, max_new_per_sec: 0 };
    ctx.interceptor().set_settings(px_proxy::ProjectSettings { limits, ..Default::default() });
    let proxy = ProxyServer::bind("127.0.0.1:0".parse().unwrap(), ctx).await.unwrap();
    let up = upstream(None).await;

    // 1 本目は keep-alive のまま上流接続を持ち続ける
    let mut a = Conn::new(TcpStream::connect(proxy.local_addr()).await.unwrap());
    let (st, _) = roundtrip(&mut a, &format!("GET http://127.0.0.1:{up}/a HTTP/1.1
Host: 127.0.0.1:{up}

")).await;
    assert_eq!(st, 200);
    // 2 本目は、1 本目の使っていない上流接続が閉じられて枠が空くので通る
    let mut b = Conn::new(TcpStream::connect(proxy.local_addr()).await.unwrap());
    let req = format!("GET http://127.0.0.1:{up}/b HTTP/1.1
Host: 127.0.0.1:{up}

");
    let (st, body) = tokio::time::timeout(Duration::from_secs(5), roundtrip(&mut b, &req)).await.expect("枠が空かない");
    assert_eq!((st, body.as_slice()), (200, &b"GET /b body="[..]));
    // 1 本目も引き続き使える（上流は張り直す）
    let (st, _) = tokio::time::timeout(Duration::from_secs(5), roundtrip(&mut a, &req)).await.expect("1 本目が詰まった");
    assert_eq!(st, 200);
}

/// 設定済みのプロキシと案件を用意する。
async fn setup(settings: px_proxy::ProjectSettings) -> (tempfile::TempDir, Arc<CertAuthority>, Project, Arc<ProxyContext>, ProxyServer) {
    let tmp = tempfile::tempdir().unwrap();
    let ca = Arc::new(CertAuthority::load_or_create(tmp.path().join("ca")).unwrap());
    let project = Project::create(tmp.path().join("x.pxproj"), None).unwrap();
    let ctx = ProxyContext::new(ca.clone()).unwrap();
    ctx.set_sink(Some(project.sink()));
    assert_eq!(ctx.interceptor().set_settings(settings), None);
    let proxy = ProxyServer::bind("127.0.0.1:0".parse().unwrap(), ctx.clone()).await.unwrap();
    (tmp, ca, project, ctx, proxy)
}

/// 受け取ったリクエストヘッドをそのまま Body に入れて返す、偽の上流プロキシ。
/// CONNECT は `Proxy-Authorization` が無ければ 407 で断る。
async fn fake_upstream_proxy() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (s, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut c = Conn::new(s);
                while let Ok(Some(h)) = c.read_request_head().await {
                    let res = if h.method == "CONNECT" && h.headers.get("proxy-authorization").is_none() {
                        "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n".to_string()
                    } else {
                        let body = String::from_utf8_lossy(&h.raw).into_owned();
                        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len())
                    };
                    c.io.write_all(res.as_bytes()).await.unwrap();
                }
            });
        }
    });
    port
}

#[tokio::test(flavor = "multi_thread")]
async fn upstream_proxy_forwards_http_and_tunnels_https() {
    // --- 平文 HTTP は absolute-form + Proxy-Authorization で上流プロキシへ
    let fake = fake_upstream_proxy().await;
    let upstream_proxy =
        px_proxy::UpstreamProxy { enabled: true, address: format!("127.0.0.1:{fake}"), username: "u".into(), password: "p".into(), bypass: String::new() };
    let settings = px_proxy::ProjectSettings { upstream: upstream_proxy, ..Default::default() };
    let (_tmp, _ca, project, _ctx, proxy) = setup(settings).await;
    let mut c = Conn::new(TcpStream::connect(proxy.local_addr()).await.unwrap());
    let (st, body) = roundtrip(&mut c, "GET http://site.invalid/a?b=1 HTTP/1.1\r\nHost: site.invalid\r\n\r\n").await;
    assert_eq!(st, 200);
    let seen = String::from_utf8(body).unwrap();
    assert!(seen.starts_with("GET http://site.invalid/a?b=1 HTTP/1.1\r\nProxy-Authorization: Basic dTpw\r\nHost: site.invalid\r\n"), "{seen}");
    let reader = wait_count(&project, 1).await;
    let d = reader.detail(1).unwrap().unwrap();
    assert!(d.req_head.starts_with(b"GET /a?b=1 HTTP/1.1\r\n"), "記録はオリジンサーバへのリクエストのまま");

    // --- HTTPS は上流プロキシへ CONNECT する（ここでは pxproxy をもう 1 つ上流に置く）
    let (_tmp2, _, project2, _, chained) = setup(Default::default()).await;
    let upstream_proxy = px_proxy::UpstreamProxy { enabled: true, address: chained.local_addr().to_string(), bypass: String::new(), ..Default::default() };
    let settings = px_proxy::ProjectSettings { upstream: upstream_proxy, ..Default::default() };
    let (_tmp, ca, project, _ctx, proxy) = setup(settings).await;
    let https_port = upstream(Some(ca.server_config("localhost").unwrap())).await;
    let mut tcp = Conn::new(TcpStream::connect(proxy.local_addr()).await.unwrap());
    tcp.io.write_all(format!("CONNECT localhost:{https_port} HTTP/1.1\r\n\r\n").as_bytes()).await.unwrap();
    assert_eq!(tcp.read_response_head().await.unwrap().unwrap().status, 200);
    let tls = trusting(&ca).connect(ServerName::try_from("localhost").unwrap(), tcp.io).await.unwrap();
    let mut c = Conn::new(tls);
    let (st, body) = roundtrip(&mut c, "GET /chained HTTP/1.1\r\nHost: localhost\r\n\r\n").await;
    assert_eq!((st, body.as_slice()), (200, &b"GET /chained body="[..]));
    // 両方の pxproxy に記録される
    assert_eq!(wait_count(&project, 1).await.count().unwrap(), 1);
    assert_eq!(wait_count(&project2, 1).await.count().unwrap(), 1);

    // --- 上流プロキシが CONNECT を断ったら 502 とその理由
    let upstream_proxy = px_proxy::UpstreamProxy { enabled: true, address: format!("127.0.0.1:{fake}"), bypass: String::new(), ..Default::default() };
    let settings = px_proxy::ProjectSettings { upstream: upstream_proxy, ..Default::default() };
    let (_tmp, _, project, _ctx, proxy) = setup(settings).await;
    let mut c = Conn::new(TcpStream::connect(proxy.local_addr()).await.unwrap());
    let (st, body) = roundtrip(&mut c, "GET https://site.invalid/ HTTP/1.1\r\nHost: site.invalid\r\n\r\n").await;
    assert_eq!(st, 502);
    assert!(String::from_utf8_lossy(&body).contains("407"), "{}", String::from_utf8_lossy(&body));
    assert!(wait_count(&project, 1).await.summary(1).unwrap().unwrap().error.is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn tls_passthrough_keeps_server_certificate() {
    let settings = px_proxy::ProjectSettings { tls_passthrough: "*.nomitm.test localhost".into(), ..Default::default() };
    let (tmp, _ca, project, _ctx, proxy) = setup(settings).await;
    // 上流は別の CA の証明書。クライアントはその CA だけを信頼するので、復号されていたら繋がらない
    let real = CertAuthority::load_or_create(tmp.path().join("real-ca")).unwrap();
    let https_port = upstream(Some(real.server_config("localhost").unwrap())).await;
    let mut tcp = Conn::new(TcpStream::connect(proxy.local_addr()).await.unwrap());
    tcp.io.write_all(format!("CONNECT localhost:{https_port} HTTP/1.1\r\n\r\n").as_bytes()).await.unwrap();
    assert_eq!(tcp.read_response_head().await.unwrap().unwrap().status, 200);
    let tls = trusting(&real)
        .connect(ServerName::try_from("localhost").unwrap(), tcp.io)
        .await
        .expect("パススルーなら上流の本物の証明書が見える");
    let mut c = Conn::new(tls);
    let (st, body) = roundtrip(&mut c, "GET /raw HTTP/1.1\r\nHost: localhost\r\n\r\n").await;
    assert_eq!((st, body.as_slice()), (200, &b"GET /raw body="[..]));

    let reader = wait_count(&project, 1).await;
    let s = reader.summary(1).unwrap().unwrap();
    assert_eq!(s.source, px_store::FlowSource::Tunnel);
    assert_eq!((s.method.as_str(), s.target.clone()), ("CONNECT", format!("localhost:{https_port}")));
    assert_eq!(reader.count().unwrap(), 1, "中身は復号しないので記録は CONNECT の 1 件だけ");
}

#[tokio::test(flavor = "multi_thread")]
async fn responses_are_streamed_and_large_bodies_truncated() {
    let settings = px_proxy::ProjectSettings { max_record_body_mb: 1, ..Default::default() };
    let (_tmp, _ca, project, _ctx, proxy) = setup(settings).await;

    // SSE のように最後まで送らない上流: 先頭のチャンクがすぐクライアントに届くこと
    let (finish_tx, finish_rx) = tokio::sync::oneshot::channel::<()>();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let sse_port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (s, _) = listener.accept().await.unwrap();
        let mut c = Conn::new(s);
        c.read_request_head().await.unwrap();
        c.io.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n6\r\ndata:1\r\n")
            .await
            .unwrap();
        let _ = finish_rx.await;
        c.io.write_all(b"0\r\n\r\n").await.unwrap();
    });
    let mut c = Conn::new(TcpStream::connect(proxy.local_addr()).await.unwrap());
    c.io.write_all(format!("GET http://127.0.0.1:{sse_port}/events HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes()).await.unwrap();
    let head = c.read_response_head().await.unwrap().unwrap();
    assert_eq!(head.status, 200);
    let first = tokio::time::timeout(Duration::from_secs(3), async {
        while !c.buf.windows(6).any(|w| w == b"data:1") {
            assert!(c.fill().await.unwrap() > 0);
        }
    })
    .await;
    assert!(first.is_ok(), "上流が終わる前に最初のイベントが届く");
    finish_tx.send(()).unwrap();
    let body = c.read_body(BodyKind::Chunked).await.unwrap();
    assert_eq!(body.decoded(), b"data:1");

    // 3MB の応答と 2MB の送信: 全部届くが、記録は先頭 1MB
    let port = upstream(None).await;
    let big = "x".repeat(2 * 1024 * 1024 + 10);
    let req = format!("POST http://127.0.0.1:{port}/up HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n{big}", big.len());
    let (st, body) = roundtrip(&mut c, &req).await;
    assert_eq!(st, 200);
    assert_eq!(body.len(), "POST /up body=".len() + big.len(), "流しても全部届く");

    let reader = wait_count(&project, 2).await;
    let sse = reader.detail(1).unwrap().unwrap();
    assert_eq!(sse.res_body, b"data:1");
    let d = reader.detail(2).unwrap().unwrap();
    assert_eq!(d.summary.truncated, px_store::TRUNCATED_REQUEST | px_store::TRUNCATED_RESPONSE);
    assert_eq!((d.req_body.len(), d.summary.req_body_len), (1024 * 1024, big.len() as i64));
    assert_eq!((d.res_body.len(), d.summary.res_body_len), (1024 * 1024, body.len() as i64));
}

/// 1 フレームを読む（テスト用: 125 バイト以下）。マスクされていれば外す。
async fn read_frame<S: AsyncRead + AsyncWrite + Unpin>(c: &mut Conn<S>) -> (u8, Vec<u8>) {
    while c.buf.len() < 2 {
        assert!(c.fill().await.unwrap() > 0);
    }
    let masked = c.buf[1] & 0x80 != 0;
    let len = (c.buf[1] & 0x7f) as usize;
    let total = 2 + if masked { 4 } else { 0 } + len;
    while c.buf.len() < total {
        assert!(c.fill().await.unwrap() > 0);
    }
    let f = c.buf.split_to(total);
    let opcode = f[0] & 0x0f;
    let payload = if masked {
        f[6..].iter().enumerate().map(|(i, b)| b ^ f[2 + i % 4]).collect()
    } else {
        f[2..].to_vec()
    };
    (opcode, payload)
}

#[tokio::test(flavor = "multi_thread")]
async fn websocket_messages_are_recorded() {
    let (_tmp, _ca, project, _ctx, proxy) = setup(Default::default()).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (s, _) = listener.accept().await.unwrap();
        let mut c = Conn::new(s);
        c.read_request_head().await.unwrap();
        // 101 と同じ書き込みで最初のフレームも送る（プロキシが読み過ぎても取りこぼさない）
        c.io.write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n\x81\x05hello")
            .await
            .unwrap();
        let (_, payload) = read_frame(&mut c).await;
        let mut reply = vec![0x81, (payload.len() + 5) as u8];
        reply.extend_from_slice(b"echo:");
        reply.extend_from_slice(&payload);
        c.io.write_all(&reply).await.unwrap();
        // クライアントからの Close に Close で応える
        let (op, _) = read_frame(&mut c).await;
        assert_eq!(op, 8);
        c.io.write_all(&[0x88, 0]).await.unwrap();
    });
    let mut c = Conn::new(TcpStream::connect(proxy.local_addr()).await.unwrap());
    c.io.write_all(
        format!("GET http://127.0.0.1:{port}/ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    assert_eq!(c.read_response_head().await.unwrap().unwrap().status, 101);
    assert_eq!(read_frame(&mut c).await, (1, b"hello".to_vec()));
    let key = [9, 8, 7, 6];
    let mut frame = vec![0x81, 0x80 | 2];
    frame.extend_from_slice(&key);
    frame.extend(b"hi".iter().enumerate().map(|(i, b)| b ^ key[i % 4]));
    c.io.write_all(&frame).await.unwrap();
    assert_eq!(read_frame(&mut c).await, (1, b"echo:hi".to_vec()));
    c.io.write_all(&[0x88, 0x80, 0, 0, 0, 0]).await.unwrap();
    assert_eq!(read_frame(&mut c).await.0, 8);

    let reader = wait_count(&project, 1).await;
    let mut msgs = Vec::new();
    for _ in 0..100 {
        msgs = reader.ws_messages(1, 0).unwrap();
        if msgs.len() >= 5 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let got: Vec<(bool, u8, &[u8])> = msgs.iter().map(|m| (m.from_client, m.opcode, m.data.as_slice())).collect();
    assert_eq!(got, [(false, 1, &b"hello"[..]), (true, 1, b"hi"), (false, 1, b"echo:hi"), (true, 8, b""), (false, 8, b"")]);
}

#[tokio::test(flavor = "multi_thread")]
async fn mock_server_answers_without_upstream() {
    use px_proxy::{MockRoute, MockServer};
    let route = |path: &str, methods: &str, status: u16, body: &str| MockRoute {
        path: path.into(),
        methods: methods.into(),
        status,
        headers: "Content-Type: application/json".into(),
        body: body.into(),
    };
    let mock = MockServer {
        enabled: true,
        host: "*.mock.invalid".into(),
        routes: vec![
            route("/", "", 200, "top"),
            route("/api", "GET", 201, "{\"ok\":true}"),
            route("/echo", "POST", 200, "q={{query.q}} name={{html:form.name}}"),
        ],
    };
    // パススルーにも書いてあるが、ダミーサーバが優先して復号する
    let settings =
        px_proxy::ProjectSettings { mock_servers: vec![mock], tls_passthrough: "*.mock.invalid".into(), ..Default::default() };
    let (_tmp, ca, project, ctx, proxy) = setup(settings).await;

    // --- 平文 HTTP。.invalid は名前解決できないので、上流へつないでいたら 502 になる
    let mut c = Conn::new(TcpStream::connect(proxy.local_addr()).await.unwrap());
    let (st, body) = roundtrip(&mut c, "GET http://www.mock.invalid/?q=1 HTTP/1.1\r\nHost: www.mock.invalid\r\n\r\n").await;
    assert_eq!((st, body.as_slice()), (200, &b"top"[..]));
    // keep-alive で続けて送れる。Body は読み捨てて次のリクエストを読む
    let req = "POST http://www.mock.invalid/api HTTP/1.1\r\nHost: www.mock.invalid\r\nContent-Length: 3\r\n\r\nabc";
    let (st, _) = roundtrip(&mut c, req).await;
    assert_eq!(st, 405, "/api は GET のみ");
    let (st, _) = roundtrip(&mut c, "GET http://www.mock.invalid/none HTTP/1.1\r\nHost: www.mock.invalid\r\n\r\n").await;
    assert_eq!(st, 404);

    // --- CONNECT + TLS（ポートは問わない）
    let mut tcp = Conn::new(TcpStream::connect(proxy.local_addr()).await.unwrap());
    tcp.io.write_all(b"CONNECT api.mock.invalid:8443 HTTP/1.1\r\n\r\n").await.unwrap();
    assert_eq!(tcp.read_response_head().await.unwrap().unwrap().status, 200);
    let tls = trusting(&ca).connect(ServerName::try_from("api.mock.invalid").unwrap(), tcp.io).await.expect("復号して応答する");
    let mut c = Conn::new(tls);
    let (st, body) = roundtrip(&mut c, "GET /api HTTP/1.1\r\nHost: api.mock.invalid:8443\r\n\r\n").await;
    assert_eq!((st, body.as_slice()), (201, &b"{\"ok\":true}"[..]));

    // --- Repeater もダミーサーバが応答する
    let flow = ctx
        .repeat(px_proxy::RepeatRequest {
            origin: px_proxy::Origin::parse("https://www.mock.invalid").unwrap(),
            head: b"GET /api HTTP/1.1\r\nHost: www.mock.invalid\r\n\r\n".to_vec(),
            body: Vec::new(),
            fix_content_length: true,
        })
        .await
        .unwrap();
    assert_eq!((flow.status, flow.error), (Some(201), None));

    // --- QueryString と POST の Body を応答に埋め込む
    let mut c = Conn::new(TcpStream::connect(proxy.local_addr()).await.unwrap());
    let req = "POST http://www.mock.invalid/echo?q=1 HTTP/1.1
Host: www.mock.invalid
Content-Length: 13

name=%3Cx%3E1";
    let (st, body) = roundtrip(&mut c, req).await;
    assert_eq!((st, body.as_slice()), (200, &b"q=1 name=&lt;x&gt;1"[..]));

    let reader = wait_count(&project, 6).await;
    let ids = reader.ids_after(0, &Filter::default()).unwrap();
    assert_eq!(ids.len(), 6);
    let d = reader.detail(ids[1]).unwrap().unwrap();
    assert_eq!(d.summary.source, px_store::FlowSource::Mock);
    assert_eq!((d.summary.status, d.req_body.as_slice()), (Some(405), &b"abc"[..]));
    assert!(String::from_utf8_lossy(d.res_head.as_deref().unwrap()).contains("Allow: GET\r\n"));
    let s = reader.summary(ids[3]).unwrap().unwrap();
    assert_eq!((s.scheme.as_str(), s.host.as_str(), s.port, s.source), ("https", "api.mock.invalid", 8443, px_store::FlowSource::Mock));
}
