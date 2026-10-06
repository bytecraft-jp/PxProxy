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
