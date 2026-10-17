//! README に載せる画面イメージを作る。架空の通信を記録した案件を開き、各タブを描画して docs/images/ へ保存する。
//!
//! ```sh
//! cargo test -p px-app readme_screenshots -- --ignored
//! ```

use std::path::{Path, PathBuf};

use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;
use px_store::{FlowSource, Highlight, NewFlow, Project, WsMessage};

use super::prefs::ThemeChoice;
use super::{PxApp, Tab};

const SHOP: &str = "shop.example.com";
const UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36";
const START_US: i64 = 1_791_455_696_789_000;

fn reason(status: u16) -> &'static str {
    match status {
        101 => "Switching Protocols",
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        302 => "Found",
        304 => "Not Modified",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "",
    }
}

/// 架空の通信を 1 件ずつ足していく。時刻は少しずつ進める。
struct Recorder {
    flows: Vec<NewFlow>,
}

impl Recorder {
    #[allow(clippy::too_many_arguments)]
    fn add(&mut self, host: &str, method: &str, target: &str, req_headers: &str, req_body: &str, status: u16, res_headers: &str, res_body: impl AsRef<[u8]>) {
        let n = self.flows.len() as i64;
        let len = if req_body.is_empty() { String::new() } else { format!("Content-Length: {}\r\n", req_body.len()) };
        let req_head = format!("{method} {target} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {UA}\r\n{req_headers}{len}\r\n");
        let res_body = res_body.as_ref();
        let res_len = if res_body.is_empty() { String::new() } else { format!("Content-Length: {}\r\n", res_body.len()) };
        let res_head = format!(
            "HTTP/1.1 {status} {}\r\nDate: Thu, 08 Oct 2026 01:14:{:02} GMT\r\n{res_headers}{res_len}\r\n",
            reason(status),
            (56 + n) % 60
        );
        self.flows.push(NewFlow {
            source: FlowSource::Proxy,
            started_at_us: START_US + n * 730_000 + (n * n * 7_919 % 400_000),
            duration_us: 18_000 + (n * 37_123 % 260_000),
            scheme: "https".into(),
            host: host.into(),
            port: 443,
            method: method.into(),
            target: target.into(),
            status: Some(status),
            req_head: req_head.into_bytes(),
            req_body: req_body.as_bytes().to_vec(),
            res_head: Some(res_head.into_bytes()),
            res_body: res_body.to_vec(),
            error: None,
            orig_request: None,
            orig_response: None,
            req_body_total: None,
            res_body_total: None,
        });
    }
}

/// 架空のネットショップを一通り操作したときの通信。
fn shop_flows() -> Vec<NewFlow> {
    let mut r = Recorder { flows: Vec::new() };
    let cookie = "Cookie: session=7f3c9a12e5b84d0c; lang=ja\r\n";
    let html_res = "Content-Type: text/html; charset=utf-8\r\nServer: nginx/1.24.0\r\nX-Powered-By: PHP/8.1.2\r\n";
    let json_res = "Content-Type: application/json; charset=utf-8\r\nServer: nginx/1.24.0\r\nCache-Control: no-store\r\n";
    let accept_json = "Accept: application/json\r\nX-Requested-With: XMLHttpRequest\r\n";

    r.add(
        SHOP,
        "GET",
        "/",
        "Accept: text/html,application/xhtml+xml\r\nAccept-Language: ja,en-US;q=0.9\r\n",
        "",
        200,
        html_res,
        r#"<!DOCTYPE html>
<html lang="ja"><head><meta charset="utf-8"><title>Example Shop</title>
<link rel="stylesheet" href="/assets/style.css"><script src="/assets/app.js" defer></script></head>
<body><header><a href="/"><img src="/images/logo.png" alt="Example Shop"></a>
<form action="/search"><input name="q" placeholder="商品を検索"></form></header>
<!-- TODO: 本番前にデバッグ用の /admin/debug へのリンクを消す -->
<main id="app"></main></body></html>"#,
    );
    r.add(SHOP, "GET", "/assets/style.css", "Accept: text/css,*/*;q=0.1\r\n", "", 200, "Content-Type: text/css\r\nCache-Control: public, max-age=86400\r\n", b"body{margin:0;font-family:sans-serif}header{display:flex;gap:16px;padding:12px 24px}");
    r.add(
        SHOP,
        "GET",
        "/assets/app.js",
        "Accept: */*\r\n",
        "",
        200,
        "Content-Type: application/javascript\r\nCache-Control: public, max-age=86400\r\n",
        b"(()=>{const api=p=>fetch('/api'+p,{headers:{'X-Requested-With':'XMLHttpRequest'}}).then(r=>r.json());api('/products?category=books&page=1').then(render)})();\n//# sourceMappingURL=app.js.map\n",
    );
    r.add(SHOP, "GET", "/images/logo.png", "Accept: image/avif,image/webp,image/png,*/*\r\n", "", 200, "Content-Type: image/png\r\nCache-Control: public, max-age=604800\r\n", include_bytes!("../../assets/icon.png"));
    r.add("cdn.example.net", "GET", "/fonts/noto-sans-jp.woff2", "Accept: */*\r\nOrigin: https://shop.example.com\r\n", "", 200, "Content-Type: font/woff2\r\nAccess-Control-Allow-Origin: *\r\n", [0x77, 0x4F, 0x46, 0x32, 0, 1, 0, 0]);
    r.add(
        SHOP,
        "POST",
        "/api/login",
        "Accept: application/json\r\nContent-Type: application/json\r\nOrigin: https://shop.example.com\r\n",
        r#"{"email":"alice@example.com","password":"correct-horse-battery"}"#,
        200,
        "Content-Type: application/json; charset=utf-8\r\nServer: nginx/1.24.0\r\nSet-Cookie: session=7f3c9a12e5b84d0c; Path=/\r\n",
        r#"{"ok":true,"user":{"id":1024,"name":"Alice","role":"customer"}}"#,
    );
    r.add(
        SHOP,
        "GET",
        "/api/products?category=books&page=1",
        &format!("{accept_json}{cookie}"),
        "",
        200,
        json_res,
        r#"{"category":"books","page":1,"total":128,"items":[{"id":42,"name":"Rust プログラミング入門","price":3520,"stock":12,"tags":["programming","rust"]},{"id":43,"name":"はじめての HTTP","price":2860,"stock":0,"tags":["network"]},{"id":44,"name":"Web セキュリティの基礎","price":3080,"stock":5,"tags":["security","web"]}]}"#,
    );
    r.add(
        SHOP,
        "GET",
        "/api/products?category=books&page=2",
        &format!("{accept_json}{cookie}"),
        "",
        200,
        json_res,
        r#"{"category":"books","page":2,"total":128,"items":[{"id":45,"name":"データベース設計","price":3300,"stock":8,"tags":["database"]},{"id":43,"name":"はじめての HTTP","price":2860,"stock":3,"tags":["network"]},{"id":47,"name":"TLS 徹底解説","price":4180,"stock":2,"tags":["security","network"]}]}"#,
    );
    r.add(SHOP, "GET", "/api/products/42", &format!("{accept_json}{cookie}"), "", 200, json_res, r#"{"id":42,"name":"Rust プログラミング入門","price":3520,"stock":12,"description":"所有権と借用から非同期処理まで。","reviews":{"count":31,"average":4.6}}"#);
    r.add(SHOP, "POST", "/api/cart/items", &format!("Accept: application/json\r\nContent-Type: application/json\r\n{cookie}"), r#"{"product_id":42,"quantity":1}"#, 201, json_res, r#"{"cart":{"items":[{"product_id":42,"quantity":1,"price":3520}],"subtotal":3520}}"#);
    r.add(SHOP, "GET", "/api/cart", &format!("{accept_json}{cookie}"), "", 200, json_res, r#"{"items":[{"product_id":42,"name":"Rust プログラミング入門","quantity":1,"price":3520}],"subtotal":3520,"shipping":0}"#);
    r.add(SHOP, "GET", "/api/users/me", &format!("{accept_json}{cookie}"), "", 200, json_res, r#"{"id":1024,"name":"Alice","email":"alice@example.com","address":{"zip":"100-0001","city":"千代田区"}}"#);
    r.add(SHOP, "GET", "/api/orders/1001", &format!("{accept_json}{cookie}"), "", 403, json_res, r#"{"error":"forbidden","message":"この注文を表示する権限がありません"}"#);
    r.add(
        SHOP,
        "OPTIONS",
        "/api/orders",
        "Origin: https://evil.example.org\r\nAccess-Control-Request-Method: POST\r\n",
        "",
        204,
        "Access-Control-Allow-Origin: https://evil.example.org\r\nAccess-Control-Allow-Credentials: true\r\nAccess-Control-Allow-Methods: GET, POST, DELETE\r\n",
        b"",
    );
    r.add(
        SHOP,
        "GET",
        "/search?q=%27+OR+1%3D1--",
        &format!("Accept: text/html\r\n{cookie}"),
        "",
        500,
        html_res,
        b"<html><body><h1>Internal Server Error</h1><pre>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''' OR 1=1--' at line 1</pre></body></html>",
    );
    r.add("analytics.example.net", "POST", "/collect", "Content-Type: text/plain\r\nOrigin: https://shop.example.com\r\n", r#"{"event":"page_view","path":"/cart"}"#, 204, "Access-Control-Allow-Origin: *\r\n", b"");
    r.add(SHOP, "GET", "/ws/notifications", "Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n", "", 101, "Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n", b"");
    r.flows
}

fn record(dir: &Path) {
    let project = Project::create(dir, None).unwrap();
    let sink = project.sink();
    for f in shop_flows() {
        let ws = f.status == Some(101);
        let id = sink.submit(f);
        if ws {
            for (i, (from_client, text)) in
                [(true, r#"{"type":"subscribe","topics":["cart","orders"]}"#), (false, r#"{"type":"cart","subtotal":3520}"#), (false, r#"{"type":"ping"}"#)]
                    .into_iter()
                    .enumerate()
            {
                sink.submit_ws(WsMessage {
                    id: 0,
                    flow_id: id,
                    at_us: START_US + 13_000_000 + i as i64 * 1_500_000,
                    from_client,
                    opcode: WsMessage::TEXT,
                    len: text.len() as u64,
                    data: text.as_bytes().to_vec(),
                });
            }
        }
    }
    drop(sink);
    project.close();
}

/// 描画を進めながら、`label` を含む表示が出る（記録の読み込みやパッシブチェックが終わる）のを待つ。
fn settle(h: &mut Harness<'_, PxApp>, label: &str) {
    for _ in 0..300 {
        h.run_steps(1);
        if h.query_all_by_label_contains(label).next().is_some() {
            h.run_steps(5);
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    panic!("{label} が表示されません");
}

/// 読み込み（別スレッド）が終わるまで描画を進める。
fn idle(h: &mut Harness<'_, PxApp>) {
    for _ in 0..50 {
        h.run_steps(1);
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

fn save(h: &mut Harness<'_, PxApp>, out: &Path, name: &str) {
    h.run_steps(3);
    let image = h.render().expect("描画できる");
    image.save(out.join(name)).unwrap();
}

#[test]
#[ignore = "README の画像を作り直すときだけ動かす"]
fn readme_screenshots() {
    let out = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../docs/images");
    std::fs::create_dir_all(&out).unwrap();
    // 画面に出るパス（案件・CA の場所）に手元のフォルダ名が写らないよう、一時フォルダからの相対パスにする。
    let tmp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(tmp.path()).unwrap();
    // SAFETY: このテストは単独で動かす（--ignored）。APPDATA を読むのは px-app のテストだけ
    unsafe { std::env::set_var("APPDATA", r"AppData\Roaming") };
    let dir = PathBuf::from("example-shop");
    record(&dir);

    let opts = crate::cli::LaunchOptions { project: Some(dir), ..Default::default() };
    let mut h = Harness::builder().with_size([1440.0, 960.0]).build_eframe(|cc| {
        crate::fonts::install(&cc.egui_ctx);
        egui_extras::install_image_loaders(&cc.egui_ctx);
        let mut app = PxApp::new(cc.egui_ctx.clone(), opts).expect("アプリを起動できる");
        // 一覧の先頭から見せる
        app.history.follow = false;
        app
    });
    h.state_mut().prefs.theme = ThemeChoice::Dark;
    h.state().prefs.apply(&h.ctx);
    settle(&mut h, "/api/products/42");

    // History: 行に色を付け、JSON の API を選んで詳細を出す
    h.state_mut().set_color(vec![6], Some(Highlight::Orange));
    h.state_mut().set_color(vec![13, 15], Some(Highlight::Red));
    h.state_mut().select(7);
    idle(&mut h);
    save(&mut h, &out, "history.png");

    // 検出: パッシブチェックの結果
    h.state_mut().tab = Tab::Findings;
    settle(&mut h, "ソフトウェアのバージョンを開示");
    h.query_all_by_label_contains("SQL のエラーメッセージ").next().unwrap().click();
    h.remove_cursor();
    settle(&mut h, "/search?q=");
    h.state_mut().select(15);
    idle(&mut h);
    save(&mut h, &out, "findings.png");

    // Comparer: 1 ページ目と 2 ページ目の Response
    h.state_mut().send_to_comparer(7);
    h.state_mut().send_to_comparer(8);
    h.state_mut().tab = Tab::Comparer;
    settle(&mut h, "差分");
    save(&mut h, &out, "comparer.png");

    std::env::set_current_dir(env!("CARGO_MANIFEST_DIR")).unwrap();
}
