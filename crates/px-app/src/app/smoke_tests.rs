//! 実際のアプリをウィンドウなしで動かし、記録済みの案件で各タブを描画できることを確かめる。

use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;
use px_store::{FlowSource, NewFlow, Project, SiteFilter, WsMessage};

use super::{PxApp, Tab};

fn flow(host: &str, target: &str, status: u16, res_head: &str, res_body: &[u8]) -> NewFlow {
    NewFlow {
        source: FlowSource::Proxy,
        started_at_us: 1_791_455_696_789_000,
        duration_us: 12_000,
        scheme: "https".into(),
        host: host.into(),
        port: 443,
        method: "GET".into(),
        target: target.into(),
        status: Some(status),
        req_head: format!("GET {target} HTTP/1.1\r\nHost: {host}\r\n\r\n").into_bytes(),
        req_body: Vec::new(),
        res_head: Some(res_head.as_bytes().to_vec()),
        res_body: res_body.to_vec(),
        error: None,
        orig_request: None,
        orig_response: None,
        req_body_total: None,
        res_body_total: None,
    }
}

/// HTML・JSON・WebSocket・TLS パススルー・切り詰めた Body の 5 件を記録した案件を作る。
fn recorded_project(dir: &std::path::Path) {
    let project = Project::create(dir, None).unwrap();
    let sink = project.sink();
    let html = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nServer: Apache/2.4.1\r\n\r\n";
    sink.submit(flow("example.com", "/a/b", 200, html, b"<html><body><p>one</p></body></html>"));
    let json = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n";
    sink.submit(flow("example.com", "/a/c?x=1", 200, json, br#"{"user":"alice","role":"admin"}"#));
    let ws = sink.submit(flow("chat.example.com", "/ws", 101, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n", b""));
    for (i, text) in [r#"{"hello":1}"#, "pong"].iter().enumerate() {
        sink.submit_ws(WsMessage {
            id: 0,
            flow_id: ws,
            at_us: 1_791_455_697_000_000 + i as i64,
            from_client: i == 0,
            opcode: WsMessage::TEXT,
            len: text.len() as u64,
            data: text.as_bytes().to_vec(),
        });
    }
    let mut tunnel = flow("pinned.example.com", "pinned.example.com:443", 200, "HTTP/1.1 200 Connection Established\r\n\r\n", b"");
    tunnel.source = FlowSource::Tunnel;
    tunnel.method = "CONNECT".into();
    sink.submit(tunnel);
    let mut big = flow("files.example.com", "/big.bin", 200, "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\n", &[0u8; 1024]);
    big.res_body_total = Some(50 * 1024 * 1024);
    sink.submit(big);
    drop(sink);
    project.close();
}

fn has_label(h: &Harness<'_, PxApp>, text: &str) -> bool {
    h.query_all_by_label_contains(text).next().is_some()
}

#[test]
fn every_tab_renders_recorded_traffic() {
    let tmp = tempfile::tempdir().unwrap();
    // CA と「最近の案件」を利用者の設定フォルダに書かないよう、一時フォルダへ向ける。
    // SAFETY: px-app のテストで APPDATA を読むのはこのテストだけ
    unsafe { std::env::set_var("APPDATA", tmp.path().join("appdata")) };
    let dir = tmp.path().join("smoke.pxproj");
    recorded_project(&dir);

    let opts = crate::cli::LaunchOptions { project: Some(dir), ..Default::default() };
    let mut h = Harness::builder()
        .with_size([1400.0, 900.0])
        .build_eframe(|cc| PxApp::new(cc.egui_ctx.clone(), opts).expect("アプリを起動できる"));
    h.run_steps(3);
    assert_eq!(h.state().ids.len(), 5, "History に記録が並ぶ");
    assert!(has_label(&h, "10-08"), "時刻の列");
    assert!(has_label(&h, "TLS パススルー") && has_label(&h, "一部のみ記録"), "備考");

    // 各行の詳細
    for id in 1..=5 {
        h.state_mut().select(id);
        h.run_steps(2);
    }
    assert!(has_label(&h, "Response の Body は先頭"), "切り詰めの注記");
    h.state_mut().select(1);
    h.run_steps(2);
    assert!(has_label(&h, "検出"), "パッシブチェックの検出");
    h.state_mut().select(3);
    h.run_steps(2);
    assert!(has_label(&h, "WebSocket (2)"), "WebSocket のメッセージ");
    assert!(has_label(&h, "メッセージ 2 件"));

    // サイトマップ: ノードを選ぶとその配下だけになる
    h.get_by_label("サイトマップ").click();
    h.run_steps(3);
    assert_eq!(h.state().tab, Tab::SiteMap);
    assert!(has_label(&h, "https://example.com  (2)"));
    h.state_mut().site_map.selected =
        Some(SiteFilter { scheme: "https".into(), host: "example.com".into(), port: 443, path: "/a".into() });
    h.run_steps(3);
    assert_eq!(h.state().ids, [1, 2]);
    // History に戻るとノードの絞り込みは外れる
    h.state_mut().tab = Tab::History;
    h.run_steps(2);
    assert_eq!(h.state().ids.len(), 5);

    // Comparer
    h.state_mut().send_to_comparer(1);
    h.state_mut().send_to_comparer(2);
    h.state_mut().tab = Tab::Comparer;
    h.run_steps(3);
    assert!(has_label(&h, "差分"), "差分の数が出る");

    // 検出
    h.state_mut().tab = Tab::Findings;
    h.run_steps(3);
    assert!(has_label(&h, "ソフトウェアのバージョンを開示"));

    // 設定
    h.state_mut().tab = Tab::Settings;
    h.run_steps(2);
    assert!(has_label(&h, "上流プロキシを使う"));
    assert!(has_label(&h, "記録する Body の上限"));

    // ダミーサーバ: 追加すると / の応答が付いた状態で作られ、settings.toml に保存される
    h.state_mut().tab = Tab::Mock;
    h.run_steps(2);
    h.get_by_label("＋ ダミーサーバを追加").click();
    h.run_steps(3);
    assert_eq!(h.state().settings.mock_servers.len(), 1);
    assert_eq!(h.state().settings.mock_servers[0].routes[0].path, "/");
    assert!(has_label(&h, "ホスト名を入力してください"));
    h.get_by_label("＋ パスを追加").click();
    h.run_steps(3);
    assert_eq!(h.state().settings.mock_servers[0].routes.len(), 2);
    assert!(has_label(&h, "パスは / で始めてください"), "追加したパスは空");
    let saved = std::fs::read_to_string(h.state().project.as_ref().unwrap().settings_path()).unwrap();
    assert!(saved.contains("[[mock_servers]]"), "{saved}");

    // 案件でも空でもないフォルダは開かない
    let other = tmp.path().join("other");
    std::fs::create_dir_all(&other).unwrap();
    std::fs::write(other.join("memo.txt"), "x").unwrap();
    h.state_mut().open_dir(other.clone());
    assert!(h.state().project.as_ref().is_some_and(|p| p.dir().ends_with("smoke.pxproj")), "元の案件のまま");
    assert!(!other.join("project.toml").exists());

    // 空のフォルダを開くと、新しい案件として初期化して開く
    let empty = tmp.path().join("empty");
    std::fs::create_dir_all(&empty).unwrap();
    h.state_mut().open_dir(empty.clone());
    h.run_steps(2);
    assert!(empty.join("project.toml").exists());
    assert_eq!(h.state().project.as_ref().map(|p| p.manifest().name.as_str()), Some("empty"));
    assert!(h.state().ids.is_empty());
    assert!(h.state().status.contains("初期化しました"), "{}", h.state().status);
}
