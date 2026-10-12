use px_store::{ALL_KINDS, ALL_STATUS, Filter, FlowKind, FlowSource, INLINE_THRESHOLD, NewFlow, Project, StatusClass};

fn flow(host: &str, body: Vec<u8>) -> NewFlow {
    NewFlow {
        source: FlowSource::Proxy,
        started_at_us: 1,
        duration_us: 2,
        scheme: "https".into(),
        host: host.into(),
        port: 443,
        method: "GET".into(),
        target: "/index".into(),
        status: Some(200),
        req_head: b"GET /index HTTP/1.1\r\nHost: x\r\n\r\n".to_vec(),
        req_body: Vec::new(),
        res_head: Some(b"HTTP/1.1 200 OK\r\n\r\n".to_vec()),
        res_body: body,
        error: None,
        orig_request: None,
        orig_response: None,
        req_body_total: None,
        res_body_total: None,
    }
}

#[test]
fn write_read_export_import() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("a.pxproj");
    let small = b"hello".to_vec();
    let large: Vec<u8> = (0..INLINE_THRESHOLD * 3).map(|i| (i % 251) as u8).collect();

    let project = Project::create(&dir, None).unwrap();
    let sink = project.sink();
    sink.submit(flow("example.com", small.clone()));
    sink.submit(flow("example.org", large.clone()));
    sink.submit(flow("example.org", large.clone())); // 重複排除される
    drop(sink);

    // writer がコミットするまで待つ
    let reader = project.reader().unwrap();
    for _ in 0..100 {
        if reader.count().unwrap() == 3 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let ids = reader.ids_after(0, &Filter::default()).unwrap();
    assert_eq!(ids.len(), 3);
    let org = reader.ids_after(0, &Filter { text: "ORG".into(), ..Default::default() }).unwrap();
    assert_eq!(org.len(), 2);
    let only = |kinds, status| reader.ids_after(0, &Filter { kinds, status, ..Default::default() }).unwrap().len();
    assert_eq!(only(FlowKind::Other.bit(), ALL_STATUS), 3);
    assert_eq!(only(FlowKind::Image.bit() | FlowKind::Xhr.bit(), ALL_STATUS), 0);
    assert_eq!(only(ALL_KINDS, StatusClass::Ok.bit()), 3);
    assert_eq!(only(ALL_KINDS, StatusClass::NoResponse.bit() | StatusClass::ServerError.bit()), 0);
    assert_eq!(only(ALL_KINDS, 0), 0);
    let scoped = Filter { in_scope_only: true, ..Default::default() };
    assert_eq!(reader.ids_after(0, &scoped).unwrap().len(), 3, "default predicate = everything");
    reader.set_scope(|host, _| host == "example.org").unwrap();
    assert_eq!(reader.ids_after(0, &scoped).unwrap().len(), 2);
    assert_eq!(reader.ids_after(0, &Filter::default()).unwrap().len(), 3, "flag off = no scope filter");
    assert_eq!(reader.detail(ids[0]).unwrap().unwrap().res_body, small);
    assert_eq!(reader.detail(ids[1]).unwrap().unwrap().res_body, large);

    let zip = tmp.path().join("a.zip");
    project.export_zip(&zip).unwrap();
    drop(reader);
    project.close();

    let imported = Project::import_zip(&zip, tmp.path().join("b.pxproj"), None).unwrap();
    let r = imported.reader().unwrap();
    assert_eq!(r.count().unwrap(), 3);
    assert_eq!(r.detail(ids[2]).unwrap().unwrap().res_body, large);
}

#[test]
fn edited_flow_keeps_original() {
    let tmp = tempfile::tempdir().unwrap();
    let project = Project::create(tmp.path().join("e.pxproj"), None).unwrap();
    let mut f = flow("example.com", b"edited-res".to_vec());
    f.orig_request = Some((b"GET /orig HTTP/1.1\r\n\r\n".to_vec(), b"orig-req-body".to_vec()));
    f.orig_response = Some((b"HTTP/1.1 500 X\r\n\r\n".to_vec(), Vec::new()));
    project.sink().submit(f);
    let reader = project.reader().unwrap();
    for _ in 0..100 {
        if reader.count().unwrap() == 1 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let d = reader.detail(1).unwrap().unwrap();
    assert_eq!(d.summary.edited, px_store::EDITED_REQUEST | px_store::EDITED_RESPONSE);
    assert_eq!(d.orig_request.unwrap().1, b"orig-req-body");
    assert_eq!(d.orig_response.unwrap(), (b"HTTP/1.1 500 X\r\n\r\n".to_vec(), Vec::new()));
}

#[test]
fn export_and_extract_report_progress_and_cancel() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("p.pxproj");
    let project = Project::create(&dir, None).unwrap();
    let large: Vec<u8> = (0..INLINE_THRESHOLD * 2).map(|i| (i % 7) as u8).collect();
    project.sink().submit(flow("example.com", large));
    project.close();

    // 中止すると書きかけの zip は残らない
    let zip = tmp.path().join("p.zip");
    let err = Project::export_dir(&dir, &zip, &mut |done, _| done == 0).unwrap_err();
    assert!(matches!(err, px_store::StoreError::Cancelled), "{err}");
    assert!(!zip.exists());

    let mut last = (0, 0);
    Project::export_dir(&dir, &zip, &mut |d, t| {
        last = (d, t);
        true
    })
    .unwrap();
    assert!(last.1 > 0 && last.0 == last.1, "{last:?}");

    // 展開を中止すると作ったフォルダは消える
    let dest = tmp.path().join("q.pxproj");
    let err = Project::extract_zip(&zip, &dest, &mut |done, _| done < 2).unwrap_err();
    assert!(matches!(err, px_store::StoreError::Cancelled), "{err}");
    assert!(!dest.exists());

    Project::extract_zip(&zip, &dest, &mut |_, _| true).unwrap();
    let opened = Project::open(&dest, None).unwrap();
    assert_eq!(opened.reader().unwrap().count().unwrap(), 1);
}

#[test]
fn notes_are_saved_cleared_and_kept_after_reopen() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("n.pxproj");
    let project = Project::create(&dir, None).unwrap();
    let sink = project.sink();
    sink.submit(flow("a.test", Vec::new()));
    sink.submit(flow("b.test", Vec::new()));
    // 記録の直後に積んでも、記録と同じ順に書かれる
    sink.set_note(1, "ログイン後のトークン");
    sink.set_note(2, "消す予定");
    sink.set_note(2, "   "); // 空白だけなら削除
    drop(sink);
    project.close();

    let project = Project::open(&dir, None).unwrap();
    let reader = project.reader().unwrap();
    assert_eq!(reader.summary(1).unwrap().unwrap().note.as_deref(), Some("ログイン後のトークン"));
    assert_eq!(reader.summary(2).unwrap().unwrap().note, None);
}

fn wait_for(reader: &px_store::Reader, n: i64) {
    for _ in 0..200 {
        if reader.count().unwrap() >= n && reader.passive_progress().unwrap().0 >= n {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    panic!("記録が {n} 件になりません");
}

#[test]
fn ids_websocket_and_truncation() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("w.pxproj");
    let project = Project::create(&dir, None).unwrap();
    let sink = project.sink();
    assert_eq!(sink.submit(flow("a.test", Vec::new())), 1, "submit が記録される ID を返す");
    let mut big = flow("a.test", b"head".to_vec());
    big.res_body_total = Some(10_000);
    let ws_flow = sink.submit(big);
    assert_eq!(ws_flow, 2);
    for (i, text) in ["hello", "world"].iter().enumerate() {
        sink.submit_ws(px_store::WsMessage {
            id: 0,
            flow_id: ws_flow,
            at_us: i as i64,
            from_client: i == 0,
            opcode: px_store::WsMessage::TEXT,
            len: text.len() as u64,
            data: text.as_bytes().to_vec(),
        });
    }
    drop(sink);
    project.close();

    // 開き直しても ID は続きから振る
    let project = Project::open(&dir, None).unwrap();
    assert_eq!(project.sink().submit(flow("b.test", Vec::new())), 3);
    let reader = project.reader().unwrap();
    wait_for(&reader, 3);
    let s = reader.summary(2).unwrap().unwrap();
    assert_eq!((s.res_body_len, s.truncated), (10_000, px_store::TRUNCATED_RESPONSE));
    let msgs = reader.ws_messages(ws_flow, 0).unwrap();
    assert_eq!(msgs.iter().map(|m| (m.from_client, m.data.as_slice())).collect::<Vec<_>>(), [(true, &b"hello"[..]), (false, b"world")]);
    assert_eq!(reader.ws_messages(ws_flow, msgs[0].id).unwrap().len(), 1, "差分だけ取れる");
}

#[test]
fn site_filter_matches_path_prefix() {
    let tmp = tempfile::tempdir().unwrap();
    let project = Project::create(tmp.path().join("s.pxproj"), None).unwrap();
    let sink = project.sink();
    for target in ["/a", "/a/b?x=1", "/a?q", "/ab", "/", "/a/"] {
        let mut f = flow("example.com", Vec::new());
        f.target = target.into();
        sink.submit(f);
    }
    let mut other = flow("example.com", Vec::new());
    other.port = 8443;
    sink.submit(other);
    let reader = project.reader().unwrap();
    wait_for(&reader, 7);
    let site = |path: &str| {
        let f = Filter {
            site: Some(px_store::SiteFilter { scheme: "https".into(), host: "example.com".into(), port: 443, path: path.into() }),
            ..Default::default()
        };
        reader.ids_after(0, &f).unwrap()
    };
    assert_eq!(site(""), [1, 2, 3, 4, 5, 6], "ホスト全体（別ポートは含めない）");
    assert_eq!(site("/a"), [1, 2, 3, 6], "/ab は含めない");
    assert_eq!(site("/a/b"), [2]);
    assert_eq!(reader.site_rows_after(5, false).unwrap().len(), 2);
}

#[test]
fn advanced_filters_and_content_search() {
    use px_store::{ALL_METHODS, ContentQuery, MethodClass, SearchIn};
    use std::io::Write;

    let tmp = tempfile::tempdir().unwrap();
    let project = Project::create(tmp.path().join("f.pxproj"), None).unwrap();
    let sink = project.sink();
    // 1: GET、gzip の Body に「秘密のトークン」
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gz.write_all("{\"msg\":\"秘密のトークン\"}".as_bytes()).unwrap();
    let mut f = flow("api.example.com", gz.finish().unwrap());
    f.res_head = Some(b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n".to_vec());
    f.target = "/v1/users".into();
    sink.submit(f);
    // 2: POST、Request の Body に password、大きい Response（ファイルに置かれる）、遅い
    let mut f = flow("www.example.com", vec![b'x'; INLINE_THRESHOLD * 2]);
    f.method = "POST".into();
    f.req_body = b"user=a&password=Hunter2".to_vec();
    f.duration_us = 1_500_000;
    sink.submit(f);
    // 3: CONNECT（その他のメソッド）
    let mut f = flow("www.example.com", Vec::new());
    f.method = "CONNECT".into();
    sink.submit(f);
    sink.set_note(3, "メモ");
    drop(sink);
    let reader = project.reader().unwrap();
    wait_for(&reader, 3);

    let ids = |f: Filter| reader.ids_after(0, &f).unwrap();
    let methods = |m: &[MethodClass]| m.iter().fold(0, |acc, m| acc | m.bit());
    assert_eq!(ids(Filter { methods: methods(&[MethodClass::Post]), ..Default::default() }), [2]);
    assert_eq!(ids(Filter { methods: methods(&[MethodClass::Get, MethodClass::Other]), ..Default::default() }), [1, 3]);
    assert_eq!(ids(Filter { methods: ALL_METHODS & !MethodClass::Other.bit(), ..Default::default() }), [1, 2]);
    assert_eq!(ids(Filter { noted_only: true, ..Default::default() }), [3]);
    assert_eq!(ids(Filter { length: (Some(1), Some(100)), ..Default::default() }), [1]);
    assert_eq!(ids(Filter { length: (Some(INLINE_THRESHOLD as u64), None), ..Default::default() }), [2]);
    assert_eq!(ids(Filter { duration_ms: (Some(1000), None), ..Default::default() }), [2]);
    assert_eq!(ids(Filter { duration_ms: (None, Some(0)), ..Default::default() }), [1, 3], "2 µs は 0 ms");
    assert_eq!(ids(Filter { text: r"^/v\d+/".into(), text_regex: true, ..Default::default() }), [1]);
    assert_eq!(ids(Filter { text: r"^API\.".into(), text_regex: true, ..Default::default() }), [1], "大文字小文字無視");

    let content = |text: &str, regex: bool, case_sensitive: bool, target: SearchIn| Filter {
        content: ContentQuery { text: text.into(), regex, case_sensitive, target },
        ..Default::default()
    };
    assert_eq!(ids(content("秘密のトークン", false, false, SearchIn::Both)), [1], "gzip を展開して探す");
    assert_eq!(ids(content("HUNTER2", false, false, SearchIn::Both)), [2]);
    assert!(ids(content("HUNTER2", false, true, SearchIn::Both)).is_empty(), "大文字小文字を区別");
    assert!(ids(content("Hunter2", false, false, SearchIn::Response)).is_empty(), "Response だけ");
    assert_eq!(ids(content("x{1000}", true, false, SearchIn::Response)), [2], "ファイルに置いた Body も");
    assert_eq!(ids(content("content-encoding: gzip", false, false, SearchIn::Response)), [1], "ヘッダも");
    assert_eq!(ids(content("a.b", false, false, SearchIn::Both)), Vec::<i64>::new(), "正規表現でなければ . はそのまま");

    let bad = content("(", true, false, SearchIn::Both);
    assert!(bad.error().is_some());
    assert!(reader.ids_after(0, &bad).is_err());

    // 期限を過ぎていても 1 件は進み、続きから調べられる
    let all = content("e", false, false, SearchIn::Both);
    let past = Some(std::time::Instant::now());
    let first = reader.scan_after(0, &all, past).unwrap();
    assert_eq!((first.upto, first.complete), (1, false));
    let rest = reader.scan_after(first.upto, &all, None).unwrap();
    assert_eq!((rest.upto, rest.complete), (3, true));
}

#[test]
fn colors_and_delete() {
    use px_store::{ALL_COLORS, Highlight, NO_COLOR};

    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("d.pxproj");
    let project = Project::create(&dir, None).unwrap();
    let sink = project.sink();
    let large: Vec<u8> = (0..INLINE_THRESHOLD * 2).map(|i| (i % 13) as u8).collect();
    let shared: Vec<u8> = (0..INLINE_THRESHOLD * 2).map(|i| (i % 17) as u8).collect();
    sink.submit(flow("a.test", large)); // 1: このフローだけが参照する大きい Body
    sink.submit(flow("a.test", shared.clone())); // 2, 3: 同じ Body を共有
    sink.submit(flow("a.test", shared.clone()));
    let mut ws = flow("a.test", Vec::new());
    ws.status = Some(101);
    let ws_id = sink.submit(ws);
    sink.submit_ws(px_store::WsMessage {
        id: 0,
        flow_id: ws_id,
        at_us: 0,
        from_client: true,
        opcode: px_store::WsMessage::TEXT,
        len: 2,
        data: b"hi".to_vec(),
    });
    sink.set_color(vec![1, 2], Some(Highlight::Red));
    sink.set_color(vec![2], Some(Highlight::Blue));
    sink.set_color(vec![4], Some(Highlight::Green));
    sink.set_color(vec![4], None);
    let reader = project.reader().unwrap();
    wait_for(&reader, 4);
    let files = |dir: &std::path::Path| {
        let mut n = 0;
        let mut stack = vec![dir.join("bodies")];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(d).unwrap() {
                let e = e.unwrap();
                if e.file_type().unwrap().is_dir() {
                    stack.push(e.path());
                } else {
                    n += 1;
                }
            }
        }
        n
    };
    for _ in 0..100 {
        if reader.summary(4).unwrap().unwrap().color.is_none() && reader.summary(2).unwrap().unwrap().color.is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert_eq!(reader.summary(1).unwrap().unwrap().color, Some(Highlight::Red));
    assert_eq!(reader.summary(2).unwrap().unwrap().color, Some(Highlight::Blue));
    assert_eq!(reader.summary(4).unwrap().unwrap().color, None);
    let colored = |colors| reader.ids_after(0, &Filter { colors, ..Default::default() }).unwrap();
    assert_eq!(colored(Highlight::Red.bit() | Highlight::Blue.bit()), [1, 2]);
    assert_eq!(colored(NO_COLOR), [3, 4]);
    assert!(colored(0).is_empty());
    assert_eq!(colored(ALL_COLORS).len(), 4);
    assert_eq!(files(&dir), 2);

    // 1 と 2 と 4 を消す。共有している Body は 3 が使うので残る
    sink.delete(vec![1, 2, 4]);
    drop(sink);
    project.close();
    let project = Project::open(&dir, None).unwrap();
    let reader = project.reader().unwrap();
    assert_eq!(reader.ids_after(0, &Filter::default()).unwrap(), [3]);
    assert!(reader.ws_messages(ws_id, 0).unwrap().is_empty(), "WebSocket のメッセージも消える");
    assert_eq!(files(&dir), 1, "参照されなくなった Body のファイルだけ消える");
    assert_eq!(reader.detail(3).unwrap().unwrap().res_body, shared);
}

#[test]
fn out_of_scope_ids() {
    let tmp = tempfile::tempdir().unwrap();
    let project = Project::create(tmp.path().join("o.pxproj"), None).unwrap();
    let sink = project.sink();
    for host in ["a.test", "b.test", "a.test"] {
        sink.submit(flow(host, Vec::new()));
    }
    let reader = project.reader().unwrap();
    wait_for(&reader, 3);
    assert!(reader.ids_out_of_scope().unwrap().is_empty(), "既定はすべて診断対象");
    reader.set_scope(|host, _| host == "a.test").unwrap();
    assert_eq!(reader.ids_out_of_scope().unwrap(), [2]);
}

#[test]
fn passive_findings_are_recorded_and_rescanned() {
    let tmp = tempfile::tempdir().unwrap();
    let project = Project::create(tmp.path().join("p.pxproj"), None).unwrap();
    let sink = project.sink();
    let mut f = flow("example.com", b"<html>Traceback (most recent call last):</html>".to_vec());
    f.res_head = Some(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nSet-Cookie: SID=1; Secure; HttpOnly\r\n\r\n".to_vec());
    sink.submit(f);
    sink.submit(flow("example.org", Vec::new()));
    let reader = project.reader().unwrap();
    wait_for(&reader, 2);
    let found = reader.findings_of(1).unwrap();
    let ids: Vec<&str> = found.iter().map(|f| f.check.as_str()).collect();
    assert!(ids.contains(&"error-message") && ids.contains(&"cookie-no-samesite"), "{ids:?}");
    assert_eq!(found[0].severity, px_store::Severity::Low, "重い順");
    assert_eq!(reader.summary(1).unwrap().unwrap().max_severity, Some(px_store::Severity::Low));
    assert_eq!(reader.summary(2).unwrap().unwrap().max_severity, None);
    let groups = reader.finding_groups(false).unwrap();
    assert!(groups.iter().all(|g| g.host == "example.com" && g.flows == 1));
    assert_eq!(reader.findings_in("error-message", "example.com").unwrap().len(), 1);

    let before = groups.len();
    sink.rescan_passive();
    for _ in 0..100 {
        std::thread::sleep(std::time::Duration::from_millis(20));
        if reader.passive_progress().unwrap() == (2, 2) && reader.finding_groups(false).unwrap().len() == before {
            return;
        }
    }
    panic!("再スキャンが終わりません: {:?}", reader.passive_progress().unwrap());
}
