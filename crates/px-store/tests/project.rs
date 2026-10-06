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
