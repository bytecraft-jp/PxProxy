//! 単一の writer スレッド。プロキシ側は `FlowSink::submit` でキューに積むだけで
//! DB を待たない。writer はまとめてトランザクションでコミットする。
//!
//! パッシブチェックもこのスレッドで行う。新しいフローは記録と同じトランザクションで調べ、
//! 調べ残し（v4 より前に記録したもの・再スキャン）は空いた時間に少しずつ調べる。
//! どこまで調べたかは meta.passive_upto に残すので、途中で閉じても次に開いたとき続きから進む。

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crossbeam_channel::{Receiver, RecvTimeoutError, Sender, TryRecvError};
use parking_lot::Mutex;
use rusqlite::{Connection, Transaction, params};

use crate::classify::{classify, content_type};
use crate::model::{EDITED_REQUEST, EDITED_RESPONSE, NewFlow, TRUNCATED_REQUEST, TRUNCATED_RESPONSE, WsMessage};
use crate::passive::{self, Exchange};
use crate::{FlowSource, Result, body, schema};

const BATCH_MAX: usize = 1024;
const BATCH_WINDOW: Duration = Duration::from_millis(30);
/// 調べ残しを 1 回に調べるフロー数（記録を待たせすぎないように小分けにする）
const SCAN_SLICE: i64 = 200;
/// どこまでパッシブチェックを済ませたか（この ID 以下は済み）
const PASSIVE_UPTO: &str = "passive_upto";

pub type CommitHook = Arc<dyn Fn() + Send + Sync>;

/// writer スレッドへの書き込み要求。
enum Op {
    Insert(i64, Box<NewFlow>),
    Ws(Box<WsMessage>),
    /// メモの更新（None で削除）
    SetNote { id: i64, note: Option<String> },
    /// パッシブチェックの結果を消して最初から調べ直す
    Rescan,
}

/// プロキシ等からフローを投入するためのハンドル。clone して使う。
#[derive(Clone)]
pub struct FlowSink {
    tx: Sender<Op>,
    /// 次に振るフロー ID。採番と送信を同じロックの中で行い、キューの順と ID の順を揃える。
    next_id: Arc<Mutex<i64>>,
}

impl FlowSink {
    /// ノンブロッキング。記録される ID を返す（writer が終了済みなら破棄する）。
    pub fn submit(&self, flow: NewFlow) -> i64 {
        let mut next = self.next_id.lock();
        let id = *next;
        *next += 1;
        if self.tx.send(Op::Insert(id, Box::new(flow))).is_err() {
            tracing::warn!("flow dropped: writer closed");
        }
        id
    }

    /// WebSocket のメッセージを記録する。`msg.flow_id` は `submit` が返した ID。
    pub fn submit_ws(&self, msg: WsMessage) {
        if self.tx.send(Op::Ws(Box::new(msg))).is_err() {
            tracing::warn!("websocket message dropped: writer closed");
        }
    }

    /// フローのメモを設定する（空白だけなら削除）。ノンブロッキングで、記録と同じ順に書き込む。
    pub fn set_note(&self, id: i64, note: &str) {
        let note = (!note.trim().is_empty()).then(|| note.to_owned());
        if self.tx.send(Op::SetNote { id, note }).is_err() {
            tracing::warn!("note dropped: writer closed");
        }
    }

    /// パッシブチェックを全フローについてやり直す（バックグラウンドで進む）。
    pub fn rescan_passive(&self) {
        let _ = self.tx.send(Op::Rescan);
    }
}

pub(crate) struct Writer {
    tx: Option<Sender<Op>>,
    next_id: Arc<Mutex<i64>>,
    join: Option<JoinHandle<()>>,
}

impl Writer {
    pub fn spawn(conn: Connection, bodies_dir: PathBuf, on_commit: Option<CommitHook>) -> Result<Self> {
        let max: i64 = conn.query_row("SELECT IFNULL(MAX(id), 0) FROM flows", [], |r| r.get(0))?;
        let upto = schema::meta_get(&conn, PASSIVE_UPTO)?;
        let (tx, rx) = crossbeam_channel::unbounded();
        let join = std::thread::Builder::new()
            .name("px-store-writer".into())
            .spawn(move || State { conn, bodies_dir, upto, max_id: max }.run(rx, on_commit))
            .expect("spawn writer thread");
        Ok(Self { tx: Some(tx), next_id: Arc::new(Mutex::new(max + 1)), join: Some(join) })
    }

    pub fn sink(&self) -> FlowSink {
        FlowSink { tx: self.tx.clone().expect("writer open"), next_id: self.next_id.clone() }
    }

    /// 自身の送信側を閉じ、残りを書き終えるまで待つ。
    /// 他に FlowSink が生きている間は戻らないので、先にそれらを捨てること。
    pub fn close(&mut self) {
        self.tx.take();
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        self.close();
    }
}

struct State {
    conn: Connection,
    bodies_dir: PathBuf,
    /// この ID 以下はパッシブチェック済み
    upto: i64,
    /// 記録済みの最大の ID
    max_id: i64,
}

impl State {
    fn backlog(&self) -> bool {
        self.upto < self.max_id
    }

    fn run(mut self, rx: Receiver<Op>, on_commit: Option<CommitHook>) {
        let mut batch = Vec::with_capacity(BATCH_MAX);
        loop {
            // 調べ残しがあれば待たずに進める
            let first = if self.backlog() {
                match rx.try_recv() {
                    Ok(op) => Some(op),
                    Err(TryRecvError::Empty) => None,
                    Err(TryRecvError::Disconnected) => break,
                }
            } else {
                match rx.recv() {
                    Ok(op) => Some(op),
                    Err(_) => break,
                }
            };
            let mut closed = false;
            if let Some(op) = first {
                batch.push(op);
                let deadline = Instant::now() + BATCH_WINDOW;
                while batch.len() < BATCH_MAX {
                    match rx.recv_deadline(deadline) {
                        Ok(op) => batch.push(op),
                        Err(RecvTimeoutError::Timeout) => break,
                        Err(RecvTimeoutError::Disconnected) => {
                            closed = true;
                            break;
                        }
                    }
                }
                let (upto, max_id) = (self.upto, self.max_id);
                match self.write_batch(&batch) {
                    Ok(()) => {
                        if let Some(hook) = &on_commit {
                            hook();
                        }
                    }
                    Err(e) => {
                        tracing::error!("failed to write {} operations: {e}", batch.len());
                        (self.upto, self.max_id) = (upto, max_id);
                    }
                }
                batch.clear();
            }
            if closed {
                break;
            }
            if self.backlog() {
                let upto = self.upto;
                match self.scan_slice() {
                    Ok(()) => {
                        if let Some(hook) = &on_commit {
                            hook();
                        }
                    }
                    Err(e) => {
                        // 同じところで失敗し続けないよう、調べ残しは諦める（再スキャンでやり直せる）
                        tracing::error!("passive scan failed: {e}");
                        self.upto = upto.max(self.max_id);
                    }
                }
            }
        }
        // 閉じる前に WAL を本体へ反映しておく（コピー時に -wal を持ち回らなくて済む）。
        let _ = self.conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
    }

    fn write_batch(&mut self, batch: &[Op]) -> Result<()> {
        let tx = self.conn.transaction()?;
        for op in batch {
            match op {
                Op::Insert(id, f) => {
                    insert_flow(&tx, &self.bodies_dir, *id, f)?;
                    // 調べ残しが無ければ、手元のデータでそのまま調べる
                    if self.upto == self.max_id && self.upto == id - 1 {
                        insert_findings(&tx, *id, f)?;
                        self.upto = *id;
                    }
                    self.max_id = self.max_id.max(*id);
                }
                Op::Ws(m) => {
                    tx.prepare_cached(
                        "INSERT INTO ws_messages(flow_id, at_us, from_client, opcode, len, data) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    )?
                    .execute(params![m.flow_id, m.at_us, m.from_client, m.opcode, m.len as i64, m.data])?;
                }
                Op::SetNote { id, note } => {
                    tx.prepare_cached("UPDATE flows SET note = ?2 WHERE id = ?1")?.execute(params![id, note])?;
                }
                Op::Rescan => {
                    tx.execute("DELETE FROM findings", [])?;
                    self.upto = 0;
                }
            }
        }
        schema::meta_set(&tx, PASSIVE_UPTO, self.upto)?;
        tx.commit()?;
        Ok(())
    }

    /// 調べ残しのフローを少しだけ調べる。
    fn scan_slice(&mut self) -> Result<()> {
        let tx = self.conn.transaction()?;
        let rows: Vec<(i64, NewFlow)> = {
            let mut st = tx.prepare_cached(
                "SELECT id, source, scheme, host, method, target, req_head, req_body, res_head, res_body
                 FROM flows WHERE id > ?1 ORDER BY id LIMIT ?2",
            )?;
            let mut rows = st.query(params![self.upto, SCAN_SLICE])?;
            let mut out = Vec::new();
            while let Some(r) = rows.next()? {
                let req_hash: Option<Vec<u8>> = r.get(7)?;
                let res_hash: Option<Vec<u8>> = r.get(9)?;
                let flow = NewFlow {
                    source: FlowSource::from_i64(r.get(1)?),
                    started_at_us: 0,
                    duration_us: 0,
                    scheme: r.get(2)?,
                    host: r.get(3)?,
                    port: 0,
                    method: r.get(4)?,
                    target: r.get(5)?,
                    status: None,
                    req_head: r.get(6)?,
                    req_body: body::get(&tx, &self.bodies_dir, req_hash)?,
                    res_head: r.get(8)?,
                    res_body: body::get(&tx, &self.bodies_dir, res_hash)?,
                    error: None,
                    orig_request: None,
                    orig_response: None,
                    req_body_total: None,
                    res_body_total: None,
                };
                out.push((r.get(0)?, flow));
            }
            out
        };
        for (id, f) in &rows {
            insert_findings(&tx, *id, f)?;
        }
        self.upto = match rows.last() {
            Some((id, _)) => *id,
            None => self.max_id,
        };
        schema::meta_set(&tx, PASSIVE_UPTO, self.upto)?;
        tx.commit()?;
        Ok(())
    }
}

fn insert_flow(tx: &Transaction<'_>, bodies_dir: &Path, id: i64, f: &NewFlow) -> Result<()> {
    let req_body = body::put(tx, bodies_dir, &f.req_body)?;
    let res_body = body::put(tx, bodies_dir, &f.res_body)?;
    let ct = content_type(f.res_head.as_deref());
    let orig_req_body = match &f.orig_request {
        Some((_, b)) => body::put(tx, bodies_dir, b)?,
        None => None,
    };
    let orig_res_body = match &f.orig_response {
        Some((_, b)) => body::put(tx, bodies_dir, b)?,
        None => None,
    };
    let edited = (f.orig_request.is_some() as u8 * EDITED_REQUEST) | (f.orig_response.is_some() as u8 * EDITED_RESPONSE);
    let truncated = (f.req_body_total.is_some() as u8 * TRUNCATED_REQUEST) | (f.res_body_total.is_some() as u8 * TRUNCATED_RESPONSE);
    let kind = classify(&f.target, &f.req_head, ct.as_deref());
    tx.prepare_cached(
        "INSERT INTO flows(id, source, started_at, duration_us, scheme, host, port, method, target,
                           status, req_head, req_body, req_body_len, res_head, res_body, res_body_len, error,
                           kind, content_type, edited, orig_req_head, orig_req_body, orig_res_head, orig_res_body, truncated)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18,
                 ?19, ?20, ?21, ?22, ?23, ?24, ?25)",
    )?
    .execute(params![
        id,
        f.source as u8,
        f.started_at_us,
        f.duration_us,
        f.scheme,
        f.host,
        f.port,
        f.method,
        f.target,
        f.status,
        f.req_head,
        req_body.as_ref().map(|h| &h[..]),
        f.req_body_total.map_or(f.req_body.len() as i64, |n| n as i64),
        f.res_head,
        res_body.as_ref().map(|h| &h[..]),
        f.res_body_total.map_or(f.res_body.len() as i64, |n| n as i64),
        f.error,
        kind as u8,
        ct,
        edited,
        f.orig_request.as_ref().map(|(h, _)| h),
        orig_req_body.as_ref().map(|h| &h[..]),
        f.orig_response.as_ref().map(|(h, _)| h),
        orig_res_body.as_ref().map(|h| &h[..]),
        truncated,
    ])?;
    Ok(())
}

fn insert_findings(tx: &Transaction<'_>, id: i64, f: &NewFlow) -> Result<()> {
    // パススルーは中身が無く、ダミーサーバは自分で決めた応答なので調べない
    if matches!(f.source, FlowSource::Tunnel | FlowSource::Mock) {
        return Ok(());
    }
    let hits = passive::scan(&Exchange {
        scheme: &f.scheme,
        host: &f.host,
        method: &f.method,
        target: &f.target,
        req_head: &f.req_head,
        req_body: &f.req_body,
        res_head: f.res_head.as_deref(),
        res_body: &f.res_body,
    });
    for h in hits {
        tx.prepare_cached("INSERT INTO findings(flow_id, check_id, severity, detail) VALUES (?1, ?2, ?3, ?4)")?
            .execute(params![id, h.check.id, h.check.severity as u8, h.detail])?;
    }
    Ok(())
}

pub(crate) fn open_conn(path: &std::path::Path) -> Result<Connection> {
    let conn = Connection::open(path)?;
    schema::tune(&conn, true)?;
    Ok(conn)
}
