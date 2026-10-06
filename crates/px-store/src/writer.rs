//! 単一の writer スレッド。プロキシ側は `FlowSink::submit` でキューに積むだけで
//! DB を待たない。writer はまとめてトランザクションでコミットする。

use std::path::PathBuf;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crossbeam_channel::{Receiver, RecvTimeoutError, Sender};
use rusqlite::{Connection, params};

use crate::classify::{classify, content_type};
use crate::model::{EDITED_REQUEST, EDITED_RESPONSE, NewFlow};
use crate::{Result, body, schema};

const BATCH_MAX: usize = 1024;
const BATCH_WINDOW: Duration = Duration::from_millis(30);

pub type CommitHook = Arc<dyn Fn() + Send + Sync>;

/// writer スレッドへの書き込み要求。
enum Op {
    Insert(Box<NewFlow>),
    /// メモの更新（None で削除）
    SetNote { id: i64, note: Option<String> },
}

/// プロキシ等からフローを投入するためのハンドル。clone して使う。
#[derive(Clone)]
pub struct FlowSink {
    tx: Sender<Op>,
}

impl FlowSink {
    /// ノンブロッキング。writer が終了済みなら破棄する。
    pub fn submit(&self, flow: NewFlow) {
        if self.tx.send(Op::Insert(Box::new(flow))).is_err() {
            tracing::warn!("flow dropped: writer closed");
        }
    }

    /// フローのメモを設定する（空白だけなら削除）。ノンブロッキングで、記録と同じ順に書き込む。
    pub fn set_note(&self, id: i64, note: &str) {
        let note = (!note.trim().is_empty()).then(|| note.to_owned());
        if self.tx.send(Op::SetNote { id, note }).is_err() {
            tracing::warn!("note dropped: writer closed");
        }
    }
}

pub(crate) struct Writer {
    tx: Option<Sender<Op>>,
    join: Option<JoinHandle<()>>,
}

impl Writer {
    pub fn spawn(conn: Connection, bodies_dir: PathBuf, on_commit: Option<CommitHook>) -> Self {
        let (tx, rx) = crossbeam_channel::unbounded();
        let join = std::thread::Builder::new()
            .name("px-store-writer".into())
            .spawn(move || run(conn, bodies_dir, rx, on_commit))
            .expect("spawn writer thread");
        Self { tx: Some(tx), join: Some(join) }
    }

    pub fn sink(&self) -> FlowSink {
        FlowSink { tx: self.tx.clone().expect("writer open") }
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

fn run(mut conn: Connection, bodies_dir: PathBuf, rx: Receiver<Op>, on_commit: Option<CommitHook>) {
    let mut batch = Vec::with_capacity(BATCH_MAX);
    while let Ok(f) = rx.recv() {
        batch.push(f);
        let deadline = Instant::now() + BATCH_WINDOW;
        let mut closed = false;
        while batch.len() < BATCH_MAX {
            match rx.recv_deadline(deadline) {
                Ok(f) => batch.push(f),
                Err(RecvTimeoutError::Timeout) => break,
                Err(RecvTimeoutError::Disconnected) => {
                    closed = true;
                    break;
                }
            }
        }
        if let Err(e) = write_batch(&mut conn, &bodies_dir, &batch) {
            tracing::error!("failed to write {} operations: {e}", batch.len());
        } else if let Some(hook) = &on_commit {
            hook();
        }
        batch.clear();
        if closed {
            break;
        }
    }
    // 閉じる前に WAL を本体へ反映しておく（コピー時に -wal を持ち回らなくて済む）。
    let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
}

fn write_batch(conn: &mut Connection, bodies_dir: &std::path::Path, batch: &[Op]) -> Result<()> {
    let tx = conn.transaction()?;
    for op in batch {
        let f = match op {
            Op::Insert(f) => f,
            Op::SetNote { id, note } => {
                tx.prepare_cached("UPDATE flows SET note = ?2 WHERE id = ?1")?.execute(params![id, note])?;
                continue;
            }
        };
        let req_body = body::put(&tx, bodies_dir, &f.req_body)?;
        let res_body = body::put(&tx, bodies_dir, &f.res_body)?;
        let ct = content_type(f.res_head.as_deref());
        let orig_req_body = match &f.orig_request {
            Some((_, b)) => body::put(&tx, bodies_dir, b)?,
            None => None,
        };
        let orig_res_body = match &f.orig_response {
            Some((_, b)) => body::put(&tx, bodies_dir, b)?,
            None => None,
        };
        let edited = (f.orig_request.is_some() as u8 * EDITED_REQUEST) | (f.orig_response.is_some() as u8 * EDITED_RESPONSE);
        let kind = classify(&f.target, &f.req_head, ct.as_deref());
        tx.prepare_cached(
            "INSERT INTO flows(source, started_at, duration_us, scheme, host, port, method, target,
                               status, req_head, req_body, req_body_len, res_head, res_body, res_body_len, error,
                               kind, content_type, edited, orig_req_head, orig_req_body, orig_res_head, orig_res_body)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18,
                     ?19, ?20, ?21, ?22, ?23)",
        )?
        .execute(params![
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
            f.req_body.len() as i64,
            f.res_head,
            res_body.as_ref().map(|h| &h[..]),
            f.res_body.len() as i64,
            f.error,
            kind as u8,
            ct,
            edited,
            f.orig_request.as_ref().map(|(h, _)| h),
            orig_req_body.as_ref().map(|h| &h[..]),
            f.orig_response.as_ref().map(|(h, _)| h),
            orig_res_body.as_ref().map(|h| &h[..]),
        ])?;
    }
    tx.commit()?;
    Ok(())
}

pub(crate) fn open_conn(path: &std::path::Path) -> Result<Connection> {
    let conn = Connection::open(path)?;
    schema::tune(&conn, true)?;
    Ok(conn)
}
