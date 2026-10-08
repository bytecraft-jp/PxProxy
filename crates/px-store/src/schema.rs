use rusqlite::{Connection, params};

use crate::Result;
use crate::classify::{classify, content_type};

pub const SCHEMA_VERSION: i64 = 4;

/// 接続設定。journal_mode の変更は書き込み接続でのみ行う。
pub fn tune(conn: &Connection, writable: bool) -> Result<()> {
    if writable {
        conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;")?;
    }
    conn.execute_batch(
        "PRAGMA temp_store = MEMORY;
         PRAGMA mmap_size = 268435456;
         PRAGMA cache_size = -65536;
         PRAGMA busy_timeout = 5000;",
    )?;
    Ok(())
}

pub fn migrate(conn: &Connection) -> Result<()> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version >= SCHEMA_VERSION {
        return Ok(());
    }
    if version < 1 {
        create_v1(conn)?;
    }
    if version < 2 {
        migrate_v2(conn)?;
    }
    if version < 3 {
        // v3: Intercept で編集された場合の編集前データ
        conn.execute_batch(
            "BEGIN;
             ALTER TABLE flows ADD COLUMN edited INTEGER NOT NULL DEFAULT 0;
             ALTER TABLE flows ADD COLUMN orig_req_head BLOB;
             ALTER TABLE flows ADD COLUMN orig_req_body BLOB REFERENCES bodies(hash);
             ALTER TABLE flows ADD COLUMN orig_res_head BLOB;
             ALTER TABLE flows ADD COLUMN orig_res_body BLOB REFERENCES bodies(hash);
             PRAGMA user_version = 3;
             COMMIT;",
        )?;
    }
    if version < 4 {
        // v4: Body の切り詰め、WebSocket のメッセージ、パッシブチェックの検出。
        // 既存のフローは meta.passive_upto = 0 から writer が順に調べる。
        conn.execute_batch(
            "BEGIN;
             ALTER TABLE flows ADD COLUMN truncated INTEGER NOT NULL DEFAULT 0;
             CREATE TABLE IF NOT EXISTS ws_messages(
                 id          INTEGER PRIMARY KEY,
                 flow_id     INTEGER NOT NULL,
                 at_us       INTEGER NOT NULL,
                 from_client INTEGER NOT NULL,
                 opcode      INTEGER NOT NULL,
                 len         INTEGER NOT NULL,   -- 実際の長さ（data は切り詰めることがある）
                 data        BLOB
             );
             CREATE INDEX IF NOT EXISTS ws_flow ON ws_messages(flow_id, id);
             CREATE TABLE IF NOT EXISTS findings(
                 id       INTEGER PRIMARY KEY,
                 flow_id  INTEGER NOT NULL,
                 check_id TEXT NOT NULL,
                 severity INTEGER NOT NULL,
                 detail   TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS findings_flow ON findings(flow_id);
             CREATE INDEX IF NOT EXISTS findings_check ON findings(check_id, flow_id);
             CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value INTEGER NOT NULL) WITHOUT ROWID;
             PRAGMA user_version = 4;
             COMMIT;",
        )?;
    }
    Ok(())
}

/// meta テーブルの整数値（無ければ 0）。
pub fn meta_get(conn: &Connection, key: &str) -> Result<i64> {
    use rusqlite::OptionalExtension;
    Ok(conn
        .prepare_cached("SELECT value FROM meta WHERE key = ?1")?
        .query_row([key], |r| r.get(0))
        .optional()?
        .unwrap_or(0))
}

pub fn meta_set(conn: &Connection, key: &str, value: i64) -> Result<()> {
    conn.prepare_cached("INSERT INTO meta(key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = ?2")?
        .execute(params![key, value])?;
    Ok(())
}

fn create_v1(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "BEGIN;
         CREATE TABLE IF NOT EXISTS bodies(
             hash     BLOB PRIMARY KEY,   -- blake3 (32 bytes)
             size     INTEGER NOT NULL,   -- 非圧縮サイズ
             location INTEGER NOT NULL,   -- 0: inline(data 列), 1: bodies/ 配下のファイル(zstd)
             data     BLOB
         ) WITHOUT ROWID;
         CREATE TABLE IF NOT EXISTS flows(
             id           INTEGER PRIMARY KEY,
             source       INTEGER NOT NULL,
             started_at   INTEGER NOT NULL,
             duration_us  INTEGER NOT NULL,
             scheme       TEXT NOT NULL,
             host         TEXT NOT NULL,
             port         INTEGER NOT NULL,
             method       TEXT NOT NULL,
             target       TEXT NOT NULL,
             status       INTEGER,
             req_head     BLOB NOT NULL,
             req_body     BLOB REFERENCES bodies(hash),
             req_body_len INTEGER NOT NULL,
             res_head     BLOB,
             res_body     BLOB REFERENCES bodies(hash),
             res_body_len INTEGER NOT NULL,
             error        TEXT,
             note         TEXT
         );
         CREATE INDEX IF NOT EXISTS flows_host ON flows(host);
         PRAGMA user_version = 1;
         COMMIT;",
    )?;
    Ok(())
}

/// v2: フィルタ用に kind（FlowKind）と content_type を追加し、既存行を埋める。
fn migrate_v2(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "BEGIN;
         ALTER TABLE flows ADD COLUMN kind INTEGER NOT NULL DEFAULT 7;
         ALTER TABLE flows ADD COLUMN content_type TEXT;",
    )?;
    let result = (|| -> Result<()> {
        let mut select = conn.prepare("SELECT id, target, req_head, res_head FROM flows")?;
        let mut update = conn.prepare("UPDATE flows SET kind = ?2, content_type = ?3 WHERE id = ?1")?;
        let mut rows = select.query([])?;
        while let Some(r) = rows.next()? {
            let (id, target, req_head, res_head): (i64, String, Vec<u8>, Option<Vec<u8>>) =
                (r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?);
            let ct = content_type(res_head.as_deref());
            let kind = classify(&target, &req_head, ct.as_deref());
            update.execute(params![id, kind as u8, ct])?;
        }
        conn.execute_batch("CREATE INDEX IF NOT EXISTS flows_kind ON flows(kind); PRAGMA user_version = 2;")?;
        Ok(())
    })();
    match result {
        Ok(()) => conn.execute_batch("COMMIT;")?,
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK;");
            return Err(e);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrates_v1_rows() {
        let conn = Connection::open_in_memory().unwrap();
        create_v1(&conn).unwrap();
        conn.execute(
            "INSERT INTO flows(source, started_at, duration_us, scheme, host, port, method, target, status,
                               req_head, req_body_len, res_head, res_body_len)
             VALUES (0, 0, 0, 'https', 'a', 443, 'GET', '/logo', 200, ?1, 0, ?2, 0)",
            params![b"GET /logo HTTP/1.1\r\n\r\n".to_vec(), b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n".to_vec()],
        )
        .unwrap();
        migrate(&conn).unwrap();
        let (kind, ct, ver): (i64, String, i64) = conn
            .query_row("SELECT kind, content_type, (SELECT user_version FROM pragma_user_version) FROM flows", [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .unwrap();
        assert_eq!((kind, ct.as_str(), ver), (crate::FlowKind::Image as i64, "image/png", SCHEMA_VERSION));
    }
}
