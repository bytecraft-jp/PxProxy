use std::path::PathBuf;

use rusqlite::functions::FunctionFlags;
use rusqlite::{Connection, OpenFlags, OptionalExtension, Row, params};

/// 診断対象の判定に使う SQL 関数名
const SCOPE_FN: &str = "px_in_scope";

use crate::classify::FlowKind;
use crate::model::{FlowDetail, FlowSource, FlowSummary};
use crate::{Result, body, schema};

/// ステータスの大分類。値はビット位置。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StatusClass {
    /// 1xx / 2xx
    Ok = 0,
    Redirect = 1,
    ClientError = 2,
    ServerError = 3,
    /// レスポンス無し（接続エラー等）
    NoResponse = 4,
}

impl StatusClass {
    pub const ALL: [StatusClass; 5] =
        [Self::Ok, Self::Redirect, Self::ClientError, Self::ServerError, Self::NoResponse];

    pub fn bit(self) -> u32 {
        1 << self as u8
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Ok => "2xx",
            Self::Redirect => "3xx",
            Self::ClientError => "4xx",
            Self::ServerError => "5xx",
            Self::NoResponse => "エラー",
        }
    }

    fn sql(self) -> &'static str {
        match self {
            Self::Ok => "status < 300",
            Self::Redirect => "(status >= 300 AND status < 400)",
            Self::ClientError => "(status >= 400 AND status < 500)",
            Self::ServerError => "status >= 500",
            Self::NoResponse => "status IS NULL",
        }
    }
}

pub const ALL_KINDS: u32 = (1 << FlowKind::ALL.len()) - 1;
pub const ALL_STATUS: u32 = (1 << StatusClass::ALL.len()) - 1;

/// 一覧の絞り込み条件。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Filter {
    /// host / target の部分一致（大文字小文字無視）
    pub text: String,
    /// 表示する FlowKind のビットマスク
    pub kinds: u32,
    /// 表示する StatusClass のビットマスク
    pub status: u32,
    /// 診断対象（`Reader::set_scope` で登録した判定）に含まれるものだけ
    pub in_scope_only: bool,
}

impl Default for Filter {
    fn default() -> Self {
        Self { text: String::new(), kinds: ALL_KINDS, status: ALL_STATUS, in_scope_only: false }
    }
}

impl Filter {
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }

    /// WHERE 句（id > ?1 に続く条件）と LIKE パラメータ。マスク値は整数リテラルで埋め込む。
    fn where_clause(&self) -> (String, Option<String>) {
        let mut sql = String::new();
        if self.kinds & ALL_KINDS != ALL_KINDS {
            let kinds: Vec<String> =
                FlowKind::ALL.iter().filter(|k| self.kinds & k.bit() != 0).map(|k| (*k as u8).to_string()).collect();
            sql.push_str(&format!(" AND kind IN ({})", kinds.join(",")));
        }
        if self.status & ALL_STATUS != ALL_STATUS {
            let parts: Vec<&str> =
                StatusClass::ALL.iter().filter(|s| self.status & s.bit() != 0).map(|s| s.sql()).collect();
            if parts.is_empty() {
                sql.push_str(" AND 0");
            } else {
                sql.push_str(&format!(" AND ({})", parts.join(" OR ")));
            }
        }
        if self.in_scope_only {
            sql.push_str(&format!(" AND {SCOPE_FN}(host, target)"));
        }
        let like = (!self.text.is_empty()).then(|| {
            sql.push_str(" AND (host LIKE ?2 ESCAPE '\\' OR target LIKE ?2 ESCAPE '\\')");
            like_pattern(&self.text)
        });
        (sql, like)
    }
}

/// UI 用の読み取り専用接続。WAL なので writer と並行して読める。
pub struct Reader {
    conn: Connection,
    bodies_dir: PathBuf,
}

const SUMMARY_COLS: &str = "id, source, started_at, duration_us, scheme, host, port, method, target,
                            status, req_body_len, res_body_len, error, kind, content_type, edited, note";

fn summary_from_row(r: &Row<'_>) -> rusqlite::Result<FlowSummary> {
    Ok(FlowSummary {
        id: r.get(0)?,
        source: FlowSource::from_i64(r.get(1)?),
        started_at_us: r.get(2)?,
        duration_us: r.get(3)?,
        scheme: r.get(4)?,
        host: r.get(5)?,
        port: r.get(6)?,
        method: r.get(7)?,
        target: r.get(8)?,
        status: r.get(9)?,
        req_body_len: r.get(10)?,
        res_body_len: r.get(11)?,
        error: r.get(12)?,
        kind: FlowKind::from_i64(r.get(13)?),
        content_type: r.get(14)?,
        edited: r.get(15)?,
        note: r.get(16)?,
    })
}

fn like_pattern(text: &str) -> String {
    let escaped = text.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_");
    format!("%{escaped}%")
}

impl Reader {
    pub(crate) fn open(db_path: &std::path::Path, bodies_dir: PathBuf) -> Result<Self> {
        let conn = Connection::open_with_flags(
            db_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        schema::tune(&conn, false)?;
        let reader = Self { conn, bodies_dir };
        reader.set_scope(|_, _| true)?;
        Ok(reader)
    }

    /// 診断対象の判定 (host, target) -> bool を登録する。`Filter::in_scope_only` で使われる。
    /// 判定はアプリ側（ワイルドカード等）にあるので、SQL 関数として差し込む。
    pub fn set_scope(&self, in_scope: impl Fn(&str, &str) -> bool + Send + 'static) -> Result<()> {
        // 古い関数を参照するキャッシュ済みステートメントを捨ててから差し替える
        self.conn.flush_prepared_statement_cache();
        self.conn.create_scalar_function(
            SCOPE_FN,
            2,
            FunctionFlags::SQLITE_UTF8,
            move |ctx| {
                let host: String = ctx.get(0)?;
                let target: String = ctx.get(1)?;
                Ok(in_scope(&host, &target))
            },
        )?;
        Ok(())
    }

    /// `after` より大きい ID を昇順で返す（差分取得用）。
    pub fn ids_after(&self, after: i64, filter: &Filter) -> Result<Vec<i64>> {
        let (cond, like) = filter.where_clause();
        let mut st = self.conn.prepare_cached(&format!("SELECT id FROM flows WHERE id > ?1{cond} ORDER BY id"))?;
        let rows = match &like {
            Some(p) => st.query_map(params![after, p], |r| r.get(0))?.collect::<rusqlite::Result<Vec<i64>>>(),
            None => st.query_map([after], |r| r.get(0))?.collect(),
        };
        Ok(rows?)
    }

    pub fn summary(&self, id: i64) -> Result<Option<FlowSummary>> {
        let sql = format!("SELECT {SUMMARY_COLS} FROM flows WHERE id = ?1");
        Ok(self.conn.prepare_cached(&sql)?.query_row([id], summary_from_row).optional()?)
    }

    pub fn detail(&self, id: i64) -> Result<Option<FlowDetail>> {
        let Some(summary) = self.summary(id)? else {
            return Ok(None);
        };
        type Blob = Option<Vec<u8>>;
        let row: (Vec<u8>, Blob, Blob, Blob, Blob, Blob, Blob, Blob) = self
            .conn
            .prepare_cached(
                "SELECT req_head, req_body, res_head, res_body, orig_req_head, orig_req_body, orig_res_head, orig_res_body
                 FROM flows WHERE id = ?1",
            )?
            .query_row([id], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?))
            })?;
        let (req_head, req_hash, res_head, res_hash, oq_head, oq_hash, os_head, os_hash) = row;
        let orig = |head: Blob, hash: Blob| -> Result<Option<(Vec<u8>, Vec<u8>)>> {
            match head {
                Some(h) => Ok(Some((h, body::get(&self.conn, &self.bodies_dir, hash)?))),
                None => Ok(None),
            }
        };
        Ok(Some(FlowDetail {
            summary,
            req_head,
            req_body: body::get(&self.conn, &self.bodies_dir, req_hash)?,
            res_head,
            res_body: body::get(&self.conn, &self.bodies_dir, res_hash)?,
            orig_request: orig(oq_head, oq_hash)?,
            orig_response: orig(os_head, os_hash)?,
        }))
    }

    pub fn count(&self) -> Result<i64> {
        Ok(self.conn.query_row("SELECT count(*) FROM flows", [], |r| r.get(0))?)
    }

    /// 一貫したスナップショットを別ファイルに書き出す（エクスポート用）。
    pub(crate) fn vacuum_into(&self, dest: &std::path::Path) -> Result<()> {
        self.conn.execute("VACUUM INTO ?1", [dest.to_string_lossy()])?;
        Ok(())
    }
}
