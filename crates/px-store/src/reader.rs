use std::path::PathBuf;
use std::time::Instant;

use regex::bytes::{Regex as BytesRegex, RegexBuilder as BytesRegexBuilder};
use rusqlite::functions::FunctionFlags;
use rusqlite::types::Value;
use rusqlite::{Connection, OpenFlags, OptionalExtension, Row, params, params_from_iter};

/// 診断対象の判定に使う SQL 関数名
const SCOPE_FN: &str = "px_in_scope";
/// 正規表現の照合に使う SQL 関数名 `px_regexp(パターン, 値)`（大文字小文字無視）
const REGEXP_FN: &str = "px_regexp";
/// 本文検索で 1 回に読み出す行数
const CONTENT_BATCH: usize = 256;

use crate::classify::FlowKind;
use crate::decode::{decode_content, header};
use crate::model::{Finding, FindingGroup, FlowDetail, FlowSource, FlowSummary, Highlight, WsMessage};
use crate::passive::Severity;
use crate::{Result, StoreError, body, schema};

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

/// メソッドの分類。値はビット位置。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MethodClass {
    Get = 0,
    Post = 1,
    Put = 2,
    Patch = 3,
    Delete = 4,
    Options = 5,
    Head = 6,
    /// 上記以外（CONNECT など）
    Other = 7,
}

impl MethodClass {
    pub const ALL: [MethodClass; 8] =
        [Self::Get, Self::Post, Self::Put, Self::Patch, Self::Delete, Self::Options, Self::Head, Self::Other];
    /// `Other` 以外の名前（値の順）
    const NAMED: [&str; 7] = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"];

    pub fn bit(self) -> u32 {
        1 << self as u8
    }

    pub fn label(self) -> &'static str {
        Self::NAMED.get(self as usize).copied().unwrap_or("その他")
    }

    fn sql(self) -> String {
        match self {
            Self::Other => {
                let names: Vec<String> = Self::NAMED.iter().map(|n| format!("'{n}'")).collect();
                format!("method NOT IN ({})", names.join(","))
            }
            m => format!("method = '{}'", m.label()),
        }
    }
}

pub const ALL_KINDS: u32 = (1 << FlowKind::ALL.len()) - 1;
pub const ALL_STATUS: u32 = (1 << StatusClass::ALL.len()) - 1;
pub const ALL_METHODS: u32 = (1 << MethodClass::ALL.len()) - 1;
/// `Filter::colors` の「色なし」のビット
pub const NO_COLOR: u32 = 1;
pub const ALL_COLORS: u32 = (1 << (Highlight::ALL.len() + 1)) - 1;

/// 本文検索の対象。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SearchIn {
    #[default]
    Both,
    Request,
    Response,
}

/// ヘッダと Body（Content-Encoding を展開したもの）の検索条件。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ContentQuery {
    pub text: String,
    /// `text` を正規表現として扱う
    pub regex: bool,
    /// 大文字小文字を区別する
    pub case_sensitive: bool,
    pub target: SearchIn,
}

impl ContentQuery {
    pub fn is_active(&self) -> bool {
        !self.text.is_empty()
    }

    fn compile(&self) -> std::result::Result<BytesRegex, regex::Error> {
        let pattern = if self.regex { self.text.clone() } else { regex::escape(&self.text) };
        BytesRegexBuilder::new(&pattern).case_insensitive(!self.case_sensitive).build()
    }
}

/// 一覧の絞り込み条件。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Filter {
    /// host / target の部分一致（大文字小文字無視）
    pub text: String,
    /// `text` を正規表現として host / target に照合する（大文字小文字無視）
    pub text_regex: bool,
    /// 表示する FlowKind のビットマスク
    pub kinds: u32,
    /// 表示する StatusClass のビットマスク
    pub status: u32,
    /// 表示する MethodClass のビットマスク
    pub methods: u32,
    /// 表示する色のビットマスク（`NO_COLOR` と `Highlight::bit`）
    pub colors: u32,
    /// メモのある行だけ
    pub noted_only: bool,
    /// Response の Body の長さ（バイト、両端を含む）
    pub length: (Option<u64>, Option<u64>),
    /// 所要時間（ミリ秒、両端を含む）
    pub duration_ms: (Option<u64>, Option<u64>),
    /// ヘッダ・Body の検索。SQL では調べられないので `Reader::scan_after` が少しずつ調べる
    pub content: ContentQuery,
    /// 診断対象（`Reader::set_scope` で登録した判定）に含まれるものだけ
    pub in_scope_only: bool,
    /// サイトマップで選んだホスト・パス配下だけ
    pub site: Option<SiteFilter>,
}

/// サイトマップのノード（ホスト、またはその下のパス）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SiteFilter {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    /// `/a/b` ならそのパスと `/a/b/…`・`/a/b?…`。空ならホスト全体
    pub path: String,
}

impl Default for Filter {
    fn default() -> Self {
        Self {
            text: String::new(),
            text_regex: false,
            kinds: ALL_KINDS,
            status: ALL_STATUS,
            methods: ALL_METHODS,
            colors: ALL_COLORS,
            noted_only: false,
            length: (None, None),
            duration_ms: (None, None),
            content: ContentQuery::default(),
            in_scope_only: false,
            site: None,
        }
    }
}

impl Filter {
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }

    /// 正規表現の誤りなど、この条件では検索できない理由。
    pub fn error(&self) -> Option<String> {
        if self.text_regex
            && !self.text.is_empty()
            && let Err(e) = regex::RegexBuilder::new(&self.text).case_insensitive(true).build()
        {
            return Some(format!("ホスト / パスの正規表現: {e}"));
        }
        if self.content.is_active()
            && let Err(e) = self.content.compile()
        {
            return Some(format!("本文検索の正規表現: {e}"));
        }
        None
    }

    /// WHERE 句（id > ?1 に続く条件）と ?2 以降のパラメータ。マスク値は整数リテラルで埋め込む。
    /// `content` は含まない（`Reader::scan_after` が行ごとに調べる）。
    fn where_clause(&self) -> (String, Vec<Value>) {
        let mut sql = String::new();
        let mut params: Vec<Value> = Vec::new();
        let mut param = |v: Value| {
            params.push(v);
            format!("?{}", params.len() + 1)
        };
        if self.kinds & ALL_KINDS != ALL_KINDS {
            let kinds: Vec<String> =
                FlowKind::ALL.iter().filter(|k| self.kinds & k.bit() != 0).map(|k| (*k as u8).to_string()).collect();
            sql.push_str(&format!(" AND kind IN ({})", kinds.join(",")));
        }
        if self.status & ALL_STATUS != ALL_STATUS {
            let parts: Vec<&str> =
                StatusClass::ALL.iter().filter(|s| self.status & s.bit() != 0).map(|s| s.sql()).collect();
            push_any(&mut sql, &parts);
        }
        if self.methods & ALL_METHODS != ALL_METHODS {
            let parts: Vec<String> =
                MethodClass::ALL.iter().filter(|m| self.methods & m.bit() != 0).map(|m| m.sql()).collect();
            push_any(&mut sql, &parts);
        }
        if self.colors & ALL_COLORS != ALL_COLORS {
            let mut parts = Vec::new();
            if self.colors & NO_COLOR != 0 {
                parts.push("color IS NULL".to_string());
            }
            let colors: Vec<String> =
                Highlight::ALL.iter().filter(|h| self.colors & h.bit() != 0).map(|h| (*h as u8).to_string()).collect();
            if !colors.is_empty() {
                parts.push(format!("color IN ({})", colors.join(",")));
            }
            push_any(&mut sql, &parts);
        }
        if self.noted_only {
            sql.push_str(" AND note IS NOT NULL AND note != ''");
        }
        // 所要時間は ms の整数で表示しているので、上限は「その ms の終わり」まで含める
        for (column, (min, max), unit) in [("res_body_len", self.length, 1), ("duration_us", self.duration_ms, 1000)] {
            let clamp = |v: u64| v.min(i64::MAX as u64);
            if let Some(min) = min {
                sql.push_str(&format!(" AND {column} >= {}", clamp(min.saturating_mul(unit))));
            }
            if let Some(max) = max {
                sql.push_str(&format!(" AND {column} < {}", clamp(max.saturating_add(1).saturating_mul(unit))));
            }
        }
        if self.in_scope_only {
            sql.push_str(&format!(" AND {SCOPE_FN}(host, target)"));
        }
        if !self.text.is_empty() {
            if self.text_regex {
                let p = param(Value::Text(self.text.clone()));
                sql.push_str(&format!(" AND ({REGEXP_FN}({p}, host) OR {REGEXP_FN}({p}, target))"));
            } else {
                let p = param(Value::Text(like_pattern(&self.text)));
                sql.push_str(&format!(" AND (host LIKE {p} ESCAPE '\\' OR target LIKE {p} ESCAPE '\\')"));
            }
        }
        if let Some(site) = &self.site {
            let (scheme, host, port) = (
                param(Value::Text(site.scheme.clone())),
                param(Value::Text(site.host.clone())),
                param(Value::Integer(site.port.into())),
            );
            sql.push_str(&format!(" AND scheme = {scheme} AND host = {host} AND port = {port}"));
            if !site.path.is_empty() {
                let path = site.path.trim_end_matches('/');
                let exact = param(Value::Text(path.to_string()));
                let dir = param(Value::Text(format!("{path}/")));
                let query = param(Value::Text(format!("{path}?")));
                // substr は文字単位なので、文字数で切り出して比べる
                let n = path.chars().count() + 1;
                sql.push_str(&format!(" AND (target = {exact} OR substr(target, 1, {n}) IN ({dir}, {query}))"));
            }
        }
        (sql, params)
    }
}

/// `AND (a OR b …)`。どれも無ければ何も一致しない。
fn push_any(sql: &mut String, parts: &[impl AsRef<str>]) {
    if parts.is_empty() {
        sql.push_str(" AND 0");
    } else {
        let parts: Vec<&str> = parts.iter().map(AsRef::as_ref).collect();
        sql.push_str(&format!(" AND ({})", parts.join(" OR ")));
    }
}

/// `Reader::scan_after` の結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scan {
    /// 条件に一致した ID（昇順）
    pub ids: Vec<i64>,
    /// この ID まで調べた。次はこれより後から調べる
    pub upto: i64,
    /// 記録済みのものは調べ終えた。false なら時間切れで続きがある
    pub complete: bool,
}

/// サイトマップ用の 1 行: (id, scheme, host, port, target)
pub type SiteRow = (i64, String, String, u16, String);

/// UI 用の読み取り専用接続。WAL なので writer と並行して読める。
pub struct Reader {
    conn: Connection,
    bodies_dir: PathBuf,
}

const SUMMARY_COLS: &str = "id, source, started_at, duration_us, scheme, host, port, method, target,
                            status, req_body_len, res_body_len, error, kind, content_type, edited, note, truncated,
                            (SELECT MAX(severity) FROM findings WHERE flow_id = flows.id), color";

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
        truncated: r.get(17)?,
        max_severity: r.get::<_, Option<i64>>(18)?.map(Severity::from_i64),
        color: r.get::<_, Option<i64>>(19)?.and_then(Highlight::from_i64),
    })
}

fn finding_from_row(r: &Row<'_>) -> rusqlite::Result<Finding> {
    Ok(Finding { flow_id: r.get(0)?, check: r.get(1)?, severity: Severity::from_i64(r.get(2)?), detail: r.get(3)? })
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
        conn.create_scalar_function(
            REGEXP_FN,
            2,
            FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
            |ctx| {
                // パターンは同じ文の中では変わらないので、コンパイルしたものを SQLite に持たせて使い回す
                type BoxError = Box<dyn std::error::Error + Send + Sync>;
                let re = ctx.get_or_create_aux(0, |v| -> std::result::Result<regex::Regex, BoxError> {
                    Ok(regex::RegexBuilder::new(v.as_str()?).case_insensitive(true).build()?)
                })?;
                Ok(ctx.get_raw(1).as_str().is_ok_and(|s| re.is_match(s)))
            },
        )?;
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

    /// `after` より大きい ID を昇順で返す（差分取得用）。本文検索があれば全件を調べ終えるまで戻らない。
    pub fn ids_after(&self, after: i64, filter: &Filter) -> Result<Vec<i64>> {
        Ok(self.scan_after(after, filter, None)?.ids)
    }

    /// `after` より大きい ID のうち条件に一致するものを昇順で返す。
    /// 本文検索（`Filter::content`）は Body を読んで展開するので、`deadline` を過ぎたらそこで切り上げ、
    /// 続きは `Scan::upto` から調べ直せるようにする（少なくとも 1 件は進める）。
    pub fn scan_after(&self, after: i64, filter: &Filter, deadline: Option<Instant>) -> Result<Scan> {
        if let Some(e) = filter.error() {
            return Err(StoreError::Invalid(e));
        }
        let (cond, values) = filter.where_clause();
        let with_after = |after: i64| {
            let mut v = values.clone();
            v.insert(0, Value::Integer(after));
            v
        };
        if !filter.content.is_active() {
            let mut st = self.conn.prepare_cached(&format!("SELECT id FROM flows WHERE id > ?1{cond} ORDER BY id"))?;
            let ids =
                st.query_map(params_from_iter(with_after(after)), |r| r.get(0))?.collect::<rusqlite::Result<Vec<i64>>>()?;
            let upto = ids.last().copied().unwrap_or(after);
            return Ok(Scan { ids, upto, complete: true });
        }

        let re = filter.content.compile().map_err(|e| StoreError::Invalid(e.to_string()))?;
        let target = filter.content.target;
        let sql = format!(
            "SELECT id, req_head, req_body, res_head, res_body FROM flows WHERE id > ?1{cond} ORDER BY id LIMIT {CONTENT_BATCH}"
        );
        type Blob = Option<Vec<u8>>;
        let mut scan = Scan { ids: Vec::new(), upto: after, complete: false };
        loop {
            let rows: Vec<(i64, Vec<u8>, Blob, Blob, Blob)> = self
                .conn
                .prepare_cached(&sql)?
                .query_map(params_from_iter(with_after(scan.upto)), |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
                })?
                .collect::<rusqlite::Result<_>>()?;
            let n = rows.len();
            for (id, req_head, req_body, res_head, res_body) in rows {
                if scan.upto > after && deadline.is_some_and(|d| Instant::now() >= d) {
                    return Ok(scan);
                }
                let hit = (target != SearchIn::Response && self.message_matches(&re, Some(&req_head), req_body))
                    || (target != SearchIn::Request && self.message_matches(&re, res_head.as_deref(), res_body));
                if hit {
                    scan.ids.push(id);
                }
                scan.upto = id;
            }
            if n < CONTENT_BATCH {
                scan.complete = true;
                return Ok(scan);
            }
        }
    }

    /// ヘッダか Body（Content-Encoding を展開したもの）が `re` に一致するか。Body が読めなければヘッダだけ見る。
    fn message_matches(&self, re: &BytesRegex, head: Option<&[u8]>, body_hash: Option<Vec<u8>>) -> bool {
        let Some(head) = head else { return false };
        if re.is_match(head) {
            return true;
        }
        if body_hash.is_none() {
            return false;
        }
        let body = match body::get(&self.conn, &self.bodies_dir, body_hash) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!("search: body unreadable: {e}");
                return false;
            }
        };
        let encoding = header(&String::from_utf8_lossy(head), "content-encoding").unwrap_or_default().to_ascii_lowercase();
        match decode_content(&encoding, &body) {
            Ok(Some(decoded)) => re.is_match(&decoded),
            _ => re.is_match(&body),
        }
    }

    /// 診断対象（`set_scope` で登録した判定）に含まれない通信の ID（昇順）。
    pub fn ids_out_of_scope(&self) -> Result<Vec<i64>> {
        let sql = format!("SELECT id FROM flows WHERE NOT {SCOPE_FN}(host, target) ORDER BY id");
        let ids = self.conn.prepare_cached(&sql)?.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<Vec<i64>>>()?;
        Ok(ids)
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

    /// サイトマップ用: `after` より大きい ID のフローの (id, scheme, host, port, target)。
    /// TLS パススルーは含めない。`in_scope_only` なら診断対象のものだけ。
    pub fn site_rows_after(&self, after: i64, in_scope_only: bool) -> Result<Vec<SiteRow>> {
        let scope = if in_scope_only { format!(" AND {SCOPE_FN}(host, target)") } else { String::new() };
        let sql = format!(
            "SELECT id, scheme, host, port, target FROM flows WHERE id > ?1 AND source != {}{scope} ORDER BY id",
            FlowSource::Tunnel as u8
        );
        let rows = self
            .conn
            .prepare_cached(&sql)?
            .query_map([after], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// フローに記録した WebSocket のメッセージ（`after` より大きい ID、古い順）。
    pub fn ws_messages(&self, flow_id: i64, after: i64) -> Result<Vec<WsMessage>> {
        let rows = self
            .conn
            .prepare_cached(
                "SELECT id, flow_id, at_us, from_client, opcode, len, data FROM ws_messages
                 WHERE flow_id = ?1 AND id > ?2 ORDER BY id",
            )?
            .query_map(params![flow_id, after], |r| {
                Ok(WsMessage {
                    id: r.get(0)?,
                    flow_id: r.get(1)?,
                    at_us: r.get(2)?,
                    from_client: r.get(3)?,
                    opcode: r.get(4)?,
                    len: r.get::<_, i64>(5)? as u64,
                    data: r.get::<_, Option<Vec<u8>>>(6)?.unwrap_or_default(),
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// パッシブチェックの検出を、チェックとホストでまとめて返す（重い順）。
    pub fn finding_groups(&self, in_scope_only: bool) -> Result<Vec<FindingGroup>> {
        let scope = if in_scope_only { format!(" WHERE {SCOPE_FN}(f.host, f.target)") } else { String::new() };
        let sql = format!(
            "SELECT d.check_id, MAX(d.severity), f.host, COUNT(DISTINCT d.flow_id) FROM findings d
             JOIN flows f ON f.id = d.flow_id{scope}
             GROUP BY d.check_id, f.host ORDER BY MAX(d.severity) DESC, d.check_id, f.host"
        );
        let rows = self
            .conn
            .prepare_cached(&sql)?
            .query_map([], |r| {
                Ok(FindingGroup {
                    check: r.get(0)?,
                    severity: Severity::from_i64(r.get(1)?),
                    host: r.get(2)?,
                    flows: r.get(3)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// あるチェック・ホストの検出（フロー ID の昇順）。
    pub fn findings_in(&self, check: &str, host: &str) -> Result<Vec<Finding>> {
        let rows = self
            .conn
            .prepare_cached(
                "SELECT d.flow_id, d.check_id, d.severity, d.detail FROM findings d JOIN flows f ON f.id = d.flow_id
                 WHERE d.check_id = ?1 AND f.host = ?2 ORDER BY d.flow_id, d.id",
            )?
            .query_map(params![check, host], finding_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// 1 フローの検出（重い順）。
    pub fn findings_of(&self, flow_id: i64) -> Result<Vec<Finding>> {
        let rows = self
            .conn
            .prepare_cached(
                "SELECT flow_id, check_id, severity, detail FROM findings WHERE flow_id = ?1 ORDER BY severity DESC, id",
            )?
            .query_map([flow_id], finding_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// パッシブチェックの進み具合 (調べ終えた数, 全体)。
    pub fn passive_progress(&self) -> Result<(i64, i64)> {
        let upto = schema::meta_get(&self.conn, "passive_upto")?;
        Ok(self.conn.query_row(
            "SELECT (SELECT COUNT(*) FROM flows WHERE id <= ?1), (SELECT COUNT(*) FROM flows)",
            [upto],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?)
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
