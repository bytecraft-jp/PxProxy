use crate::classify::FlowKind;

/// フローの発生元。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FlowSource {
    Proxy = 0,
    Repeater = 1,
    Intruder = 2,
}

impl FlowSource {
    pub fn from_i64(v: i64) -> Self {
        match v {
            1 => Self::Repeater,
            2 => Self::Intruder,
            _ => Self::Proxy,
        }
    }
}

/// writer に渡す 1 往復分のデータ。ヘッダは送受信したバイト列そのまま、
/// Body は Transfer-Encoding を外したもの（Content-Encoding はそのまま）。
#[derive(Debug, Clone)]
pub struct NewFlow {
    pub source: FlowSource,
    /// UNIX epoch からのマイクロ秒
    pub started_at_us: i64,
    pub duration_us: i64,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub method: String,
    pub target: String,
    pub status: Option<u16>,
    pub req_head: Vec<u8>,
    pub req_body: Vec<u8>,
    pub res_head: Option<Vec<u8>>,
    pub res_body: Vec<u8>,
    pub error: Option<String>,
    /// Intercept で編集された場合の編集前リクエスト (head, body)
    pub orig_request: Option<(Vec<u8>, Vec<u8>)>,
    /// Intercept で編集された場合の編集前レスポンス (head, body)
    pub orig_response: Option<(Vec<u8>, Vec<u8>)>,
}

/// `FlowSummary::edited` のビット。
pub const EDITED_REQUEST: u8 = 1;
pub const EDITED_RESPONSE: u8 = 2;

/// 一覧表示用の軽量な行。
#[derive(Debug, Clone)]
pub struct FlowSummary {
    pub id: i64,
    pub source: FlowSource,
    pub started_at_us: i64,
    pub duration_us: i64,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub method: String,
    pub target: String,
    pub status: Option<u16>,
    pub req_body_len: i64,
    pub res_body_len: i64,
    pub error: Option<String>,
    pub kind: FlowKind,
    pub content_type: Option<String>,
    /// EDITED_REQUEST / EDITED_RESPONSE のビット和
    pub edited: u8,
    /// 利用者が付けたメモ
    pub note: Option<String>,
}

#[derive(Debug, Clone)]
pub struct FlowDetail {
    pub summary: FlowSummary,
    pub req_head: Vec<u8>,
    pub req_body: Vec<u8>,
    pub res_head: Option<Vec<u8>>,
    pub res_body: Vec<u8>,
    pub orig_request: Option<(Vec<u8>, Vec<u8>)>,
    pub orig_response: Option<(Vec<u8>, Vec<u8>)>,
}
