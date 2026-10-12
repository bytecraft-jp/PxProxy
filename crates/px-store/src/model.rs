use crate::classify::FlowKind;
use crate::passive::Severity;

/// フローの発生元。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FlowSource {
    Proxy = 0,
    Repeater = 1,
    Intruder = 2,
    /// TLS パススルー（復号せずに中継した接続）
    Tunnel = 3,
    /// ダミーサーバが応答した通信
    Mock = 4,
}

impl FlowSource {
    pub fn from_i64(v: i64) -> Self {
        match v {
            1 => Self::Repeater,
            2 => Self::Intruder,
            3 => Self::Tunnel,
            4 => Self::Mock,
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
    /// Body が大きく先頭だけ記録した場合の実際の大きさ（`req_body` は先頭部分）
    pub req_body_total: Option<u64>,
    /// 同上（レスポンス）
    pub res_body_total: Option<u64>,
}

/// `FlowSummary::truncated` のビット（Body の先頭だけを記録した）。
pub const TRUNCATED_REQUEST: u8 = 1;
pub const TRUNCATED_RESPONSE: u8 = 2;

/// `FlowSummary::edited` のビット。
pub const EDITED_REQUEST: u8 = 1;
pub const EDITED_RESPONSE: u8 = 2;

/// 利用者が行に付ける色。値は DB に保存するので変更しないこと。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Highlight {
    Red = 1,
    Orange = 2,
    Yellow = 3,
    Green = 4,
    Cyan = 5,
    Blue = 6,
    Purple = 7,
    Gray = 8,
}

impl Highlight {
    pub const ALL: [Highlight; 8] =
        [Self::Red, Self::Orange, Self::Yellow, Self::Green, Self::Cyan, Self::Blue, Self::Purple, Self::Gray];

    pub fn from_i64(v: i64) -> Option<Self> {
        Self::ALL.into_iter().find(|h| *h as i64 == v)
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Red => "赤",
            Self::Orange => "橙",
            Self::Yellow => "黄",
            Self::Green => "緑",
            Self::Cyan => "水色",
            Self::Blue => "青",
            Self::Purple => "紫",
            Self::Gray => "灰",
        }
    }

    /// `Filter::colors` のビット（0 ビット目は `NO_COLOR`）
    pub fn bit(self) -> u32 {
        1 << self as u8
    }
}

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
    /// TRUNCATED_REQUEST / TRUNCATED_RESPONSE のビット和
    pub truncated: u8,
    /// パッシブチェックの検出のうち最も重いもの
    pub max_severity: Option<Severity>,
    /// 利用者が付けた色
    pub color: Option<Highlight>,
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

/// WebSocket のメッセージ 1 件（分割されたフレームはまとめたもの）。
#[derive(Debug, Clone)]
pub struct WsMessage {
    /// 記録時は無視される（DB の ID）
    pub id: i64,
    /// 101 Switching Protocols を記録したフローの ID
    pub flow_id: i64,
    /// UNIX epoch からのマイクロ秒
    pub at_us: i64,
    pub from_client: bool,
    /// 1: テキスト, 2: バイナリ, 8: Close, 9: Ping, 10: Pong
    pub opcode: u8,
    /// 実際の長さ（`data` は上限で切り詰めることがある）
    pub len: u64,
    /// マスクを外し、permessage-deflate を展開したペイロード
    pub data: Vec<u8>,
}

impl WsMessage {
    pub const TEXT: u8 = 1;
    pub const BINARY: u8 = 2;
    pub const CLOSE: u8 = 8;
    pub const PING: u8 = 9;
    pub const PONG: u8 = 10;

    pub fn opcode_label(&self) -> &'static str {
        match self.opcode {
            Self::TEXT => "Text",
            Self::BINARY => "Binary",
            Self::CLOSE => "Close",
            Self::PING => "Ping",
            Self::PONG => "Pong",
            _ => "?",
        }
    }
}

/// パッシブチェックの検出を、チェックとホストでまとめたもの。
#[derive(Debug, Clone)]
pub struct FindingGroup {
    pub check: String,
    pub severity: Severity,
    pub host: String,
    /// 検出したフローの数
    pub flows: i64,
}

/// 1 フローの検出。
#[derive(Debug, Clone)]
pub struct Finding {
    pub flow_id: i64,
    pub check: String,
    pub severity: Severity,
    pub detail: String,
}
