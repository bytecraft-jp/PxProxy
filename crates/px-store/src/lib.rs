//! 案件（プロジェクト）単位の永続化層。
//!
//! 1 案件 = 1 ディレクトリ:
//! ```text
//! <name>.pxproj/
//! ├─ project.toml      フォーマットバージョン等
//! ├─ project.sqlite    メタデータ (WAL)
//! └─ bodies/ab/cd/<blake3>.zst   大きい Body (zstd 圧縮, コンテンツアドレス)
//! ```
//! パスはすべて相対で扱うので、ディレクトリごとコピー/zip すれば移動できる。

mod body;
mod classify;
mod decode;
mod error;
mod model;
pub mod passive;
mod project;
mod reader;
mod schema;
mod writer;

pub use body::INLINE_THRESHOLD;
pub use classify::FlowKind;
pub use error::{Result, StoreError};
pub use classify::{classify, content_type};
pub use decode::decode_content;
pub use model::{
    EDITED_REQUEST, EDITED_RESPONSE, Finding, FindingGroup, FlowDetail, FlowSource, FlowSummary, NewFlow,
    TRUNCATED_REQUEST, TRUNCATED_RESPONSE, WsMessage,
};
pub use passive::Severity;
pub use project::{Manifest, Progress, Project};
pub use reader::{ALL_KINDS, ALL_STATUS, Filter, Reader, SiteFilter, SiteRow, StatusClass};
pub use writer::{CommitHook, FlowSink};
