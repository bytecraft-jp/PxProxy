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
mod error;
mod model;
mod project;
mod reader;
mod schema;
mod writer;

pub use body::INLINE_THRESHOLD;
pub use classify::FlowKind;
pub use error::{Result, StoreError};
pub use classify::{classify, content_type};
pub use model::{EDITED_REQUEST, EDITED_RESPONSE, FlowDetail, FlowSource, FlowSummary, NewFlow};
pub use project::{Manifest, Progress, Project};
pub use reader::{ALL_KINDS, ALL_STATUS, Filter, Reader, StatusClass};
pub use writer::{CommitHook, FlowSink};
