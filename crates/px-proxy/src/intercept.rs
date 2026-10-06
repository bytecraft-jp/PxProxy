//! Intercept: 条件に一致したリクエスト/レスポンスをその接続タスク内で待たせ、
//! UI の判断（Forward / 編集して Forward / Drop）を受けて再開する。
//! 他の接続は止めない。OFF のときはフラグを 1 回読むだけ。

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use parking_lot::{Mutex, RwLock};
use tokio::sync::oneshot;

use crate::rules::{CompiledRules, ProjectSettings};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Request,
    Response,
}

/// 停止中のメッセージ。Body は Transfer-Encoding を外したもの。
#[derive(Debug)]
pub struct Held {
    pub id: u64,
    pub direction: Direction,
    pub scheme: &'static str,
    pub host: String,
    pub port: u16,
    pub method: String,
    pub target: String,
    pub status: Option<u16>,
    pub head: Vec<u8>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// `edited` が None なら無変更。`intercept_response` はリクエスト時のみ有効。
    Forward { edited: Option<(Vec<u8>, Vec<u8>)>, intercept_response: bool },
    Drop,
}

impl Decision {
    pub const FORWARD: Decision = Decision::Forward { edited: None, intercept_response: false };
}

type Notify = Arc<dyn Fn() + Send + Sync>;

pub struct Interceptor {
    enabled: AtomicBool,
    rules: RwLock<Arc<CompiledRules>>,
    queue: Mutex<VecDeque<(Arc<Held>, oneshot::Sender<Decision>)>>,
    next_id: AtomicU64,
    version: AtomicU64,
    notify: RwLock<Option<Notify>>,
}

impl Default for Interceptor {
    fn default() -> Self {
        Self {
            enabled: AtomicBool::new(false),
            rules: RwLock::new(Arc::new(CompiledRules::compile(ProjectSettings::default()).0)),
            queue: Mutex::new(VecDeque::new()),
            next_id: AtomicU64::new(1),
            version: AtomicU64::new(0),
            notify: RwLock::new(None),
        }
    }
}

impl Interceptor {
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    /// OFF にすると停止中のものは全て無変更で Forward する。
    pub fn set_enabled(&self, on: bool) {
        self.enabled.store(on, Ordering::Release);
        if !on {
            self.forward_all();
        }
        self.bump();
    }

    /// 設定を反映する。正規表現が不正ならそのエラーを返す（その条件だけ無効）。
    pub fn set_settings(&self, settings: ProjectSettings) -> Option<String> {
        let (compiled, err) = CompiledRules::compile(settings);
        *self.rules.write() = Arc::new(compiled);
        err
    }

    pub fn rules(&self) -> Arc<CompiledRules> {
        self.rules.read().clone()
    }

    /// キューが変化したとき（停止・解除）に呼ばれる。UI の再描画用。
    pub fn set_notify(&self, f: Option<Notify>) {
        *self.notify.write() = f;
    }

    /// キューの変化を検出するためのカウンタ。
    pub fn version(&self) -> u64 {
        self.version.load(Ordering::Acquire)
    }

    /// 停止中の一覧（古い順）。接続が切れて待ち手がいないものは取り除く。
    pub fn pending(&self) -> Vec<Arc<Held>> {
        let mut q = self.queue.lock();
        let before = q.len();
        q.retain(|(_, tx)| !tx.is_closed());
        if q.len() != before {
            self.version.fetch_add(1, Ordering::AcqRel);
        }
        q.iter().map(|(h, _)| h.clone()).collect()
    }

    pub fn pending_count(&self) -> usize {
        self.queue.lock().len()
    }

    /// 判断を返す。既に解除済み/切断済みなら false。
    pub fn resolve(&self, id: u64, decision: Decision) -> bool {
        let entry = {
            let mut q = self.queue.lock();
            q.iter().position(|(h, _)| h.id == id).and_then(|i| q.remove(i))
        };
        self.bump();
        match entry {
            Some((_, tx)) => tx.send(decision).is_ok(),
            None => false,
        }
    }

    pub fn forward_all(&self) {
        let drained: Vec<_> = self.queue.lock().drain(..).collect();
        for (_, tx) in drained {
            let _ = tx.send(Decision::FORWARD);
        }
        self.bump();
    }

    /// 呼び出し元の接続タスクを、判断が来るまで待たせる。
    pub(crate) async fn hold(&self, mut held: Held) -> Decision {
        held.id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.queue.lock().push_back((Arc::new(held), tx));
        self.bump();
        // 送信側が捨てられた（キュー破棄など）場合は無変更で通す
        rx.await.unwrap_or(Decision::FORWARD)
    }

    fn bump(&self) {
        self.version.fetch_add(1, Ordering::AcqRel);
        if let Some(n) = self.notify.read().as_ref() {
            n();
        }
    }
}
