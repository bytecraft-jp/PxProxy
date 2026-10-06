//! zip のエクスポート / インポートをバックグラウンドスレッドで実行する。

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::JoinHandle;

use egui::RichText;
use px_store::{Project, StoreError};

use super::PxApp;

pub(super) enum TaskKind {
    Export { dest: PathBuf },
    /// 展開が終わったら `dest` を開く
    Import { dest: PathBuf },
}

impl TaskKind {
    fn label(&self) -> &'static str {
        match self {
            Self::Export { .. } => "エクスポート",
            Self::Import { .. } => "インポート",
        }
    }
}

#[derive(Default)]
struct Shared {
    done: AtomicU64,
    total: AtomicU64,
    cancel: AtomicBool,
}

pub(super) struct BgTask {
    kind: TaskKind,
    shared: Arc<Shared>,
    handle: JoinHandle<px_store::Result<()>>,
}

impl BgTask {
    fn spawn(
        kind: TaskKind,
        egui_ctx: egui::Context,
        work: impl FnOnce(px_store::Progress<'_>) -> px_store::Result<()> + Send + 'static,
    ) -> std::io::Result<Self> {
        let shared = Arc::new(Shared::default());
        let s = shared.clone();
        let handle = std::thread::Builder::new().name("px-task".into()).spawn(move || {
            let mut last_pct = u64::MAX;
            let result = work(&mut |done, total| {
                s.done.store(done, Ordering::Relaxed);
                s.total.store(total, Ordering::Relaxed);
                // 再描画は 1% 進むごとに
                let pct = done.saturating_mul(100).checked_div(total).unwrap_or(0);
                if pct != last_pct {
                    last_pct = pct;
                    egui_ctx.request_repaint();
                }
                !s.cancel.load(Ordering::Relaxed)
            });
            egui_ctx.request_repaint();
            result
        })?;
        Ok(Self { kind, shared, handle })
    }

    fn percent(&self) -> u64 {
        let total = self.shared.total.load(Ordering::Relaxed);
        self.shared.done.load(Ordering::Relaxed).saturating_mul(100).checked_div(total).unwrap_or(0)
    }

    fn cancel(&self) {
        self.shared.cancel.store(true, Ordering::Relaxed);
    }

    /// 中止して終わるまで待つ（アプリ終了時）。
    pub(super) fn cancel_and_wait(self) {
        self.cancel();
        let _ = self.handle.join();
    }
}

impl PxApp {
    pub(super) fn task_running(&self) -> bool {
        self.task.is_some()
    }

    fn start_task(
        &mut self,
        kind: TaskKind,
        work: impl FnOnce(px_store::Progress<'_>) -> px_store::Result<()> + Send + 'static,
    ) {
        let label = kind.label();
        match BgTask::spawn(kind, self.egui_ctx.clone(), work) {
            Ok(t) => {
                self.status = format!("{label}中…");
                self.task = Some(t);
            }
            Err(e) => self.status = format!("{label}を開始できませんでした: {e}"),
        }
    }

    pub(super) fn menu_export(&mut self) {
        if self.task_running() {
            return;
        }
        let Some(project) = &self.project else { return };
        let name = format!("{}.zip", project.manifest().name);
        let dir = project.dir().to_path_buf();
        if let Some(dest) =
            rfd::FileDialog::new().set_title("案件をエクスポート").set_file_name(name).add_filter("zip", &["zip"]).save_file()
        {
            let d = dest.clone();
            self.start_task(TaskKind::Export { dest }, move |p| Project::export_dir(&dir, &d, p));
        }
    }

    pub(super) fn menu_import(&mut self) {
        if self.task_running() {
            return;
        }
        let Some(zip) = rfd::FileDialog::new().set_title("案件 zip を選択").add_filter("zip", &["zip"]).pick_file() else {
            return;
        };
        let Some(parent) = rfd::FileDialog::new().set_title("展開先のフォルダを選択").pick_folder() else {
            return;
        };
        let stem = zip.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "imported".into());
        let dest = parent.join(format!("{stem}.pxproj"));
        if dest.exists() {
            self.status = format!("展開先が既に存在します: {}", dest.display());
            return;
        }
        let d = dest.clone();
        self.start_task(TaskKind::Import { dest }, move |p| Project::extract_zip(&zip, &d, p));
    }

    /// 終わったタスクの後始末。毎フレーム呼ぶ。
    pub(super) fn poll_task(&mut self) {
        if !self.task.as_ref().is_some_and(|t| t.handle.is_finished()) {
            return;
        }
        let BgTask { kind, handle, .. } = self.task.take().expect("checked above");
        let label = kind.label();
        let result = handle.join().unwrap_or_else(|_| Err(StoreError::Invalid("内部エラーで終了しました".into())));
        match (kind, result) {
            (TaskKind::Export { dest }, Ok(())) => self.status = format!("エクスポートしました: {}", dest.display()),
            (TaskKind::Import { dest }, Ok(())) => self.open_dir(dest),
            (_, Err(StoreError::Cancelled)) => self.status = format!("{label}を中止しました"),
            (_, Err(e)) => self.status = format!("{label}失敗: {e}"),
        }
    }

    /// ステータスバーの進捗表示。
    pub(super) fn task_status(&mut self, ui: &mut egui::Ui) {
        let Some(t) = &self.task else { return };
        ui.spinner();
        ui.label(RichText::new(format!("{}中… {}%", t.kind.label(), t.percent())).small());
        if ui.small_button("中止").clicked() {
            t.cancel();
        }
        ui.separator();
    }
}
