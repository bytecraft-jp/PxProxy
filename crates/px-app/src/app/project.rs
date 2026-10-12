//! 案件の作成・オープン・クローズと、最近の案件の一覧。

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use egui::RichText;
use px_proxy::CertAuthority;
use px_store::{CommitHook, Project};

use super::sitemap_tab::SiteMap;
use super::style::RED;
use super::{PxApp, Tab};

const RECENT_MAX: usize = 10;

/// 「新規案件」ダイアログの入力状態。
pub(super) struct NewProjectForm {
    name: String,
    parent: String,
    error: Option<String>,
    /// 開いた直後に案件名欄へフォーカスを移す
    focus_name: bool,
}

impl NewProjectForm {
    fn target(&self) -> PathBuf {
        Path::new(self.parent.trim()).join(format!("{}.pxproj", self.name.trim()))
    }

    fn validate(&self) -> Result<PathBuf, String> {
        let name = self.name.trim();
        if name.is_empty() {
            return Err("案件名を入力してください".into());
        }
        if name.chars().any(|c| r#"\/:*?"<>|"#.contains(c)) {
            return Err(r#"案件名に \ / : * ? " < > | は使えません"#.into());
        }
        if self.parent.trim().is_empty() {
            return Err("保存先を指定してください".into());
        }
        let target = self.target();
        if target.exists() {
            return Err(format!("既に存在します: {}", target.display()));
        }
        Ok(target)
    }
}

impl PxApp {
    fn open_project(&mut self, open: impl FnOnce(CommitHook) -> px_store::Result<Project>) {
        let dirty = self.dirty.clone();
        let egui_ctx = self.egui_ctx.clone();
        let hook: CommitHook = Arc::new(move || {
            dirty.store(true, Ordering::Release);
            egui_ctx.request_repaint();
        });
        // 今の案件を閉じる（プロキシも止め、sink を外してから writer を join）
        self.close_project();
        match open(hook).and_then(|p| p.reader().map(|r| (p, r))) {
            Ok((project, reader)) => {
                self.ctx.set_sink(Some(project.sink()));
                self.status = format!("案件を開きました: {}  — 「プロキシ開始」で記録を始めます", project.dir().display());
                self.set_title(Some(&project.manifest().name));
                self.push_recent(project.dir().to_path_buf());
                self.project = Some(project);
                self.reader = Some(reader);
                self.load_settings();
                self.sync_scope_filter();
                self.tab = Tab::History;
                self.reset_list();
            }
            Err(e) => self.status = format!("案件を開けませんでした: {e}"),
        }
    }

    pub(super) fn close_project(&mut self) {
        // 入力途中のメモは閉じる前の案件に保存する（別の案件の同じ id に書かないように）
        if let Some(e) = self.note_edit.take() {
            self.save_note(e.id, e.text);
        }
        self.stop_proxy();
        // 停止中の通信は全て転送してから閉じる
        self.ctx.interceptor().set_enabled(false);
        self.held.clear();
        self.editors.clear();
        self.held_selected = None;
        self.clear_repeater();
        self.ctx.set_sink(None);
        self.reader = None;
        if let Some(p) = self.project.take() {
            p.close();
            self.status = "案件を閉じました".into();
        }
        self.set_title(None);
        self.ids.clear();
        self.cache.clear();
        self.total = 0;
        self.forget_detail_images();
        self.detail = None;
        self.selected = None;
        self.confirm_delete = None;
        self.pending_deletes.clear();
        self.site_map = SiteMap::default();
        self.findings.clear();
        for uri in self.comparer.image_uris() {
            self.egui_ctx.forget_image(uri);
        }
        self.comparer.clear();
    }

    pub(super) fn set_title(&self, name: Option<&str>) {
        let title = match name {
            Some(n) => format!("pxproxy — {n}"),
            None => "pxproxy".into(),
        };
        self.egui_ctx.send_viewport_cmd(egui::ViewportCommand::Title(title));
    }

    fn push_recent(&mut self, dir: PathBuf) {
        self.recent.retain(|p| p != &dir);
        self.recent.insert(0, dir);
        self.recent.truncate(RECENT_MAX);
        save_recent(&self.recent);
    }

    pub(super) fn create_project(&mut self, target: PathBuf) {
        self.open_project(|hook| Project::create(&target, Some(hook)));
    }

    pub(super) fn menu_open_project(&mut self) {
        if let Some(dir) =
            rfd::FileDialog::new().set_title("案件フォルダ (*.pxproj)、または新しい案件にする空のフォルダを選択").pick_folder()
        {
            self.open_dir(dir);
        }
    }

    /// 案件を開く。空のフォルダなら、そこを新しい案件として初期化する。
    pub(super) fn open_dir(&mut self, dir: PathBuf) {
        if is_empty_dir(&dir) {
            self.create_project(dir.clone());
            if self.project.as_ref().is_some_and(|p| p.dir() == dir) {
                self.status = format!("空のフォルダを新しい案件として初期化しました: {}", dir.display());
            }
            return;
        }
        if !dir.join("project.toml").exists() {
            self.status = format!("案件フォルダではありません（project.toml がありません）: {}", dir.display());
            return;
        }
        self.open_project(|hook| Project::open(&dir, Some(hook)));
    }

    pub(super) fn welcome(&mut self, ui: &mut egui::Ui) {
        ui.vertical_centered(|ui| {
            ui.add_space(ui.available_height() * 0.15);
            ui.heading(RichText::new("pxproxy").size(28.0));
            ui.add_space(6.0);
            ui.label(RichText::new("案件を作成または開くと、プロキシを開始できます").weak());
            ui.add_space(20.0);
            let size = egui::vec2(220.0, 36.0);
            if ui.add(egui::Button::new("＋ 新規案件を作成").min_size(size)).clicked() {
                self.new_project = Some(default_form());
            }
            if ui.add(egui::Button::new("案件を開く…").min_size(size)).clicked() {
                self.menu_open_project();
            }
            if ui.add_enabled(!self.task_running(), egui::Button::new("zip からインポート…").min_size(size)).clicked() {
                self.menu_import();
            }
            if self.recent.is_empty() {
                return;
            }
            ui.add_space(28.0);
            ui.strong("最近の案件");
            ui.add_space(6.0);
            let mut open = None;
            let mut remove = None;
            for p in &self.recent {
                let exists = p.join("project.toml").exists();
                let mut name = RichText::new(display_name(p)).strong();
                if !exists {
                    name = name.strikethrough().weak();
                }
                let resp = ui
                    .add_enabled(exists, egui::Button::new(name).frame(false).min_size(egui::vec2(size.x, 0.0)))
                    .on_hover_text(if exists { "クリックで開く / 右クリックでメニュー" } else { "見つかりません" });
                if resp.clicked() {
                    open = Some(p.clone());
                }
                resp.context_menu(|ui| {
                    if ui.button("一覧から削除").clicked() {
                        remove = Some(p.clone());
                    }
                });
                ui.label(RichText::new(p.display().to_string()).small().weak());
                ui.add_space(6.0);
            }
            if let Some(p) = open {
                self.open_dir(p);
            }
            if let Some(p) = remove {
                self.recent.retain(|r| r != &p);
                save_recent(&self.recent);
            }
        });
    }

    pub(super) fn new_project_window(&mut self, ctx: &egui::Context) {
        let Some(form) = &mut self.new_project else { return };
        let mut open = true;
        let mut create = None;
        let mut cancel = false;
        egui::Window::new("新規案件")
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .show(ctx, |ui| {
                egui::Grid::new("new_project").num_columns(2).spacing([8.0, 8.0]).show(ui, |ui| {
                    ui.label("案件名");
                    let name = ui.add(egui::TextEdit::singleline(&mut form.name).desired_width(320.0));
                    if std::mem::take(&mut form.focus_name) {
                        name.request_focus();
                    }
                    if name.changed() {
                        form.error = None;
                    }
                    ui.end_row();
                    ui.label("保存先");
                    ui.horizontal(|ui| {
                        ui.add(egui::TextEdit::singleline(&mut form.parent).desired_width(248.0));
                        if ui.button("参照…").clicked()
                            && let Some(d) = rfd::FileDialog::new().set_directory(&form.parent).pick_folder()
                        {
                            form.parent = d.display().to_string();
                        }
                    });
                    ui.end_row();
                    ui.label("");
                    ui.label(RichText::new(form.target().display().to_string()).small().weak());
                    ui.end_row();
                });
                if let Some(e) = &form.error {
                    ui.colored_label(RED, e);
                }
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    let enter = ui.input(|i| i.key_pressed(egui::Key::Enter));
                    if ui.button("作成").clicked() || enter {
                        match form.validate() {
                            Ok(t) => create = Some(t),
                            Err(e) => form.error = Some(e),
                        }
                    }
                    if ui.button("キャンセル").clicked() {
                        cancel = true;
                    }
                });
            });
        if !open || cancel {
            self.new_project = None;
        } else if let Some(target) = create {
            self.new_project = None;
            self.create_project(target);
        }
    }
}

/// 中身の無いフォルダか（存在しない・読めないなら false）。
fn is_empty_dir(p: &Path) -> bool {
    std::fs::read_dir(p).is_ok_and(|mut entries| entries.next().is_none())
}

pub(super) fn display_name(p: &Path) -> String {
    p.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| p.display().to_string())
}

pub(super) fn default_form() -> NewProjectForm {
    let parent = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(|h| PathBuf::from(h).join("Documents").join("pxproxy"))
        .unwrap_or_else(|| PathBuf::from("."));
    NewProjectForm { name: String::new(), parent: parent.display().to_string(), error: None, focus_name: true }
}

fn recent_file() -> PathBuf {
    CertAuthority::default_dir().join("recent.txt")
}

pub(super) fn load_recent() -> Vec<PathBuf> {
    std::fs::read_to_string(recent_file())
        .map(|s| s.lines().filter(|l| !l.trim().is_empty()).map(PathBuf::from).take(RECENT_MAX).collect())
        .unwrap_or_default()
}

fn save_recent(list: &[PathBuf]) {
    let text: String = list.iter().map(|p| format!("{}\n", p.display())).collect();
    let result = std::fs::create_dir_all(CertAuthority::default_dir()).and_then(|_| std::fs::write(recent_file(), text));
    if let Err(e) = result {
        tracing::warn!("failed to save recent projects: {e}");
    }
}
