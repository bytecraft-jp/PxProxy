mod detail;
mod intercept_tab;
mod repeater_tab;
mod settings_tab;
mod tasks;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use egui::{Align, Color32, Layout, RichText};
use egui_extras::{Column, TableBuilder};
use px_proxy::{CertAuthority, Held, ProjectSettings, ProxyContext, ProxyServer};
use px_store::{
    ALL_KINDS, ALL_STATUS, CommitHook, Filter, FlowKind, FlowSummary, Project, Reader, StatusClass,
};

use crate::view;
use detail::{CodecWindow, Detail, Search, Selection, ViewMode};
use intercept_tab::Editor;
use repeater_tab::Repeater;
use tasks::BgTask;

type DynError = Box<dyn std::error::Error + Send + Sync>;

const SUMMARY_CACHE_MAX: usize = 20_000;
const RECENT_MAX: usize = 10;
const RED: Color32 = Color32::from_rgb(230, 80, 80);
const GREEN: Color32 = Color32::from_rgb(80, 200, 120);
const YELLOW: Color32 = Color32::from_rgb(240, 200, 80);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    Intercept,
    History,
    Repeater,
    Settings,
}

/// History の一覧でメモを編集中の行。
struct NoteEdit {
    id: i64,
    text: String,
    /// 次のフレームで入力欄にフォーカスを移す
    focus: bool,
}

/// 「新規案件」ダイアログの入力状態。
struct NewProjectForm {
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

pub struct PxApp {
    rt: tokio::runtime::Runtime,
    ctx: Arc<ProxyContext>,
    proxy: Option<ProxyServer>,
    listen: String,

    project: Option<Project>,
    reader: Option<Reader>,
    /// writer がコミットしたら立つ。UI はこれを見て差分を取りに行く。
    dirty: Arc<AtomicBool>,
    egui_ctx: egui::Context,
    recent: Vec<PathBuf>,
    new_project: Option<NewProjectForm>,

    filter: Filter,
    /// 現在のフィルタに一致する ID（昇順）。行 i は ids[i]。
    ids: Vec<i64>,
    last_id: i64,
    total: i64,
    cache: HashMap<i64, FlowSummary>,
    follow: bool,
    selected: Option<i64>,
    scroll_to: Option<usize>,
    detail: Option<Detail>,
    /// 詳細ペインの希望の表示方法 [Request, Response]
    view_pref: [ViewMode; 2],
    search: Search,
    /// 詳細ペインで最後に選択したテキスト（デコード窓の入力に使う）
    selection: Option<Selection>,
    codec: CodecWindow,
    /// History の一覧で編集中のメモ
    note_edit: Option<NoteEdit>,
    /// 実行中のバックグラウンド処理（エクスポート / インポート）
    task: Option<BgTask>,

    tab: Tab,
    settings: ProjectSettings,
    settings_error: Option<String>,
    /// Intercept の停止中キュー（UI 側のコピー）
    held: Vec<Arc<Held>>,
    held_version: u64,
    held_checked: Instant,
    held_selected: Option<u64>,
    editors: HashMap<u64, Editor>,
    repeater: Repeater,

    status: String,
}

impl PxApp {
    pub fn new(egui_ctx: egui::Context, opts: crate::cli::LaunchOptions) -> Result<Self, DynError> {
        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().thread_name("px-net").build()?;
        let ca = Arc::new(CertAuthority::load_or_create(CertAuthority::default_dir())?);
        let ctx = ProxyContext::new(ca)?;
        let repaint = egui_ctx.clone();
        ctx.interceptor().set_notify(Some(Arc::new(move || repaint.request_repaint())));
        let mut app = Self {
            rt,
            ctx,
            proxy: None,
            listen: "127.0.0.1:8080".into(),
            project: None,
            reader: None,
            dirty: Arc::new(AtomicBool::new(false)),
            egui_ctx,
            recent: load_recent(),
            new_project: None,
            filter: Filter::default(),
            ids: Vec::new(),
            last_id: 0,
            total: 0,
            cache: HashMap::new(),
            follow: true,
            selected: None,
            scroll_to: None,
            detail: None,
            view_pref: [ViewMode::Pretty; 2],
            search: Search::default(),
            selection: None,
            codec: CodecWindow::default(),
            note_edit: None,
            task: None,
            tab: Tab::History,
            settings: ProjectSettings::default(),
            settings_error: None,
            held: Vec::new(),
            held_version: u64::MAX,
            held_checked: Instant::now(),
            held_selected: None,
            editors: HashMap::new(),
            repeater: Repeater::default(),
            status: "案件を作成するか、既存の案件を開いてください".into(),
        };
        app.apply_launch(opts);
        Ok(app)
    }

    /// コマンドラインで指定された案件を開き、必要ならプロキシを開始する。
    fn apply_launch(&mut self, opts: crate::cli::LaunchOptions) {
        if let Some(listen) = opts.listen {
            self.listen = listen;
        }
        let Some(dir) = opts.project else { return };
        if dir.join("project.toml").exists() {
            self.open_dir(dir);
        } else {
            self.create_project(dir);
        }
        if opts.start && self.project.is_some() {
            self.start_proxy();
        }
    }

    // ---- 案件 -------------------------------------------------------------

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

    fn close_project(&mut self) {
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
    }

    fn set_title(&self, name: Option<&str>) {
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

    fn reset_list(&mut self) {
        self.ids.clear();
        self.cache.clear();
        self.last_id = 0;
        self.dirty.store(true, Ordering::Release);
    }

    fn set_filter(&mut self, f: Filter) {
        if f != self.filter {
            self.filter = f;
            self.reset_list();
        }
    }

    fn refresh(&mut self) {
        if !self.dirty.swap(false, Ordering::AcqRel) {
            return;
        }
        let Some(reader) = &self.reader else { return };
        match reader.ids_after(self.last_id, &self.filter) {
            Ok(new) => {
                if let Some(&last) = new.last() {
                    self.last_id = last;
                }
                self.ids.extend(new);
            }
            Err(e) => self.status = format!("読み込みエラー: {e}"),
        }
        self.total = reader.count().unwrap_or(self.total);
    }

    fn create_project(&mut self, target: PathBuf) {
        self.open_project(|hook| Project::create(&target, Some(hook)));
    }

    fn menu_open_project(&mut self) {
        if let Some(dir) = rfd::FileDialog::new().set_title("案件フォルダ (*.pxproj) を選択").pick_folder() {
            self.open_dir(dir);
        }
    }

    fn open_dir(&mut self, dir: PathBuf) {
        if !dir.join("project.toml").exists() {
            self.status = format!("案件フォルダではありません（project.toml がありません）: {}", dir.display());
            return;
        }
        self.open_project(|hook| Project::open(&dir, Some(hook)));
    }

    fn menu_save_ca(&mut self) {
        if let Some(dest) = rfd::FileDialog::new().set_title("CA 証明書を保存").set_file_name("pxproxy-ca.crt").save_file() {
            self.status = match std::fs::write(&dest, self.ctx.ca().ca_pem()) {
                Ok(()) => format!("CA 証明書を保存しました: {}（OS/ブラウザの信頼されたルートに登録してください）", dest.display()),
                Err(e) => format!("保存失敗: {e}"),
            };
        }
    }

    // ---- プロキシ ---------------------------------------------------------

    fn start_proxy(&mut self) {
        if self.project.is_none() {
            self.status = "先に案件を作成するか開いてください".into();
            return;
        }
        let addr: SocketAddr = match self.listen.trim().parse() {
            Ok(a) => a,
            Err(e) => {
                self.status = format!("待受アドレスが不正です: {e}");
                return;
            }
        };
        match self.rt.block_on(ProxyServer::bind(addr, self.ctx.clone())) {
            Ok(p) => {
                self.status = format!("プロキシ待受開始: {}", p.local_addr());
                self.proxy = Some(p);
            }
            Err(e) => self.status = format!("待受に失敗しました ({addr}): {e}"),
        }
    }

    fn stop_proxy(&mut self) {
        if let Some(p) = self.proxy.take() {
            let _guard = self.rt.enter();
            p.stop();
            self.status = "プロキシを停止しました".into();
        }
    }

    // ---- 選択 -------------------------------------------------------------

    fn select(&mut self, id: i64) {
        self.selected = Some(id);
        if self.detail.as_ref().is_some_and(|d| d.id == id) {
            return;
        }
        let Some(reader) = &self.reader else { return };
        match reader.detail(id) {
            Ok(Some(d)) => {
                let request = view::render_message(&d.req_head, &d.req_body, &format!("{id}/req"));
                let response = match &d.res_head {
                    Some(h) => view::render_message(h, &d.res_body, &format!("{id}/res")),
                    None => view::Rendered::plain(d.summary.error.clone().map(|e| format!("[エラー] {e}")).unwrap_or_default()),
                };
                let originals = [
                    d.orig_request.as_ref().map(|(h, b)| view::render_message(h, b, &format!("{id}/req-orig"))),
                    d.orig_response.as_ref().map(|(h, b)| view::render_message(h, b, &format!("{id}/res-orig"))),
                ];
                self.forget_detail_images();
                self.detail = Some(Detail::new(id, [request, response], originals));
                self.selection = None;
                self.search.reset_position();
            }
            Ok(None) => self.detail = None,
            Err(e) => self.status = format!("詳細の読み込みに失敗: {e}"),
        }
    }

    /// 表示を切り替えたら前の画像をデコード済みキャッシュから捨てる。
    fn forget_detail_images(&self) {
        if let Some(d) = &self.detail {
            for uri in d.image_uris() {
                self.egui_ctx.forget_image(uri);
            }
        }
    }

    fn handle_keys(&mut self, ctx: &egui::Context) {
        if ctx.egui_wants_keyboard_input()
            || self.ids.is_empty()
            || self.new_project.is_some()
            || self.tab != Tab::History
        {
            return;
        }
        let (up, down) = ctx.input(|i| (i.key_pressed(egui::Key::ArrowUp), i.key_pressed(egui::Key::ArrowDown)));
        if !up && !down {
            return;
        }
        let cur = self.selected.and_then(|id| self.ids.binary_search(&id).ok());
        let next = match (cur, down) {
            (None, _) => self.ids.len() - 1,
            (Some(i), true) => (i + 1).min(self.ids.len() - 1),
            (Some(i), false) => i.saturating_sub(1),
        };
        self.follow = false;
        self.scroll_to = Some(next);
        self.select(self.ids[next]);
    }

    // ---- UI: 上部 ---------------------------------------------------------

    fn menu_bar(&mut self, ui: &mut egui::Ui) {
        let has_project = self.project.is_some();
        egui::MenuBar::new().ui(ui, |ui| {
            ui.menu_button("案件", |ui| {
                if ui.button("新規作成…").clicked() {
                    self.new_project = Some(default_form());
                }
                if ui.button("開く…").clicked() {
                    self.menu_open_project();
                }
                ui.add_enabled_ui(!self.recent.is_empty(), |ui| {
                    ui.menu_button("最近の案件", |ui| {
                        let mut open = None;
                        for p in &self.recent {
                            if ui.button(display_name(p)).on_hover_text(p.display().to_string()).clicked() {
                                open = Some(p.clone());
                            }
                        }
                        if let Some(p) = open {
                            self.open_dir(p);
                        }
                    });
                });
                ui.separator();
                let idle = !self.task_running();
                if ui
                    .add_enabled(has_project && idle, egui::Button::new("zip にエクスポート…"))
                    .on_disabled_hover_text("案件を開いていないか、他のエクスポート / インポートを実行中です")
                    .clicked()
                {
                    self.menu_export();
                }
                if ui
                    .add_enabled(idle, egui::Button::new("zip からインポート…"))
                    .on_disabled_hover_text("他のエクスポート / インポートを実行中です")
                    .clicked()
                {
                    self.menu_import();
                }
                ui.separator();
                if ui.add_enabled(has_project, egui::Button::new("案件を閉じる")).clicked() {
                    self.close_project();
                }
            });
            ui.menu_button("CA", |ui| {
                if ui.button("CA 証明書を保存…").clicked() {
                    self.menu_save_ca();
                }
            });
            ui.menu_button("ツール", |ui| {
                if ui.button("エンコード / デコード…").clicked() {
                    self.codec.open_with(self.selection.as_ref());
                }
            });
        });
    }

    fn toolbar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            let has_project = self.project.is_some();
            let running = self.proxy.is_some();
            ui.label("待受");
            ui.add_enabled(!running, egui::TextEdit::singleline(&mut self.listen).desired_width(140.0));
            if running {
                if ui.button("■ プロキシ停止").clicked() {
                    self.stop_proxy();
                }
                ui.label(RichText::new("● 記録中").color(GREEN));
            } else {
                let resp = ui
                    .add_enabled(has_project, egui::Button::new("▶ プロキシ開始"))
                    .on_disabled_hover_text("先に案件を作成するか開いてください");
                if resp.clicked() {
                    self.start_proxy();
                }
                ui.label(RichText::new("● 停止中").color(Color32::GRAY));
            }
            ui.separator();
            let intercepting = self.ctx.interceptor().is_enabled();
            let (label, color) =
                if intercepting { ("Intercept: ON", YELLOW) } else { ("Intercept: OFF", Color32::GRAY) };
            let resp = ui
                .add_enabled(has_project, egui::Button::new(RichText::new(label).color(color)))
                .on_hover_text("ルールに一致した通信を止めて編集できます（設定タブで条件を変更）");
            if resp.clicked() {
                self.set_intercept(!intercepting);
            }
            ui.separator();
            match &self.project {
                Some(p) => {
                    ui.label("案件:");
                    ui.strong(&p.manifest().name).on_hover_text(p.dir().display().to_string());
                }
                None => {
                    ui.label(RichText::new("案件未選択").weak());
                }
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if has_project {
                    ui.checkbox(&mut self.follow, "末尾に追従");
                    ui.separator();
                    if self.filter.is_default() {
                        ui.label(format!("{} 件", self.total));
                    } else {
                        ui.label(format!("{} / {} 件", self.ids.len(), self.total));
                    }
                }
            });
        });
    }

    fn tab_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            let n = self.held.len();
            let intercept = if n > 0 {
                RichText::new(format!("Intercept ({n})")).color(YELLOW).strong()
            } else {
                RichText::new("Intercept")
            };
            let repeater = match self.repeater.len() {
                0 => RichText::new("Repeater"),
                n => RichText::new(format!("Repeater ({n})")),
            };
            for (tab, label) in [
                (Tab::Intercept, intercept),
                (Tab::History, RichText::new("History")),
                (Tab::Repeater, repeater),
                (Tab::Settings, RichText::new("診断対象 / ルール")),
            ] {
                if ui.selectable_label(self.tab == tab, label).clicked() && self.tab != tab {
                    self.tab = tab;
                    // 別タブで選んだ文字列をデコード窓に持ち込まない
                    self.selection = None;
                }
            }
        });
    }

    fn filter_bar(&mut self, ui: &mut egui::Ui) {
        let mut f = self.filter.clone();
        ui.horizontal_wrapped(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut f.text).hint_text("🔍 ホスト / パスで絞り込み").desired_width(180.0),
            );
            ui.separator();
            ui.label("種類");
            for k in FlowKind::ALL {
                chip(ui, &mut f.kinds, k.bit(), k.label());
            }
            ui.separator();
            ui.label("ステータス");
            for s in StatusClass::ALL {
                chip(ui, &mut f.status, s.bit(), s.label());
            }
            ui.separator();
            ui.toggle_value(&mut f.in_scope_only, "診断対象のみ")
                .on_hover_text("「診断対象 / ルール」タブで設定したホスト・パスだけを表示");
            ui.separator();
            if ui.button("リセット").on_hover_text("すべて表示").clicked() {
                f = Filter::default();
            }
            if ui.button("静的ファイルを隠す").on_hover_text("JS / CSS / 画像 / フォント / メディアを非表示").clicked() {
                f.kinds = ALL_KINDS
                    & !(FlowKind::Script.bit()
                        | FlowKind::Css.bit()
                        | FlowKind::Image.bit()
                        | FlowKind::Font.bit()
                        | FlowKind::Media.bit());
            }
            if ui.button("XHR のみ").clicked() {
                f.kinds = FlowKind::Xhr.bit();
            }
            if ui.button("エラーのみ").on_hover_text("4xx / 5xx / 応答なし").clicked() {
                f.status = ALL_STATUS & !(StatusClass::Ok.bit() | StatusClass::Redirect.bit());
            }
        });
        self.set_filter(f);
    }

    fn status_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            self.task_status(ui);
            ui.label(RichText::new(&self.status).small());
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let ca = CertAuthority::default_dir().join("ca.crt");
                ui.label(RichText::new(format!("CA: {}", ca.display())).small().weak());
            });
        });
    }

    // ---- UI: 中央 ---------------------------------------------------------

    fn welcome(&mut self, ui: &mut egui::Ui) {
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

    fn new_project_window(&mut self, ctx: &egui::Context) {
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

    fn history_table(&mut self, ui: &mut egui::Ui) {
        let row_h = ui.text_style_height(&egui::TextStyle::Body) + 6.0;
        // 選択可能なラベルはクリックを奪い、行が選択できなくなる
        ui.style_mut().interaction.selectable_labels = false;
        let mut table = TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .sense(egui::Sense::click())
            .cell_layout(Layout::left_to_right(Align::Center))
            .stick_to_bottom(self.follow)
            .column(Column::exact(60.0))
            .column(Column::initial(240.0).clip(true))
            .column(Column::exact(64.0))
            .column(Column::initial(400.0).clip(true))
            .column(Column::exact(56.0))
            .column(Column::exact(72.0))
            .column(Column::exact(72.0))
            .column(Column::exact(64.0))
            .column(Column::initial(160.0).clip(true))
            .column(Column::remainder().at_least(120.0).clip(true));
        if let Some(i) = self.scroll_to.take() {
            table = table.scroll_to_row(i, None);
        }

        let ids = &self.ids;
        let cache = &mut self.cache;
        let reader = self.reader.as_ref();
        let selected = self.selected;
        let mut clicked = None;
        let mut scope_add: Option<(String, bool)> = None;
        let mut to_repeater = None;
        let note_edit = &mut self.note_edit;
        // (id, 確定したメモ)。None は取り消し
        let mut note_done: Option<Option<(i64, String)>> = None;
        let mut note_start = None;
        if cache.len() > SUMMARY_CACHE_MAX {
            cache.clear();
        }

        table
            .header(row_h, |mut h| {
                for title in ["#", "Host", "Method", "Path", "Status", "種類", "Length", "ms", "備考", "メモ"] {
                    let (_, r) = h.col(|ui| {
                        ui.strong(title);
                    });
                    match title {
                        "備考" => r.on_hover_text("エラー・Intercept での編集・Repeater から送った通信を表示します"),
                        "メモ" => r.on_hover_text("セルをダブルクリック（または右クリック →「メモを編集」）で入力します"),
                        _ => r,
                    };
                }
            })
            .body(|body| {
                body.rows(row_h, ids.len(), |mut row| {
                    let id = ids[row.index()];
                    if let std::collections::hash_map::Entry::Vacant(e) = cache.entry(id)
                        && let Some(s) = reader.and_then(|r| r.summary(id).ok().flatten())
                    {
                        e.insert(s);
                    }
                    let Some(s) = cache.get(&id) else { return };
                    row.set_selected(selected == Some(id));
                    row.col(|ui| {
                        ui.label(RichText::new(id.to_string()).weak());
                    });
                    row.col(|ui| {
                        let default_port = if s.scheme == "https" { 443 } else { 80 };
                        let host = if s.port == default_port {
                            format!("{}://{}", s.scheme, s.host)
                        } else {
                            format!("{}://{}:{}", s.scheme, s.host, s.port)
                        };
                        ui.add(egui::Label::new(host).truncate());
                    });
                    row.col(|ui| {
                        ui.label(&s.method);
                    });
                    row.col(|ui| {
                        ui.add(egui::Label::new(&s.target).truncate());
                    });
                    row.col(|ui| match s.status {
                        Some(code) => {
                            ui.label(RichText::new(code.to_string()).color(status_color(code)));
                        }
                        None => {
                            ui.label(RichText::new("ERR").color(RED));
                        }
                    });
                    row.col(|ui| {
                        let r = ui.label(s.kind.label());
                        if let Some(ct) = &s.content_type {
                            r.on_hover_text(ct);
                        }
                    });
                    row.col(|ui| {
                        ui.label(view::human_size(s.res_body_len));
                    });
                    row.col(|ui| {
                        ui.label(format!("{}", s.duration_us / 1000));
                    });
                    row.col(|ui| {
                        if let Some(e) = &s.error {
                            ui.add(egui::Label::new(RichText::new(e).color(RED)).truncate());
                        } else if s.edited != 0 {
                            let what = match s.edited {
                                px_store::EDITED_REQUEST => "Req",
                                px_store::EDITED_RESPONSE => "Res",
                                _ => "Req/Res",
                            };
                            ui.label(RichText::new(format!("編集済み ({what})")).color(YELLOW));
                        } else if s.source == px_store::FlowSource::Repeater {
                            ui.label(RichText::new("Repeater").weak());
                        }
                    });
                    let (_, note_cell) = row.col(|ui| match note_edit.as_mut().filter(|e| e.id == id) {
                        Some(e) => {
                            let r = ui.add(
                                egui::TextEdit::singleline(&mut e.text)
                                    .desired_width(f32::INFINITY)
                                    .hint_text("Enter で確定 / Esc で取消"),
                            );
                            if std::mem::take(&mut e.focus) {
                                r.request_focus();
                            }
                            if r.lost_focus() {
                                let cancel = ui.input(|i| i.key_pressed(egui::Key::Escape));
                                note_done = Some((!cancel).then(|| (id, e.text.clone())));
                            }
                        }
                        None => {
                            if let Some(n) = &s.note {
                                ui.add(egui::Label::new(n).truncate()).on_hover_text(n);
                            }
                        }
                    });
                    if note_cell.double_clicked() {
                        note_start = Some(id);
                    }
                    let resp = row.response();
                    if resp.clicked() {
                        clicked = Some(id);
                    }
                    resp.context_menu(|ui| {
                        if ui.button("Repeater に送る (Ctrl+R)").clicked() {
                            to_repeater = Some(id);
                        }
                        if ui.button("メモを編集").clicked() {
                            note_start = Some(id);
                        }
                        ui.separator();
                        ui.label(RichText::new(&s.host).strong());
                        if ui.button("このホストを診断対象に追加").clicked() {
                            scope_add = Some((s.host.clone(), false));
                        }
                        if ui.button("このホストを診断対象から除外").clicked() {
                            scope_add = Some((s.host.clone(), true));
                        }
                    });
                });
            });

        if let Some(id) = clicked {
            self.follow = false;
            self.select(id);
        }
        if let Some((host, exclude)) = scope_add {
            self.add_scope_host(&host, exclude);
        }
        if let Some(id) = to_repeater {
            self.send_to_repeater(id);
        }
        if let Some(done) = note_done {
            self.note_edit = None;
            if let Some((id, text)) = done {
                self.save_note(id, text);
            }
        }
        if let Some(id) = note_start {
            let text = self.cache.get(&id).and_then(|s| s.note.clone()).unwrap_or_default();
            self.note_edit = Some(NoteEdit { id, text, focus: true });
        }
    }

    /// メモを DB に書き、一覧のキャッシュにもすぐ反映する。
    fn save_note(&mut self, id: i64, text: String) {
        let Some(project) = &self.project else { return };
        let text = text.trim().to_owned();
        if self.cache.get(&id).is_some_and(|s| s.note.as_deref().unwrap_or("") == text) {
            return;
        }
        project.sink().set_note(id, &text);
        if let Some(s) = self.cache.get_mut(&id) {
            s.note = (!text.is_empty()).then_some(text);
        }
    }

}

/// ビットマスクの 1 ビットをトグルするボタン。
fn chip(ui: &mut egui::Ui, mask: &mut u32, bit: u32, label: &str) {
    let mut on = *mask & bit != 0;
    if ui.toggle_value(&mut on, label).changed() {
        if on {
            *mask |= bit;
        } else {
            *mask &= !bit;
        }
    }
}

fn status_color(code: u16) -> Color32 {
    match code {
        100..=299 => GREEN,
        300..=399 => Color32::from_rgb(100, 160, 240),
        400..=499 => Color32::from_rgb(240, 170, 60),
        _ => RED,
    }
}

fn display_name(p: &Path) -> String {
    p.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| p.display().to_string())
}

fn default_form() -> NewProjectForm {
    let parent = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(|h| PathBuf::from(h).join("Documents").join("pxproxy"))
        .unwrap_or_else(|| PathBuf::from("."));
    NewProjectForm { name: String::new(), parent: parent.display().to_string(), error: None, focus_name: true }
}

fn recent_file() -> PathBuf {
    CertAuthority::default_dir().join("recent.txt")
}

fn load_recent() -> Vec<PathBuf> {
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

impl eframe::App for PxApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.refresh();
        self.refresh_held();
        self.poll_task();
        self.poll_repeater();
        self.handle_keys(&ctx);
        if self.tab == Tab::History
            && self.new_project.is_none()
            && let Some(id) = self.selected
            && ctx.input_mut(|i| i.consume_shortcut(&repeater_tab::SEND_TO_REPEATER_KEY))
        {
            self.send_to_repeater(id);
        }
        if self.tab == Tab::History
            && self.detail.is_some()
            && self.new_project.is_none()
            && ctx.input_mut(|i| i.consume_shortcut(&detail::SEARCH_KEY))
        {
            self.search.focus();
        }

        egui::Panel::top("top").show(ui, |ui| {
            self.menu_bar(ui);
            ui.add_space(2.0);
            self.toolbar(ui);
            if self.project.is_some() {
                ui.add_space(4.0);
                self.tab_bar(ui);
                if self.tab == Tab::History {
                    ui.add_space(2.0);
                    self.filter_bar(ui);
                }
            }
            ui.add_space(2.0);
        });
        egui::Panel::bottom("status").show(ui, |ui| self.status_bar(ui));
        if self.project.is_some() {
            match self.tab {
                Tab::History => {
                    egui::Panel::bottom("detail")
                        .resizable(true)
                        .default_size(360.0)
                        .min_size(120.0)
                        .show(ui, |ui| self.detail_pane(ui));
                    egui::CentralPanel::default_margins().show(ui, |ui| {
                        // 列の合計が画面より広いときは横にスクロールする（縦はテーブル自身がスクロールする）
                        egui::ScrollArea::horizontal()
                            .id_salt("history_h")
                            .auto_shrink(false)
                            .show(ui, |ui| self.history_table(ui));
                    });
                }
                Tab::Intercept => {
                    egui::CentralPanel::default_margins().show(ui, |ui| self.intercept_tab(ui));
                }
                Tab::Repeater => {
                    egui::CentralPanel::default_margins().show(ui, |ui| self.repeater_tab(ui));
                }
                Tab::Settings => {
                    egui::CentralPanel::default_margins().show(ui, |ui| self.settings_tab(ui));
                }
            }
        } else {
            egui::CentralPanel::default_margins().show(ui, |ui| self.welcome(ui));
        }
        self.new_project_window(&ctx);
        self.codec_window(&ctx);
    }

    fn on_exit(&mut self) {
        // 書きかけの zip / 展開途中のフォルダを残さないよう中止して待つ
        if let Some(t) = self.task.take() {
            t.cancel_and_wait();
        }
        self.close_project();
    }
}
