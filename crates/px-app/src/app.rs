mod comparer_tab;
mod detail;
mod filter_bar;
mod findings_tab;
mod history_tab;
mod intercept_tab;
mod layout;
mod list;
mod mock_tab;
mod prefs;
mod project;
mod repeater_tab;
mod rows;
mod settings_tab;
mod sitemap_tab;
mod split;
#[cfg(test)]
mod smoke_tests;
mod style;
mod tasks;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use px_proxy::{CertAuthority, ProjectSettings, ProxyContext, ProxyServer};
use px_store::{Project, Reader};

use comparer_tab::Comparer;
use detail::{CodecWindow, Detail, Search, Selection, ViewMode};
use findings_tab::Findings;
use history_tab::HistoryState;
use intercept_tab::InterceptState;
use prefs::UiPrefs;
use project::{NewProjectForm, load_recent};
use repeater_tab::Repeater;
use sitemap_tab::SiteMap;
use tasks::BgTask;

type DynError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    Intercept,
    History,
    SiteMap,
    Repeater,
    Comparer,
    Findings,
    Settings,
    Mock,
}

impl Tab {
    /// 通信の一覧（History と同じ表）を出すタブ
    fn has_list(self) -> bool {
        matches!(self, Self::History | Self::SiteMap)
    }

    /// 詳細ペインを出すタブ
    fn has_detail(self) -> bool {
        matches!(self, Self::History | Self::SiteMap | Self::Findings)
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

    /// History / サイトマップの一覧
    history: HistoryState,
    /// 詳細を表示している行
    selected: Option<i64>,
    detail: Option<Detail>,
    /// 詳細ペインの希望の表示方法 [Request, Response]
    view_pref: [ViewMode; 2],
    search: Search,
    /// 詳細ペインで最後に選択したテキスト（デコード窓の入力に使う）
    selection: Option<Selection>,
    codec: CodecWindow,
    /// 実行中のバックグラウンド処理（エクスポート / インポート）
    task: Option<BgTask>,

    tab: Tab,
    settings: ProjectSettings,
    settings_error: Option<String>,
    /// Intercept の停止中キューと編集中の内容
    intercept: InterceptState,
    repeater: Repeater,
    site_map: SiteMap,
    findings: Findings,
    comparer: Comparer,
    /// テーマ・文字の大きさ
    prefs: UiPrefs,

    status: String,
}

impl PxApp {
    pub fn new(egui_ctx: egui::Context, opts: crate::cli::LaunchOptions) -> Result<Self, DynError> {
        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().thread_name("px-net").build()?;
        let ca = Arc::new(CertAuthority::load_or_create(CertAuthority::default_dir())?);
        let ctx = ProxyContext::new(ca)?;
        let repaint = egui_ctx.clone();
        ctx.interceptor().set_notify(Some(Arc::new(move || repaint.request_repaint())));
        let prefs = UiPrefs::load();
        prefs.apply(&egui_ctx);
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
            history: HistoryState::default(),
            selected: None,
            detail: None,
            view_pref: [ViewMode::Pretty; 2],
            search: Search::default(),
            selection: None,
            codec: CodecWindow::default(),
            task: None,
            tab: Tab::History,
            settings: ProjectSettings::default(),
            settings_error: None,
            intercept: InterceptState::default(),
            repeater: Repeater::default(),
            site_map: SiteMap::default(),
            findings: Findings::default(),
            comparer: Comparer::default(),
            prefs,
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
}

impl eframe::App for PxApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.refresh();
        self.refresh_held();
        self.poll_task();
        self.poll_repeater();
        self.handle_keys(&ctx);
        if self.tab == Tab::Findings {
            self.refresh_findings(&ctx);
        }
        if self.tab.has_detail()
            && self.new_project.is_none()
            && let Some(id) = self.selected
            && ctx.input_mut(|i| i.consume_shortcut(&repeater_tab::SEND_TO_REPEATER_KEY))
        {
            self.send_to_repeater(id);
        }
        if self.tab.has_detail()
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
                if self.tab.has_list() {
                    ui.add_space(2.0);
                    self.filter_bar(ui);
                }
            }
            ui.add_space(2.0);
        });
        egui::Panel::bottom("status").show(ui, |ui| self.status_bar(ui));
        if self.project.is_some() {
            match self.tab {
                Tab::SiteMap => {
                    egui::Panel::left("site_map")
                        .resizable(true)
                        .default_size(320.0)
                        .min_size(160.0)
                        .show(ui, |ui| self.site_map_tree(ui));
                }
                Tab::Findings => {
                    egui::Panel::left("findings")
                        .resizable(true)
                        .default_size(380.0)
                        .min_size(200.0)
                        .show(ui, |ui| self.findings_list(ui));
                }
                _ => {}
            }
            if self.tab.has_detail() {
                egui::Panel::bottom("detail")
                    .resizable(true)
                    .default_size(360.0)
                    .min_size(120.0)
                    .show(ui, |ui| self.detail_pane(ui));
            }
            match self.tab {
                Tab::History | Tab::SiteMap => {
                    egui::CentralPanel::default_margins().show(ui, |ui| {
                        // 列の合計が画面より広いときは横にスクロールする（縦はテーブル自身がスクロールする）
                        egui::ScrollArea::horizontal()
                            .id_salt("history_h")
                            .auto_shrink(false)
                            .show(ui, |ui| self.history_table(ui));
                    });
                }
                Tab::Findings => {
                    egui::CentralPanel::default_margins().show(ui, |ui| self.findings_items(ui));
                }
                Tab::Comparer => {
                    egui::CentralPanel::default_margins().show(ui, |ui| self.comparer_tab(ui));
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
                Tab::Mock => {
                    egui::CentralPanel::default_margins().show(ui, |ui| self.mock_tab(ui));
                }
            }
        } else {
            egui::CentralPanel::default_margins().show(ui, |ui| self.welcome(ui));
        }
        self.new_project_window(&ctx);
        self.codec_window(&ctx);
        self.delete_confirm_window(&ctx);
    }

    fn on_exit(&mut self) {
        // 書きかけの zip / 展開途中のフォルダを残さないよう中止して待つ
        if let Some(t) = self.task.take() {
            t.cancel_and_wait();
        }
        self.close_project();
    }
}
