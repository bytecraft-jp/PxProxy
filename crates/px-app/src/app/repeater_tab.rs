//! Repeater タブ: History / Intercept のリクエストを編集して何度でも送り直す。
//! 送った内容と結果はタブごとに残り、◀ ▶ で戻れる。送った結果は History にも記録される。

use egui::text::LayoutJob;
use egui::{Color32, Key, KeyboardShortcut, Modifiers, RichText};
use px_proxy::{Origin, RepeatRequest};
use px_store::NewFlow;
use tokio::task::JoinHandle;

use super::detail::{EditTarget, ViewMode, image_view, selection_menu, show_keeping_selection};
use super::intercept_tab::split_head_body;
use super::{PxApp, RED, Tab, status_color};
use crate::highlight::{self, Theme};
use crate::view::{self, Rendered};

const SEND_KEY: KeyboardShortcut = KeyboardShortcut::new(Modifiers::CTRL, Key::Enter);
/// History / Intercept で選択中のリクエストを Repeater に送る
pub(super) const SEND_TO_REPEATER_KEY: KeyboardShortcut = KeyboardShortcut::new(Modifiers::CTRL, Key::R);
const PREV_KEY: KeyboardShortcut = KeyboardShortcut::new(Modifiers::ALT, Key::ArrowLeft);
const NEXT_KEY: KeyboardShortcut = KeyboardShortcut::new(Modifiers::ALT, Key::ArrowRight);
/// タブごとに残す送信の数
const MAX_HISTORY: usize = 50;

/// 受け取ったレスポンスの表示状態。
struct Response {
    rendered: Rendered,
    status: Option<u16>,
    duration_ms: i64,
    body_len: usize,
    error: Option<String>,
    /// ハイライト済みの表示（表示方法と色が変わったら作り直す）
    job: Option<(ViewMode, Theme, LayoutJob)>,
}

impl Response {
    fn new(flow: NewFlow, uri_key: &str) -> Self {
        let rendered = match &flow.res_head {
            Some(h) => view::render_message(h, &flow.res_body, uri_key),
            None => Rendered::plain(String::new()),
        };
        Self {
            rendered,
            status: flow.status,
            duration_ms: flow.duration_us / 1000,
            body_len: flow.res_body.len(),
            error: flow.error,
            job: None,
        }
    }

    fn image_uri(&self) -> Option<&str> {
        self.rendered.image.as_ref().map(|i| i.uri.as_str())
    }
}

/// 送信 1 回分。送った時点のリクエストと、その結果。
struct Sent {
    origin: String,
    text: String,
    binary_body: Option<Vec<u8>>,
    /// 応答待ち・中止なら None
    response: Option<Response>,
}

pub(super) struct RepeaterTab {
    id: u64,
    title: String,
    origin: String,
    /// 編集中のリクエスト。ヘッドの改行は LF で表示し、送信時に CRLF へ戻す。
    text: String,
    /// UTF-8 でない Body は編集不可としてそのまま送る
    binary_body: Option<Vec<u8>>,
    fix_content_length: bool,
    /// 送信中なら `history` の末尾がその送信
    pending: Option<JoinHandle<px_proxy::Result<NewFlow>>>,
    history: Vec<Sent>,
    /// 表示中の `history` の位置
    cursor: usize,
    /// 送る前の検証エラー
    error: Option<String>,
    /// 画像キャッシュのキーを送信ごとに変える
    sent: u64,
}

impl RepeaterTab {
    fn image_uris(&self) -> impl Iterator<Item = &str> {
        self.history.iter().filter_map(|s| s.response.as_ref()?.image_uri())
    }

    /// 履歴の `to` 番目に送った内容をエディタに戻す。
    fn go(&mut self, to: usize) {
        if let Some(s) = self.history.get(to) {
            self.cursor = to;
            self.origin = s.origin.clone();
            self.text = s.text.clone();
            self.binary_body = s.binary_body.clone();
            self.error = None;
        }
    }
}

/// Repeater タブ全体の状態。
pub(super) struct Repeater {
    tabs: Vec<RepeaterTab>,
    selected: u64,
    next_id: u64,
    /// 応答表示の希望の表示方法
    view_pref: ViewMode,
}

impl Default for Repeater {
    fn default() -> Self {
        Self { tabs: Vec::new(), selected: 0, next_id: 1, view_pref: ViewMode::Pretty }
    }
}

impl Repeater {
    /// タブの Request の編集中テキスト（デコード窓からの書き戻し用）。
    pub(super) fn text_mut(&mut self, id: u64) -> Option<&mut String> {
        self.tabs.iter_mut().find(|t| t.id == id).map(|t| &mut t.text)
    }

    fn add(&mut self, origin: String, text: String, binary_body: Option<Vec<u8>>, title: String) {
        let id = self.next_id;
        self.next_id += 1;
        self.tabs.push(RepeaterTab {
            id,
            title: format!("#{id} {title}"),
            origin,
            text,
            binary_body,
            fix_content_length: true,
            pending: None,
            history: Vec::new(),
            cursor: 0,
            error: None,
            sent: 0,
        });
        self.selected = id;
    }

    pub(super) fn len(&self) -> usize {
        self.tabs.len()
    }
}

impl PxApp {
    /// 新しい Repeater タブを開いて切り替える。`text` はヘッド（LF 改行可）+ Body。
    pub(super) fn open_in_repeater(&mut self, origin: Origin, text: String, binary_body: Option<Vec<u8>>, title: String) {
        self.repeater.add(origin.to_string(), text, binary_body, title);
        self.tab = Tab::Repeater;
        self.status = "Repeater に送りました（Ctrl+Enter で送信）".into();
    }

    /// History の行を新しい Repeater タブで開く。
    pub(super) fn send_to_repeater(&mut self, id: i64) {
        let Some(reader) = &self.reader else { return };
        let d = match reader.detail(id) {
            Ok(Some(d)) => d,
            Ok(None) => return,
            Err(e) => {
                self.status = format!("詳細の読み込みに失敗: {e}");
                return;
            }
        };
        let s = &d.summary;
        let origin = Origin { https: s.scheme == "https", host: s.host.clone(), port: s.port };
        let title = format!("{} {}", s.method, s.host);
        // Intercept と同じく、ヘッダの CR はエディタ上で壊しやすいので LF で表示する
        let head = String::from_utf8_lossy(&d.req_head).replace("\r\n", "\n");
        let (text, binary) = match String::from_utf8(d.req_body) {
            Ok(b) => (head + &b, None),
            Err(e) => (head, Some(e.into_bytes())),
        };
        self.open_in_repeater(origin, text, binary, title);
    }

    fn repeater_send(&mut self, tab_id: u64) {
        let Some(tab) = self.repeater.tabs.iter_mut().find(|t| t.id == tab_id) else { return };
        if tab.pending.is_some() {
            return;
        }
        let Some(origin) = Origin::parse(&tab.origin) else {
            tab.error = Some("宛先は https://host:port の形で指定してください".into());
            return;
        };
        let (head, body) = split_head_body(&tab.text);
        if let Err(e) = px_proxy::http1::validate_head(head.as_bytes(), true) {
            tab.error = Some(e);
            return;
        }
        let body = tab.binary_body.clone().unwrap_or_else(|| body.as_bytes().to_vec());
        let req = RepeatRequest { origin, head: head.as_bytes().to_vec(), body, fix_content_length: tab.fix_content_length };

        if tab.history.len() >= MAX_HISTORY {
            let old = tab.history.remove(0);
            if let Some(uri) = old.response.as_ref().and_then(Response::image_uri) {
                self.egui_ctx.forget_image(uri);
            }
        }
        tab.history.push(Sent {
            origin: tab.origin.clone(),
            text: tab.text.clone(),
            binary_body: tab.binary_body.clone(),
            response: None,
        });
        tab.cursor = tab.history.len() - 1;
        tab.error = None;
        let (ctx, repaint) = (self.ctx.clone(), self.egui_ctx.clone());
        tab.pending = Some(self.rt.spawn(async move {
            let result = ctx.repeat(req).await;
            repaint.request_repaint();
            result
        }));
    }

    /// 終わった送信の結果を取り込む。毎フレーム呼ぶ。
    pub(super) fn poll_repeater(&mut self) {
        for tab in &mut self.repeater.tabs {
            if !tab.pending.as_ref().is_some_and(JoinHandle::is_finished) {
                continue;
            }
            let handle = tab.pending.take().expect("checked above");
            tab.sent += 1;
            match self.rt.block_on(handle) {
                Ok(Ok(flow)) => {
                    let uri_key = format!("repeater/{}/{}", tab.id, tab.sent);
                    if let Some(last) = tab.history.last_mut() {
                        last.response = Some(Response::new(flow, &uri_key));
                    }
                }
                // 送れなかったものは履歴に残さない
                Ok(Err(e)) => {
                    tab.history.pop();
                    tab.cursor = tab.history.len().saturating_sub(1);
                    tab.error = Some(e.to_string());
                }
                Err(e) => tab.error = Some(format!("送信処理が異常終了しました: {e}")),
            }
        }
    }

    fn forget_repeater_tab(&self, tab: &RepeaterTab) {
        if let Some(h) = &tab.pending {
            h.abort();
        }
        for uri in tab.image_uris() {
            self.egui_ctx.forget_image(uri);
        }
    }

    /// 案件を閉じたら Repeater も空にする（送信中のものは中止）。
    pub(super) fn clear_repeater(&mut self) {
        for tab in std::mem::take(&mut self.repeater.tabs) {
            self.forget_repeater_tab(&tab);
        }
    }

    fn close_repeater_tab(&mut self, id: u64) {
        let Some(i) = self.repeater.tabs.iter().position(|t| t.id == id) else { return };
        let tab = self.repeater.tabs.remove(i);
        self.forget_repeater_tab(&tab);
        if self.repeater.selected == id {
            let next = self.repeater.tabs.get(i).or(self.repeater.tabs.last());
            self.repeater.selected = next.map_or(0, |t| t.id);
        }
    }

    pub(super) fn repeater_tab(&mut self, ui: &mut egui::Ui) {
        let (send_key, prev_key, next_key) = ui.input_mut(|i| {
            (i.consume_shortcut(&SEND_KEY), i.consume_shortcut(&PREV_KEY), i.consume_shortcut(&NEXT_KEY))
        });

        // ---- タブ列
        let mut close = None;
        ui.horizontal_wrapped(|ui| {
            for t in &self.repeater.tabs {
                let label = if t.pending.is_some() { format!("{} …", t.title) } else { t.title.clone() };
                if ui.selectable_label(self.repeater.selected == t.id, label).clicked() {
                    self.repeater.selected = t.id;
                }
                if ui.small_button("×").on_hover_text("このタブを閉じる").clicked() {
                    close = Some(t.id);
                }
                ui.add_space(6.0);
            }
            if ui.button("＋").on_hover_text("空のタブを追加").clicked() {
                let text = "GET / HTTP/1.1\nHost: example.com\n\n".to_string();
                self.repeater.add("https://example.com".into(), text, None, "新規".into());
            }
        });
        if let Some(id) = close {
            self.close_repeater_tab(id);
        }
        ui.separator();

        let selected = self.repeater.selected;
        let Some(tab) = self.repeater.tabs.iter_mut().find(|t| t.id == selected) else {
            ui.centered_and_justified(|ui| {
                ui.label(
                    RichText::new(
                        "History の行を右クリック →「Repeater に送る」（または行を選んで Ctrl+R）で開きます。\
                         Intercept で止めたリクエストからも送れます",
                    )
                    .weak(),
                )
            });
            return;
        };

        // ---- 履歴の移動・宛先・送信
        let mut send = send_key;
        let n = tab.history.len();
        let mut go = None;
        let mut open_codec_now = false;
        if prev_key && tab.cursor > 0 {
            go = Some(tab.cursor - 1);
        }
        if next_key && tab.cursor + 1 < n {
            go = Some(tab.cursor + 1);
        }
        ui.horizontal(|ui| {
            let back = ui
                .add_enabled(tab.cursor > 0, egui::Button::new("◀"))
                .on_hover_text("前に送った内容に戻す (Alt+←)。編集中の内容は置き換わります");
            if back.clicked() {
                go = Some(tab.cursor - 1);
            }
            if ui.add_enabled(tab.cursor + 1 < n, egui::Button::new("▶")).on_hover_text("次に送った内容へ (Alt+→)").clicked() {
                go = Some(tab.cursor + 1);
            }
            if n > 0 {
                ui.label(RichText::new(format!("{} / {n}", tab.cursor + 1)).weak());
            }
            ui.separator();
            ui.label("宛先");
            ui.add(
                egui::TextEdit::singleline(&mut tab.origin).hint_text("https://example.com:443").desired_width(280.0),
            )
            .on_hover_text("接続先。Host ヘッダとは別に指定します");
            if tab.pending.is_some() {
                ui.spinner();
                if ui.button("中止").clicked()
                    && let Some(h) = tab.pending.take()
                {
                    h.abort();
                }
            } else if ui.button("▶ 送信").on_hover_text("Ctrl+Enter").clicked() {
                send = true;
            }
            ui.checkbox(&mut tab.fix_content_length, "Content-Length を自動更新");
            if ui.button("デコード…").on_hover_text("選択中のテキストをエンコード / デコード（右クリックからも）").clicked() {
                open_codec_now = true;
            }
            if let Some(r) = tab.history.get(tab.cursor).and_then(|s| s.response.as_ref()) {
                ui.separator();
                match r.status {
                    Some(code) => ui.label(RichText::new(code.to_string()).color(status_color(code)).strong()),
                    None => ui.label(RichText::new("ERR").color(RED).strong()),
                };
                ui.label(format!("{} ms  {} bytes", r.duration_ms, r.body_len));
            }
        });
        if let Some(to) = go {
            tab.go(to);
        }
        if open_codec_now {
            self.codec.open_with(self.selection.as_ref());
        }
        if let Some(e) = &tab.error {
            ui.colored_label(RED, e);
        }
        ui.add_space(4.0);

        // ---- Request（編集） / Response
        let pref = &mut self.repeater.view_pref;
        let theme = Theme {
            font: egui::TextStyle::Monospace.resolve(ui.style()),
            dark: ui.visuals().dark_mode,
            plain: ui.visuals().text_color(),
        };
        let waiting = tab.pending.is_some() && tab.cursor + 1 == n;
        let selection = &mut self.selection;
        let mut open_codec = false;
        ui.columns(2, |cols| {
            cols[0].strong("Request");
            if let Some(b) = &tab.binary_body {
                cols[0].label(
                    RichText::new(format!("Body はバイナリ（{} bytes）のため編集できません。そのまま送ります", b.len()))
                        .color(Color32::GRAY),
                );
            }
            egui::ScrollArea::both().id_salt(("repeater_req", tab.id)).auto_shrink(false).show(&mut cols[0], |ui| {
                let edit = egui::TextEdit::multiline(&mut tab.text)
                    .font(egui::TextStyle::Monospace)
                    .desired_width(f32::INFINITY)
                    .desired_rows(24)
                    .code_editor();
                let out = show_keeping_selection(ui, ("repeater_req", tab.id), edit);
                open_codec |= selection_menu(&out, &tab.text, Some(EditTarget::Repeater(tab.id)), selection);
            });

            let ui = &mut cols[1];
            let Some(r) = tab.history.get_mut(tab.cursor).and_then(|s| s.response.as_mut()) else {
                ui.strong("Response");
                let msg = match (n, waiting) {
                    (0, _) => "送信すると結果がここに表示されます",
                    (_, true) => "応答を待っています…",
                    _ => "応答なし（中止しました）",
                };
                ui.label(RichText::new(msg).weak());
                return;
            };
            let mode = pref.resolve(&r.rendered);
            ui.horizontal(|ui| {
                ui.strong("Response");
                let available: Vec<ViewMode> = ViewMode::ALL.into_iter().filter(|m| m.available(&r.rendered)).collect();
                if available.len() > 1 {
                    ui.separator();
                    for m in available {
                        if ui.selectable_label(mode == m, m.label()).clicked() {
                            *pref = m;
                        }
                    }
                }
                ui.separator();
                if ui.small_button("コピー").on_hover_text("表示中のテキストをコピー").clicked() {
                    ui.ctx().copy_text(shown_text(&r.rendered, mode).to_owned());
                }
            });
            if let Some(e) = &r.error {
                ui.colored_label(RED, format!("[エラー] {e}"));
            }
            let scroll_id = ("repeater_res", tab.id, tab.cursor, mode);
            egui::ScrollArea::both().id_salt(scroll_id).auto_shrink(false).show(ui, |ui| {
                if mode == ViewMode::Preview
                    && let Some(img) = &r.rendered.image
                {
                    image_view(ui, &r.rendered.head, img);
                    return;
                }
                if r.job.as_ref().is_none_or(|(m, t, _)| *m != mode || *t != theme) {
                    let text = shown_text(&r.rendered, mode);
                    let job = highlight::layout_job(text, r.rendered.body_start, r.rendered.syntax, &[], None, &theme);
                    r.job = Some((mode, theme.clone(), job));
                }
                let job = &r.job.as_ref().expect("built above").2;
                let mut text = shown_text(&r.rendered, mode);
                let mut layouter =
                    |ui: &egui::Ui, _: &dyn egui::TextBuffer, _wrap: f32| ui.fonts_mut(|f| f.layout_job(job.clone()));
                let edit = egui::TextEdit::multiline(&mut text)
                    .font(egui::TextStyle::Monospace)
                    .desired_width(f32::INFINITY)
                    .code_editor()
                    .layouter(&mut layouter);
                let out = show_keeping_selection(ui, scroll_id, edit);
                open_codec |= selection_menu(&out, text, None, selection);
            });
        });

        if open_codec {
            self.codec.open_with(self.selection.as_ref());
        }
        if send {
            self.repeater_send(selected);
        }
    }
}

fn shown_text(r: &Rendered, mode: ViewMode) -> &str {
    match (mode, &r.pretty) {
        (ViewMode::Pretty, Some(p)) => p,
        _ => &r.text,
    }
}
