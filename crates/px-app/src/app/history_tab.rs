//! History / サイトマップの通信の一覧（表とメモの編集）。

use std::collections::{BTreeSet, HashMap};

use egui::{Align, Color32, Layout, RichText};
use egui_extras::{Column, TableBuilder};
use px_store::{Filter, FlowSource, FlowSummary, Highlight};

use super::filter_bar::FilterForm;
use super::rows::{self, DeleteRequest, RowAction};
use super::style::{RED, highlight_color, severity_color, status_color, yellow};
use super::PxApp;
use crate::view;

const SUMMARY_CACHE_MAX: usize = 20_000;

/// History / サイトマップの一覧の状態。
pub(super) struct HistoryState {
    /// フィルタバーの条件
    pub(super) filter: Filter,
    /// フィルタバーの数値の入力欄
    pub(super) filter_form: FilterForm,
    /// 一覧に適用中の条件（フィルタバー + サイトマップで選んだノード）。`ids` はこの条件の結果
    pub(super) applied: Filter,
    /// 現在のフィルタに一致する ID（昇順）。行 i は ids[i]。
    pub(super) ids: Vec<i64>,
    /// この ID まで調べた（次はこれより後を取りに行く）
    pub(super) last_id: i64,
    /// 本文検索の途中（記録済みの通信を調べ終えていない）
    pub(super) scanning: bool,
    pub(super) total: i64,
    pub(super) cache: HashMap<i64, FlowSummary>,
    pub(super) follow: bool,
    /// 一覧で選んだ行（Ctrl / Shift で複数）。色付け・削除の対象
    pub(super) picked: BTreeSet<i64>,
    /// Shift で範囲を選ぶときの起点
    pub(super) anchor: Option<i64>,
    /// 確認待ちの削除
    pub(super) confirm_delete: Option<DeleteRequest>,
    /// 書き込み待ちの削除（その削除で消える ID の 1 つ）。消えたらサイトマップと検出を読み直す
    pub(super) pending_deletes: Vec<i64>,
    pub(super) scroll_to: Option<usize>,
    /// 編集中のメモ
    pub(super) note_edit: Option<NoteEdit>,
}

impl Default for HistoryState {
    fn default() -> Self {
        Self {
            filter: Filter::default(),
            filter_form: FilterForm::default(),
            applied: Filter::default(),
            ids: Vec::new(),
            last_id: 0,
            scanning: false,
            total: 0,
            cache: HashMap::new(),
            follow: true,
            picked: BTreeSet::new(),
            anchor: None,
            confirm_delete: None,
            pending_deletes: Vec::new(),
            scroll_to: None,
            note_edit: None,
        }
    }
}

/// History の一覧でメモを編集中の行。
pub(super) struct NoteEdit {
    pub(super) id: i64,
    pub(super) text: String,
    /// 次のフレームで入力欄にフォーカスを移す
    focus: bool,
}

impl PxApp {
    pub(super) fn history_table(&mut self, ui: &mut egui::Ui) {
        let row_h = ui.text_style_height(&egui::TextStyle::Body) + 6.0;
        // 選択可能なラベルはクリックを奪い、行が選択できなくなる
        ui.style_mut().interaction.selectable_labels = false;
        let mut table = TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .sense(egui::Sense::click())
            .cell_layout(Layout::left_to_right(Align::Center))
            .stick_to_bottom(self.history.follow)
            .column(Column::exact(60.0))
            .column(Column::exact(112.0))
            .column(Column::initial(240.0).clip(true))
            .column(Column::exact(64.0))
            .column(Column::initial(400.0).clip(true))
            .column(Column::exact(56.0))
            .column(Column::exact(72.0))
            .column(Column::exact(72.0))
            .column(Column::exact(64.0))
            .column(Column::initial(160.0).clip(true))
            .column(Column::remainder().at_least(120.0).clip(true));
        if let Some(i) = self.history.scroll_to.take() {
            table = table.scroll_to_row(i, None);
        }

        let HistoryState { ids, cache, picked, note_edit, .. } = &mut self.history;
        let reader = self.reader.as_ref();
        let selected = self.selected;
        let shown = ids.len();
        // (行, クリックしたときの修飾キー)
        let mut clicked: Option<(i64, egui::Modifiers)> = None;
        let mut row_action: Option<RowAction> = None;
        let mut scope_add: Option<(String, bool)> = None;
        let mut passthrough_add: Option<String> = None;
        let mut to_repeater = None;
        let mut to_comparer = None;
        // (id, 確定したメモ)。None は取り消し
        let mut note_done: Option<Option<(i64, String)>> = None;
        let mut note_start = None;
        if cache.len() > SUMMARY_CACHE_MAX {
            cache.clear();
        }

        table
            .header(row_h, |mut h| {
                for title in ["#", "時刻", "Host", "Method", "Path", "Status", "種類", "Length", "ms", "備考", "メモ"] {
                    let (_, r) = h.col(|ui| {
                        ui.strong(title);
                    });
                    match title {
                        "時刻" => r.on_hover_text("リクエストを受け取った時刻（ローカル時刻）"),
                        "備考" => r.on_hover_text(
                            "エラー・Intercept での編集・Repeater から送った通信・TLS パススルー・WebSocket・Body の切り詰め・パッシブチェックの検出を表示します",
                        ),
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
                    row.set_selected(selected == Some(id) || picked.contains(&id));
                    let tint = s.color.map(row_tint);
                    row.col(|ui| {
                        tint_cell(ui, tint);
                        ui.label(RichText::new(id.to_string()).weak());
                    });
                    row.col(|ui| {
                        tint_cell(ui, tint);
                        ui.label(view::format_time_short(s.started_at_us)).on_hover_text(view::format_datetime(s.started_at_us));
                    });
                    row.col(|ui| {
                        tint_cell(ui, tint);
                        let default_port = if s.scheme == "https" { 443 } else { 80 };
                        let host = if s.port == default_port {
                            format!("{}://{}", s.scheme, s.host)
                        } else {
                            format!("{}://{}:{}", s.scheme, s.host, s.port)
                        };
                        ui.add(egui::Label::new(host).truncate());
                    });
                    row.col(|ui| {
                        tint_cell(ui, tint);
                        ui.label(&s.method);
                    });
                    row.col(|ui| {
                        tint_cell(ui, tint);
                        ui.add(egui::Label::new(&s.target).truncate());
                    });
                    row.col(|ui| {
                        tint_cell(ui, tint);
                        match s.status {
                            _ if s.source == FlowSource::Tunnel && s.error.is_none() => {
                                ui.label(RichText::new("—").weak());
                            }
                            Some(code) => {
                                ui.label(RichText::new(code.to_string()).color(status_color(code)));
                            }
                            None => {
                                ui.label(RichText::new("ERR").color(RED));
                            }
                        }
                    });
                    row.col(|ui| {
                        tint_cell(ui, tint);
                        let r = ui.label(s.kind.label());
                        if let Some(ct) = &s.content_type {
                            r.on_hover_text(ct);
                        }
                    });
                    row.col(|ui| {
                        tint_cell(ui, tint);
                        ui.label(view::human_size(s.res_body_len));
                    });
                    row.col(|ui| {
                        tint_cell(ui, tint);
                        ui.label(format!("{}", s.duration_us / 1000));
                    });
                    row.col(|ui| {
                        tint_cell(ui, tint);
                        if let Some(sev) = s.max_severity {
                            ui.label(RichText::new("⚠").color(severity_color(ui, sev)))
                                .on_hover_text(format!("パッシブチェックの検出あり（最大の重要度: {}）", sev.label()));
                        }
                        if let Some(e) = &s.error {
                            ui.add(egui::Label::new(RichText::new(e).color(RED)).truncate());
                            return;
                        }
                        if s.edited != 0 {
                            let what = match s.edited {
                                px_store::EDITED_REQUEST => "Req",
                                px_store::EDITED_RESPONSE => "Res",
                                _ => "Req/Res",
                            };
                            ui.label(RichText::new(format!("編集済み ({what})")).color(yellow(ui)));
                        }
                        match s.source {
                            FlowSource::Repeater => {
                                ui.label(RichText::new("Repeater").weak());
                            }
                            FlowSource::Tunnel => {
                                ui.label(RichText::new("TLS パススルー").weak());
                            }
                            FlowSource::Mock => {
                                ui.label(RichText::new("ダミーサーバ").weak());
                            }
                            _ => {}
                        }
                        if s.status == Some(101) {
                            ui.label(RichText::new("WebSocket").color(Color32::from_rgb(100, 160, 240)));
                        }
                        if s.truncated != 0 {
                            ui.label(RichText::new("一部のみ記録").color(yellow(ui)))
                                .on_hover_text("Body が記録の上限を超えたため、先頭だけを記録しました");
                        }
                    });
                    let (_, note_cell) = row.col(|ui| {
                        tint_cell(ui, tint);
                        match note_edit.as_mut().filter(|e| e.id == id) {
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
                        }
                    });
                    if note_cell.double_clicked() {
                        note_start = Some(id);
                    }
                    let resp = row.response();
                    if resp.clicked() {
                        clicked = Some((id, resp.ctx.input(|i| i.modifiers)));
                    }
                    resp.context_menu(|ui| {
                        if ui.button("Repeater に送る (Ctrl+R)").clicked() {
                            to_repeater = Some(id);
                        }
                        if ui.button("Comparer に送る").on_hover_text("2 件送ると差分を表示します").clicked() {
                            to_comparer = Some(id);
                        }
                        if ui.button("メモを編集").clicked() {
                            note_start = Some(id);
                        }
                        ui.separator();
                        let targets = if picked.contains(&id) { picked.iter().copied().collect() } else { vec![id] };
                        rows::row_menu(ui, &targets, shown, &mut row_action);
                        ui.separator();
                        ui.label(RichText::new(&s.host).strong());
                        if ui.button("このホストを診断対象に追加").clicked() {
                            scope_add = Some((s.host.clone(), false));
                        }
                        if ui.button("このホストを診断対象から除外").clicked() {
                            scope_add = Some((s.host.clone(), true));
                        }
                        if s.scheme == "https"
                            && ui
                                .button("このホストを TLS パススルーに追加")
                                .on_hover_text("以降、このホストの HTTPS は復号せずにそのまま中継します（証明書ピンニングで失敗するアプリ向け）")
                                .clicked()
                        {
                            passthrough_add = Some(s.host.clone());
                        }
                    });
                });
            });

        if let Some((id, modifiers)) = clicked {
            self.click_row(id, modifiers);
        }
        if let Some(action) = row_action {
            self.apply_row_action(action);
        }
        if let Some((host, exclude)) = scope_add {
            self.add_scope_host(&host, exclude);
        }
        if let Some(host) = passthrough_add {
            self.add_passthrough_host(&host);
        }
        if let Some(id) = to_repeater {
            self.send_to_repeater(id);
        }
        if let Some(id) = to_comparer {
            self.send_to_comparer(id);
        }
        if let Some(done) = note_done {
            self.history.note_edit = None;
            if let Some((id, text)) = done {
                self.save_note(id, text);
            }
        }
        if let Some(id) = note_start {
            let text = self.history.cache.get(&id).and_then(|s| s.note.clone()).unwrap_or_default();
            self.history.note_edit = Some(NoteEdit { id, text, focus: true });
        }
    }

    /// メモを DB に書き、一覧のキャッシュにもすぐ反映する。
    pub(super) fn save_note(&mut self, id: i64, text: String) {
        let Some(project) = &self.project else { return };
        let text = text.trim().to_owned();
        if self.history.cache.get(&id).is_some_and(|s| s.note.as_deref().unwrap_or("") == text) {
            return;
        }
        project.sink().set_note(id, &text);
        if let Some(s) = self.history.cache.get_mut(&id) {
            s.note = (!text.is_empty()).then_some(text);
        }
    }
}

/// 一覧の行の背景（選択・縞模様が透けるよう半透明にする）。
fn row_tint(h: Highlight) -> Color32 {
    highlight_color(h).gamma_multiply(0.35)
}

/// セルの背景を塗る。文字より先に呼ぶ。
/// 列の間の隙間も塗るため、横方向だけセルの切り取り範囲の外まで描く（縦はスクロール範囲の切り取りに従う）。
fn tint_cell(ui: &egui::Ui, tint: Option<Color32>) {
    if let Some(c) = tint {
        let rect = ui.max_rect().expand2(egui::vec2(ui.spacing().item_spacing.x / 2.0, 0.0));
        let clip = egui::Rect::from_x_y_ranges(rect.x_range(), ui.clip_rect().y_range());
        ui.ctx().layer_painter(ui.layer_id()).with_clip_rect(clip).rect_filled(rect, 0.0, c);
    }
}
