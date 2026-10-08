//! History の詳細ペイン（整形・ハイライト・検索・WebSocket のメッセージ）と、エンコード / デコード窓。

use std::ops::Range;

use egui::text::{CCursor, LayoutJob};
use egui::{Align, Color32, Key, KeyboardShortcut, Layout, Modifiers, RichText};
use egui_extras::{Column, TableBuilder};
use px_store::{Finding, FlowSummary, Reader, WsMessage};

use super::{GREEN, PxApp, YELLOW, severity_color};
use crate::codec::{self, Output};
use crate::highlight::{self, MAX_MATCHES, Theme};
use crate::view::{self, Rendered};

pub(super) const SEARCH_KEY: KeyboardShortcut = KeyboardShortcut::new(Modifiers::CTRL, Key::F);
/// 変換結果 1 件の表示上限
const MAX_CODEC_SHOWN: usize = 64 * 1024;

/// Body の表示方法。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum ViewMode {
    Preview,
    Pretty,
    Raw,
}

impl ViewMode {
    pub(super) const ALL: [ViewMode; 3] = [Self::Preview, Self::Pretty, Self::Raw];

    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Preview => "プレビュー",
            Self::Pretty => "整形",
            Self::Raw => "Raw",
        }
    }

    pub(super) fn available(self, r: &Rendered) -> bool {
        match self {
            Self::Preview => r.image.is_some(),
            Self::Pretty => r.pretty.is_some(),
            Self::Raw => true,
        }
    }

    /// 希望の表示が使えなければ近いものにする。
    pub(super) fn resolve(self, r: &Rendered) -> Self {
        let order: &[Self] = match self {
            Self::Pretty => &[Self::Pretty, Self::Preview, Self::Raw],
            Self::Preview => &[Self::Preview, Self::Pretty, Self::Raw],
            Self::Raw => &[Self::Raw],
        };
        *order.iter().find(|m| m.available(r)).unwrap_or(&Self::Raw)
    }
}

/// 表示中テキストの一致箇所とハイライトのキャッシュ。
struct Painted {
    /// (編集前を表示, 表示方法, 検索語)
    text_key: (bool, ViewMode, String),
    matches: Vec<Range<usize>>,
    /// (現在の一致, 色とフォント)
    job_key: Option<(Option<usize>, Theme)>,
    job: LayoutJob,
}

pub(super) struct Detail {
    pub(super) id: i64,
    /// 一覧の行（時刻・所要時間・Body の切り詰めなど）
    summary: FlowSummary,
    /// パッシブチェックの検出（重い順）
    findings: Vec<Finding>,
    /// 記録した Body の長さ [Request, Response]（切り詰めの表示用）
    kept: [usize; 2],
    /// [Request, Response]
    sides: [Rendered; 2],
    /// Intercept で編集された場合の編集前 [Request, Response]
    originals: [Option<Rendered>; 2],
    /// 編集前を表示するか
    show_orig: [bool; 2],
    painted: [Option<Painted>; 2],
    /// WebSocket に切り替わった通信なら、そのメッセージ
    ws: Option<WsView>,
    /// HTTP ではなく WebSocket のメッセージを表示中
    show_ws: bool,
}

impl Detail {
    pub(super) fn new(
        summary: FlowSummary,
        findings: Vec<Finding>,
        kept: [usize; 2],
        sides: [Rendered; 2],
        originals: [Option<Rendered>; 2],
        ws: Option<Vec<WsMessage>>,
    ) -> Self {
        let show_ws = ws.as_ref().is_some_and(|m| !m.is_empty());
        Self {
            id: summary.id,
            summary,
            findings,
            kept,
            sides,
            originals,
            show_orig: [false; 2],
            painted: [None, None],
            ws: ws.map(WsView::new),
            show_ws,
        }
    }

    /// 記録が増えたら WebSocket のメッセージを読み足す。
    pub(super) fn refresh_ws(&mut self, reader: &Reader) {
        let Some(ws) = &mut self.ws else { return };
        match reader.ws_messages(self.id, ws.last_id) {
            Ok(more) => ws.append(more),
            Err(e) => tracing::warn!("websocket messages: {e}"),
        }
    }

    pub(super) fn image_uris(&self) -> impl Iterator<Item = &str> {
        self.sides
            .iter()
            .chain(self.originals.iter().flatten())
            .filter_map(|s| s.image.as_ref().map(|i| i.uri.as_str()))
    }

    fn shown(&self, i: usize) -> &Rendered {
        match &self.originals[i] {
            Some(o) if self.show_orig[i] => o,
            _ => &self.sides[i],
        }
    }

    fn text(&self, i: usize, mode: ViewMode) -> &str {
        let r = self.shown(i);
        match (mode, &r.pretty) {
            (ViewMode::Pretty, Some(p)) => p,
            _ => &r.text,
        }
    }

    /// 検索語・表示が変わったら一致箇所を数え直す。プレビュー表示中は検索しない。
    fn update_matches(&mut self, i: usize, mode: ViewMode, query: &str) {
        let key = (self.show_orig[i], mode, query.to_string());
        if self.painted[i].as_ref().is_some_and(|p| p.text_key == key) {
            return;
        }
        let matches = if query.is_empty() || mode == ViewMode::Preview {
            Vec::new()
        } else {
            highlight::find_matches(self.text(i, mode), query)
        };
        self.painted[i] = Some(Painted { text_key: key, matches, job_key: None, job: LayoutJob::default() });
    }

    fn matches(&self, i: usize) -> &[Range<usize>] {
        self.painted[i].as_ref().map_or(&[], |p| &p.matches)
    }

    /// ハイライト済みの (LayoutJob, 表示テキスト, 一致箇所)。`update_matches` の後に呼ぶ。
    fn painted(
        &mut self,
        i: usize,
        mode: ViewMode,
        current: Option<usize>,
        theme: &Theme,
    ) -> (&LayoutJob, &str, &[Range<usize>]) {
        let key = Some((current, theme.clone()));
        let r = match &self.originals[i] {
            Some(o) if self.show_orig[i] => o,
            _ => &self.sides[i],
        };
        let text = match (mode, &r.pretty) {
            (ViewMode::Pretty, Some(p)) => p,
            _ => &r.text,
        };
        let p = self.painted[i].as_mut().expect("update_matches first");
        if p.job_key != key {
            p.job = highlight::layout_job(text, r.body_start, r.syntax, &p.matches, current, theme);
            p.job_key = key;
        }
        (&p.job, text, &p.matches)
    }
}

/// 詳細ペインの検索状態。案件内で行を移っても残す。
#[derive(Default)]
pub(super) struct Search {
    query: String,
    /// Request → Response の順に通した一致の番号
    current: usize,
    /// 次のフレームで現在の一致までスクロールする
    scroll: bool,
    focus: bool,
}

impl Search {
    pub(super) fn focus(&mut self) {
        self.focus = true;
    }

    /// 表示する行が変わったら先頭の一致に戻る。
    pub(super) fn reset_position(&mut self) {
        self.current = 0;
        self.scroll = !self.query.is_empty();
    }
}

/// 変換結果のキャッシュ: (入力, デコード結果, エンコード結果)
type CodecResults = (String, Vec<(&'static str, Option<Output>)>, Vec<(&'static str, String)>);

/// 書き戻しのできる（編集可能な）エディタ。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EditTarget {
    /// Intercept で停止中のメッセージ（Held の id）
    Held(u64),
    /// Repeater のタブ（タブの id）
    Repeater(u64),
}

/// 詳細ペインやエディタで最後に選択したテキスト。
#[derive(Debug, Clone)]
pub(super) struct Selection {
    pub(super) text: String,
    /// 編集できるエディタでの選択なら、その場所とバイト範囲
    pub(super) edit: Option<(EditTarget, Range<usize>)>,
}

impl Selection {
    /// エディタの文字単位の選択範囲から作る。書き戻し用にバイト範囲へ直しておく。
    fn new(text: &str, range: egui::text::CCursorRange, edit: Option<EditTarget>) -> Self {
        let s = range.slice_str(text);
        let start = s.as_ptr() as usize - text.as_ptr() as usize;
        Self { text: s.to_owned(), edit: edit.map(|at| (at, start..start + s.len())) }
    }
}

/// 「選択範囲を置き換え」の書き戻し先。
struct ReplaceTarget {
    at: EditTarget,
    /// 置き換える範囲（バイト位置）
    range: Range<usize>,
    /// その範囲にあるはずのテキスト。食い違ったらエディタ側が編集されたとみなして置き換えない
    expected: String,
}

/// 変換結果に対する操作。
enum CodecAction {
    /// 結果で入力欄を置き換える
    Input(String),
    /// 結果で元のエディタの選択範囲を置き換える
    Replace(String),
}

/// エンコード / デコード窓。
#[derive(Default)]
pub(super) struct CodecWindow {
    open: bool,
    input: String,
    cache: Option<CodecResults>,
    target: Option<ReplaceTarget>,
}

impl CodecWindow {
    /// 窓を開く。選択があればそれを入力にし、編集できるエディタの選択なら書き戻し先も覚える。
    pub(super) fn open_with(&mut self, selection: Option<&Selection>) {
        self.open = true;
        if let Some(s) = selection {
            self.input = s.text.clone();
            self.target = s.edit.clone().map(|(at, range)| ReplaceTarget { at, range, expected: s.text.clone() });
        }
    }
}

impl PxApp {
    pub(super) fn detail_pane(&mut self, ui: &mut egui::Ui) {
        let Self { detail, search, view_pref, codec, selection, .. } = self;
        let Some(d) = detail else {
            ui.centered_and_justified(|ui| ui.label(RichText::new("行を選択するとリクエスト/レスポンスを表示します").weak()));
            return;
        };
        let modes: [ViewMode; 2] = std::array::from_fn(|i| view_pref[i].resolve(d.shown(i)));

        // ---- 日時・所要時間・記録の注記・検出
        info_bar(ui, d);
        if d.show_ws
            && let Some(ws) = &mut d.ws
        {
            ws_pane(ui, ws, selection);
            return;
        }

        // ---- 検索バー
        ui.horizontal(|ui| {
            let edit = ui.add(
                egui::TextEdit::singleline(&mut search.query)
                    .hint_text("🔍 Request / Response 内を検索 (Ctrl+F)")
                    .desired_width(280.0),
            );
            if std::mem::take(&mut search.focus) {
                edit.request_focus();
            }
            if edit.changed() {
                search.reset_position();
            }
            let enter = edit.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
            for (i, &mode) in modes.iter().enumerate() {
                d.update_matches(i, mode, &search.query);
            }
            let total = d.matches(0).len() + d.matches(1).len();
            let shift = ui.input(|i| i.modifiers.shift);
            let prev = ui.add_enabled(total > 0, egui::Button::new("▲").small()).on_hover_text("前へ (Shift+Enter)").clicked();
            let next = ui.add_enabled(total > 0, egui::Button::new("▼").small()).on_hover_text("次へ (Enter)").clicked();
            if total > 0 && (prev || next || enter) {
                let back = prev || (enter && shift);
                search.current = if back { (search.current + total - 1) % total } else { (search.current + 1) % total };
                search.scroll = true;
            }
            if enter {
                // Enter で続けて次へ進めるようにフォーカスを戻す
                edit.request_focus();
            }
            if total > 0 {
                search.current = search.current.min(total - 1);
                let capped = if d.matches(0).len() >= MAX_MATCHES || d.matches(1).len() >= MAX_MATCHES { "+" } else { "" };
                ui.label(format!("{} / {total}{capped}", search.current + 1));
            } else if !search.query.is_empty() {
                ui.label(RichText::new("見つかりません").weak());
            }
            ui.separator();
            if ui.button("デコード…").on_hover_text("選択中のテキストをエンコード / デコード（右クリックからも）").clicked() {
                codec.open_with(selection.as_ref());
            }
        });
        ui.add_space(2.0);

        // ---- Request / Response
        let n0 = d.matches(0).len();
        let total = n0 + d.matches(1).len();
        let current_in = |i: usize| -> Option<usize> {
            let c = (total > 0).then_some(search.current)?;
            match i {
                0 => (c < n0).then_some(c),
                _ => c.checked_sub(n0),
            }
        };
        let theme = Theme {
            font: egui::TextStyle::Monospace.resolve(ui.style()),
            dark: ui.visuals().dark_mode,
            plain: ui.visuals().text_color(),
        };
        let mut open_codec = false;

        ui.columns(2, |cols| {
            for (i, (ui, title)) in cols.iter_mut().zip(["Request", "Response"]).enumerate() {
                ui.horizontal(|ui| {
                    ui.strong(title);
                    if d.originals[i].is_some() {
                        ui.separator();
                        if ui.selectable_label(!d.show_orig[i], "編集後").clicked() {
                            d.show_orig[i] = false;
                        }
                        if ui.selectable_label(d.show_orig[i], RichText::new("編集前").color(YELLOW)).clicked() {
                            d.show_orig[i] = true;
                        }
                    }
                    let side = d.shown(i);
                    let available: Vec<ViewMode> = ViewMode::ALL.into_iter().filter(|m| m.available(side)).collect();
                    if available.len() > 1 {
                        ui.separator();
                        for m in available {
                            if ui.selectable_label(modes[i] == m, m.label()).clicked() {
                                view_pref[i] = m;
                            }
                        }
                    }
                    ui.separator();
                    if ui.small_button("コピー").on_hover_text("表示中のテキストをコピー").clicked() {
                        ui.ctx().copy_text(d.text(i, modes[i]).to_owned());
                    }
                });
                let scroll_id = (title, d.show_orig[i], modes[i]);
                egui::ScrollArea::both().id_salt(scroll_id).auto_shrink(false).show(ui, |ui| {
                    if modes[i] == ViewMode::Preview
                        && let Some(img) = &d.shown(i).image
                    {
                        image_view(ui, &d.shown(i).head, img);
                        return;
                    }
                    let current = current_in(i);
                    let (job, mut text, matches) = d.painted(i, modes[i], current, &theme);
                    let mut layouter =
                        |ui: &egui::Ui, _: &dyn egui::TextBuffer, _wrap: f32| ui.fonts_mut(|f| f.layout_job(job.clone()));
                    let edit = egui::TextEdit::multiline(&mut text)
                        .font(egui::TextStyle::Monospace)
                        .desired_width(f32::INFINITY)
                        .code_editor()
                        .layouter(&mut layouter);
                    let out = show_keeping_selection(ui, scroll_id, edit);
                    open_codec |= selection_menu(&out, text, None, selection);
                    if search.scroll
                        && let Some(c) = current
                        && let Some(hit) = matches.get(c)
                    {
                        let char_index = text[..hit.start].chars().count();
                        let rect = out.galley.pos_from_cursor(CCursor::new(char_index)).translate(out.galley_pos.to_vec2());
                        ui.scroll_to_rect(rect.expand(16.0), Some(Align::Center));
                        search.scroll = false;
                    }
                });
            }
        });
        if open_codec {
            codec.open_with(selection.as_ref());
        }
    }

    pub(super) fn codec_window(&mut self, ctx: &egui::Context) {
        let codec = &mut self.codec;
        if !codec.open {
            return;
        }
        if codec.cache.as_ref().is_none_or(|(input, ..)| *input != codec.input) {
            codec.cache = Some((codec.input.clone(), codec::decode_all(&codec.input), codec::encode_all(&codec.input)));
        }
        let mut open = true;
        let mut action = None;
        let can_replace = codec.target.is_some();
        egui::Window::new("エンコード / デコード").open(&mut open).default_size([560.0, 520.0]).show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label("入力");
                if let Some(t) = &codec.target {
                    let place = match t.at {
                        EditTarget::Held(_) => "Intercept の編集欄",
                        EditTarget::Repeater(_) => "Repeater の Request",
                    };
                    ui.label(RichText::new(format!("（置き換え先: {place} の選択範囲）")).weak());
                }
            });
            egui::ScrollArea::vertical().id_salt("codec_input").max_height(120.0).show(ui, |ui| {
                ui.add(
                    egui::TextEdit::multiline(&mut codec.input)
                        .font(egui::TextStyle::Monospace)
                        .desired_rows(3)
                        .desired_width(f32::INFINITY)
                        .hint_text("変換したい文字列を貼り付け（詳細ペインで選択して「デコード…」でも入ります）"),
                );
            });
            ui.separator();
            if codec.input.is_empty() {
                ui.label(RichText::new("入力すると、各方式でデコード / エンコードした結果がここに並びます。").weak());
                return;
            }
            let Some((_, decoded, encoded)) = &codec.cache else { return };
            egui::ScrollArea::vertical().id_salt("codec_results").auto_shrink([false, true]).show(ui, |ui| {
                ui.strong("デコード");
                for (name, out) in decoded {
                    let text = out.as_ref().map(|o| o.to_string());
                    let reusable = match out {
                        Some(Output::Text(t)) => Some(t.as_str()),
                        _ => None,
                    };
                    result_row(ui, name, text.as_deref(), reusable, can_replace, &mut action);
                }
                ui.add_space(8.0);
                ui.strong("エンコード");
                for (name, out) in encoded {
                    result_row(ui, name, Some(out), Some(out), can_replace, &mut action);
                }
            });
        });
        codec.open = open;
        match action {
            Some(CodecAction::Input(t)) => codec.input = t,
            Some(CodecAction::Replace(t)) => self.replace_selection(t),
            None => {}
        }
    }

    /// デコード窓の結果で、窓を開いたときのエディタの選択範囲を置き換える。
    fn replace_selection(&mut self, new: String) {
        let Some(t) = &mut self.codec.target else { return };
        let text = match t.at {
            EditTarget::Held(id) => self.editors.get_mut(&id).map(|e| &mut e.text),
            EditTarget::Repeater(id) => self.repeater.text_mut(id),
        };
        self.status = match text {
            None => "置き換え先のエディタはもう閉じられています".into(),
            Some(text) => match t.apply(text, new) {
                Ok(()) => "選択範囲を置き換えました".into(),
                Err(()) => "元の選択範囲が編集されたため置き換えられません。選択し直してから開いてください".into(),
            },
        };
    }
}

impl ReplaceTarget {
    /// `text` の範囲を `new` で置き換える。範囲のテキストが `expected` と違えば何もせず Err。
    fn apply(&mut self, text: &mut String, new: String) -> Result<(), ()> {
        if text.get(self.range.clone()) != Some(self.expected.as_str()) {
            return Err(());
        }
        text.replace_range(self.range.clone(), &new);
        // 続けて別の結果で置き換え直せるよう、置き換えた後の範囲を追う
        self.range = self.range.start..self.range.start + new.len();
        self.expected = new;
        Ok(())
    }
}

/// 複数行エディタを表示する。egui はどのボタンでも押した位置にカーソルを移すので、
/// 右クリックでコンテキストメニューを開くと選択が消えてしまう。右ボタンを押している間は直前の選択に戻す。
/// `id_salt` は画面内でエディタごとに一意な値（`ui.columns` の左右などは親の id が同じになるため）。
pub(super) fn show_keeping_selection(
    ui: &mut egui::Ui,
    id_salt: impl std::hash::Hash + std::fmt::Debug,
    edit: egui::TextEdit<'_>,
) -> egui::text_edit::TextEditOutput {
    let id = egui::Id::new(("text_edit", id_salt));
    let before = egui::text_edit::TextEditState::load(ui.ctx(), id).and_then(|s| s.cursor.char_range());
    let mut out = edit.id(id).show(ui);
    let right_down = ui.input(|i| i.pointer.secondary_down() || i.pointer.secondary_pressed());
    // `out.cursor_range` はポインタ処理より前の値なので、実際に保存された `out.state` と比べる
    if right_down
        && out.response.response.hovered()
        && let Some(range) = before.filter(|r| !r.is_empty())
        && out.state.cursor.char_range() != Some(range)
    {
        out.state.cursor.set_char_range(Some(range));
        out.state.clone().store(ui.ctx(), id);
        out.cursor_range = Some(range);
    }
    out
}

/// 複数行エディタの選択範囲を `selection` に覚え、右クリックメニューに「選択範囲をデコード…」を出す。
/// `edit` は書き戻しのできるエディタならその場所（読み取り専用なら None）。
/// メニューで選ばれたら true を返すので、呼び出し側でデコード窓を開く。
pub(super) fn selection_menu(
    out: &egui::text_edit::TextEditOutput,
    text: &str,
    edit: Option<EditTarget>,
    selection: &mut Option<Selection>,
) -> bool {
    // 選択範囲はフォーカスがある間だけ取れるので、外れても直前の選択を覚えておく
    if let Some(range) = out.cursor_range {
        *selection = (!range.is_empty()).then(|| Selection::new(text, range, edit));
    }
    let mut open = false;
    out.response.response.context_menu(|ui| {
        if ui.add_enabled(selection.is_some(), egui::Button::new("選択範囲をデコード…")).clicked() {
            open = true;
            ui.close();
        }
    });
    open
}

/// 変換結果 1 件: 見出し行（方式名・コピー・入力へ）と、その下に全幅で折り返す等幅テキスト。
/// `text` が None ならその方式では解釈できないものとして「—」だけ出す。
/// `reusable` はテキストとして再利用できる結果（バイナリは None）、`can_replace` は書き戻し先があるか。
fn result_row(
    ui: &mut egui::Ui,
    name: &str,
    text: Option<&str>,
    reusable: Option<&str>,
    can_replace: bool,
    action: &mut Option<CodecAction>,
) {
    ui.add_space(4.0);
    ui.horizontal(|ui| {
        ui.label(RichText::new(name).strong());
        let Some(text) = text else {
            ui.label(RichText::new("—").weak());
            return;
        };
        if ui.small_button("📋 コピー").on_hover_text("この結果をクリップボードへコピー").clicked() {
            ui.ctx().copy_text(text.to_owned());
        }
        if let Some(r) = reusable
            && ui
                .small_button("↑ 入力にする")
                .on_hover_text("この結果で入力欄を置き換える（二重エンコードなどを続けて変換するとき）")
                .clicked()
        {
            *action = Some(CodecAction::Input(r.to_owned()));
        }
        if can_replace
            && let Some(r) = reusable
            && ui
                .small_button("選択範囲を置き換え")
                .on_hover_text("この結果で、デコード窓を開いたときのエディタの選択範囲を置き換える")
                .clicked()
        {
            *action = Some(CodecAction::Replace(r.to_owned()));
        }
    });
    if let Some(text) = text {
        let shown = view::truncate_str(text, MAX_CODEC_SHOWN);
        egui::Frame::new().fill(ui.visuals().faint_bg_color).inner_margin(4.0).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.add(egui::Label::new(RichText::new(shown).monospace()).wrap().selectable(true));
        });
    }
}

/// 詳細ペインの先頭の 1 行: 日時・所要時間・Body の切り詰め・パッシブチェックの検出・HTTP / WebSocket の切り替え。
fn info_bar(ui: &mut egui::Ui, d: &mut Detail) {
    let s = &d.summary;
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new(format!("#{}", s.id)).strong());
        ui.label(view::format_datetime(s.started_at_us)).on_hover_text("リクエストを受け取った時刻（ローカル時刻）");
        ui.label(RichText::new(format!("{} ms", s.duration_us / 1000)).weak()).on_hover_text("所要時間");
        for (bit, side, len, kept) in [
            (px_store::TRUNCATED_REQUEST, "Request", s.req_body_len, d.kept[0]),
            (px_store::TRUNCATED_RESPONSE, "Response", s.res_body_len, d.kept[1]),
        ] {
            if s.truncated & bit != 0 {
                ui.separator();
                ui.label(RichText::new(format!("{side} の Body は先頭 {} のみ記録（全体 {}）", view::human_size(kept as i64), view::human_size(len))).color(YELLOW))
                    .on_hover_text("「診断対象 / ルール」の「記録する Body の上限」を超えたため、通信はそのまま流し、先頭だけを記録しました");
            }
        }
        if let Some(worst) = d.findings.first().map(|f| f.severity) {
            ui.separator();
            let label = RichText::new(format!("⚠ 検出 {} 件", d.findings.len())).color(severity_color(worst));
            ui.label(label).on_hover_ui(|ui| {
                for f in &d.findings {
                    let title = px_store::passive::check(&f.check).map_or(f.check.as_str(), |c| c.title);
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(format!("[{}]", f.severity.label())).color(severity_color(f.severity)));
                        ui.label(format!("{title}: {}", f.detail));
                    });
                }
            });
        }
        if let Some(ws) = &d.ws {
            ui.separator();
            if ui.selectable_label(!d.show_ws, "HTTP").clicked() {
                d.show_ws = false;
            }
            if ui.selectable_label(d.show_ws, format!("WebSocket ({})", ws.messages.len())).clicked() {
                d.show_ws = true;
            }
        }
    });
}

/// WebSocket のメッセージ一覧と、選んだメッセージの中身。
pub(super) struct WsView {
    messages: Vec<WsMessage>,
    last_id: i64,
    selected: Option<usize>,
    /// 選んだメッセージの表示用テキスト (位置, テキスト)
    shown: Option<(usize, String)>,
    /// 新しいメッセージが来たら末尾を表示する
    follow: bool,
}

/// 一覧に出す中身の長さ
const WS_PREVIEW: usize = 160;
/// メッセージの中身の表示上限
const WS_MAX_SHOWN: usize = 512 * 1024;

impl WsView {
    fn new(messages: Vec<WsMessage>) -> Self {
        let mut v = Self { messages: Vec::new(), last_id: 0, selected: None, shown: None, follow: true };
        v.append(messages);
        v
    }

    fn append(&mut self, more: Vec<WsMessage>) {
        if let Some(m) = more.last() {
            self.last_id = m.id;
        }
        self.messages.extend(more);
    }

    fn text_of(m: &WsMessage) -> String {
        if m.opcode == WsMessage::BINARY || std::str::from_utf8(&m.data).is_err() {
            let mut out = String::new();
            let shown = &m.data[..m.data.len().min(64 * 1024)];
            view::hexdump(&mut out, shown);
            if m.data.len() > shown.len() {
                out.push_str(&format!("[... {} bytes 省略 ...]", m.data.len() - shown.len()));
            }
            return out;
        }
        let text = String::from_utf8_lossy(&m.data);
        let text = view::pretty_json(&text).unwrap_or_else(|| text.into_owned());
        view::truncate_str(&text, WS_MAX_SHOWN).to_string()
    }
}

fn ws_preview(m: &WsMessage) -> String {
    if m.data.is_empty() {
        return String::new();
    }
    match std::str::from_utf8(&m.data[..m.data.len().min(WS_PREVIEW * 4)]) {
        Ok(s) if m.opcode != WsMessage::BINARY => s.chars().take(WS_PREVIEW).map(|c| if c.is_control() { ' ' } else { c }).collect(),
        _ => m.data.iter().take(32).map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" "),
    }
}

fn ws_pane(ui: &mut egui::Ui, ws: &mut WsView, selection: &mut Option<Selection>) {
    if ws.messages.is_empty() {
        ui.centered_and_justified(|ui| ui.label(RichText::new("まだメッセージがありません（通信が続いている間は届いたものから表示します）").weak()));
        return;
    }
    let row_h = ui.text_style_height(&egui::TextStyle::Body) + 4.0;
    let mut clicked = None;
    ui.columns(2, |cols| {
        let ui = &mut cols[0];
        ui.horizontal(|ui| {
            ui.strong(format!("メッセージ {} 件", ws.messages.len()));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| ui.checkbox(&mut ws.follow, "末尾に追従"));
        });
        ui.style_mut().interaction.selectable_labels = false;
        TableBuilder::new(ui)
            .id_salt("ws_messages")
            .striped(true)
            .sense(egui::Sense::click())
            .cell_layout(Layout::left_to_right(Align::Center))
            .stick_to_bottom(ws.follow)
            .column(Column::exact(28.0))
            .column(Column::exact(96.0))
            .column(Column::exact(52.0))
            .column(Column::exact(60.0))
            .column(Column::remainder().clip(true))
            .header(row_h, |mut h| {
                for t in ["", "時刻", "種類", "長さ", "内容"] {
                    h.col(|ui| {
                        ui.strong(t);
                    });
                }
            })
            .body(|body| {
                body.rows(row_h, ws.messages.len(), |mut row| {
                    let i = row.index();
                    let m = &ws.messages[i];
                    row.set_selected(ws.selected == Some(i));
                    row.col(|ui| {
                        let (arrow, color, tip) = if m.from_client {
                            ("↑", GREEN, "クライアント → サーバ")
                        } else {
                            ("↓", Color32::from_rgb(100, 160, 240), "サーバ → クライアント")
                        };
                        ui.label(RichText::new(arrow).color(color).strong()).on_hover_text(tip);
                    });
                    row.col(|ui| {
                        ui.label(RichText::new(view::format_clock(m.at_us)).weak());
                    });
                    row.col(|ui| {
                        ui.label(m.opcode_label());
                    });
                    row.col(|ui| {
                        ui.label(view::human_size(m.len as i64));
                    });
                    row.col(|ui| {
                        ui.add(egui::Label::new(RichText::new(ws_preview(m)).monospace()).truncate());
                    });
                    if row.response().clicked() {
                        clicked = Some(i);
                    }
                });
            });

        let ui = &mut cols[1];
        let Some(i) = ws.selected else {
            ui.centered_and_justified(|ui| ui.label(RichText::new("メッセージを選ぶと中身を表示します").weak()));
            return;
        };
        let m = &ws.messages[i];
        if ws.shown.as_ref().is_none_or(|(at, _)| *at != i) {
            ws.shown = Some((i, WsView::text_of(m)));
        }
        let text = &ws.shown.as_ref().expect("set above").1;
        ui.horizontal_wrapped(|ui| {
            ui.strong(if m.from_client { "↑ クライアント → サーバ" } else { "↓ サーバ → クライアント" });
            ui.label(format!("{}  {} bytes  {}", m.opcode_label(), m.len, view::format_datetime(m.at_us)));
            if m.len > m.data.len() as u64 {
                ui.label(RichText::new(format!("（先頭 {} のみ記録）", view::human_size(m.data.len() as i64))).color(YELLOW));
            }
            if ui.small_button("コピー").clicked() {
                ui.ctx().copy_text(text.clone());
            }
        });
        egui::ScrollArea::both().id_salt(("ws_body", i)).auto_shrink(false).show(ui, |ui| {
            let mut shown = text.as_str();
            let edit = egui::TextEdit::multiline(&mut shown)
                .font(egui::TextStyle::Monospace)
                .desired_width(f32::INFINITY)
                .code_editor();
            let out = show_keeping_selection(ui, ("ws_body", i), edit);
            selection_menu(&out, shown, None, selection);
        });
    });
    if let Some(i) = clicked {
        ws.selected = Some(i);
        ws.follow = false;
    }
}

/// ヘッダ + 画像プレビュー。原寸より大きくはせず、ペイン幅に収まるよう縮小する。
pub(super) fn image_view(ui: &mut egui::Ui, head: &str, img: &view::ImagePreview) {
    ui.add(egui::Label::new(RichText::new(head.trim_end()).monospace()).selectable(true));
    ui.add_space(4.0);
    let dims = img.size.map(|(w, h)| format!("  {w}×{h}")).unwrap_or_default();
    ui.label(RichText::new(format!("{}{dims}  {}", img.mime, view::human_size(img.bytes.len() as i64))).weak());
    ui.add_space(4.0);
    egui::Frame::new().fill(ui.visuals().extreme_bg_color).inner_margin(8.0).show(ui, |ui| {
        ui.add(
            egui::Image::new(egui::ImageSource::Bytes { uri: img.uri.clone().into(), bytes: img.bytes.clone().into() })
                .fit_to_original_size(1.0)
                .max_width(ui.available_width()),
        );
    });
}

#[cfg(test)]
mod tests {
    use egui::text::{CCursor, CCursorRange};

    use super::*;

    fn target(text: &str, range: Range<usize>) -> ReplaceTarget {
        ReplaceTarget { at: EditTarget::Repeater(1), expected: text[range.clone()].to_owned(), range }
    }

    #[test]
    fn selection_converts_char_range_to_bytes() {
        // マルチバイト文字の後ろを選んでもバイト位置で覚える。選ぶ向き（後ろ→前）にもよらない
        let text = "日本 a=QUJD&b";
        let range = CCursorRange::two(CCursor::new(7), CCursor::new(3));
        let s = Selection::new(text, range, Some(EditTarget::Held(9)));
        assert_eq!(s.text, "a=QU");
        let (at, r) = s.edit.unwrap();
        assert_eq!(at, EditTarget::Held(9));
        assert_eq!(&text[r], "a=QU");
        assert!(Selection::new(text, range, None).edit.is_none(), "読み取り専用なら書き戻し先なし");
    }

    #[test]
    fn replace_then_replace_again() {
        let mut text = "Cookie: s=eyJ1IjoiZyJ9; x=1".to_owned();
        let start = text.find("eyJ").unwrap();
        let mut t = target(&text, start..start + 12);
        t.apply(&mut text, "{\"u\":\"g\"}".into()).unwrap();
        assert_eq!(text, "Cookie: s={\"u\":\"g\"}; x=1");
        // 置き換えた範囲を追っているので、別の結果（長さ違い・マルチバイト）でやり直せる
        t.apply(&mut text, "管理者".into()).unwrap();
        assert_eq!(text, "Cookie: s=管理者; x=1");
        t.apply(&mut text, "eyJ1IjoiYSJ9".into()).unwrap();
        assert_eq!(text, "Cookie: s=eyJ1IjoiYSJ9; x=1");
    }

    #[test]
    fn replace_refuses_when_editor_changed() {
        let mut text = "a=QUJD".to_owned();
        let mut t = target(&text, 2..6);
        text.insert(0, 'X'); // 窓を開いた後にエディタ側が編集された
        assert!(t.apply(&mut text, "ABC".into()).is_err());
        assert_eq!(text, "Xa=QUJD", "食い違ったら触らない");
        text.truncate(3); // 範囲が文字列の外に出ても panic しない
        assert!(t.apply(&mut text, "ABC".into()).is_err());
    }
}

#[cfg(test)]
mod gui_tests {
    use egui::{Event, Modifiers, PointerButton, Pos2, Rect};
    use egui_kittest::Harness;
    use egui_kittest::kittest::Queryable;

    use super::*;

    struct State {
        text: String,
        selection: Option<Selection>,
        rect: Rect,
        open: bool,
    }

    fn harness() -> Harness<'static, State> {
        let state = State { text: "Cookie: s=QUJDREVG; x=1".into(), selection: None, rect: Rect::NOTHING, open: false };
        Harness::new_ui_state(
            |ui, s: &mut State| {
                let edit = egui::TextEdit::multiline(&mut s.text).desired_width(400.0);
                let out = show_keeping_selection(ui, "test", edit);
                s.rect = out.galley.rect.translate(out.galley_pos.to_vec2());
                s.open |= selection_menu(&out, &s.text, Some(EditTarget::Repeater(1)), &mut s.selection);
            },
            state,
        )
    }

    fn button(h: &mut Harness<'_, State>, pos: Pos2, button: PointerButton, pressed: bool) {
        h.event(Event::PointerMoved(pos));
        h.event(Event::PointerButton { pos, button, pressed, modifiers: Modifiers::NONE });
        h.step();
    }

    #[test]
    fn right_click_keeps_selection_and_menu_opens_codec() {
        let mut h = harness();
        h.run_steps(2);
        let r = h.state().rect;
        let y = r.center().y;
        let x = |frac: f32| r.left() + r.width() * frac;
        // ドラッグで選択
        button(&mut h, Pos2::new(x(0.3), y), PointerButton::Primary, true);
        for f in [0.4, 0.5, 0.6] {
            h.event(Event::PointerMoved(Pos2::new(x(f), y)));
            h.step();
        }
        button(&mut h, Pos2::new(x(0.6), y), PointerButton::Primary, false);
        h.run_steps(2);
        let before = h.state().selection.clone().expect("ドラッグで選択できている").text;
        assert!(!before.is_empty());

        // 選択の内側で右クリック
        button(&mut h, Pos2::new(x(0.45), y), PointerButton::Secondary, true);
        button(&mut h, Pos2::new(x(0.45), y), PointerButton::Secondary, false);
        h.run_steps(3);
        assert_eq!(h.state().selection.as_ref().map(|s| s.text.clone()), Some(before.clone()), "右クリックで選択が消えない");

        // メニューの「選択範囲をデコード…」が押せる
        h.get_by_label("選択範囲をデコード…").click();
        h.run_steps(3);
        assert!(h.state().open, "メニューからデコード窓を開ける");
        assert_eq!(h.state().selection.as_ref().map(|s| s.text.clone()), Some(before));
    }
}
