//! Comparer タブ: 2 つの通信のリクエスト / レスポンスを左右に並べて差分を表示する。
//! 権限の違うアカウントで同じ操作をしたときの応答の違いなどを見る。

use std::ops::Range;

use egui::text::{LayoutJob, TextFormat};
use egui::{Align, Color32, Layout, RichText};
use egui_extras::{Column, TableBuilder};

use super::PxApp;
use crate::diff::{self, Diff, Line};
use crate::view::{self, Rendered};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Part {
    Request,
    Response,
}

/// 比べる通信 1 件。表示用に Content-Encoding を展開した状態で持つ。
pub(super) struct CompareItem {
    id: i64,
    label: String,
    /// [Request, Response]
    sides: [Rendered; 2],
}

impl CompareItem {
    pub(super) fn new(id: i64, label: String, sides: [Rendered; 2]) -> Self {
        Self { id, label, sides }
    }

    fn text(&self, part: Part, pretty: bool) -> &str {
        let r = &self.sides[part as usize];
        match (&r.pretty, pretty) {
            (Some(p), true) => p,
            _ => &r.text,
        }
    }
}

/// 差分の計算に使った条件（変わったら計算し直す）。
type DiffKey = (i64, i64, Part, bool);

pub(super) struct Comparer {
    /// [A, B]
    slots: [Option<CompareItem>; 2],
    part: Part,
    /// JSON / HTML / XML は整形してから比べる
    pretty: bool,
    diff: Option<(DiffKey, Diff)>,
    /// 今いる変更のかたまり
    hunk: usize,
    scroll_to: Option<usize>,
}

impl Default for Comparer {
    fn default() -> Self {
        Self { slots: [None, None], part: Part::Response, pretty: true, diff: None, hunk: 0, scroll_to: None }
    }
}

impl Comparer {
    /// 空いている方に入れる。両方埋まっていれば B を A へ送り、新しいものを B にする。
    /// 入れた側の名前（"A" / "B"）を返す。
    pub(super) fn push(&mut self, item: CompareItem) -> &'static str {
        self.diff = None;
        if self.slots[0].is_none() {
            self.slots[0] = Some(item);
            "A"
        } else if self.slots[1].is_none() {
            self.slots[1] = Some(item);
            "B"
        } else {
            self.slots[0] = self.slots[1].take();
            self.slots[1] = Some(item);
            "B"
        }
    }

    pub(super) fn len(&self) -> usize {
        self.slots.iter().flatten().count()
    }

    pub(super) fn clear(&mut self) {
        *self = Self::default();
    }

    pub(super) fn image_uris(&self) -> impl Iterator<Item = &str> {
        self.slots.iter().flatten().flat_map(|i| i.sides.iter()).filter_map(|r| r.image.as_ref().map(|i| i.uri.as_str()))
    }
}

/// 削除・追加された行の背景と、行内で違う箇所の背景。
fn colors(dark: bool, left: bool) -> (Color32, Color32) {
    match (dark, left) {
        (true, true) => (Color32::from_rgba_unmultiplied(200, 60, 60, 40), Color32::from_rgba_unmultiplied(230, 80, 80, 110)),
        (true, false) => (Color32::from_rgba_unmultiplied(60, 170, 90, 40), Color32::from_rgba_unmultiplied(80, 200, 120, 110)),
        (false, true) => (Color32::from_rgb(255, 235, 235), Color32::from_rgb(255, 190, 190)),
        (false, false) => (Color32::from_rgb(230, 255, 236), Color32::from_rgb(170, 240, 190)),
    }
}

/// 表示する行の長さの上限（それ以上はホバーで全体を出す）
const MAX_LINE_SHOWN: usize = 2000;

fn line_job(text: &str, spans: &[Range<usize>], font: egui::FontId, color: Color32, highlight: Color32) -> LayoutJob {
    let text = view::truncate_str(text, MAX_LINE_SHOWN);
    let mut job = LayoutJob::default();
    let plain = TextFormat { font_id: font.clone(), color, ..Default::default() };
    let marked = TextFormat { background: highlight, ..plain.clone() };
    let mut at = 0;
    for s in spans {
        let (start, end) = (s.start.min(text.len()), s.end.min(text.len()));
        if start < at || !text.is_char_boundary(start) || !text.is_char_boundary(end) {
            continue;
        }
        if at < start {
            job.append(&text[at..start], 0.0, plain.clone());
        }
        job.append(&text[start..end], 0.0, marked.clone());
        at = end;
    }
    if at < text.len() || job.sections.is_empty() {
        job.append(&text[at..], 0.0, plain);
    }
    job
}

impl PxApp {
    /// History の通信を Comparer に入れる。
    pub(super) fn send_to_comparer(&mut self, id: i64) {
        let Some(reader) = &self.reader else { return };
        match reader.detail(id) {
            Ok(Some(d)) => {
                let s = &d.summary;
                let label = format!("#{id} {} {}{} → {}", s.method, s.host, s.target, s.status.map_or("ERR".into(), |c| c.to_string()));
                let request = view::render_message(&d.req_head, &d.req_body, &format!("{id}/cmp-req"));
                let response = match &d.res_head {
                    Some(h) => view::render_message(h, &d.res_body, &format!("{id}/cmp-res")),
                    None => Rendered::plain(s.error.clone().map(|e| format!("[エラー] {e}")).unwrap_or_default()),
                };
                for uri in self.comparer.image_uris() {
                    self.egui_ctx.forget_image(uri);
                }
                let slot = self.comparer.push(CompareItem::new(id, label, [request, response]));
                self.status = format!("#{id} を Comparer の {slot} に入れました");
            }
            Ok(None) => {}
            Err(e) => self.status = format!("読み込みに失敗: {e}"),
        }
    }

    pub(super) fn comparer_tab(&mut self, ui: &mut egui::Ui) {
        let c = &mut self.comparer;
        ui.horizontal_wrapped(|ui| {
            let mut remove = None;
            for (i, name) in ["A", "B"].into_iter().enumerate() {
                ui.label(RichText::new(name).strong());
                match &c.slots[i] {
                    Some(item) => {
                        ui.label(RichText::new(&item.label).monospace());
                        if ui.small_button("×").on_hover_text("外す").clicked() {
                            remove = Some(i);
                        }
                    }
                    None => {
                        ui.label(RichText::new("（未設定）").weak());
                    }
                }
                ui.separator();
            }
            if let Some(i) = remove {
                c.slots[i] = None;
                c.diff = None;
            }
            if ui.add_enabled(c.len() == 2, egui::Button::new("⇄ 入れ替え")).clicked() {
                c.slots.swap(0, 1);
                c.diff = None;
            }
        });
        ui.horizontal(|ui| {
            for (part, label) in [(Part::Request, "Request"), (Part::Response, "Response")] {
                if ui.selectable_label(c.part == part, label).clicked() {
                    c.part = part;
                }
            }
            ui.separator();
            ui.checkbox(&mut c.pretty, "整形してから比べる").on_hover_text("JSON / HTML / XML を整形してから行ごとに比べます");
            if let Some((_, d)) = &c.diff {
                ui.separator();
                let n = d.hunks.len();
                if n == 0 {
                    ui.label(RichText::new("違いはありません").weak());
                } else {
                    ui.label(format!("差分 {n} 箇所（{} / {n}）", c.hunk.min(n - 1) + 1));
                    let prev = ui.small_button("▲").on_hover_text("前の差分").clicked();
                    let next = ui.small_button("▼").on_hover_text("次の差分").clicked();
                    if prev || next {
                        c.hunk = if prev { (c.hunk + n - 1) % n } else { (c.hunk + 1) % n };
                        c.scroll_to = Some(d.hunks[c.hunk]);
                    }
                }
            }
        });
        ui.separator();

        let (Some(a), Some(b)) = (&c.slots[0], &c.slots[1]) else {
            ui.centered_and_justified(|ui| {
                ui.label(
                    RichText::new("History・サイトマップ・検出の一覧で右クリック →「Comparer に送る」で、比べる通信を 2 件選んでください")
                        .weak(),
                )
            });
            return;
        };
        let key = (a.id, b.id, c.part, c.pretty);
        if c.diff.as_ref().is_none_or(|(k, _)| *k != key) {
            let d = diff::diff(a.text(c.part, c.pretty), b.text(c.part, c.pretty));
            c.hunk = 0;
            c.scroll_to = d.hunks.first().copied();
            c.diff = Some((key, d));
        }
        let Some((_, d)) = &c.diff else { return };

        let dark = ui.visuals().dark_mode;
        let font = egui::TextStyle::Monospace.resolve(ui.style());
        let text_color = ui.visuals().text_color();
        let row_h = ui.text_style_height(&egui::TextStyle::Monospace) + 4.0;
        let spacing = ui.spacing().item_spacing.x;
        let no_w = 48.0;
        let text_w = ((ui.available_width() - 2.0 * no_w - 3.0 * spacing) / 2.0).max(80.0);
        let mut table = TableBuilder::new(ui)
            .id_salt("comparer")
            .striped(false)
            .cell_layout(Layout::left_to_right(Align::Center))
            .column(Column::exact(no_w))
            .column(Column::exact(text_w).clip(true))
            .column(Column::exact(no_w))
            .column(Column::exact(text_w).clip(true));
        if let Some(row) = c.scroll_to.take() {
            table = table.scroll_to_row(row, Some(Align::Center));
        }
        let cell = |ui: &mut egui::Ui, line: Option<&Line>, changed: bool, left: bool| {
            let (bg, mark) = colors(dark, left);
            if changed {
                ui.painter().rect_filled(ui.max_rect(), 0.0, if line.is_some() { bg } else { ui.visuals().faint_bg_color });
            }
            if let Some(l) = line {
                let job = line_job(&l.text, &l.spans, font.clone(), text_color, mark);
                let r = ui.add(egui::Label::new(job).truncate());
                if l.text.len() > 120 {
                    r.on_hover_text(view::truncate_str(&l.text, 8 * 1024));
                }
            }
        };
        table
            .header(row_h, |mut h| {
                for (t, label) in [("", ""), ("A", &a.label), ("", ""), ("B", &b.label)] {
                    h.col(|ui| {
                        if !t.is_empty() {
                            ui.add(egui::Label::new(RichText::new(format!("{t}: {label}")).strong()).truncate());
                        }
                    });
                }
            })
            .body(|body| {
                body.rows(row_h, d.rows.len(), |mut row| {
                    let r = &d.rows[row.index()];
                    for (line, left) in [(&r.left, true), (&r.right, false)] {
                        row.col(|ui| {
                            if let Some(l) = line {
                                ui.label(RichText::new(l.no.to_string()).weak().monospace());
                            }
                        });
                        row.col(|ui| cell(ui, line.as_ref(), r.changed, left));
                    }
                });
            });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(id: i64) -> CompareItem {
        CompareItem::new(id, format!("#{id}"), [Rendered::plain(String::new()), Rendered::plain(String::new())])
    }

    #[test]
    fn push_fills_then_shifts() {
        let mut c = Comparer::default();
        assert_eq!(c.push(item(1)), "A");
        assert_eq!(c.push(item(2)), "B");
        assert_eq!(c.push(item(3)), "B");
        let ids: Vec<i64> = c.slots.iter().flatten().map(|i| i.id).collect();
        assert_eq!(ids, [2, 3], "古い A が押し出される");
    }

    #[test]
    fn job_marks_spans() {
        let job = line_job("Cookie: s=1", std::slice::from_ref(&(8..11)), egui::FontId::monospace(12.0), Color32::WHITE, Color32::RED);
        assert_eq!(job.text, "Cookie: s=1");
        assert_eq!(job.sections.len(), 2);
        assert_eq!(job.sections[1].format.background, Color32::RED);
    }
}
