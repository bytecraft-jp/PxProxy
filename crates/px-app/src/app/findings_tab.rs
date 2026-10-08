//! 検出タブ: パッシブチェックの結果を、チェックの種類とホストでまとめて表示する。

use std::time::{Duration, Instant};

use egui::{Align, Layout, RichText};
use egui_extras::{Column, TableBuilder};
use px_store::{Finding, FindingGroup, Severity, passive};

use super::{PxApp, status_color};

/// 記録が続いている間に一覧を読み直す間隔
const RELOAD_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Default)]
pub(super) struct Findings {
    groups: Vec<FindingGroup>,
    /// 記録が増えた（読み直しが要る）
    pub(super) dirty: bool,
    loaded_at: Option<Instant>,
    in_scope_only: bool,
    /// 選んだ (チェック, ホスト)
    selected: Option<(String, String)>,
    items: Vec<Finding>,
    /// パッシブチェックの進み具合 (調べ終えた数, 全体)
    progress: (i64, i64),
}

impl Findings {
    pub(super) fn clear(&mut self) {
        *self = Self { dirty: true, ..Self::default() };
    }
}

impl PxApp {
    /// 表示中なら、記録が増えた分を（間隔を空けて）読み直す。
    pub(super) fn refresh_findings(&mut self, ctx: &egui::Context) {
        let f = &mut self.findings;
        if !f.dirty {
            return;
        }
        if let Some(at) = f.loaded_at
            && at.elapsed() < RELOAD_INTERVAL
        {
            ctx.request_repaint_after(RELOAD_INTERVAL - at.elapsed());
            return;
        }
        let Some(reader) = &self.reader else { return };
        f.dirty = false;
        f.loaded_at = Some(Instant::now());
        let loaded = (|| -> px_store::Result<()> {
            f.groups = reader.finding_groups(f.in_scope_only)?;
            f.progress = reader.passive_progress()?;
            if let Some((check, host)) = &f.selected {
                f.items = reader.findings_in(check, host)?;
            }
            Ok(())
        })();
        if let Err(e) = loaded {
            self.status = format!("検出の読み込みに失敗: {e}");
        }
    }

    pub(super) fn findings_list(&mut self, ui: &mut egui::Ui) {
        let f = &mut self.findings;
        let mut select = None;
        let mut rescan = false;
        ui.horizontal_wrapped(|ui| {
            ui.strong("パッシブチェック");
            if ui
                .toggle_value(&mut f.in_scope_only, "診断対象のみ")
                .on_hover_text("「診断対象 / ルール」タブで設定したホスト・パスの検出だけを表示")
                .changed()
            {
                f.dirty = true;
                f.loaded_at = None;
            }
            if ui.button("再スキャン").on_hover_text("記録済みの通信をすべて調べ直します").clicked() {
                rescan = true;
            }
        });
        let (done, total) = f.progress;
        if done < total {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(RichText::new(format!("調べています… {done} / {total} 件")).small());
            });
        }
        ui.label(
            RichText::new("記録した通信のヘッダや本文を調べるだけで、通信は送りません。").small().weak(),
        );
        ui.separator();
        egui::ScrollArea::vertical().id_salt("finding_groups").auto_shrink(false).show(ui, |ui| {
            if f.groups.is_empty() {
                ui.label(RichText::new("検出はまだありません").weak());
            }
            let mut last: Option<Severity> = None;
            for g in &f.groups {
                if last != Some(g.severity) {
                    last = Some(g.severity);
                    ui.add_space(4.0);
                    ui.label(RichText::new(format!("重要度: {}", g.severity.label())).color(super::severity_color(g.severity)).strong());
                }
                let title = passive::check(&g.check).map_or(g.check.as_str(), |c| c.title);
                let is_sel = f.selected.as_ref().is_some_and(|(c, h)| *c == g.check && *h == g.host);
                let resp = ui.selectable_label(is_sel, format!("{title}\n    {}  ({} 件)", g.host, g.flows));
                if resp.clicked() {
                    select = Some((g.check.clone(), g.host.clone()));
                }
            }
        });
        if let Some(sel) = select {
            f.selected = Some(sel);
            f.items.clear();
            f.dirty = true;
            f.loaded_at = None;
        }
        if rescan && let Some(p) = &self.project {
            p.sink().rescan_passive();
            self.status = "パッシブチェックをやり直しています".into();
            self.findings.dirty = true;
            self.findings.loaded_at = None;
        }
    }

    pub(super) fn findings_items(&mut self, ui: &mut egui::Ui) {
        let Some((check_id, host)) = self.findings.selected.clone() else {
            ui.centered_and_justified(|ui| ui.label(RichText::new("左の一覧から検出を選ぶと、該当する通信を表示します").weak()));
            return;
        };
        let check = passive::check(&check_id);
        ui.horizontal(|ui| {
            if let Some(c) = check {
                ui.label(RichText::new(format!("[{}]", c.severity.label())).color(super::severity_color(c.severity)).strong());
                ui.heading(c.title);
            } else {
                ui.heading(&check_id);
            }
            ui.label(RichText::new(&host).weak());
        });
        if let Some(c) = check {
            ui.label(c.description);
        }
        ui.add_space(4.0);

        let row_h = ui.text_style_height(&egui::TextStyle::Body) + 6.0;
        let mut clicked = None;
        let mut to_repeater = None;
        let mut to_comparer = None;
        let items = &self.findings.items;
        let reader = self.reader.as_ref();
        let cache = &mut self.cache;
        let selected = self.selected;
        ui.style_mut().interaction.selectable_labels = false;
        TableBuilder::new(ui)
            .id_salt("finding_items")
            .striped(true)
            .resizable(true)
            .sense(egui::Sense::click())
            .cell_layout(Layout::left_to_right(Align::Center))
            .column(Column::exact(60.0))
            .column(Column::exact(64.0))
            .column(Column::initial(360.0).clip(true))
            .column(Column::exact(56.0))
            .column(Column::remainder().at_least(160.0).clip(true))
            .header(row_h, |mut h| {
                for t in ["#", "Method", "Path", "Status", "見つかったもの"] {
                    h.col(|ui| {
                        ui.strong(t);
                    });
                }
            })
            .body(|body| {
                body.rows(row_h, items.len(), |mut row| {
                    let f = &items[row.index()];
                    if let std::collections::hash_map::Entry::Vacant(e) = cache.entry(f.flow_id)
                        && let Some(s) = reader.and_then(|r| r.summary(f.flow_id).ok().flatten())
                    {
                        e.insert(s);
                    }
                    let s = cache.get(&f.flow_id);
                    row.set_selected(selected == Some(f.flow_id));
                    row.col(|ui| {
                        ui.label(RichText::new(f.flow_id.to_string()).weak());
                    });
                    row.col(|ui| {
                        ui.label(s.map_or("", |s| s.method.as_str()));
                    });
                    row.col(|ui| {
                        ui.add(egui::Label::new(s.map_or("", |s| s.target.as_str())).truncate());
                    });
                    row.col(|ui| {
                        if let Some(code) = s.and_then(|s| s.status) {
                            ui.label(RichText::new(code.to_string()).color(status_color(code)));
                        }
                    });
                    row.col(|ui| {
                        ui.add(egui::Label::new(RichText::new(&f.detail).monospace()).truncate()).on_hover_text(&f.detail);
                    });
                    let resp = row.response();
                    if resp.clicked() {
                        clicked = Some(f.flow_id);
                    }
                    resp.context_menu(|ui| {
                        if ui.button("Repeater に送る").clicked() {
                            to_repeater = Some(f.flow_id);
                        }
                        if ui.button("Comparer に送る").clicked() {
                            to_comparer = Some(f.flow_id);
                        }
                    });
                });
            });
        if let Some(id) = clicked {
            self.select(id);
        }
        if let Some(id) = to_repeater {
            self.send_to_repeater(id);
        }
        if let Some(id) = to_comparer {
            self.send_to_comparer(id);
        }
    }
}
