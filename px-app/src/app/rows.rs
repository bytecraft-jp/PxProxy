//! History の行の操作（複数選択・色付け・削除）。

use std::collections::{BTreeSet, HashSet};

use egui::{Key, KeyboardShortcut, Modifiers, RichText};
use px_store::{Highlight, Reader};

use super::style::{RED, highlight_color};
use super::PxApp;

/// 表示中の行をすべて選ぶ
pub(super) const SELECT_ALL_KEY: KeyboardShortcut = KeyboardShortcut::new(Modifiers::COMMAND, Key::A);

/// 確認待ちの削除。
pub(super) struct DeleteRequest {
    ids: Vec<i64>,
    /// 確認の文言（「選択した 3 件」など）
    what: String,
}

/// 行のクリックで複数選択を更新する。Ctrl で 1 行ずつ追加 / 解除、Shift で起点からの範囲を選ぶ。
/// `ids` は一覧の ID（昇順）。
fn update_picked(picked: &mut BTreeSet<i64>, anchor: &mut Option<i64>, ids: &[i64], id: i64, m: Modifiers) {
    if m.shift
        && let Some(a) = *anchor
        && let (Ok(x), Ok(y)) = (ids.binary_search(&a), ids.binary_search(&id))
    {
        if !m.command {
            picked.clear();
        }
        picked.extend(&ids[x.min(y)..=x.max(y)]);
        return;
    }
    if m.command {
        if !picked.remove(&id) {
            picked.insert(id);
        }
    } else {
        picked.clear();
        picked.insert(id);
    }
    *anchor = Some(id);
}

impl PxApp {
    /// 行のクリック（選択と詳細の表示）。
    pub(super) fn click_row(&mut self, id: i64, modifiers: Modifiers) {
        update_picked(&mut self.history.picked, &mut self.history.anchor, &self.history.ids, id, modifiers);
        self.history.follow = false;
        self.select(id);
    }

    /// 1 行だけを選ぶ（矢印キーなど）。
    pub(super) fn pick_only(&mut self, id: i64) {
        update_picked(&mut self.history.picked, &mut self.history.anchor, &self.history.ids, id, Modifiers::NONE);
    }

    pub(super) fn select_all_rows(&mut self) {
        self.history.picked = self.history.ids.iter().copied().collect();
        self.history.anchor = self.history.ids.first().copied();
    }

    /// 行に色を付ける（None で外す）。一覧にはすぐ反映する。
    /// 色で絞り込んでいても、付け替えた行は条件を変えるまで一覧に残す（操作中の行が消えないように）。
    pub(super) fn set_color(&mut self, ids: Vec<i64>, color: Option<Highlight>) {
        let Some(project) = &self.project else { return };
        for id in &ids {
            if let Some(s) = self.history.cache.get_mut(id) {
                s.color = color;
            }
        }
        let n = ids.len();
        project.sink().set_color(ids, color);
        self.status = match color {
            Some(c) => format!("{n} 件に色（{}）を付けました", c.label()),
            None => format!("{n} 件の色を外しました"),
        };
    }

    /// 削除の確認ダイアログを出す。
    pub(super) fn request_delete(&mut self, ids: Vec<i64>, what: String) {
        if ids.is_empty() {
            self.status = format!("{what}はありません");
            return;
        }
        self.history.confirm_delete = Some(DeleteRequest { ids, what });
    }

    /// 診断対象外の通信をすべて削除する（確認あり）。
    pub(super) fn request_delete_out_of_scope(&mut self) {
        let Some(reader) = &self.reader else { return };
        match reader.ids_out_of_scope() {
            Ok(ids) => self.request_delete(ids, "診断対象外の通信".into()),
            Err(e) => self.status = format!("読み込みエラー: {e}"),
        }
    }

    /// 通信を消す。一覧からはすぐ外し、サイトマップ・検出は削除が書き込まれてから読み直す。
    fn delete_flows(&mut self, ids: Vec<i64>) {
        let Some(project) = &self.project else { return };
        let Some(&probe) = ids.first() else { return };
        let n = ids.len();
        let gone: HashSet<i64> = ids.iter().copied().collect();
        project.sink().delete(ids);
        self.history.pending_deletes.push(probe);
        self.history.ids.retain(|id| !gone.contains(id));
        self.history.cache.retain(|id, _| !gone.contains(id));
        self.history.picked.retain(|id| !gone.contains(id));
        if self.history.anchor.is_some_and(|a| gone.contains(&a)) {
            self.history.anchor = None;
        }
        if self.selected.is_some_and(|s| gone.contains(&s)) {
            self.forget_detail_images();
            self.detail = None;
            self.selected = None;
        }
        if self.history.note_edit.as_ref().is_some_and(|e| gone.contains(&e.id)) {
            self.history.note_edit = None;
        }
        self.status = format!("{n} 件の通信を削除しました");
    }

    /// 削除が書き込まれたら（確かめに使う ID が消えたら）、サイトマップと検出を読み直す。
    pub(super) fn finish_deletes(&mut self, reader: &Reader) {
        if self.history.pending_deletes.is_empty() {
            return;
        }
        self.history.pending_deletes.retain(|id| reader.summary(*id).ok().flatten().is_some());
        if self.history.pending_deletes.is_empty() {
            self.site_map.reset();
            self.findings.reload();
        }
    }

    pub(super) fn delete_confirm_window(&mut self, ctx: &egui::Context) {
        let Some(req) = &self.history.confirm_delete else { return };
        let mut decided = None;
        let modal = egui::Modal::new(egui::Id::new("confirm_delete")).show(ctx, |ui| {
            ui.set_max_width(420.0);
            ui.heading("通信の削除");
            ui.add_space(6.0);
            ui.label(format!("{}（{} 件）を案件から削除します。", req.what, req.ids.len()));
            ui.label(RichText::new("元に戻せません。メモ・色・WebSocket のメッセージ・検出もあわせて消えます。").color(RED));
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui.button(RichText::new("削除する").color(RED)).clicked() {
                    decided = Some(true);
                }
                if ui.button("キャンセル").clicked() {
                    decided = Some(false);
                }
            });
        });
        if modal.should_close() && decided.is_none() {
            decided = Some(false);
        }
        match decided {
            Some(true) => {
                let req = self.history.confirm_delete.take().expect("shown above");
                self.delete_flows(req.ids);
            }
            Some(false) => self.history.confirm_delete = None,
            None => {}
        }
    }

    pub(super) fn apply_row_action(&mut self, action: RowAction) {
        match action {
            RowAction::Color(ids, color) => self.set_color(ids, color),
            RowAction::Delete(ids, what) => self.request_delete(ids, what),
            RowAction::DeleteShown => {
                let what = if self.history.scanning { "一覧に表示中（本文の検索途中）の通信" } else { "一覧に表示中の通信" };
                self.request_delete(self.history.ids.clone(), what.into());
            }
            RowAction::DeleteOutOfScope => self.request_delete_out_of_scope(),
        }
    }
}

/// 一覧の右クリックメニューの「色」「削除」。`targets` は操作する行。
pub(super) fn row_menu(ui: &mut egui::Ui, targets: &[i64], shown: usize, action: &mut Option<RowAction>) {
    let n = targets.len();
    let what = if n == 1 { "この通信".to_string() } else { format!("選択した {n} 件") };
    ui.menu_button(format!("色を付ける（{what}）"), |ui| {
        for h in Highlight::ALL {
            let text = RichText::new(format!("■ {}", h.label())).color(highlight_color(h));
            if ui.button(text).clicked() {
                *action = Some(RowAction::Color(targets.to_vec(), Some(h)));
            }
        }
        ui.separator();
        if ui.button("色を外す").clicked() {
            *action = Some(RowAction::Color(targets.to_vec(), None));
        }
    });
    ui.menu_button("削除", |ui| {
        if ui.button(format!("{what}を削除… (Delete)")).clicked() {
            *action = Some(RowAction::Delete(targets.to_vec(), what.clone()));
        }
        if ui.button(format!("一覧に表示中の {shown} 件を削除…")).on_hover_text("いまの絞り込み条件に一致する通信").clicked() {
            *action = Some(RowAction::DeleteShown);
        }
        if ui.button("診断対象外の通信をすべて削除…").on_hover_text("「診断対象 / ルール」の設定で判定します").clicked() {
            *action = Some(RowAction::DeleteOutOfScope);
        }
    });
}

/// 右クリックメニューで選ばれた操作。
pub(super) enum RowAction {
    Color(Vec<i64>, Option<Highlight>),
    Delete(Vec<i64>, String),
    DeleteShown,
    DeleteOutOfScope,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(command: bool, shift: bool) -> Modifiers {
        Modifiers { command, ctrl: command, shift, ..Modifiers::NONE }
    }

    #[test]
    fn click_ctrl_and_shift() {
        let ids = [1, 2, 4, 7, 9];
        let (mut picked, mut anchor) = (BTreeSet::new(), None);
        update_picked(&mut picked, &mut anchor, &ids, 2, m(false, false));
        update_picked(&mut picked, &mut anchor, &ids, 7, m(false, true));
        assert_eq!(picked.iter().copied().collect::<Vec<_>>(), [2, 4, 7], "Shift で起点から範囲");
        update_picked(&mut picked, &mut anchor, &ids, 1, m(false, true));
        assert_eq!(picked.iter().copied().collect::<Vec<_>>(), [1, 2], "起点は変わらない");
        update_picked(&mut picked, &mut anchor, &ids, 9, m(true, false));
        update_picked(&mut picked, &mut anchor, &ids, 1, m(true, false));
        assert_eq!(picked.iter().copied().collect::<Vec<_>>(), [2, 9], "Ctrl で追加 / 解除");
        update_picked(&mut picked, &mut anchor, &ids, 4, m(true, true));
        assert_eq!(picked.iter().copied().collect::<Vec<_>>(), [1, 2, 4, 9], "Ctrl+Shift で範囲を追加");
        update_picked(&mut picked, &mut anchor, &ids, 4, m(false, false));
        assert_eq!(picked.iter().copied().collect::<Vec<_>>(), [4]);
    }
}
