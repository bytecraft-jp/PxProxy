//! 画面の上下の枠（メニュー・ツールバー・タブ・ステータスバー）とキー操作。

use egui::{Align, Color32, Layout, RichText};
use px_proxy::CertAuthority;

use super::project::{default_form, display_name};
use super::rows;
use super::style::{GREEN, yellow};
use super::{PxApp, Tab};

impl PxApp {
    pub(super) fn handle_keys(&mut self, ctx: &egui::Context) {
        if ctx.egui_wants_keyboard_input()
            || self.ids.is_empty()
            || self.new_project.is_some()
            || self.confirm_delete.is_some()
            || !self.tab.has_list()
        {
            return;
        }
        if ctx.input_mut(|i| i.consume_shortcut(&rows::SELECT_ALL_KEY)) {
            self.select_all_rows();
            return;
        }
        if ctx.input(|i| i.key_pressed(egui::Key::Delete)) {
            let ids: Vec<i64> = match (self.picked.is_empty(), self.selected) {
                (false, _) => self.picked.iter().copied().collect(),
                (true, Some(id)) => vec![id],
                (true, None) => return,
            };
            let what = if ids.len() == 1 { "この通信".to_string() } else { format!("選択した {} 件", ids.len()) };
            self.request_delete(ids, what);
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
        self.pick_only(self.ids[next]);
        self.select(self.ids[next]);
    }

    pub(super) fn menu_bar(&mut self, ui: &mut egui::Ui) {
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
                if ui
                    .add_enabled(has_project, egui::Button::new("診断対象外の通信を削除…"))
                    .on_hover_text("「診断対象 / ルール」の設定で判定します（確認してから削除します）")
                    .clicked()
                {
                    self.request_delete_out_of_scope();
                }
                ui.separator();
                if ui.add_enabled(has_project, egui::Button::new("案件を閉じる")).clicked() {
                    self.close_project();
                }
            });
            ui.menu_button("表示", |ui| self.view_menu(ui));
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

    pub(super) fn toolbar(&mut self, ui: &mut egui::Ui) {
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
                if intercepting { ("Intercept: ON", yellow(ui)) } else { ("Intercept: OFF", Color32::GRAY) };
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
                    if self.applied.is_default() {
                        ui.label(format!("{} 件", self.total));
                    } else {
                        ui.label(format!("{} / {} 件", self.ids.len(), self.total));
                    }
                    if self.scanning {
                        ui.label(RichText::new(format!("本文を検索中… #{} まで", self.last_id)).weak());
                        ui.spinner();
                    }
                    if self.picked.len() > 1 {
                        ui.separator();
                        ui.label(format!("{} 件を選択中", self.picked.len()))
                            .on_hover_text("右クリックで色付け・削除（Ctrl+クリックで追加 / 解除、Shift+クリックで範囲、Ctrl+A ですべて）");
                    }
                }
            });
        });
    }

    pub(super) fn tab_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            let n = self.held.len();
            let intercept = if n > 0 {
                RichText::new(format!("Intercept ({n})")).color(yellow(ui)).strong()
            } else {
                RichText::new("Intercept")
            };
            let repeater = match self.repeater.len() {
                0 => RichText::new("Repeater"),
                n => RichText::new(format!("Repeater ({n})")),
            };
            let comparer = match self.comparer.len() {
                0 => RichText::new("Comparer"),
                n => RichText::new(format!("Comparer ({n}/2)")),
            };
            for (tab, label) in [
                (Tab::Settings, RichText::new("診断対象 / ルール")),
                (Tab::History, RichText::new("History")),
                (Tab::SiteMap, RichText::new("サイトマップ")),
                (Tab::Findings, RichText::new("検出")),
                (Tab::Intercept, intercept),
                (Tab::Repeater, repeater),
                (Tab::Comparer, comparer),
                (Tab::Mock, RichText::new("ダミーサーバ")),
            ] {
                if ui.selectable_label(self.tab == tab, label).clicked() && self.tab != tab {
                    self.tab = tab;
                    // 別タブで選んだ文字列をデコード窓に持ち込まない
                    self.selection = None;
                }
            }
        });
    }

    /// 左にメッセージ、右に CA の場所。重ならないよう右を先に置き（幅の 4 割まで）、
    /// 左は残りの幅に収まらなければ末尾を省略する。省略した全文はマウスを乗せると出す。
    pub(super) fn status_bar(&mut self, ui: &mut egui::Ui) {
        let ca = format!("CA: {}", CertAuthority::default_dir().join("ca.crt").display());
        let ca_max = ui.available_width() * 0.4;
        egui::Sides::new().shrink_left().truncate().show(
            ui,
            |ui| {
                self.task_status(ui);
                ui.add(egui::Label::new(RichText::new(&self.status).small())).on_hover_text(&self.status);
            },
            |ui| {
                ui.scope(|ui| {
                    ui.set_max_width(ca_max);
                    ui.add(egui::Label::new(RichText::new(&ca).small().weak()).truncate()).on_hover_text(&ca);
                });
            },
        );
    }

    fn menu_save_ca(&mut self) {
        if let Some(dest) = rfd::FileDialog::new().set_title("CA 証明書を保存").set_file_name("pxproxy-ca.crt").save_file() {
            self.status = match std::fs::write(&dest, self.ctx.ca().ca_pem()) {
                Ok(()) => format!("CA 証明書を保存しました: {}（OS/ブラウザの信頼されたルートに登録してください）", dest.display()),
                Err(e) => format!("保存失敗: {e}"),
            };
        }
    }
}
