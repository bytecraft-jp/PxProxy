//! 設定タブ（診断対象 / Intercept ルール / hosts / 接続の制限）と settings.toml の読み書き。

use egui::RichText;
use px_proxy::{ProjectSettings, ScopeRule};
use px_store::FlowKind;

use super::{PxApp, RED, chip};

impl PxApp {
    /// 案件の settings.toml を読み込んで反映する（無ければ既定値）。
    pub(super) fn load_settings(&mut self) {
        let settings = match &self.project {
            Some(p) => match std::fs::read_to_string(p.settings_path()) {
                Ok(text) => toml::from_str(&text).unwrap_or_else(|e| {
                    self.status = format!("settings.toml を読めませんでした（既定値を使用）: {e}");
                    ProjectSettings::default()
                }),
                Err(_) => ProjectSettings::default(),
            },
            None => ProjectSettings::default(),
        };
        self.settings = settings.clone();
        self.settings_error = self.ctx.interceptor().set_settings(settings);
    }

    /// History の「診断対象のみ」で使う判定を、現在の設定で読み取り接続に登録する。
    pub(super) fn sync_scope_filter(&mut self) {
        let Some(reader) = &self.reader else { return };
        let scope = self.settings.scope.clone();
        if let Err(e) = reader.set_scope(move |host, target| scope.contains(host, target)) {
            self.status = format!("診断対象フィルタの設定に失敗: {e}");
        }
        if self.filter.in_scope_only {
            self.reset_list();
        }
    }

    pub(super) fn apply_settings(&mut self, settings: ProjectSettings) {
        let scope_changed = settings.scope != self.settings.scope;
        self.settings = settings.clone();
        self.settings_error = self.ctx.interceptor().set_settings(settings);
        if scope_changed {
            self.sync_scope_filter();
        }
        let Some(p) = &self.project else { return };
        let result = toml::to_string_pretty(&self.settings)
            .map_err(|e| e.to_string())
            .and_then(|text| std::fs::write(p.settings_path(), text).map_err(|e| e.to_string()));
        if let Err(e) = result {
            self.status = format!("設定の保存に失敗: {e}");
        }
    }

    /// History の右クリックから診断対象にホストを追加する。
    pub(super) fn add_scope_host(&mut self, host: &str, exclude: bool) {
        let mut s = self.settings.clone();
        let list = if exclude { &mut s.scope.exclude } else { &mut s.scope.include };
        if !list.iter().any(|r| r.host.eq_ignore_ascii_case(host) && r.path.is_empty()) {
            list.push(ScopeRule { enabled: true, host: host.to_string(), path: String::new() });
        }
        self.apply_settings(s);
        self.status = format!("{host} を診断対象{}", if exclude { "から除外しました" } else { "に追加しました" });
    }

    pub(super) fn settings_tab(&mut self, ui: &mut egui::Ui) {
        let mut s = self.settings.clone();
        egui::ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
            ui.set_max_width(900.0);
            ui.heading("診断対象（ホスト・パス）");
            ui.label(
                RichText::new(
                    "この案件で診断するホスト・パスの範囲です。「含める」が空なら全ホストが対象になります。ホストは * と ? のワイルドカード（例: *.example.com）、パスは前方一致で、「除外」が優先されます。",
                )
                .weak(),
            );
            ui.add_space(6.0);
            ui.strong("診断対象に含める");
            rule_list(ui, "scope_include", &mut s.scope.include);
            ui.add_space(8.0);
            ui.strong("診断対象から除外");
            rule_list(ui, "scope_exclude", &mut s.scope.exclude);

            ui.add_space(16.0);
            ui.separator();
            ui.heading("Intercept ルール");
            let r = &mut s.intercept;
            ui.checkbox(&mut r.only_in_scope, "診断対象の通信だけ止める");
            ui.horizontal_wrapped(|ui| {
                ui.label("止めない種類");
                for k in FlowKind::ALL {
                    chip(ui, &mut r.skip_kinds, k.bit(), k.label());
                }
            });
            ui.horizontal(|ui| {
                ui.label("URL 正規表現");
                ui.add(
                    egui::TextEdit::singleline(&mut r.url_regex)
                        .hint_text("空なら全て（例: /api/|\\.php）")
                        .desired_width(420.0)
                        .font(egui::TextStyle::Monospace),
                );
            });
            if let Some(e) = &self.settings_error {
                ui.colored_label(RED, e);
            }
            ui.add_space(6.0);
            ui.checkbox(&mut r.responses, "レスポンスもルールで止める（個別指定は Intercept 画面の「このレスポンスも止める」）");
            ui.add_enabled_ui(r.responses, |ui| {
                ui.horizontal(|ui| {
                    ui.label("Content-Type に含む");
                    ui.add(
                        egui::TextEdit::singleline(&mut r.response_content_types)
                            .hint_text("カンマ区切り、空なら全て（例: html, json）")
                            .desired_width(320.0),
                    );
                });
            });
            ui.add_space(6.0);
            ui.checkbox(&mut r.fix_content_length, "Body を編集したら Content-Length / chunked を自動で付け直す");
            ui.checkbox(&mut r.switch_to_tab, "通信を止めたら Intercept タブへ切り替える");

            ui.add_space(16.0);
            ui.separator();
            ui.heading("hosts（名前解決の上書き）");
            ui.label(
                RichText::new(
                    "OS の hosts ファイルと同じ書式で、接続先の IP アドレスを指定します（1 行に「IP ホスト名…」、# 以降はコメント）。ホスト名には * と ? のワイルドカードが使え、上の行が優先されます。Host ヘッダや TLS の SNI・証明書の検証は元のホスト名のままです。Repeater の送信にも適用されます。",
                )
                .weak(),
            );
            ui.add(
                egui::TextEdit::multiline(&mut s.hosts)
                    .hint_text("192.0.2.10   www.example.com api.example.com\n127.0.0.1    *.staging.example.com")
                    .desired_rows(6)
                    .desired_width(f32::INFINITY)
                    .font(egui::TextStyle::Monospace),
            );
            for e in px_proxy::parse_hosts(&s.hosts).1 {
                ui.colored_label(RED, e);
            }

            ui.add_space(16.0);
            ui.separator();
            ui.heading("接続の制限");
            ui.label(
                RichText::new(
                    "ルータの IP フラッド検出などに引っ掛かる場合に、接続先への接続を抑えます（0 は無制限）。上限に達した通信は空きが出るまで待ち、待っている通信があれば keep-alive で使っていない接続から閉じます。Repeater の送信にも適用されます。",
                )
                .weak(),
            );
            let l = &mut s.limits;
            egui::Grid::new("limits").num_columns(2).spacing([8.0, 4.0]).show(ui, |ui| {
                ui.label("同時接続数の上限");
                ui.add(egui::DragValue::new(&mut l.max_connections).range(0..=1000).suffix(" 本"));
                ui.end_row();
                ui.label("新規接続の上限");
                ui.add(egui::DragValue::new(&mut l.max_new_per_sec).range(0..=1000).prefix("1 秒あたり ").suffix(" 本"));
                ui.end_row();
            });
            ui.add_space(12.0);
            if ui.button("既定値に戻す").clicked() {
                s = ProjectSettings::default();
            }
            ui.label(RichText::new("設定は案件フォルダの settings.toml に保存され、zip エクスポートにも含まれます。").small().weak());
        });
        if s != self.settings {
            self.apply_settings(s);
        }
    }
}

fn rule_list(ui: &mut egui::Ui, id: &str, rules: &mut Vec<ScopeRule>) {
    let mut remove = None;
    if !rules.is_empty() {
        egui::Grid::new(id).num_columns(4).spacing([8.0, 4.0]).show(ui, |ui| {
            ui.label("");
            ui.label(RichText::new("ホスト").weak());
            ui.label(RichText::new("パス（前方一致）").weak());
            ui.label("");
            ui.end_row();
            for (i, r) in rules.iter_mut().enumerate() {
                ui.checkbox(&mut r.enabled, "").on_hover_text("有効 / 無効");
                // Grid のセル内では desired_width が効かないのでサイズを固定する
                let h = ui.spacing().interact_size.y;
                ui.add_sized([280.0, h], egui::TextEdit::singleline(&mut r.host).hint_text("*.example.com"));
                ui.add_sized([220.0, h], egui::TextEdit::singleline(&mut r.path).hint_text("/api（空なら全て）"));
                if ui.small_button("削除").clicked() {
                    remove = Some(i);
                }
                ui.end_row();
            }
        });
    }
    if let Some(i) = remove {
        rules.remove(i);
    }
    if ui.button("＋ 追加").clicked() {
        rules.push(ScopeRule::default());
    }
}
