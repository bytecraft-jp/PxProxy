//! ダミーサーバタブ: 仮想 Web サーバのホストと、パスごとの応答を設定する（settings.toml に保存）。

use egui::{Align, Layout, RichText};
use px_proxy::mock::ROOT_PATH;
use px_proxy::{MockRoute, MockServer};

use super::{PxApp, RED};

/// ボタンで選べるメソッド（これ以外も settings.toml に書けば受け付ける）
const METHODS: [&str; 7] = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];

/// 応答に書けるプレースホルダの説明
const PLACEHOLDERS: &[(&str, &str)] = &[
    ("{{method}} / {{path}}", "メソッド / パス"),
    ("{{query}}", "QueryString 全体（? の後ろ、デコードしない）"),
    ("{{query.名前}}", "QueryString のパラメータの値（URL デコード後）"),
    ("{{body}}", "リクエストの Body 全体"),
    ("{{form.名前}}", "a=1&b=2 形式の Body のパラメータの値（URL デコード後）"),
    ("{{json.a.b.0}}", "JSON の Body の値（文字列は中身、それ以外は JSON の表記）"),
    ("{{header.名前}}", "リクエストヘッダの値（大文字小文字を区別しない）"),
    ("{{html:…}}", "HTML エスケープして埋め込む（例: {{html:query.q}}）"),
    ("{{url:…}} / {{json:…}}", "URL エンコード / JSON 文字列の中身としてエスケープして埋め込む"),
];

impl PxApp {
    pub(super) fn mock_tab(&mut self, ui: &mut egui::Ui) {
        let mut servers = self.settings.mock_servers.clone();
        egui::ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
            ui.set_max_width(900.0);
            ui.heading("ダミーサーバ（仮想 Web サーバ）");
            ui.label(
                RichText::new(
                    "プロキシに届いた通信のうち、ホスト名が一致するものには上流へ接続せず、ここで設定した応答を返します。待受は増やさず、HTTP / HTTPS・ポートを問わず応答します（存在しないドメインでも使えます）。\
                     パスはクエリを除いた完全一致（* と ? のワイルドカード可）で、上から順に調べます。一致するパスが無ければ 404、パスはあってもメソッドが違えば 405 を返します。\
                     Intercept の対象外で、Repeater からの送信にも同じ応答を返します。",
                )
                .weak(),
            );
            egui::CollapsingHeader::new("プレースホルダ（応答にリクエストの内容を埋め込む）").show(ui, |ui| {
                ui.label(
                    RichText::new(
                        "レスポンスヘッダと Body に {{名前}} と書くと、リクエストの内容に置き換えます。値が無ければ空になり、解釈できない名前はそのまま残します。既定ではエスケープせずに埋め込みます。",
                    )
                    .weak(),
                );
                egui::Grid::new("mock_placeholders").num_columns(2).spacing([16.0, 2.0]).show(ui, |ui| {
                    for (name, what) in PLACEHOLDERS {
                        ui.label(RichText::new(*name).monospace());
                        ui.label(*what);
                        ui.end_row();
                    }
                });
            });
            ui.add_space(8.0);
            let mut remove = None;
            for (i, server) in servers.iter_mut().enumerate() {
                ui.push_id(i, |ui| {
                    egui::Frame::group(ui.style()).inner_margin(8.0).show(ui, |ui| {
                        if server_editor(ui, server) {
                            remove = Some(i);
                        }
                    });
                });
                ui.add_space(8.0);
            }
            if let Some(i) = remove {
                servers.remove(i);
            }
            if ui.button("＋ ダミーサーバを追加").clicked() {
                servers.push(MockServer::default());
            }
            ui.label(RichText::new("設定は案件フォルダの settings.toml に保存され、zip エクスポートにも含まれます。").small().weak());
        });
        if servers != self.settings.mock_servers {
            let mut s = self.settings.clone();
            s.mock_servers = servers;
            self.apply_settings(s);
        }
    }
}

/// 1 つのダミーサーバの編集欄。「削除」を押したら true。
fn server_editor(ui: &mut egui::Ui, server: &mut MockServer) -> bool {
    let mut delete = false;
    ui.horizontal(|ui| {
        ui.checkbox(&mut server.enabled, "").on_hover_text("有効 / 無効");
        ui.strong("ホスト");
        ui.add(
            egui::TextEdit::singleline(&mut server.host)
                .hint_text("dummy.example.com（* と ? のワイルドカード可）")
                .desired_width(360.0),
        );
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if ui.small_button("このサーバを削除").clicked() {
                delete = true;
            }
        });
    });
    for p in server.problems() {
        ui.colored_label(RED, p);
    }

    // `/` は必須なので、最初の `/` はパスの変更と削除をできなくする
    let root = server.routes.iter().position(|r| r.path.trim() == ROOT_PATH);
    let mut remove = None;
    for (i, route) in server.routes.iter_mut().enumerate() {
        ui.separator();
        ui.push_id(i, |ui| {
            if route_editor(ui, route, root == Some(i)) {
                remove = Some(i);
            }
        });
    }
    if let Some(i) = remove {
        server.routes.remove(i);
    }
    ui.separator();
    if ui.button("＋ パスを追加").clicked() {
        let path = if root.is_some() { String::new() } else { ROOT_PATH.to_string() };
        server.routes.push(MockRoute { path, ..Default::default() });
    }
    delete
}

/// パスごとの応答の編集欄。「削除」を押したら true。
fn route_editor(ui: &mut egui::Ui, r: &mut MockRoute, root: bool) -> bool {
    let mut delete = false;
    ui.horizontal(|ui| {
        let h = ui.spacing().interact_size.y;
        ui.label("パス");
        if root {
            ui.add_sized([260.0, h], egui::Label::new(RichText::new(ROOT_PATH).monospace()))
                .on_hover_text("/ は必須のため、変更・削除できません");
        } else {
            ui.add_sized(
                [260.0, h],
                egui::TextEdit::singleline(&mut r.path)
                    .hint_text("/api/users（* と ? 可）")
                    .font(egui::TextStyle::Monospace),
            );
        }
        ui.label("ステータス");
        ui.add(egui::DragValue::new(&mut r.status).range(200..=599));
        if !root {
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.small_button("削除").clicked() {
                    delete = true;
                }
            });
        }
    });
    ui.horizontal_wrapped(|ui| {
        ui.label("メソッド");
        let mut list = r.method_list();
        let mut changed = false;
        for m in METHODS {
            let mut on = list.iter().any(|x| x == m);
            if ui.toggle_value(&mut on, m).changed() {
                changed = true;
                if on {
                    list.push(m.to_string());
                } else {
                    list.retain(|x| x != m);
                }
            }
        }
        if changed {
            r.methods = list.join(" ");
        }
        let others: Vec<&str> = list.iter().map(String::as_str).filter(|m| !METHODS.contains(m)).collect();
        if !others.is_empty() {
            ui.label(others.join(" "));
        }
        if list.is_empty() {
            ui.label(RichText::new("（未選択なら全てのメソッドを受け付けます）").weak());
        }
    });
    ui.label(RichText::new("レスポンスヘッダ（1 行に「名前: 値」。Content-Length は Body から付けます）").weak());
    ui.add(
        egui::TextEdit::multiline(&mut r.headers)
            .hint_text("Content-Type: application/json")
            .desired_rows(2)
            .desired_width(f32::INFINITY)
            .font(egui::TextStyle::Monospace),
    );
    ui.label(RichText::new("Body").weak());
    ui.add(
        egui::TextEdit::multiline(&mut r.body)
            .hint_text("{\"q\": \"{{json:query.q}}\", \"name\": \"{{json:form.name}}\"}")
            .desired_rows(5)
            .desired_width(f32::INFINITY)
            .font(egui::TextStyle::Monospace),
    );
    delete
}
