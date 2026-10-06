//! Intercept タブ: 停止中キューと編集画面。

use std::collections::HashSet;
use std::time::{Duration, Instant};

use egui::{Color32, Key, KeyboardShortcut, Modifiers, RichText};
use px_proxy::{Decision, Direction, Held, Origin};

use super::detail::{EditTarget, selection_menu, show_keeping_selection};
use super::repeater_tab::SEND_TO_REPEATER_KEY;
use super::{GREEN, PxApp, RED, Tab};
use crate::view;

const FORWARD_KEY: KeyboardShortcut = KeyboardShortcut::new(Modifiers::CTRL, Key::F);
const DROP_KEY: KeyboardShortcut = KeyboardShortcut::new(Modifiers::CTRL, Key::D);
/// 接続切れで待ち手のいなくなった項目を掃除する間隔
const PRUNE_INTERVAL: Duration = Duration::from_secs(1);

/// 停止中メッセージの編集状態。
pub(super) struct Editor {
    original: String,
    pub(super) text: String,
    /// UTF-8 でない Body は編集不可としてそのまま送る
    binary_body: Option<Vec<u8>>,
    pub(super) intercept_response: bool,
    /// Forward 前の検証エラー
    error: Option<String>,
}

impl Editor {
    pub(super) fn new(held: &Held) -> Self {
        // ヘッダの CR はエディタ上で見えず、行末の編集で壊しやすいので LF で表示する。
        // 送信時にプロキシ側で CRLF に戻す。Body の改行はそのまま。
        let head = String::from_utf8_lossy(&held.head).replace("\r\n", "\n");
        let (text, binary_body) = match std::str::from_utf8(&held.body) {
            Ok(b) => (format!("{head}{b}"), None),
            Err(_) => (head, Some(held.body.clone())),
        };
        Self { original: text.clone(), text, binary_body, intercept_response: false, error: None }
    }

    /// 送信する (head, body)。変更が無ければ None。
    pub(super) fn edited(&self) -> Option<(Vec<u8>, Vec<u8>)> {
        if self.text == self.original {
            return None;
        }
        let (head, body) = split_head_body(&self.text);
        let body = match &self.binary_body {
            Some(b) => b.clone(),
            None => body.as_bytes().to_vec(),
        };
        Some((head.as_bytes().to_vec(), body))
    }

    fn content_encoding(&self) -> Option<String> {
        let (head, _) = split_head_body(&self.text);
        view::header_value(head, "content-encoding").map(str::to_string).filter(|v| !v.eq_ignore_ascii_case("identity"))
    }

    /// Content-Encoding を展開し、ヘッダを外して編集できる形にする。
    fn decode_body(&mut self) -> Result<(), String> {
        let (head, body) = split_head_body(&self.text);
        let encoding = view::header_value(head, "content-encoding").unwrap_or_default().to_ascii_lowercase();
        let body = self.binary_body.clone().unwrap_or_else(|| body.as_bytes().to_vec());
        let decoded = view::decode_content(&encoding, &body)?.ok_or("Content-Encoding がありません")?;
        // ヘッダ行の改行コードは保ったまま Content-Encoding 行だけ取り除く
        let new_head: String = head
            .split_inclusive('\n')
            .filter(|l| !l.split_once(':').is_some_and(|(n, _)| n.trim().eq_ignore_ascii_case("content-encoding")))
            .collect();
        match String::from_utf8(decoded) {
            Ok(s) => {
                self.text = new_head + &s;
                self.binary_body = None;
            }
            Err(e) => {
                self.text = new_head;
                self.binary_body = Some(e.into_bytes());
            }
        }
        Ok(())
    }
}

/// 最初の空行で head / body に分ける（CRLF / LF どちらでも）。head は空行を含む。
pub(super) fn split_head_body(text: &str) -> (&str, &str) {
    let mut pos = 0;
    for line in text.split_inclusive('\n') {
        pos += line.len();
        if line == "\n" || line == "\r\n" {
            return (&text[..pos], &text[pos..]);
        }
    }
    (text, "")
}

fn held_label(h: &Held) -> String {
    let url = format!("{}://{}{}", h.scheme, h.host, h.target);
    match h.direction {
        Direction::Request => format!("→ {} {url}", h.method),
        Direction::Response => format!("← {} {url}", h.status.unwrap_or(0)),
    }
}

impl PxApp {
    pub(super) fn set_intercept(&mut self, on: bool) {
        self.ctx.interceptor().set_enabled(on);
        self.status = if on {
            "Intercept ON: ルールに一致した通信を止めます".into()
        } else {
            "Intercept OFF: 停止中の通信はすべて転送しました".into()
        };
    }

    /// キューの変化を取り込む。新着があり設定が有効なら Intercept タブへ切り替える。
    pub(super) fn refresh_held(&mut self) {
        let it = self.ctx.interceptor();
        let stale = !self.held.is_empty() && self.held_checked.elapsed() >= PRUNE_INTERVAL;
        if it.version() == self.held_version && !stale {
            return;
        }
        let known: HashSet<u64> = self.held.iter().map(|h| h.id).collect();
        self.held = it.pending();
        self.held_version = it.version();
        self.held_checked = Instant::now();

        let ids: HashSet<u64> = self.held.iter().map(|h| h.id).collect();
        self.editors.retain(|id, _| ids.contains(id));
        for h in &self.held {
            self.editors.entry(h.id).or_insert_with(|| Editor::new(h));
        }
        if self.held_selected.is_none_or(|id| !ids.contains(&id)) {
            self.held_selected = self.held.first().map(|h| h.id);
        }
        let arrived = self.held.iter().any(|h| !known.contains(&h.id));
        if arrived && self.settings.intercept.switch_to_tab {
            self.tab = Tab::Intercept;
        }
        if !self.held.is_empty() {
            self.egui_ctx.request_repaint_after(PRUNE_INTERVAL);
        }
    }

    fn resolve_selected(&mut self, drop: bool) {
        let Some(id) = self.held_selected else { return };
        let is_request = self.held.iter().find(|h| h.id == id).is_none_or(|h| h.direction == Direction::Request);
        let decision = match (drop, self.editors.get_mut(&id)) {
            (true, _) => Decision::Drop,
            (false, Some(e)) => {
                let edited = e.edited();
                // 壊れたメッセージは送らずにその場で知らせる
                if let Some((head, _)) = &edited
                    && let Err(msg) = px_proxy::http1::validate_head(head, is_request)
                {
                    self.status = format!("Forward できません: {msg}");
                    e.error = Some(msg);
                    return;
                }
                Decision::Forward { edited, intercept_response: e.intercept_response }
            }
            (false, None) => Decision::FORWARD,
        };
        if !self.ctx.interceptor().resolve(id, decision) {
            self.status = "接続が既に切れていました".into();
        }
        let pos = self.held.iter().position(|h| h.id == id).unwrap_or(0);
        self.held.retain(|h| h.id != id);
        self.editors.remove(&id);
        self.held_selected = self.held.get(pos.min(self.held.len().saturating_sub(1))).map(|h| h.id);
    }

    /// 選択中の停止リクエストを（編集中の内容のまま）Repeater に送る。停止中のものはそのまま残す。
    fn intercept_to_repeater(&mut self) {
        let Some(id) = self.held_selected else { return };
        let Some(h) = self.held.iter().find(|h| h.id == id) else { return };
        if h.direction != Direction::Request {
            self.status = "Repeater に送れるのはリクエストだけです".into();
            return;
        }
        let Some(e) = self.editors.get(&id) else { return };
        let origin = Origin { https: h.scheme == "https", host: h.host.clone(), port: h.port };
        let title = format!("{} {}", h.method, h.host);
        let (text, binary) = (e.text.clone(), e.binary_body.clone());
        self.open_in_repeater(origin, text, binary, title);
        self.status = "Repeater に送りました（Intercept で止めたリクエストはそのまま停止中です）".into();
    }

    pub(super) fn intercept_tab(&mut self, ui: &mut egui::Ui) {
        let (fwd, drop, to_repeater) = ui.input_mut(|i| {
            (i.consume_shortcut(&FORWARD_KEY), i.consume_shortcut(&DROP_KEY), i.consume_shortcut(&SEND_TO_REPEATER_KEY))
        });
        if to_repeater {
            self.intercept_to_repeater();
            return;
        }
        if fwd {
            self.resolve_selected(false);
        }
        if drop {
            self.resolve_selected(true);
        }

        let enabled = self.ctx.interceptor().is_enabled();
        let selected = self.held_selected.and_then(|id| self.held.iter().find(|h| h.id == id).cloned());
        let mut to_repeater = false;
        ui.horizontal(|ui| {
            let (label, color) = if enabled { ("● Intercept ON", GREEN) } else { ("○ Intercept OFF", Color32::GRAY) };
            if ui.add(egui::Button::new(RichText::new(label).color(color).strong()).min_size(egui::vec2(140.0, 0.0))).clicked()
            {
                self.set_intercept(!enabled);
            }
            ui.separator();
            let has = selected.is_some();
            if ui.add_enabled(has, egui::Button::new("Forward")).on_hover_text("Ctrl+F").clicked() {
                self.resolve_selected(false);
            }
            if ui.add_enabled(has, egui::Button::new("Drop")).on_hover_text("Ctrl+D").clicked() {
                self.resolve_selected(true);
            }
            if ui.add_enabled(!self.held.is_empty(), egui::Button::new("すべて Forward")).clicked() {
                self.ctx.interceptor().forward_all();
            }
            ui.separator();
            if let Some(h) = &selected
                && let Some(editor) = self.editors.get_mut(&h.id)
            {
                if h.direction == Direction::Request {
                    ui.checkbox(&mut editor.intercept_response, "このレスポンスも止める");
                    to_repeater = ui
                        .button("Repeater に送る")
                        .on_hover_text("編集中の内容で Repeater タブを開きます（Ctrl+R）。停止中のリクエストはそのまま残ります")
                        .clicked();
                }
                let encoding = editor.content_encoding();
                let resp = ui
                    .add_enabled(encoding.is_some(), egui::Button::new("展開して編集"))
                    .on_hover_text("Content-Encoding を展開し、ヘッダを外して平文で編集します")
                    .on_disabled_hover_text("Content-Encoding がありません");
                if resp.clicked()
                    && let Err(e) = editor.decode_body()
                {
                    self.status = e;
                }
                ui.separator();
                if ui.button("デコード…").on_hover_text("選択中のテキストをエンコード / デコード（右クリックからも）").clicked() {
                    self.codec.open_with(self.selection.as_ref());
                }
            }
        });
        if to_repeater {
            self.intercept_to_repeater();
            return;
        }
        ui.separator();

        if self.held.is_empty() {
            ui.centered_and_justified(|ui| {
                let msg = if enabled {
                    "停止中の通信はありません。ルールに一致した通信がここに表示されます"
                } else {
                    "Intercept は OFF です。上のボタンで ON にすると、ルールに一致した通信を止めます"
                };
                ui.label(RichText::new(msg).weak());
            });
            return;
        }

        egui::Panel::left("held_list").resizable(true).default_size(340.0).min_size(200.0).show(ui, |ui| {
            ui.strong(format!("停止中 {} 件", self.held.len()));
            ui.add_space(4.0);
            egui::ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
                for h in &self.held {
                    let text = RichText::new(held_label(h)).color(match h.direction {
                        Direction::Request => ui.visuals().text_color(),
                        Direction::Response => Color32::from_rgb(100, 160, 240),
                    });
                    let resp = ui.add(egui::Button::selectable(self.held_selected == Some(h.id), text).truncate());
                    if resp.clicked() {
                        self.held_selected = Some(h.id);
                    }
                }
            });
        });

        egui::CentralPanel::no_frame().show(ui, |ui| {
            let Some(h) = selected else { return };
            let Some(editor) = self.editors.get_mut(&h.id) else { return };
            ui.horizontal(|ui| {
                let kind = if h.direction == Direction::Request { "リクエスト" } else { "レスポンス" };
                ui.strong(kind);
                ui.label(format!("{}://{}:{}{}", h.scheme, h.host, h.port, h.target));
                if editor.text != editor.original {
                    ui.label(RichText::new("編集済み").color(Color32::from_rgb(240, 200, 80)));
                }
            });
            if let Some(e) = &editor.error {
                ui.colored_label(RED, format!("Forward できません: {e}"));
            }
            if let Some(b) = &editor.binary_body {
                ui.label(
                    RichText::new(format!("[バイナリ Body {} bytes — 編集不可、そのまま送信します]", b.len())).color(RED),
                );
            }
            egui::ScrollArea::both().auto_shrink(false).id_salt(("held", h.id)).show(ui, |ui| {
                let edit = egui::TextEdit::multiline(&mut editor.text)
                    .font(egui::TextStyle::Monospace)
                    .code_editor()
                    .desired_width(f32::INFINITY)
                    .desired_rows(30);
                let out = show_keeping_selection(ui, ("held", h.id), edit);
                if out.response.changed() {
                    editor.error = None;
                }
                if selection_menu(&out, &editor.text, Some(EditTarget::Held(h.id)), &mut self.selection) {
                    self.codec.open_with(self.selection.as_ref());
                }
            });
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn held(head: &[u8], body: &[u8]) -> Held {
        Held {
            id: 1,
            direction: Direction::Response,
            scheme: "https",
            host: "h".into(),
            port: 443,
            method: "GET".into(),
            target: "/".into(),
            status: Some(200),
            head: head.to_vec(),
            body: body.to_vec(),
        }
    }

    #[test]
    fn split_handles_crlf_and_lf() {
        assert_eq!(split_head_body("A\r\nB: c\r\n\r\nbody\r\n\r\nx"), ("A\r\nB: c\r\n\r\n", "body\r\n\r\nx"));
        assert_eq!(split_head_body("A\nB: c\n\nbody"), ("A\nB: c\n\n", "body"));
        assert_eq!(split_head_body("A\r\n"), ("A\r\n", ""));
    }

    #[test]
    fn unchanged_editor_sends_nothing_and_edit_is_split() {
        let mut e = Editor::new(&held(b"HTTP/1.1 200 OK\r\n\r\n", b"a\r\nhi"));
        assert_eq!(e.text, "HTTP/1.1 200 OK\n\na\r\nhi", "head shown with LF, body untouched");
        assert!(e.edited().is_none());
        e.text = e.text.replace("hi", "bye");
        assert_eq!(e.edited(), Some((b"HTTP/1.1 200 OK\n\n".to_vec(), b"a\r\nbye".to_vec())));
    }

    #[test]
    fn binary_body_is_kept() {
        let mut e = Editor::new(&held(b"HTTP/1.1 200 OK\r\n\r\n", &[0xff, 0x00]));
        e.text = e.text.replace("200 OK", "403 Forbidden");
        assert_eq!(e.edited().unwrap().1, vec![0xff, 0x00]);
    }

    #[test]
    fn decode_body_removes_encoding_header() {
        use std::io::Write;
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(b"plain").unwrap();
        let mut e = Editor::new(&held(b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nX: 1\r\n\r\n", &gz.finish().unwrap()));
        e.decode_body().unwrap();
        assert_eq!(e.text, "HTTP/1.1 200 OK\nX: 1\n\nplain");
        assert!(e.content_encoding().is_none());
    }
}
