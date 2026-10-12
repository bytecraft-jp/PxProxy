//! History / サイトマップの一覧の絞り込み（フィルタバー）。
//! 1 行目はよく使う条件、「詳細条件」を開くと本文検索・メソッド・長さ・所要時間・メモ・色で絞り込める。

use egui::RichText;
use px_store::{
    ALL_COLORS, ALL_KINDS, ALL_METHODS, ALL_STATUS, Filter, FlowKind, Highlight, MethodClass, NO_COLOR, SearchIn,
    StatusClass,
};

use super::{PxApp, RED, chip, highlight_color};

/// 数値の条件の入力欄（空欄は指定なし）。`Filter` には解釈した値を入れる。
#[derive(Default)]
pub(super) struct FilterForm {
    /// 詳細条件の行を表示する
    pub(super) expanded: bool,
    len_min: String,
    len_max: String,
    ms_min: String,
    ms_max: String,
}

impl FilterForm {
    /// 入力欄を空にする（開閉の状態は残す）。
    fn clear(&mut self) {
        *self = Self { expanded: self.expanded, ..Self::default() };
    }
}

/// `10`・`1.5k`・`2M`（`units` が true のとき。k = 1024）を数にする。空欄は Ok(None)。
fn parse_amount(s: &str, units: bool) -> Result<Option<u64>, ()> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(None);
    }
    let (num, mul) = match s.chars().last() {
        Some('k' | 'K') if units => (&s[..s.len() - 1], 1024.0),
        Some('m' | 'M') if units => (&s[..s.len() - 1], 1024.0 * 1024.0),
        _ => (s, 1.0),
    };
    let v: f64 = num.trim().parse().map_err(|_| ())?;
    if !v.is_finite() || v < 0.0 {
        return Err(());
    }
    Ok(Some((v * mul).round() as u64))
}

fn search_in_label(t: SearchIn) -> &'static str {
    match t {
        SearchIn::Both => "Req / Res",
        SearchIn::Request => "Request",
        SearchIn::Response => "Response",
    }
}

/// 詳細条件のうち指定されているものの数。
fn advanced_count(f: &Filter) -> usize {
    [
        f.content.is_active(),
        f.methods & ALL_METHODS != ALL_METHODS,
        f.length != (None, None),
        f.duration_ms != (None, None),
        f.noted_only,
        f.colors & ALL_COLORS != ALL_COLORS,
    ]
    .into_iter()
    .filter(|on| *on)
    .count()
}

/// 数値の入力欄。読めない値は赤字にして、条件には使わない。
fn amount_input(ui: &mut egui::Ui, text: &mut String, units: bool, hint: &str) {
    let ok = parse_amount(text, units).is_ok();
    let edit = egui::TextEdit::singleline(text).hint_text(hint).desired_width(56.0).text_color_opt((!ok).then_some(RED));
    let r = ui.add(edit);
    if !ok {
        r.on_hover_text("数値を入力してください（この条件は使っていません）");
    }
}

/// 色で絞り込むボタン（■ を色で塗る）。
fn color_chip(ui: &mut egui::Ui, mask: &mut u32, h: Highlight) {
    let mut on = *mask & h.bit() != 0;
    let text = RichText::new("■").color(highlight_color(h));
    if ui.toggle_value(&mut on, text).on_hover_text(h.label()).changed() {
        *mask ^= h.bit();
    }
}

impl PxApp {
    pub(super) fn filter_bar(&mut self, ui: &mut egui::Ui) {
        let mut f = self.filter.clone();
        let form = &mut self.filter_form;
        ui.horizontal_wrapped(|ui| {
            let hint = if f.text_regex { "🔍 ホスト / パス（正規表現）" } else { "🔍 ホスト / パスで絞り込み" };
            ui.add(egui::TextEdit::singleline(&mut f.text).hint_text(hint).desired_width(180.0));
            ui.toggle_value(&mut f.text_regex, ".*").on_hover_text("正規表現として照合します（大文字小文字は区別しません）");
            ui.separator();
            ui.label("種類");
            for k in FlowKind::ALL {
                chip(ui, &mut f.kinds, k.bit(), k.label());
            }
            ui.separator();
            ui.label("ステータス");
            for s in StatusClass::ALL {
                chip(ui, &mut f.status, s.bit(), s.label());
            }
            ui.separator();
            ui.toggle_value(&mut f.in_scope_only, "診断対象のみ")
                .on_hover_text("「診断対象 / ルール」タブで設定したホスト・パスだけを表示");
            ui.separator();
            let label = match advanced_count(&f) {
                0 => "詳細条件".to_string(),
                n => format!("詳細条件 ({n})"),
            };
            ui.toggle_value(&mut form.expanded, label)
                .on_hover_text("ヘッダ・Body の検索、メソッド・長さ・所要時間・メモ・色で絞り込みます");
            ui.separator();
            if ui.button("リセット").on_hover_text("すべて表示").clicked() {
                f = Filter::default();
                form.clear();
            }
            if ui.button("静的ファイルを隠す").on_hover_text("JS / CSS / 画像 / フォント / メディアを非表示").clicked() {
                f.kinds = ALL_KINDS
                    & !(FlowKind::Script.bit()
                        | FlowKind::Css.bit()
                        | FlowKind::Image.bit()
                        | FlowKind::Font.bit()
                        | FlowKind::Media.bit());
            }
            if ui.button("XHR のみ").clicked() {
                f.kinds = FlowKind::Xhr.bit();
            }
            if ui.button("エラーのみ").on_hover_text("4xx / 5xx / 応答なし").clicked() {
                f.status = ALL_STATUS & !(StatusClass::Ok.bit() | StatusClass::Redirect.bit());
            }
        });
        if form.expanded {
            ui.horizontal_wrapped(|ui| {
                ui.label("本文");
                ui.add(
                    egui::TextEdit::singleline(&mut f.content.text)
                        .hint_text("🔍 ヘッダ・Body を検索（gzip などは展開して検索）")
                        .desired_width(280.0),
                );
                egui::ComboBox::from_id_salt("content_target")
                    .selected_text(search_in_label(f.content.target))
                    .width(96.0)
                    .show_ui(ui, |ui| {
                        for t in [SearchIn::Both, SearchIn::Request, SearchIn::Response] {
                            ui.selectable_value(&mut f.content.target, t, search_in_label(t));
                        }
                    });
                ui.toggle_value(&mut f.content.regex, ".*").on_hover_text("正規表現として検索します");
                ui.toggle_value(&mut f.content.case_sensitive, "Aa").on_hover_text("大文字小文字を区別します");
                ui.separator();
                ui.label("メソッド");
                for m in MethodClass::ALL {
                    chip(ui, &mut f.methods, m.bit(), m.label());
                }
            });
            ui.horizontal_wrapped(|ui| {
                ui.label("Response の長さ");
                amount_input(ui, &mut form.len_min, true, "最小");
                ui.label("〜");
                amount_input(ui, &mut form.len_max, true, "最大");
                ui.label(RichText::new("bytes（1.5k・2M も可）").weak());
                ui.separator();
                ui.label("所要時間");
                amount_input(ui, &mut form.ms_min, false, "最小");
                ui.label("〜");
                amount_input(ui, &mut form.ms_max, false, "最大");
                ui.label(RichText::new("ms").weak());
                ui.separator();
                ui.toggle_value(&mut f.noted_only, "メモあり");
                ui.separator();
                ui.label("色");
                chip(ui, &mut f.colors, NO_COLOR, "なし");
                for h in Highlight::ALL {
                    color_chip(ui, &mut f.colors, h);
                }
            });
        }
        let amount = |s: &str, units| parse_amount(s, units).ok().flatten();
        f.length = (amount(&form.len_min, true), amount(&form.len_max, true));
        f.duration_ms = (amount(&form.ms_min, false), amount(&form.ms_max, false));
        if let Some(e) = f.error() {
            ui.colored_label(RED, format!("{e}（直す前の条件で表示しています）"));
        }
        self.filter = f;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amounts() {
        assert_eq!(parse_amount("", true), Ok(None));
        assert_eq!(parse_amount(" 100 ", true), Ok(Some(100)));
        assert_eq!(parse_amount("1.5k", true), Ok(Some(1536)));
        assert_eq!(parse_amount("2M", true), Ok(Some(2 * 1024 * 1024)));
        assert_eq!(parse_amount("2M", false), Err(()), "ms に単位は付けない");
        assert_eq!(parse_amount("-1", true), Err(()));
        assert_eq!(parse_amount("abc", true), Err(()));
    }

    #[test]
    fn counts_advanced_conditions() {
        let mut f = Filter::default();
        assert_eq!(advanced_count(&f), 0);
        f.content.text = "x".into();
        f.colors = NO_COLOR;
        f.length.1 = Some(10);
        assert_eq!(advanced_count(&f), 3);
    }
}
