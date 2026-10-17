//! 表示の設定（テーマ・文字の大きさ）。案件ではなく利用者ごとの設定なので、CA と同じフォルダの ui.toml に保存する。

use std::ops::RangeInclusive;
use std::path::PathBuf;

use egui::{TextStyle, ThemePreference};
use px_proxy::CertAuthority;
use serde::{Deserialize, Serialize};

use super::PxApp;

/// 文字の大きさ（pt）として選べる範囲
pub(super) const FONT_RANGE: RangeInclusive<f32> = 9.0..=24.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum ThemeChoice {
    /// OS の設定に合わせる
    #[default]
    System,
    Dark,
    Light,
}

impl ThemeChoice {
    pub(super) const ALL: [ThemeChoice; 3] = [Self::System, Self::Dark, Self::Light];

    pub(super) fn label(self) -> &'static str {
        match self {
            Self::System => "システムに合わせる",
            Self::Dark => "ダーク",
            Self::Light => "ライト",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub(super) struct UiPrefs {
    pub(super) theme: ThemeChoice,
    /// 画面の文字（本文）の大きさ。見出しなどは同じ比率で大きくする
    pub(super) ui_font: f32,
    /// Request / Response など等幅の文字の大きさ
    pub(super) mono_font: f32,
}

impl Default for UiPrefs {
    fn default() -> Self {
        Self { theme: ThemeChoice::System, ui_font: default_size(&TextStyle::Body), mono_font: default_size(&TextStyle::Monospace) }
    }
}

/// egui の既定の文字の大きさ。
fn default_size(style: &TextStyle) -> f32 {
    egui::Style::default().text_styles.get(style).map_or(12.5, |f| f.size)
}

fn prefs_file() -> PathBuf {
    CertAuthority::default_dir().join("ui.toml")
}

impl UiPrefs {
    /// 保存した設定を読む。無い・読めなければ既定値。
    pub(super) fn load() -> Self {
        let mut p: Self = std::fs::read_to_string(prefs_file()).ok().and_then(|s| toml::from_str(&s).ok()).unwrap_or_default();
        p.ui_font = p.ui_font.clamp(*FONT_RANGE.start(), *FONT_RANGE.end());
        p.mono_font = p.mono_font.clamp(*FONT_RANGE.start(), *FONT_RANGE.end());
        p
    }

    fn save(&self) {
        let result = toml::to_string_pretty(self)
            .map_err(|e| e.to_string())
            .and_then(|text| {
                std::fs::create_dir_all(CertAuthority::default_dir()).map_err(|e| e.to_string())?;
                std::fs::write(prefs_file(), text).map_err(|e| e.to_string())
            });
        if let Err(e) = result {
            tracing::warn!("failed to save ui preferences: {e}");
        }
    }

    /// テーマと文字の大きさを画面に反映する（ダーク・ライトの両方のスタイルに）。
    pub(super) fn apply(&self, ctx: &egui::Context) {
        ctx.set_theme(match self.theme {
            ThemeChoice::System => ThemePreference::System,
            ThemeChoice::Dark => ThemePreference::Dark,
            ThemeChoice::Light => ThemePreference::Light,
        });
        let defaults = egui::Style::default().text_styles;
        let scale = self.ui_font / default_size(&TextStyle::Body);
        ctx.all_styles_mut(|style| {
            for (text_style, font) in style.text_styles.iter_mut() {
                let base = defaults.get(text_style).map_or(font.size, |f| f.size);
                font.size = if *text_style == TextStyle::Monospace { self.mono_font } else { base * scale };
            }
        });
    }
}

impl PxApp {
    /// メニューバーの「表示」。
    pub(super) fn view_menu(&mut self, ui: &mut egui::Ui) {
        let mut p = self.prefs.clone();
        ui.label(menu_heading("テーマ"));
        for t in ThemeChoice::ALL {
            ui.radio_value(&mut p.theme, t, t.label());
        }
        ui.separator();
        ui.label(menu_heading("文字の大きさ"));
        ui.add(egui::Slider::new(&mut p.ui_font, FONT_RANGE).step_by(0.5).text("画面"));
        ui.add(egui::Slider::new(&mut p.mono_font, FONT_RANGE).step_by(0.5).text("Request / Response"));
        ui.separator();
        if ui.button("既定に戻す").clicked() {
            p = UiPrefs::default();
        }
        if p != self.prefs {
            p.apply(ui.ctx());
            p.save();
            self.prefs = p;
        }
    }
}

/// メニュー内の小見出し。
fn menu_heading(text: &str) -> egui::RichText {
    egui::RichText::new(text).small().weak()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_scales_text_styles_from_defaults() {
        let ctx = egui::Context::default();
        let p = UiPrefs { theme: ThemeChoice::Light, ui_font: default_size(&TextStyle::Body) * 2.0, mono_font: 20.0 };
        // 2 回反映しても倍々にならない（既定値から計算する）
        p.apply(&ctx);
        p.apply(&ctx);
        for theme in [egui::Theme::Dark, egui::Theme::Light] {
            let style = ctx.style_of(theme);
            assert_eq!(style.text_styles[&TextStyle::Monospace].size, 20.0);
            assert_eq!(style.text_styles[&TextStyle::Heading].size, default_size(&TextStyle::Heading) * 2.0);
        }
        assert_eq!(ctx.options(|o| o.theme_preference), ThemePreference::Light);
        let text = toml::to_string_pretty(&p).unwrap();
        assert!(text.contains("theme = \"light\""), "{text}");
        assert_eq!(toml::from_str::<UiPrefs>(&text).unwrap(), p);
        assert_eq!(toml::from_str::<UiPrefs>("").unwrap(), UiPrefs::default(), "空なら既定値");
    }
}
