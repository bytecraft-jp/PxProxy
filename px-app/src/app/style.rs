//! 色と、色を使う小さな部品。

use egui::Color32;
use px_store::{Highlight, Severity};

pub(super) const RED: Color32 = Color32::from_rgb(230, 80, 80);
pub(super) const GREEN: Color32 = Color32::from_rgb(80, 200, 120);
pub(super) const YELLOW: Color32 = Color32::from_rgb(240, 200, 80);

/// ビットマスクの 1 ビットをトグルするボタン。
pub(super) fn chip(ui: &mut egui::Ui, mask: &mut u32, bit: u32, label: &str) {
    let mut on = *mask & bit != 0;
    if ui.toggle_value(&mut on, label).changed() {
        if on {
            *mask |= bit;
        } else {
            *mask &= !bit;
        }
    }
}

/// 行に付ける色。
pub(super) fn highlight_color(h: Highlight) -> Color32 {
    match h {
        Highlight::Red => Color32::from_rgb(230, 80, 80),
        Highlight::Orange => Color32::from_rgb(240, 150, 50),
        Highlight::Yellow => Color32::from_rgb(225, 200, 60),
        Highlight::Green => Color32::from_rgb(80, 190, 110),
        Highlight::Cyan => Color32::from_rgb(60, 190, 210),
        Highlight::Blue => Color32::from_rgb(90, 140, 240),
        Highlight::Purple => Color32::from_rgb(170, 110, 230),
        Highlight::Gray => Color32::from_rgb(150, 150, 150),
    }
}

/// 注意を引く文字の黄色。ライトテーマでは白い背景で読めるよう濃くする。
pub(super) fn yellow(ui: &egui::Ui) -> Color32 {
    if ui.visuals().dark_mode { YELLOW } else { Color32::from_rgb(170, 115, 0) }
}

pub(super) fn severity_color(ui: &egui::Ui, s: Severity) -> Color32 {
    match s {
        Severity::High => RED,
        Severity::Medium => Color32::from_rgb(240, 140, 50),
        Severity::Low => yellow(ui),
        Severity::Info => Color32::from_rgb(120, 160, 200),
    }
}

pub(super) fn status_color(code: u16) -> Color32 {
    match code {
        100..=299 => GREEN,
        300..=399 => Color32::from_rgb(100, 160, 240),
        400..=499 => Color32::from_rgb(240, 170, 60),
        _ => RED,
    }
}
