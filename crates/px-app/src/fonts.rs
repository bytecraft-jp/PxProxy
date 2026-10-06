//! フォント設定。
//!
//! Windows の日本語フォント（游ゴシック / メイリオ / BIZ UD / MS ゴシック）は `\` を `¥` で描くため、
//! パスや JSON を表示するこのツールでは英数字を Latin フォントで描き、日本語だけをフォールバックで描く。
//! egui はフォールバックのグリフを「行高の差の半分」だけずらして置くのでベースラインがずれる。
//! 両フォントの縦メトリクスから補正量を計算して `FontTweak::y_offset_factor` で揃える。

use std::sync::Arc;

use egui::{FontData, FontDefinitions, FontFamily};
use skrifa::MetadataProvider as _;
use skrifa::instance::{LocationRef, Size};

/// (path, ttc 内の index)
type Face = (&'static str, u32);

const LATIN_PROPORTIONAL: &[Face] = &[(r"C:\Windows\Fonts\segoeui.ttf", 0)];
const LATIN_MONOSPACE: &[Face] = &[(r"C:\Windows\Fonts\consola.ttf", 0)];

const JP_PROPORTIONAL: &[Face] = &[
    (r"C:\Windows\Fonts\YuGothM.ttc", 1), // Yu Gothic UI Regular
    (r"C:\Windows\Fonts\meiryo.ttc", 2),  // Meiryo UI
    (r"C:\Windows\Fonts\BIZ-UDGothicR.ttc", 1),
    ("/System/Library/Fonts/ヒラギノ角ゴシック W3.ttc", 0),
    ("/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc", 0),
];
const JP_MONOSPACE: &[Face] = &[
    (r"C:\Windows\Fonts\BIZ-UDGothicR.ttc", 0), // BIZ UDGothic
    (r"C:\Windows\Fonts\msgothic.ttc", 0),
    ("/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc", 0),
];

fn load(candidates: &[Face]) -> Option<FontData> {
    candidates.iter().find_map(|(path, index)| {
        let bytes = std::fs::read(path).ok()?;
        skrifa::FontRef::from_index(&bytes, *index).ok()?;
        let mut data = FontData::from_owned(bytes);
        data.index = *index;
        Some(data)
    })
}

/// (ascent, row_height) を em 単位で。egui (epaint) と同じく skrifa の既定メトリクスを使う。
fn vertical_metrics(data: &FontData) -> Option<(f32, f32)> {
    let font = skrifa::FontRef::from_index(&data.font, data.index).ok()?;
    let m = font.metrics(Size::unscaled(), LocationRef::default());
    let upem = m.units_per_em as f32;
    Some((m.ascent / upem, (m.ascent - m.descent + m.leading) / upem))
}

/// フォールバックのベースラインを主フォントに合わせる y オフセット（em 単位）。
fn baseline_offset(primary: &FontData, fallback: &FontData) -> f32 {
    match (vertical_metrics(primary), vertical_metrics(fallback)) {
        // 主: baseline = A1。フォールバック: baseline = A2 + (H1 - H2) / 2
        (Some((a1, h1)), Some((a2, h2))) => a1 - a2 - 0.5 * (h1 - h2),
        _ => 0.0,
    }
}

pub fn install(ctx: &egui::Context) {
    let mut fonts = FontDefinitions::default();
    for (family, latin, jp, latin_name, jp_name) in [
        (FontFamily::Proportional, LATIN_PROPORTIONAL, JP_PROPORTIONAL, "latin-prop", "jp-prop"),
        (FontFamily::Monospace, LATIN_MONOSPACE, JP_MONOSPACE, "latin-mono", "jp-mono"),
    ] {
        let list = fonts.families.entry(family.clone()).or_default();
        if let Some(data) = load(latin) {
            fonts.font_data.insert(latin_name.into(), Arc::new(data));
            list.insert(0, latin_name.into());
        }
        let Some(mut data) = load(jp) else {
            tracing::warn!("no Japanese font found for {family:?}");
            continue;
        };
        if let Some(primary) = list.first().and_then(|n| fonts.font_data.get(n)) {
            data.tweak.y_offset_factor = baseline_offset(primary, &data);
        }
        fonts.font_data.insert(jp_name.into(), Arc::new(data));
        // 主フォントの直後 = 英数字以外（日本語）だけがこのフォントで描かれる
        list.insert(1.min(list.len()), jp_name.into());
    }
    ctx.set_fonts(fonts);
}
