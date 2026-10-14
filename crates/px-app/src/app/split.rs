//! 左右に並べた 2 つの領域の幅を、間のつまみのドラッグで変えられるようにする。
//! 比率は名前ごとに覚える（ダブルクリックで半分に戻す）。

use egui::{Align, CursorIcon, Id, Layout, Rect, Sense, Ui, UiBuilder, pos2, vec2};

/// 片側の最小の幅
const MIN_WIDTH: f32 = 80.0;

/// `rect` を左右に分けた位置。間の隙間（`item_spacing.x`）がつまみになる。
pub(super) struct Split {
    key: Id,
    rect: Rect,
    gap: f32,
    left: f32,
}

impl Split {
    /// `rect` を前回の比率で左右に分ける。
    pub(super) fn new(ui: &Ui, name: &str, rect: Rect) -> Self {
        let key = Id::new(("split", name));
        let gap = ui.spacing().item_spacing.x;
        let ratio = ui.data_mut(|d| d.get_persisted::<f32>(key)).unwrap_or(0.5);
        let mut s = Self { key, rect, gap, left: 0.0 };
        s.left = s.clamp(s.usable() * ratio);
        s
    }

    fn usable(&self) -> f32 {
        (self.rect.width() - self.gap).max(0.0)
    }

    fn clamp(&self, left: f32) -> f32 {
        let min = MIN_WIDTH.min(self.usable() / 2.0);
        left.clamp(min, self.usable() - min)
    }

    /// 左側の幅
    pub(super) fn left_width(&self) -> f32 {
        self.left
    }

    /// 右側の幅
    pub(super) fn right_width(&self) -> f32 {
        self.usable() - self.left
    }

    /// 左右の中身を描いた後に呼ぶ（後から置いた方が中身のドラッグより優先される）。
    /// `bottom` までつまみを置く。
    pub(super) fn handle(&self, ui: &mut Ui, bottom: f32) {
        let x = self.rect.left() + self.left;
        let rect = Rect::from_min_max(pos2(x, self.rect.top()), pos2(x + self.gap, bottom.max(self.rect.top())));
        let id = ui.id().with(self.key);
        let r = ui.interact(rect.expand2(vec2(2.0, 0.0)), id, Sense::click_and_drag());
        let active = r.hovered() || r.dragged();
        if active {
            ui.ctx().set_cursor_icon(CursorIcon::ResizeHorizontal);
        }
        let v = ui.visuals();
        let stroke = if active { v.widgets.hovered.fg_stroke } else { v.widgets.noninteractive.bg_stroke };
        ui.painter().vline(rect.center().x, rect.y_range(), stroke);

        let ratio = if r.double_clicked() {
            Some(0.5)
        } else if r.dragged()
            && let Some(p) = r.interact_pointer_pos()
            && self.usable() > 0.0
        {
            Some(self.clamp(p.x - self.rect.left() - self.gap / 2.0) / self.usable())
        } else {
            None
        };
        if let Some(ratio) = ratio {
            ui.data_mut(|d| d.insert_persisted(self.key, ratio));
            ui.ctx().request_repaint();
        }
    }
}

/// `ui.columns(2, ..)` の代わり。間のつまみで左右の幅を変えられる。
pub(super) fn columns<R>(ui: &mut Ui, name: &str, add: impl FnOnce(&mut [Ui]) -> R) -> R {
    let rect = ui.available_rect_before_wrap();
    let split = Split::new(ui, name, rect);
    let col = |ui: &mut Ui, x: f32, width: f32| {
        let r = Rect::from_min_size(pos2(x, rect.top()), vec2(width, rect.height()));
        let mut c = ui.new_child(UiBuilder::new().max_rect(r).layout(Layout::top_down_justified(Align::LEFT)));
        c.set_width(width);
        c.shrink_clip_rect(r);
        c
    };
    let mut cols = [
        col(ui, rect.left(), split.left_width()),
        col(ui, rect.left() + split.left_width() + split.gap, split.right_width()),
    ];
    let out = add(&mut cols);
    let bottom = cols.iter().map(|c| c.min_rect().bottom()).fold(rect.top(), f32::max);
    ui.advance_cursor_after_rect(Rect::from_min_max(rect.min, pos2(rect.right(), bottom)));
    split.handle(ui, bottom);
    out
}
