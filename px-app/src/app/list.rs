//! 一覧の読み込み（フィルタに一致する ID の差分取得）と、詳細を表示する行の選択。

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use px_store::{Filter, FlowSource};

use super::detail::Detail;
use super::{PxApp, Tab};
use crate::view;

/// 本文検索で 1 フレームに使う時間（超えた分は次のフレームで続ける）
const SCAN_BUDGET: Duration = Duration::from_millis(25);

impl PxApp {
    pub(super) fn reset_list(&mut self) {
        self.history.ids.clear();
        self.history.cache.clear();
        self.history.last_id = 0;
        self.history.scanning = false;
        // 見えなくなった行を選んだまま削除しないように、選択は外す
        self.history.picked.clear();
        self.history.anchor = None;
        self.dirty.store(true, Ordering::Release);
    }

    /// 一覧に適用する条件。サイトマップではツリーで選んだノードで絞る。
    fn effective_filter(&self) -> Filter {
        let mut f = self.history.filter.clone();
        if self.tab == Tab::SiteMap {
            f.site = self.site_map.selected.clone();
        }
        f
    }

    pub(super) fn refresh(&mut self) {
        let wanted = self.effective_filter();
        // 正規表現の誤りなどで使えない条件は適用しない（フィルタバーに理由を出す）
        if wanted != self.history.applied && wanted.error().is_none() {
            self.history.applied = wanted;
            self.reset_list();
        }
        let committed = self.dirty.swap(false, Ordering::AcqRel);
        if !committed && !self.history.scanning {
            return;
        }
        let Some(reader) = self.reader.take() else { return };
        // 本文検索は Body を読んで展開するので、1 フレームに使う時間を決めて少しずつ進める
        match reader.scan_after(self.history.last_id, &self.history.applied, Some(Instant::now() + SCAN_BUDGET)) {
            Ok(scan) => {
                self.history.last_id = scan.upto;
                self.history.ids.extend(scan.ids);
                self.history.scanning = !scan.complete;
                if self.history.scanning {
                    self.egui_ctx.request_repaint();
                }
            }
            Err(e) => {
                self.history.scanning = false;
                self.status = format!("読み込みエラー: {e}");
            }
        }
        if committed {
            self.history.total = reader.count().unwrap_or(self.history.total);
            self.finish_deletes(&reader);
            if let Err(e) = self.site_map.update(&reader) {
                self.status = format!("サイトマップの読み込みエラー: {e}");
            }
            self.findings.dirty = true;
            if let Some(d) = &mut self.detail {
                d.refresh_ws(&reader);
            }
        }
        self.reader = Some(reader);
    }

    pub(super) fn select(&mut self, id: i64) {
        self.selected = Some(id);
        if self.detail.as_ref().is_some_and(|d| d.id == id) {
            return;
        }
        let Some(reader) = &self.reader else { return };
        match reader.detail(id) {
            Ok(Some(d)) => {
                let request = view::render_message(&d.req_head, &d.req_body, &format!("{id}/req"));
                let response = match &d.res_head {
                    Some(h) => view::render_message(h, &d.res_body, &format!("{id}/res")),
                    None if d.summary.source == FlowSource::Tunnel => view::Rendered::plain(
                        "[TLS パススルー] 復号せずにそのまま中継したため、中身は記録していません".into(),
                    ),
                    None => view::Rendered::plain(d.summary.error.clone().map(|e| format!("[エラー] {e}")).unwrap_or_default()),
                };
                let originals = [
                    d.orig_request.as_ref().map(|(h, b)| view::render_message(h, b, &format!("{id}/req-orig"))),
                    d.orig_response.as_ref().map(|(h, b)| view::render_message(h, b, &format!("{id}/res-orig"))),
                ];
                let findings = reader.findings_of(id).unwrap_or_default();
                let ws = (d.summary.status == Some(101)).then(|| reader.ws_messages(id, 0).unwrap_or_default());
                let kept = [d.req_body.len(), d.res_body.len()];
                self.forget_detail_images();
                self.detail = Some(Detail::new(d.summary, findings, kept, [request, response], originals, ws));
                self.selection = None;
                self.search.reset_position();
            }
            Ok(None) => self.detail = None,
            Err(e) => self.status = format!("詳細の読み込みに失敗: {e}"),
        }
    }

    /// 表示を切り替えたら前の画像をデコード済みキャッシュから捨てる。
    pub(super) fn forget_detail_images(&self) {
        if let Some(d) = &self.detail {
            for uri in d.image_uris() {
                self.egui_ctx.forget_image(uri);
            }
        }
    }
}
