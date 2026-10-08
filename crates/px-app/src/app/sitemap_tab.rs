//! サイトマップ: 記録した通信をホスト → パスのツリーで表示する。
//! ノードを選ぶと、その配下の通信だけを一覧（History と同じ表）に出す。

use std::collections::BTreeMap;

use egui::RichText;
use egui::collapsing_header::CollapsingState;
use px_store::{Reader, SiteFilter};

use super::PxApp;

/// ツリーの 1 ノード（パスの 1 区切り）。`count` は配下の通信の数。
#[derive(Default)]
struct Node {
    count: u32,
    children: BTreeMap<String, Node>,
}

impl Node {
    fn add(&mut self, segments: &[&str]) {
        self.count += 1;
        if let Some((first, rest)) = segments.split_first() {
            self.children.entry((*first).to_string()).or_default().add(rest);
        }
    }
}

/// ホストのノードのキー。ホスト名の順に並べる。
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct HostKey {
    host: String,
    scheme: String,
    port: u16,
}

impl HostKey {
    fn origin(&self) -> String {
        let default_port = if self.scheme == "https" { 443 } else { 80 };
        if self.port == default_port {
            format!("{}://{}", self.scheme, self.host)
        } else {
            format!("{}://{}:{}", self.scheme, self.host, self.port)
        }
    }
}

#[derive(Default)]
pub(super) struct SiteMap {
    hosts: BTreeMap<HostKey, Node>,
    last_id: i64,
    /// 診断対象のホスト・パスだけでツリーを作る
    pub(super) in_scope_only: bool,
    /// 選んだノード。None なら全体
    pub(super) selected: Option<SiteFilter>,
}

impl SiteMap {
    /// ツリーを作り直す（次の `update` で全件を読み直す）。
    pub(super) fn reset(&mut self) {
        self.hosts.clear();
        self.last_id = 0;
    }

    /// 新しく記録された通信をツリーに足す。
    pub(super) fn update(&mut self, reader: &Reader) -> px_store::Result<()> {
        for (id, scheme, host, port, target) in reader.site_rows_after(self.last_id, self.in_scope_only)? {
            self.last_id = id;
            let path = target.split(['?', '#']).next().unwrap_or("");
            let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
            self.hosts.entry(HostKey { host, scheme, port }).or_default().add(&segments);
        }
        Ok(())
    }
}

/// ツリーで起きた操作。
enum Action {
    Select(Option<SiteFilter>),
    Scope { host: String, exclude: bool },
}

impl PxApp {
    pub(super) fn site_map_tree(&mut self, ui: &mut egui::Ui) {
        let mut action = None;
        let mut rebuild = false;
        ui.horizontal(|ui| {
            ui.strong("サイトマップ");
            rebuild = ui
                .toggle_value(&mut self.site_map.in_scope_only, "診断対象のみ")
                .on_hover_text("「診断対象 / ルール」タブで設定したホスト・パスだけでツリーを作ります")
                .changed();
        });
        ui.separator();
        let sm = &self.site_map;
        let scope = &self.settings.scope;
        egui::ScrollArea::both().id_salt("site_map").auto_shrink(false).show(ui, |ui| {
            if ui.selectable_label(sm.selected.is_none(), RichText::new("（すべての通信）").weak()).clicked() {
                action = Some(Action::Select(None));
            }
            if sm.hosts.is_empty() {
                ui.label(RichText::new("まだ記録がありません").weak());
            }
            for (key, node) in &sm.hosts {
                let site = SiteFilter { scheme: key.scheme.clone(), host: key.host.clone(), port: key.port, path: String::new() };
                let mut label = RichText::new(format!("{}  ({})", key.origin(), node.count)).strong();
                if !scope.contains(&key.host, "/") {
                    label = RichText::new(format!("{}  ({})", key.origin(), node.count)).weak();
                }
                let resp = tree_node(ui, &site, label, node, sm.selected.as_ref(), &mut action);
                resp.context_menu(|ui| {
                    ui.label(RichText::new(&key.host).strong());
                    if ui.button("このホストを診断対象に追加").clicked() {
                        action = Some(Action::Scope { host: key.host.clone(), exclude: false });
                    }
                    if ui.button("このホストを診断対象から除外").clicked() {
                        action = Some(Action::Scope { host: key.host.clone(), exclude: true });
                    }
                });
            }
        });
        if rebuild {
            self.site_map.reset();
            self.dirty.store(true, std::sync::atomic::Ordering::Release);
        }
        match action {
            Some(Action::Select(site)) => {
                self.site_map.selected = site;
                self.follow = true;
            }
            Some(Action::Scope { host, exclude }) => self.add_scope_host(&host, exclude),
            None => {}
        }
    }
}

/// 1 ノードを表示する（子があれば折りたたみ）。見出しの Response を返す。
fn tree_node(
    ui: &mut egui::Ui,
    site: &SiteFilter,
    label: RichText,
    node: &Node,
    selected: Option<&SiteFilter>,
    action: &mut Option<Action>,
) -> egui::Response {
    let is_selected = selected == Some(site);
    if node.children.is_empty() {
        let resp = ui
            .horizontal(|ui| {
                // 折りたたみボタンの分だけ下げて、兄弟の見出しと揃える
                ui.add_space(ui.spacing().indent);
                ui.selectable_label(is_selected, label)
            })
            .inner;
        if resp.clicked() {
            *action = Some(Action::Select(Some(site.clone())));
        }
        return resp;
    }
    let id = egui::Id::new(("site_map", &site.scheme, &site.host, site.port, &site.path));
    // ホストは開いた状態で始める
    let (_, header, _) = CollapsingState::load_with_default_open(ui.ctx(), id, site.path.is_empty())
        .show_header(ui, |ui| ui.selectable_label(is_selected, label))
        .body(|ui| {
            for (name, child) in &node.children {
                let child_site = SiteFilter { path: format!("{}/{name}", site.path), ..site.clone() };
                let text = if child.children.is_empty() { name.clone() } else { format!("{name}/") };
                let label = RichText::new(format!("{text}  ({})", child.count));
                tree_node(ui, &child_site, label, child, selected, action);
            }
        });
    if header.inner.clicked() {
        *action = Some(Action::Select(Some(site.clone())));
    }
    header.inner
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_counts_paths() {
        let mut root = Node::default();
        for path in ["/a/b", "/a/c", "/a", "/d"] {
            let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
            root.add(&segs);
        }
        assert_eq!(root.count, 4);
        assert_eq!(root.children["a"].count, 3);
        assert_eq!(root.children["a"].children.len(), 2);
        assert!(root.children["d"].children.is_empty());
    }
}
