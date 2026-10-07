fn main() {
    println!("cargo:rerun-if-changed=assets/icon.ico");
    // exe ファイル自体のアイコン（エクスプローラー・タスクバーのピン留めで表示される）
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        winresource::WindowsResource::new().set_icon("assets/icon.ico").compile().expect("アイコンリソースの埋め込みに失敗");
    }
}
