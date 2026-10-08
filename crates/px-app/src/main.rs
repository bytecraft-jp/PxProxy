#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod cli;
mod codec;
mod diff;
mod fonts;
mod highlight;
mod view;

fn main() -> eframe::Result {
    let opts = match cli::parse(std::env::args().skip(1)) {
        Ok(o) if o.help => {
            attach_console();
            println!("{}", cli::USAGE);
            return Ok(());
        }
        Ok(o) if o.version => {
            attach_console();
            println!("pxproxy {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        Ok(o) => o,
        Err(e) => {
            attach_console();
            eprintln!("エラー: {e}

{}", cli::USAGE);
            std::process::exit(2);
        }
    };

    // スレッドを増やす前にタイムゾーンを読む（一覧の時刻表示用）
    view::init_local_offset();

    use tracing_subscriber::prelude::*;
    // 自前クレートはデバッグビルドで debug まで出す（接続の異常終了理由など）
    let own = if cfg!(debug_assertions) { tracing::Level::DEBUG } else { tracing::Level::INFO };
    let filter = tracing_subscriber::filter::Targets::new()
        .with_default(tracing::Level::WARN)
        .with_target("px_proxy", own)
        .with_target("px_store", own)
        .with_target("px_app", own);
    tracing_subscriber::registry().with(tracing_subscriber::fmt::layer()).with(filter).init();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1280.0, 800.0])
            .with_min_inner_size([800.0, 500.0])
            .with_maximized(true)
            .with_title("pxproxy")
            .with_icon(window_icon()),
        renderer: eframe::Renderer::Wgpu,
        ..Default::default()
    };
    eframe::run_native(
        "pxproxy",
        options,
        Box::new(|cc| {
            fonts::install(&cc.egui_ctx);
            egui_extras::install_image_loaders(&cc.egui_ctx);
            Ok(Box::new(app::PxApp::new(cc.egui_ctx.clone(), opts)?))
        }),
    )
}

/// ウィンドウ（タイトルバー・タスクバー）のアイコン。
fn window_icon() -> egui::IconData {
    let img = image::load_from_memory(include_bytes!("../assets/icon-256.png")).expect("同梱アイコンの読み込みに失敗").into_rgba8();
    let (width, height) = img.dimensions();
    egui::IconData { rgba: img.into_raw(), width, height }
}

/// リリースビルドは GUI サブシステムなので、起動元のコンソールに出力をつなぐ（--help 等の表示用）。
fn attach_console() {
    #[cfg(windows)]
    // SAFETY: 引数は定数のみ。失敗しても（コンソールが無い・既にある）何もしない。
    unsafe {
        windows_sys::Win32::System::Console::AttachConsole(windows_sys::Win32::System::Console::ATTACH_PARENT_PROCESS);
    }
}
