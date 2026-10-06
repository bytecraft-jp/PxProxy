//! pxproxy-cli: GUI なしでプロキシを動かす / 案件を操作するコマンド。

mod args;

use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use args::Command;
use px_proxy::{CertAuthority, ProjectSettings, ProxyContext, ProxyServer};
use px_store::{NewFlow, Project};

type DynError = Box<dyn std::error::Error + Send + Sync>;

/// 案件フォルダの目印
const MANIFEST_FILE: &str = "project.toml";

fn main() -> ExitCode {
    let command = match args::parse(std::env::args().skip(1)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("エラー: {e}\n");
            eprintln!("{}", args::USAGE);
            return ExitCode::from(2);
        }
    };
    let result = match command {
        Command::Help => {
            println!("{}", args::USAGE);
            Ok(())
        }
        Command::Version => {
            println!("pxproxy-cli {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Command::Run { project, listen, create, quiet } => run(&project, listen, create, quiet),
        Command::Export { project, zip } => export(&project, &zip),
        Command::Import { zip, dest } => import(&zip, &dest),
        Command::Ca { out } => ca(out.as_deref()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("エラー: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(dir: &Path, listen: std::net::SocketAddr, create: bool, quiet: bool) -> Result<(), DynError> {
    // 通信ログは stdout、警告は stderr
    tracing_subscriber::fmt()
        .with_max_level(tracing_subscriber::filter::LevelFilter::WARN)
        .with_writer(std::io::stderr)
        .init();
    let project = if dir.join(MANIFEST_FILE).exists() {
        Project::open(dir, None)?
    } else if create {
        Project::create(dir, None)?
    } else {
        return Err(format!("案件がありません: {}（--create で新規作成します）", dir.display()).into());
    };
    let ca = Arc::new(CertAuthority::load_or_create(CertAuthority::default_dir())?);
    let ctx = ProxyContext::new(ca)?;
    // hosts の上書きを効かせるため案件の設定を読む（Intercept は CLI では使わない）
    if let Ok(text) = std::fs::read_to_string(project.settings_path()) {
        let settings: ProjectSettings =
            toml::from_str(&text).map_err(|e| format!("settings.toml を読めません: {e}"))?;
        for e in px_proxy::parse_hosts(&settings.hosts).1 {
            eprintln!("警告: hosts {e}");
        }
        let _ = ctx.interceptor().set_settings(settings);
    }
    let count = Arc::new(AtomicU64::new(0));
    let c = count.clone();
    ctx.set_observer(Some(Arc::new(move |flow: &NewFlow| {
        c.fetch_add(1, Ordering::Relaxed);
        if !quiet {
            println!("{}", log_line(flow));
        }
    })));
    ctx.set_sink(Some(project.sink()));

    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().thread_name("px-net").build()?;
    rt.block_on(async {
        let server = ProxyServer::bind(listen, ctx.clone()).await.map_err(|e| format!("待受に失敗しました ({listen}): {e}"))?;
        eprintln!("pxproxy-cli: {} で待ち受け中（Ctrl+C で終了）", server.local_addr());
        eprintln!("  案件: {}", project.dir().display());
        eprintln!("  CA  : {}", CertAuthority::default_dir().join("ca.crt").display());
        tokio::signal::ctrl_c().await?;
        server.stop();
        Ok::<_, DynError>(())
    })?;
    // 処理中の接続を止めてから書き込みを反映して閉じる
    drop(rt);
    ctx.set_sink(None);
    project.close();
    eprintln!("{} 件を記録しました", count.load(Ordering::Relaxed));
    Ok(())
}

/// `200 GET https://example.com/path  12 ms  1.2K`
fn log_line(f: &NewFlow) -> String {
    let default_port = if f.scheme == "https" { 443 } else { 80 };
    let host = if f.port == default_port { f.host.clone() } else { format!("{}:{}", f.host, f.port) };
    let status = f.status.map_or_else(|| "ERR".to_string(), |s| s.to_string());
    let mut line = format!(
        "{status:>3} {:<7} {}://{host}{}  {} ms  {}",
        f.method,
        f.scheme,
        f.target,
        f.duration_us / 1000,
        human_size(f.res_body.len())
    );
    if let Some(e) = &f.error {
        line.push_str(&format!("  [{e}]"));
    }
    line
}

fn human_size(n: usize) -> String {
    match n {
        n if n < 1024 => format!("{n}B"),
        n if n < 1024 * 1024 => format!("{:.1}K", n as f64 / 1024.0),
        n => format!("{:.1}M", n as f64 / (1024.0 * 1024.0)),
    }
}

/// 進捗を 1 行で上書き表示する。
fn progress(label: &'static str) -> impl FnMut(u64, u64) -> bool {
    let mut last = u64::MAX;
    move |done, total| {
        let pct = done.saturating_mul(100).checked_div(total).unwrap_or(0);
        if pct != last {
            last = pct;
            eprint!("\r{label}… {pct:>3}%");
        }
        true
    }
}

fn export(dir: &Path, zip: &Path) -> Result<(), DynError> {
    if !dir.join(MANIFEST_FILE).exists() {
        return Err(format!("案件がありません: {}", dir.display()).into());
    }
    Project::export_dir(dir, zip, &mut progress("エクスポート"))?;
    eprintln!("\nエクスポートしました: {}", zip.display());
    Ok(())
}

fn import(zip: &Path, dest: &Path) -> Result<(), DynError> {
    if dest.exists() {
        return Err(format!("展開先が既に存在します: {}", dest.display()).into());
    }
    Project::extract_zip(zip, dest, &mut progress("インポート"))?;
    eprintln!("\nインポートしました: {}", dest.display());
    Ok(())
}

fn ca(out: Option<&Path>) -> Result<(), DynError> {
    let dir = CertAuthority::default_dir();
    let ca = CertAuthority::load_or_create(&dir)?;
    match out {
        Some(path) => {
            std::fs::write(path, ca.ca_pem())?;
            eprintln!("CA 証明書を保存しました: {}", path.display());
        }
        None => print!("{}", ca.ca_pem()),
    }
    Ok(())
}
