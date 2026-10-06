//! GUI の起動オプション（`pxproxy [案件フォルダ] [-l アドレス] [-s]`）。

use std::path::PathBuf;

pub const USAGE: &str = "\
使い方: pxproxy [案件フォルダ] [オプション]

  案件フォルダ             起動時に開く案件（無ければ作成）
  -l, --listen <アドレス>  待受アドレス（既定: 127.0.0.1:8080）
  -s, --start              起動と同時にプロキシを開始する（案件の指定が必要）
  -h, --help               この説明を表示する
  -V, --version            バージョンを表示する

GUI なしで使う場合は pxproxy-cli を使ってください。";

#[derive(Debug, Default, PartialEq, Eq)]
pub struct LaunchOptions {
    pub project: Option<PathBuf>,
    pub listen: Option<String>,
    pub start: bool,
    pub help: bool,
    pub version: bool,
}

pub fn parse(args: impl IntoIterator<Item = String>) -> Result<LaunchOptions, String> {
    let mut opts = LaunchOptions::default();
    let mut args = args.into_iter();
    while let Some(a) = args.next() {
        match a.as_str() {
            "-l" | "--listen" => opts.listen = Some(args.next().ok_or_else(|| format!("{a} に値がありません"))?),
            "-s" | "--start" => opts.start = true,
            "-h" | "--help" => opts.help = true,
            "-V" | "--version" => opts.version = true,
            s if s.starts_with('-') && s.len() > 1 => return Err(format!("不明なオプション: {s}")),
            _ if opts.project.is_some() => return Err(format!("案件フォルダは 1 つだけ指定できます: {a}")),
            _ => opts.project = Some(PathBuf::from(a)),
        }
    }
    if opts.start && opts.project.is_none() {
        return Err("--start には案件フォルダの指定が必要です".into());
    }
    Ok(opts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(args: &[&str]) -> Result<LaunchOptions, String> {
        parse(args.iter().map(|s| s.to_string()))
    }

    #[test]
    fn parses_options() {
        assert_eq!(p(&[]), Ok(LaunchOptions::default()));
        let o = p(&["a.pxproj", "--listen", "127.0.0.1:9000", "-s"]).unwrap();
        assert_eq!(o.project, Some("a.pxproj".into()));
        assert_eq!(o.listen.as_deref(), Some("127.0.0.1:9000"));
        assert!(o.start);
        assert!(p(&["-h"]).unwrap().help);
        assert!(p(&["-s"]).unwrap_err().contains("案件フォルダ"));
        assert!(p(&["a", "b"]).unwrap_err().contains("1 つだけ"));
        assert!(p(&["--nope"]).unwrap_err().contains("不明なオプション"));
        assert!(p(&["-l"]).unwrap_err().contains("値がありません"));
    }
}
