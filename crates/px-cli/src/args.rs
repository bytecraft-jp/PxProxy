//! コマンドライン引数の解析。

use std::net::SocketAddr;
use std::path::PathBuf;

pub const DEFAULT_LISTEN: &str = "127.0.0.1:8080";

pub const USAGE: &str = "\
pxproxy-cli — GUI なしで pxproxy を使うコマンド

使い方:
  pxproxy-cli run <案件フォルダ> [-l <アドレス>] [--create] [-q]
      プロキシを起動して通信を案件に記録する（Ctrl+C で終了）
        -l, --listen <アドレス>  待受アドレス（既定: 127.0.0.1:8080）
            --create           案件が無ければ作成する
        -q, --quiet            通信ごとのログを出さない
  pxproxy-cli export <案件フォルダ> <出力.zip>
      案件を zip にまとめる
  pxproxy-cli import <入力.zip> <展開先フォルダ>
      zip を案件フォルダに展開する
  pxproxy-cli ca [-o <ファイル>]
      CA 証明書 (PEM) を表示する / ファイルに保存する
  pxproxy-cli help | --help
  pxproxy-cli --version";

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Help,
    Version,
    Run { project: PathBuf, listen: SocketAddr, create: bool, quiet: bool },
    Export { project: PathBuf, zip: PathBuf },
    Import { zip: PathBuf, dest: PathBuf },
    Ca { out: Option<PathBuf> },
}

pub fn parse(args: impl IntoIterator<Item = String>) -> Result<Command, String> {
    let mut args = args.into_iter();
    let Some(sub) = args.next() else {
        return Ok(Command::Help);
    };
    let mut positional = Vec::new();
    let mut listen = DEFAULT_LISTEN.to_string();
    let mut create = false;
    let mut quiet = false;
    let mut out = None;
    while let Some(a) = args.next() {
        let mut value = |name: &str| args.next().ok_or_else(|| format!("{name} に値がありません"));
        match a.as_str() {
            "-l" | "--listen" if sub == "run" => listen = value(&a)?,
            "--create" if sub == "run" => create = true,
            "-q" | "--quiet" if sub == "run" => quiet = true,
            "-o" | "--out" if sub == "ca" => out = Some(PathBuf::from(value(&a)?)),
            "-h" | "--help" => return Ok(Command::Help),
            s if s.starts_with('-') && s.len() > 1 => return Err(format!("不明なオプション: {s}")),
            _ => positional.push(PathBuf::from(a)),
        }
    }
    let expect = |n: usize| {
        if positional.len() == n {
            Ok(())
        } else {
            Err(format!("{sub} には引数が {n} 個必要です（{} 個指定されました）", positional.len()))
        }
    };
    match sub.as_str() {
        "help" | "-h" | "--help" => Ok(Command::Help),
        "-V" | "--version" | "version" => Ok(Command::Version),
        "run" => {
            expect(1)?;
            let listen = listen.parse().map_err(|e| format!("待受アドレスが不正です ({listen}): {e}"))?;
            Ok(Command::Run { project: positional.remove(0), listen, create, quiet })
        }
        "export" => {
            expect(2)?;
            let zip = positional.pop().expect("2 args");
            Ok(Command::Export { project: positional.remove(0), zip })
        }
        "import" => {
            expect(2)?;
            let dest = positional.pop().expect("2 args");
            Ok(Command::Import { zip: positional.remove(0), dest })
        }
        "ca" => {
            expect(0)?;
            Ok(Command::Ca { out })
        }
        other => Err(format!("不明なコマンド: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(args: &[&str]) -> Result<Command, String> {
        parse(args.iter().map(|s| s.to_string()))
    }

    #[test]
    fn parses_commands() {
        assert_eq!(p(&[]), Ok(Command::Help));
        assert_eq!(p(&["--version"]), Ok(Command::Version));
        assert_eq!(
            p(&["run", "a.pxproj", "-l", "0.0.0.0:9000", "--create", "-q"]),
            Ok(Command::Run { project: "a.pxproj".into(), listen: "0.0.0.0:9000".parse().unwrap(), create: true, quiet: true })
        );
        assert_eq!(
            p(&["run", "a.pxproj"]),
            Ok(Command::Run { project: "a.pxproj".into(), listen: DEFAULT_LISTEN.parse().unwrap(), create: false, quiet: false })
        );
        assert_eq!(p(&["export", "a", "b.zip"]), Ok(Command::Export { project: "a".into(), zip: "b.zip".into() }));
        assert_eq!(p(&["import", "b.zip", "c"]), Ok(Command::Import { zip: "b.zip".into(), dest: "c".into() }));
        assert_eq!(p(&["ca", "-o", "ca.crt"]), Ok(Command::Ca { out: Some("ca.crt".into()) }));
        assert_eq!(p(&["run", "a", "--help"]), Ok(Command::Help));
    }

    #[test]
    fn rejects_bad_input() {
        assert!(p(&["run"]).unwrap_err().contains("1 個必要"));
        assert!(p(&["run", "a", "-l"]).unwrap_err().contains("値がありません"));
        assert!(p(&["run", "a", "-l", "nope"]).unwrap_err().contains("待受アドレス"));
        assert!(p(&["export", "a", "-q"]).unwrap_err().contains("不明なオプション"));
        assert!(p(&["serve"]).unwrap_err().contains("不明なコマンド"));
    }
}
