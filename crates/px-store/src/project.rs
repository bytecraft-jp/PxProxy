use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use zip::CompressionMethod;
use zip::write::SimpleFileOptions;

use crate::reader::Reader;
use crate::writer::{CommitHook, FlowSink, Writer, open_conn};
use crate::{Result, StoreError, schema};

pub const MANIFEST_FILE: &str = "project.toml";
pub const DB_FILE: &str = "project.sqlite";
pub const BODIES_DIR: &str = "bodies";
/// 案件ごとの設定（Scope / Intercept ルール）。中身は利用側が決める。
pub const SETTINGS_FILE: &str = "settings.toml";
pub const FORMAT_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub format: u32,
    pub name: String,
    /// UNIX 秒
    pub created_at: u64,
}

/// 開いている案件。drop / `close` で writer を止める。
pub struct Project {
    dir: PathBuf,
    manifest: Manifest,
    writer: Writer,
}

impl Project {
    /// 既存なら開き、無ければ作成する。
    pub fn open_or_create(dir: impl AsRef<Path>, on_commit: Option<CommitHook>) -> Result<Self> {
        let dir = dir.as_ref();
        if dir.join(MANIFEST_FILE).exists() {
            Self::open(dir, on_commit)
        } else {
            Self::create(dir, on_commit)
        }
    }

    pub fn create(dir: impl AsRef<Path>, on_commit: Option<CommitHook>) -> Result<Self> {
        let dir = dir.as_ref();
        if dir.join(MANIFEST_FILE).exists() {
            return Err(StoreError::Invalid(format!("project already exists: {}", dir.display())));
        }
        fs::create_dir_all(dir.join(BODIES_DIR))?;
        let name = dir
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "project".into());
        let manifest = Manifest {
            format: FORMAT_VERSION,
            name,
            created_at: SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
        };
        fs::write(dir.join(MANIFEST_FILE), toml::to_string_pretty(&manifest)?)?;
        Self::open(dir, on_commit)
    }

    pub fn open(dir: impl AsRef<Path>, on_commit: Option<CommitHook>) -> Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        let manifest: Manifest = toml::from_str(&fs::read_to_string(dir.join(MANIFEST_FILE))?)?;
        if manifest.format > FORMAT_VERSION {
            return Err(StoreError::Invalid(format!(
                "unsupported project format {} (this build supports {FORMAT_VERSION})",
                manifest.format
            )));
        }
        fs::create_dir_all(dir.join(BODIES_DIR))?;
        let conn = open_conn(&dir.join(DB_FILE))?;
        schema::migrate(&conn)?;
        let writer = Writer::spawn(conn, dir.join(BODIES_DIR), on_commit);
        Ok(Self { dir, manifest, writer })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    pub fn settings_path(&self) -> PathBuf {
        self.dir.join(SETTINGS_FILE)
    }

    pub fn sink(&self) -> FlowSink {
        self.writer.sink()
    }

    pub fn reader(&self) -> Result<Reader> {
        Reader::open(&self.dir.join(DB_FILE), self.dir.join(BODIES_DIR))
    }

    /// 書き込みを全て反映して閉じる。外部に渡した FlowSink は先に drop しておくこと。
    pub fn close(mut self) {
        self.writer.close();
    }

    /// 案件を 1 つの zip にまとめる。DB は `VACUUM INTO` で一貫したスナップショットを取る。
    pub fn export_zip(&self, dest: impl AsRef<Path>) -> Result<()> {
        Self::export_dir(&self.dir, dest.as_ref(), &mut |_, _| true)
    }

    /// `export_zip` の本体。`Project` を借りないので別スレッドから呼べる。
    /// 失敗・中止時は書きかけの zip を消す。
    pub fn export_dir(dir: &Path, dest: &Path, progress: Progress<'_>) -> Result<()> {
        let snapshot = dir.join(".export.sqlite");
        let _ = fs::remove_file(&snapshot);
        Reader::open(&dir.join(DB_FILE), dir.join(BODIES_DIR))?.vacuum_into(&snapshot)?;
        let result = write_zip(dir, &snapshot, dest, progress);
        let _ = fs::remove_file(&snapshot);
        if result.is_err() {
            let _ = fs::remove_file(dest);
        }
        result
    }

    /// zip を `dest_dir` に展開して開く。
    pub fn import_zip(zip_path: impl AsRef<Path>, dest_dir: impl AsRef<Path>, on_commit: Option<CommitHook>) -> Result<Self> {
        let dest_dir = dest_dir.as_ref();
        Self::extract_zip(zip_path.as_ref(), dest_dir, &mut |_, _| true)?;
        Self::open(dest_dir, on_commit)
    }

    /// zip を `dest_dir` に展開する（開かない）。別スレッドから呼べる。
    /// 失敗・中止時は自分で作ったフォルダを消す。
    pub fn extract_zip(zip_path: &Path, dest_dir: &Path, progress: Progress<'_>) -> Result<()> {
        if dest_dir.join(MANIFEST_FILE).exists() {
            return Err(StoreError::Invalid(format!("project already exists: {}", dest_dir.display())));
        }
        let mut archive = zip::ZipArchive::new(fs::File::open(zip_path)?)?;
        if archive.by_name(MANIFEST_FILE).is_err() {
            return Err(StoreError::Invalid("not a project archive (project.toml missing)".into()));
        }
        let created = !dest_dir.exists();
        fs::create_dir_all(dest_dir)?;
        let result = extract(&mut archive, dest_dir, progress);
        if result.is_err() && created {
            let _ = fs::remove_dir_all(dest_dir);
        }
        result
    }
}

/// 長い処理の進捗通知。`(処理済み, 全体)` を受け取り、false を返すと中止する（`StoreError::Cancelled`）。
/// 単位は処理ごとに異なる（エクスポートはバイト数、展開はエントリ数）。
pub type Progress<'a> = &'a mut dyn FnMut(u64, u64) -> bool;

fn extract(archive: &mut zip::ZipArchive<fs::File>, dest: &Path, progress: Progress<'_>) -> Result<()> {
    let n = archive.len() as u64;
    for i in 0..archive.len() {
        if !progress(i as u64, n) {
            return Err(StoreError::Cancelled);
        }
        let mut file = archive.by_index(i)?;
        // enclosed_name で zip-slip を防ぐ。
        let Some(rel) = file.enclosed_name() else {
            return Err(StoreError::Invalid(format!("unsafe path in archive: {}", file.name())));
        };
        let path = dest.join(rel);
        if file.is_dir() {
            fs::create_dir_all(&path)?;
        } else {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            io::copy(&mut file, &mut fs::File::create(&path)?)?;
        }
    }
    progress(n, n);
    Ok(())
}

fn write_zip(dir: &Path, snapshot: &Path, dest: &Path, progress: Progress<'_>) -> Result<()> {
    // 先に一覧を作り、総バイト数を出してから書く。(zip 内の名前, 元ファイル, deflate するか, サイズ)
    let mut entries: Vec<(String, PathBuf, bool, u64)> = Vec::new();
    let mut push = |name: String, path: PathBuf, deflate: bool| -> Result<()> {
        let size = fs::metadata(&path)?.len();
        entries.push((name, path, deflate, size));
        Ok(())
    };
    push(MANIFEST_FILE.into(), dir.join(MANIFEST_FILE), true)?;
    if dir.join(SETTINGS_FILE).exists() {
        push(SETTINGS_FILE.into(), dir.join(SETTINGS_FILE), true)?;
    }
    push(DB_FILE.into(), snapshot.to_path_buf(), true)?;
    let mut stack = vec![dir.join(BODIES_DIR)];
    while let Some(d) = stack.pop() {
        for entry in fs::read_dir(&d)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "zst") {
                let rel = path.strip_prefix(dir).expect("under project dir");
                let name = rel.components().map(|c| c.as_os_str().to_string_lossy()).collect::<Vec<_>>().join("/");
                // Body は zstd 済みなので再圧縮しない。
                push(name, path, false)?;
            }
        }
    }
    let total: u64 = entries.iter().map(|e| e.3).sum();

    let file = fs::File::create(dest)?;
    let mut zip = zip::ZipWriter::new(io::BufWriter::new(file));
    let deflate = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated).large_file(true);
    let stored = SimpleFileOptions::default().compression_method(CompressionMethod::Stored).large_file(true);
    let mut done = 0;
    for (name, path, compress, size) in entries {
        if !progress(done, total) {
            return Err(StoreError::Cancelled);
        }
        zip.start_file(name, if compress { deflate } else { stored })?;
        io::copy(&mut fs::File::open(&path)?, &mut zip)?;
        done += size;
    }
    zip.finish()?;
    progress(total, total);
    Ok(())
}
