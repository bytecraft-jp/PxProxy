//! Body ストア。小さい Body は SQLite に inline、閾値を超えるものは
//! `bodies/ab/cd/<hash>.zst` に zstd 圧縮して置く。どちらも blake3 で重複排除。

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OptionalExtension, params};

use crate::{Result, StoreError};

/// これ以下のサイズは SQLite 内に保存する（小さい BLOB は DB 内の方が速い）。
pub const INLINE_THRESHOLD: usize = 64 * 1024;

const LOC_INLINE: i64 = 0;
const LOC_FILE: i64 = 1;
const ZSTD_LEVEL: i32 = 3;

pub fn hex(hash: &[u8]) -> String {
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn file_path(bodies_dir: &Path, hash: &[u8]) -> PathBuf {
    let h = hex(hash);
    bodies_dir.join(&h[0..2]).join(&h[2..4]).join(format!("{h}.zst"))
}

/// Body を保存してハッシュを返す。空なら None。トランザクション内で呼ぶ前提。
pub fn put(conn: &Connection, bodies_dir: &Path, data: &[u8]) -> Result<Option<[u8; 32]>> {
    if data.is_empty() {
        return Ok(None);
    }
    let hash = *blake3::hash(data).as_bytes();
    let exists = conn
        .prepare_cached("SELECT 1 FROM bodies WHERE hash = ?1")?
        .exists([&hash[..]])?;
    if exists {
        return Ok(Some(hash));
    }
    if data.len() <= INLINE_THRESHOLD {
        conn.prepare_cached("INSERT INTO bodies(hash, size, location, data) VALUES (?1, ?2, ?3, ?4)")?
            .execute(params![&hash[..], data.len() as i64, LOC_INLINE, data])?;
    } else {
        write_file(&file_path(bodies_dir, &hash), data)?;
        conn.prepare_cached("INSERT INTO bodies(hash, size, location, data) VALUES (?1, ?2, ?3, NULL)")?
            .execute(params![&hash[..], data.len() as i64, LOC_FILE])?;
    }
    Ok(Some(hash))
}

fn write_file(path: &Path, data: &[u8]) -> Result<()> {
    if path.exists() {
        return Ok(());
    }
    let dir = path.parent().expect("body path has parent");
    fs::create_dir_all(dir)?;
    // 一時ファイルに書いてから rename し、途中で落ちても壊れたファイルを残さない。
    let tmp = path.with_extension("tmp");
    {
        let mut f = fs::File::create(&tmp)?;
        let compressed = zstd::bulk::compress(data, ZSTD_LEVEL)?;
        f.write_all(&compressed)?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

pub fn get(conn: &Connection, bodies_dir: &Path, hash: Option<Vec<u8>>) -> Result<Vec<u8>> {
    let Some(hash) = hash else {
        return Ok(Vec::new());
    };
    let row: Option<(i64, i64, Option<Vec<u8>>)> = conn
        .prepare_cached("SELECT size, location, data FROM bodies WHERE hash = ?1")?
        .query_row([&hash], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .optional()?;
    match row {
        None => Err(StoreError::Invalid(format!("body {} not found", hex(&hash)))),
        Some((_, LOC_INLINE, data)) => Ok(data.unwrap_or_default()),
        Some((size, _, _)) => {
            let compressed = fs::read(file_path(bodies_dir, &hash))?;
            Ok(zstd::bulk::decompress(&compressed, size as usize)?)
        }
    }
}
