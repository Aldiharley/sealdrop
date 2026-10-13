//! Hardened tar extraction (spec section 7).

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use crate::hashing::HashingWriter;
use crate::pack::{Meta, META_FORMAT, META_PATH, PAYLOAD_PREFIX};
use crate::{Error, Result};

pub const META_MAX_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone)]
pub struct Limits {
    pub max_entries: u64,
    pub max_bytes: u64,
    pub max_file_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_entries: 100_000,
            max_bytes: 64 << 30,
            max_file_bytes: 64 << 30,
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ExtractError {
    #[error("forbidden entry type for {0}")]
    ForbiddenEntry(String),
    #[error("bad path {0}")]
    BadPath(String),
    #[error("first entry must be sealdrop/meta.json")]
    MetaMissing,
    #[error("meta.json too large")]
    MetaTooLarge,
    #[error("meta.json invalid: {0}")]
    MetaInvalid(String),
    #[error("too many entries")]
    TooManyEntries,
    #[error("too many bytes")]
    TooManyBytes,
    #[error("hash mismatch for {0}")]
    HashMismatch(String),
    #[error("file listed in meta.json missing from archive: {0}")]
    MissingFile(String),
    #[error("file not listed in meta.json: {0}")]
    UnlistedFile(String),
    #[error("entry root {0} does not match meta root")]
    WrongRoot(String),
}

#[derive(Debug, Clone)]
pub struct ExtractReport {
    pub root: PathBuf,
    pub files: usize,
    pub bytes: u64,
    pub meta: Meta,
}

const WINDOWS_RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Validates a tar entry path and returns it relative to `sealdrop/payload/`.
pub fn check_path(p: &str) -> std::result::Result<String, ExtractError> {
    let bad = || ExtractError::BadPath(p.to_string());
    if p.contains('\0') || p.contains('\\') || p.contains(':') || p.starts_with('/') {
        return Err(bad());
    }
    let rel = p.strip_prefix(PAYLOAD_PREFIX).ok_or_else(bad)?;
    if rel.is_empty() {
        return Err(bad());
    }
    for comp in rel.split('/') {
        if comp.is_empty() || comp == "." || comp == ".." {
            return Err(bad());
        }
        let stem = comp.split('.').next().unwrap_or("").to_ascii_uppercase();
        if WINDOWS_RESERVED.contains(&stem.as_str()) {
            return Err(bad());
        }
    }
    Ok(rel.to_string())
}

fn entry_path_string(
    entry: &tar::Entry<'_, impl Read>,
) -> std::result::Result<String, ExtractError> {
    let p = entry
        .path()
        .map_err(|e| ExtractError::BadPath(e.to_string()))?;
    let s = p.to_string_lossy().into_owned();
    // On Windows the tar crate may yield backslashes for GNU long names; normalise only
    // for the META check; payload paths with backslashes are rejected by check_path.
    Ok(s)
}

/// Extracts a sealdrop tar stream into `out_dir/<root>`, verifying every file hash.
pub fn extract<R: Read>(
    r: R,
    out_dir: &Path,
    limits: &Limits,
    overwrite: bool,
) -> Result<ExtractReport> {
    let mut archive = tar::Archive::new(r);
    archive.set_overwrite(false);
    archive.set_preserve_permissions(false);
    archive.set_unpack_xattrs(false);
    let mut entries = archive.entries()?;

    // 1. meta.json must be first.
    let first = entries.next().ok_or(ExtractError::MetaMissing)??;
    if entry_path_string(&first)? != META_PATH || !first.header().entry_type().is_file() {
        return Err(ExtractError::MetaMissing.into());
    }
    if first.header().size()? > META_MAX_BYTES {
        return Err(ExtractError::MetaTooLarge.into());
    }
    let mut meta_bytes = Vec::new();
    first
        .take(META_MAX_BYTES + 1)
        .read_to_end(&mut meta_bytes)?;
    if meta_bytes.len() as u64 > META_MAX_BYTES {
        return Err(ExtractError::MetaTooLarge.into());
    }
    let meta: Meta = serde_json::from_slice(&meta_bytes)
        .map_err(|e| ExtractError::MetaInvalid(e.to_string()))?;
    if meta.format != META_FORMAT {
        return Err(ExtractError::MetaInvalid(format!("unknown format {}", meta.format)).into());
    }
    check_path(&format!("{PAYLOAD_PREFIX}{}", meta.root))?;
    for f in &meta.files {
        let rel = check_path(&format!("{PAYLOAD_PREFIX}{}", f.path))?;
        if rel.split('/').next() != Some(meta.root.as_str()) {
            return Err(ExtractError::WrongRoot(f.path.clone()).into());
        }
    }
    let expected: HashMap<&str, &crate::pack::FileEntry> =
        meta.files.iter().map(|f| (f.path.as_str(), f)).collect();

    // 2. Temp dir inside out_dir so the final rename is atomic on the same volume.
    fs::create_dir_all(out_dir)?;
    let final_path = out_dir.join(&meta.root);
    if final_path.exists() && !overwrite {
        return Err(Error::Exists(final_path));
    }
    let tmp = tempfile::Builder::new()
        .prefix(".sealdrop-")
        .tempdir_in(out_dir)?;

    let mut n_entries = 1u64;
    let mut n_bytes = 0u64;
    let mut seen: HashMap<String, ()> = HashMap::new();

    for entry in entries {
        let mut entry = entry?;
        n_entries += 1;
        if n_entries > limits.max_entries {
            return Err(ExtractError::TooManyEntries.into());
        }
        let raw = entry_path_string(&entry)?;
        let rel = check_path(&raw)?;
        if rel.split('/').next() != Some(meta.root.as_str()) {
            return Err(ExtractError::WrongRoot(rel).into());
        }
        let dest = tmp.path().join(&rel);
        let et = entry.header().entry_type();
        if et.is_dir() {
            fs::create_dir_all(&dest)?;
            continue;
        }
        if !et.is_file() {
            return Err(ExtractError::ForbiddenEntry(rel).into());
        }
        let fe = *expected
            .get(rel.as_str())
            .ok_or_else(|| ExtractError::UnlistedFile(rel.clone()))?;
        let size = entry.header().size()?;
        if size != fe.size || size > limits.max_file_bytes {
            return Err(ExtractError::HashMismatch(rel).into());
        }
        n_bytes += size;
        if n_bytes > limits.max_bytes {
            return Err(ExtractError::TooManyBytes.into());
        }
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut hw = HashingWriter::new(File::create(&dest)?);
        io::copy(&mut entry.by_ref().take(size), &mut hw)?;
        let (mut f, hash, written) = hw.finish();
        f.flush()?;
        if written != size || hash != fe.sha256 {
            return Err(ExtractError::HashMismatch(rel).into());
        }
        seen.insert(rel, ());
    }

    for f in &meta.files {
        if !seen.contains_key(&f.path) {
            return Err(ExtractError::MissingFile(f.path.clone()).into());
        }
    }

    // 3. Move into place.
    let staged = tmp.path().join(&meta.root);
    if overwrite && final_path.exists() {
        if final_path.is_dir() {
            fs::remove_dir_all(&final_path)?;
        } else {
            fs::remove_file(&final_path)?;
        }
    }
    fs::rename(&staged, &final_path)?;
    Ok(ExtractReport {
        root: final_path,
        files: seen.len(),
        bytes: n_bytes,
        meta,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_normal_payload_paths() {
        assert_eq!(
            check_path("sealdrop/payload/report.pdf").unwrap(),
            "report.pdf"
        );
        assert_eq!(
            check_path("sealdrop/payload/findings/sub/b.bin").unwrap(),
            "findings/sub/b.bin"
        );
    }

    #[test]
    fn rejects_bad_paths() {
        for bad in [
            "/etc/passwd",
            "sealdrop/payload/../x",
            "sealdrop/payload/a/../../x",
            "sealdrop/payload/./x",
            "sealdrop/payload//x",
            "sealdrop/payload/a\\b",
            "sealdrop/payload/c:x",
            "sealdrop/payload/CON",
            "sealdrop/payload/dir/lpt1.txt",
            "other/payload/x",
            "sealdrop/payload/",
            "sealdrop/payload/a\0b",
        ] {
            assert!(check_path(bad).is_err(), "should reject {bad:?}");
        }
    }
}
