//! Streams a file or folder into a tar with `sealdrop/meta.json` first.

use std::fs::File;
use std::io::Write;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use tar::{Builder, EntryType, Header};
use walkdir::WalkDir;

use crate::hashing::{sha256_file, HashingWriter};
use crate::{Error, Result, TOOL};

pub const META_PATH: &str = "sealdrop/meta.json";
pub const PAYLOAD_PREFIX: &str = "sealdrop/payload/";
pub const META_FORMAT: &str = "sealdrop/1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileEntry {
    /// Relative path under `sealdrop/payload/`, `/`-separated, starts with `root`.
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Meta {
    pub format: String,
    pub tool: String,
    pub created: String,
    /// Top-level name inside the payload (file name or folder name).
    pub root: String,
    pub files: Vec<FileEntry>,
}

#[derive(Debug, Clone)]
pub struct PackReport {
    pub meta: Meta,
    pub total_bytes: u64,
    pub tar_sha256: String,
}

fn rel_string(root_name: &str, rel: &Path) -> Result<String> {
    let mut parts = vec![root_name.to_string()];
    for c in rel.components() {
        match c {
            Component::Normal(s) => parts.push(s.to_string_lossy().into_owned()),
            Component::CurDir => {}
            other => return Err(Error::Other(format!("unexpected path component {other:?}"))),
        }
    }
    Ok(parts.join("/"))
}

/// Packs `input` (file or folder) into `out`. Two passes: hash first (so `meta.json`
/// can be the first entry), then stream the tar. Symlinks are skipped. Returns the
/// writer so callers (the encryptor) can finish it.
pub fn pack<W: Write>(input: &Path, out: W) -> Result<(PackReport, W)> {
    let md = std::fs::metadata(input)?;
    let root_name = input
        .file_name()
        .ok_or_else(|| Error::Other("input has no file name".into()))?
        .to_string_lossy()
        .into_owned();

    // Pass 1: enumerate, sorted, hash.
    let mut files: Vec<(PathBuf, FileEntry)> = Vec::new();
    let mut dirs: Vec<String> = Vec::new();
    if md.is_file() {
        let (sha256, size) = sha256_file(input)?;
        files.push((
            input.to_path_buf(),
            FileEntry {
                path: root_name.clone(),
                size,
                sha256,
            },
        ));
    } else if md.is_dir() {
        for entry in WalkDir::new(input).follow_links(false).sort_by_file_name() {
            let entry = entry.map_err(|e| Error::Other(e.to_string()))?;
            let ft = entry.file_type();
            let rel = entry.path().strip_prefix(input).unwrap();
            if rel.as_os_str().is_empty() {
                continue;
            }
            if ft.is_symlink() {
                continue; // never packed; spec 4.1
            }
            let rel_s = rel_string(&root_name, rel)?;
            if ft.is_dir() {
                dirs.push(rel_s);
            } else if ft.is_file() {
                let (sha256, size) = sha256_file(entry.path())?;
                files.push((
                    entry.path().to_path_buf(),
                    FileEntry {
                        path: rel_s,
                        size,
                        sha256,
                    },
                ));
            }
        }
    } else {
        return Err(Error::Other("input is neither a file nor a folder".into()));
    }

    let meta = Meta {
        format: META_FORMAT.into(),
        tool: TOOL.into(),
        created: chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        root: root_name.clone(),
        files: files.iter().map(|(_, f)| f.clone()).collect(),
    };
    let meta_bytes =
        serde_json::to_vec_pretty(&meta).map_err(|e| Error::Manifest(e.to_string()))?;

    // Pass 2: write tar through a hashing writer.
    let hw = HashingWriter::new(out);
    let mut tar = Builder::new(hw);
    let now = chrono::Utc::now().timestamp() as u64;

    let mut h = Header::new_ustar();
    h.set_size(meta_bytes.len() as u64);
    h.set_mode(0o644);
    h.set_mtime(now);
    h.set_entry_type(EntryType::Regular);
    tar.append_data(&mut h, META_PATH, &meta_bytes[..])?;

    if md.is_dir() {
        let mut h = Header::new_ustar();
        h.set_size(0);
        h.set_mode(0o755);
        h.set_mtime(now);
        h.set_entry_type(EntryType::Directory);
        tar.append_data(
            &mut h,
            format!("{PAYLOAD_PREFIX}{root_name}"),
            std::io::empty(),
        )?;
        for d in &dirs {
            let mut h = Header::new_ustar();
            h.set_size(0);
            h.set_mode(0o755);
            h.set_mtime(now);
            h.set_entry_type(EntryType::Directory);
            tar.append_data(&mut h, format!("{PAYLOAD_PREFIX}{d}"), std::io::empty())?;
        }
    }

    let mut total = 0u64;
    for (abs, fe) in &files {
        let mut h = Header::new_ustar();
        h.set_size(fe.size);
        h.set_mode(0o644);
        h.set_mtime(now);
        h.set_entry_type(EntryType::Regular);
        let f = File::open(abs)?;
        tar.append_data(&mut h, format!("{PAYLOAD_PREFIX}{}", fe.path), f)?;
        total += fe.size;
    }

    let hw = tar.into_inner()?;
    let (w, tar_sha256, _) = hw.finish();
    Ok((
        PackReport {
            meta,
            total_bytes: total,
            tar_sha256,
        },
        w,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn fixture() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("findings/sub")).unwrap();
        std::fs::write(d.path().join("findings/a.txt"), b"alpha").unwrap();
        std::fs::write(d.path().join("findings/sub/b.bin"), [0u8, 1, 2, 3]).unwrap();
        std::fs::create_dir_all(d.path().join("findings/empty")).unwrap();
        d
    }

    #[test]
    fn packs_folder_with_meta_first_and_sorted_entries() {
        let d = fixture();
        let mut out = Vec::new();
        let (report, _) = pack(&d.path().join("findings"), &mut out).unwrap();
        assert_eq!(report.meta.root, "findings");
        assert_eq!(report.meta.format, "sealdrop/1");
        let paths: Vec<_> = report.meta.files.iter().map(|f| f.path.clone()).collect();
        assert_eq!(paths, vec!["findings/a.txt", "findings/sub/b.bin"]);
        assert_eq!(
            report.meta.files[0].sha256,
            "8ed3f6ad685b959ead7022518e1af76cd816f8e8ec7ccdda1ed4018e8f2223f8"
        );
        assert_eq!(report.total_bytes, 9);
        assert_eq!(report.tar_sha256, crate::hashing::sha256_hex(&out));

        let mut ar = tar::Archive::new(&out[..]);
        let names: Vec<String> = ar
            .entries()
            .unwrap()
            .map(|e| {
                e.unwrap()
                    .path()
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect();
        assert_eq!(names[0], META_PATH);
        assert!(names.contains(&"sealdrop/payload/findings/empty".to_string()));
        assert!(names.contains(&"sealdrop/payload/findings/sub/b.bin".to_string()));
    }

    #[test]
    fn packs_single_file() {
        let d = fixture();
        let mut out = Vec::new();
        let (report, _) = pack(&d.path().join("findings/a.txt"), &mut out).unwrap();
        assert_eq!(report.meta.root, "a.txt");
        assert_eq!(report.meta.files.len(), 1);
        assert_eq!(report.meta.files[0].path, "a.txt");
        let mut ar = tar::Archive::new(&out[..]);
        let mut entries = ar.entries().unwrap();
        let first = entries.next().unwrap().unwrap();
        assert_eq!(first.path().unwrap().to_string_lossy(), META_PATH);
        let mut meta_json = String::new();
        let mut first = first;
        first.read_to_string(&mut meta_json).unwrap();
        let meta: Meta = serde_json::from_str(&meta_json).unwrap();
        assert_eq!(meta.files[0].size, 5);
    }

    #[test]
    fn rejects_missing_input() {
        let mut out = Vec::new();
        assert!(pack(std::path::Path::new("/definitely/not/here"), &mut out).is_err());
    }
}
