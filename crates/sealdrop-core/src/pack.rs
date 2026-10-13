//! Streams a file or folder into a tar with `sealdrop/meta.json` first.

use std::ffi::OsStr;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tar::{Builder, EntryType, Header};
use walkdir::WalkDir;

use crate::extract::check_path;
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

/// A name component as UTF-8. Non-UTF-8 names are refused rather than converted lossily,
/// since two lossy names can collide and extraction then refuses the duplicate.
fn utf8_name<'a>(s: &'a OsStr, whole: &Path) -> Result<&'a str> {
    s.to_str().ok_or_else(|| {
        Error::Other(format!(
            "cannot seal {}: the name is not valid Unicode",
            whole.display()
        ))
    })
}

fn rel_string(root_name: &str, rel: &Path) -> Result<String> {
    let mut parts = vec![root_name.to_string()];
    for c in rel.components() {
        match c {
            Component::Normal(s) => parts.push(utf8_name(s, rel)?.to_string()),
            Component::CurDir => {}
            other => return Err(Error::Other(format!("unexpected path component {other:?}"))),
        }
    }
    Ok(parts.join("/"))
}

/// Refuses a name that extraction would refuse (spec 4.1: meta paths pass the same checks
/// as extraction), so `seal` never produces a package that `open` rejects on some system.
fn check_portable(rel: &str, abs: &Path) -> Result<()> {
    check_path(&format!("{PAYLOAD_PREFIX}{rel}")).map_err(|_| {
        Error::Other(format!(
            "cannot seal {}: the name `{rel}` cannot be restored on every system \
             (avoid \\ : * ? \" < > |, control characters, a trailing dot or space, \
             and reserved names such as CON, NUL or COM1)",
            abs.display()
        ))
    })?;
    Ok(())
}

/// What pass 1 found: files to pack (with their sizes and hashes) and folders.
struct Plan {
    is_dir: bool,
    root_name: String,
    files: Vec<(PathBuf, FileEntry)>,
    dirs: Vec<String>,
}

/// Pass 1: enumerate (sorted), check every name, hash every file.
fn plan(input: &Path) -> Result<Plan> {
    let md = std::fs::metadata(input)?;
    let root_name = utf8_name(
        input
            .file_name()
            .ok_or_else(|| Error::Other("input has no file name".into()))?,
        input,
    )?
    .to_string();
    check_portable(&root_name, input)?;

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
            check_portable(&rel_s, entry.path())?;
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
    Ok(Plan {
        is_dir: md.is_dir(),
        root_name,
        files,
        dirs,
    })
}

/// Reader that hashes and counts what passes through it.
struct HashingReader<R: Read> {
    inner: R,
    hasher: Sha256,
    bytes: u64,
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        self.bytes += n as u64;
        Ok(n)
    }
}

/// Packs `input` (file or folder) into `out`. Two passes: hash first (so `meta.json`
/// can be the first entry), then stream the tar. Symlinks are skipped. Returns the
/// writer so callers (the encryptor) can finish it.
///
/// Refuses names that extraction would refuse, names that are not valid Unicode, and files
/// that change between the two passes, so a package that seals also opens.
pub fn pack<W: Write>(input: &Path, out: W) -> Result<(PackReport, W)> {
    write_plan(plan(input)?, out)
}

/// Pass 2: write the tar through a hashing writer. Each file is read at most to the size
/// pass 1 recorded, and must still have that size and hash.
fn write_plan<W: Write>(plan: Plan, out: W) -> Result<(PackReport, W)> {
    let Plan {
        is_dir,
        root_name,
        files,
        dirs,
    } = plan;
    let meta = Meta {
        format: META_FORMAT.into(),
        tool: TOOL.into(),
        created: chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        root: root_name.clone(),
        files: files.iter().map(|(_, f)| f.clone()).collect(),
    };
    let meta_bytes =
        serde_json::to_vec_pretty(&meta).map_err(|e| Error::Manifest(e.to_string()))?;

    let hw = HashingWriter::new(out);
    let mut tar = Builder::new(hw);
    let now = chrono::Utc::now().timestamp() as u64;

    let mut h = Header::new_ustar();
    h.set_size(meta_bytes.len() as u64);
    h.set_mode(0o644);
    h.set_mtime(now);
    h.set_entry_type(EntryType::Regular);
    tar.append_data(&mut h, META_PATH, &meta_bytes[..])?;

    if is_dir {
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
        let mut r = HashingReader {
            inner: File::open(abs)?.take(fe.size),
            hasher: Sha256::new(),
            bytes: 0,
        };
        tar.append_data(&mut h, format!("{PAYLOAD_PREFIX}{}", fe.path), &mut r)?;
        // A file that shrank breaks the tar framing; one that grew or was edited in place
        // would fail its hash at open. Either way no package may be produced.
        let grew = r.inner.into_inner().read(&mut [0u8; 1])? != 0;
        if r.bytes != fe.size || grew || hex::encode(r.hasher.finalize()) != fe.sha256 {
            return Err(Error::Other(format!(
                "{} changed while packing; seal it again once nothing is writing to it",
                abs.display()
            )));
        }
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

    #[test]
    fn refuses_names_that_extraction_would_refuse() {
        // Every name extraction refuses on any OS is refused at seal time, naming the entry.
        for bad in [
            "findings/What is this?.pdf",
            "findings/a:b",
            "findings/\"final\".docx",
            "findings/notes.",
            "findings/trailing ",
            "findings/CON.txt",
            "findings/sub/lpt1",
            "findings/x|y",
        ] {
            let err = check_portable(bad, Path::new(bad)).unwrap_err();
            assert!(err.to_string().contains(bad), "{err}");
        }
        check_portable("findings/sub/b.bin", Path::new("x")).unwrap();
        check_portable("Report (final) v2.pdf", Path::new("x")).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn refuses_a_folder_holding_an_unportable_name() {
        let d = fixture();
        std::fs::write(d.path().join("findings/sub/a:b"), b"x").unwrap();
        let err = pack(&d.path().join("findings"), Vec::new())
            .map(|_| ())
            .unwrap_err();
        assert!(err.to_string().contains("findings/sub/a:b"), "{err}");
    }

    #[test]
    fn refuses_non_utf8_names() {
        #[cfg(unix)]
        let bad = {
            use std::os::unix::ffi::OsStrExt;
            OsStr::from_bytes(b"caf\xe9").to_os_string()
        };
        #[cfg(windows)]
        let bad = {
            use std::os::windows::ffi::OsStringExt;
            // An unpaired surrogate: a legal NTFS name that is not valid Unicode.
            std::ffi::OsString::from_wide(&[0x61, 0xD800])
        };
        let rel = Path::new("sub").join(&bad);
        let err = rel_string("findings", &rel).unwrap_err();
        assert!(err.to_string().contains("not valid Unicode"), "{err}");
    }

    #[test]
    fn refuses_a_file_that_changes_between_the_passes() {
        let d = fixture();
        let a = d.path().join("findings/a.txt");
        // Grew, shrank, or changed in place with the same size: all refused.
        for changed in [&b"alpha and more"[..], b"alp", b"ALPHA"] {
            std::fs::write(&a, b"alpha").unwrap();
            let p = plan(&d.path().join("findings")).unwrap();
            std::fs::write(&a, changed).unwrap();
            let err = write_plan(p, Vec::new()).map(|_| ()).unwrap_err();
            assert!(err.to_string().contains("changed while packing"), "{err}");
        }
        // Unchanged between the passes: fine.
        std::fs::write(&a, b"alpha").unwrap();
        let p = plan(&d.path().join("findings")).unwrap();
        write_plan(p, Vec::new()).unwrap();
    }
}
