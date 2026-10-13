use std::io::Write;

use sealdrop_core::extract::{extract, ExtractError, Limits};
use sealdrop_core::pack::{pack, META_PATH};
use sealdrop_core::Error;
use tar::{Builder, EntryType, Header};

fn meta_json(root: &str, files: &[(&str, &[u8])]) -> Vec<u8> {
    let files: Vec<serde_json::Value> = files
        .iter()
        .map(|(p, data)| {
            serde_json::json!({ "path": p, "size": data.len(), "sha256": sealdrop_core::hashing::sha256_hex(data) })
        })
        .collect();
    serde_json::to_vec(&serde_json::json!({
        "format": "sealdrop/1", "tool": "test", "created": "2026-01-01T00:00:00Z",
        "root": root, "files": files
    }))
    .unwrap()
}

fn add_file(b: &mut Builder<&mut Vec<u8>>, path: &str, data: &[u8]) {
    let mut h = Header::new_gnu();
    h.set_size(data.len() as u64);
    h.set_mode(0o644);
    h.set_entry_type(EntryType::Regular);
    b.append_data(&mut h, path, data).unwrap();
}

/// Writes `path` straight into the raw name field so the tar builder's own `..` and
/// absolute-path refusals are bypassed and the extractor's checks are what gets exercised.
fn add_raw_file(b: &mut Builder<&mut Vec<u8>>, path: &str, data: &[u8]) {
    let mut h = Header::new_gnu();
    h.as_old_mut().name[..path.len()].copy_from_slice(path.as_bytes());
    h.set_size(data.len() as u64);
    h.set_mode(0o644);
    h.set_entry_type(EntryType::Regular);
    h.set_cksum();
    b.append(&h, data).unwrap();
}

fn tar_with(meta: &[u8], extra: impl FnOnce(&mut Builder<&mut Vec<u8>>)) -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut b = Builder::new(&mut out);
        add_file(&mut b, META_PATH, meta);
        extra(&mut b);
        b.finish().unwrap();
    }
    out
}

fn expect_extract_err(tar: Vec<u8>) -> ExtractError {
    let out = tempfile::tempdir().unwrap();
    match extract(&tar[..], out.path(), &Limits::default(), false) {
        Err(Error::Extract(e)) => e,
        other => panic!("expected ExtractError, got {other:?}"),
    }
}

#[test]
fn rejects_path_traversal() {
    let meta = meta_json("r", &[("r/a", b"x")]);
    let t = tar_with(&meta, |b| {
        add_raw_file(b, "sealdrop/payload/r/../../evil", b"x")
    });
    assert!(matches!(expect_extract_err(t), ExtractError::BadPath(_)));
}

#[test]
fn rejects_absolute_path() {
    let meta = meta_json("r", &[("r/a", b"x")]);
    let t = tar_with(&meta, |b| add_raw_file(b, "/sealdrop/payload/r/a", b"x"));
    assert!(matches!(expect_extract_err(t), ExtractError::BadPath(_)));
}

#[test]
fn rejects_symlink_entry() {
    let meta = meta_json("r", &[("r/a", b"x")]);
    let t = tar_with(&meta, |b| {
        let mut h = Header::new_gnu();
        h.set_entry_type(EntryType::Symlink);
        h.set_size(0);
        b.append_link(&mut h, "sealdrop/payload/r/link", "/etc/passwd")
            .unwrap();
    });
    assert!(matches!(
        expect_extract_err(t),
        ExtractError::ForbiddenEntry(_)
    ));
}

#[test]
fn rejects_hash_mismatch() {
    let meta = meta_json("r", &[("r/a", b"good")]);
    let t = tar_with(&meta, |b| add_file(b, "sealdrop/payload/r/a", b"evil"));
    assert!(matches!(
        expect_extract_err(t),
        ExtractError::HashMismatch(_)
    ));
}

#[test]
fn rejects_unlisted_and_missing_files() {
    let meta = meta_json("r", &[("r/a", b"x")]);
    let t = tar_with(&meta, |b| add_file(b, "sealdrop/payload/r/b", b"x"));
    assert!(matches!(
        expect_extract_err(t),
        ExtractError::UnlistedFile(_)
    ));
    let meta = meta_json("r", &[("r/a", b"x")]);
    let t = tar_with(&meta, |_| {});
    assert!(matches!(
        expect_extract_err(t),
        ExtractError::MissingFile(_)
    ));
}

#[test]
fn rejects_missing_meta_and_oversized_meta() {
    let mut out = Vec::new();
    {
        let mut b = Builder::new(&mut out);
        add_file(&mut b, "sealdrop/payload/r/a", b"x");
        b.finish().unwrap();
    }
    assert_eq!(expect_extract_err(out), ExtractError::MetaMissing);
    let big = vec![b' '; (1024 * 1024) + 1];
    let t = tar_with(&big, |_| {});
    assert_eq!(expect_extract_err(t), ExtractError::MetaTooLarge);
}

#[test]
fn enforces_entry_limit() {
    let meta = meta_json("r", &[("r/a", b"x"), ("r/b", b"x")]);
    let t = tar_with(&meta, |b| {
        add_file(b, "sealdrop/payload/r/a", b"x");
        add_file(b, "sealdrop/payload/r/b", b"x");
    });
    let out = tempfile::tempdir().unwrap();
    let limits = Limits {
        max_entries: 2,
        ..Limits::default()
    };
    match extract(&t[..], out.path(), &limits, false) {
        Err(Error::Extract(ExtractError::TooManyEntries)) => {}
        other => panic!("{other:?}"),
    }
}

#[test]
fn round_trips_a_real_pack_and_refuses_overwrite() {
    let src = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(src.path().join("proj/sub")).unwrap();
    std::fs::write(src.path().join("proj/a.txt"), b"alpha").unwrap();
    std::fs::write(src.path().join("proj/sub/b.bin"), [9u8; 100_000]).unwrap();
    let mut tar = Vec::new();
    pack(&src.path().join("proj"), &mut tar).unwrap();

    let out = tempfile::tempdir().unwrap();
    let rep = extract(&tar[..], out.path(), &Limits::default(), false).unwrap();
    assert_eq!(rep.files, 2);
    assert_eq!(
        std::fs::read(out.path().join("proj/a.txt")).unwrap(),
        b"alpha"
    );
    assert_eq!(
        std::fs::read(out.path().join("proj/sub/b.bin"))
            .unwrap()
            .len(),
        100_000
    );
    assert!(std::fs::read_dir(out.path()).unwrap().all(|e| !e
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with(".sealdrop-")));

    match extract(&tar[..], out.path(), &Limits::default(), false) {
        Err(Error::Exists(_)) => {}
        other => panic!("{other:?}"),
    }
    extract(&tar[..], out.path(), &Limits::default(), true).unwrap();
    let _ = std::io::stdout().flush();
}
