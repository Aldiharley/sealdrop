use proptest::prelude::*;
use sealdrop_core::extract::{extract, Limits};
use sealdrop_core::pack::pack;

fn name() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9_-]{0,12}".prop_filter("reserved", |s| {
        !["con", "prn", "aux", "nul"].contains(&s.as_str())
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]
    #[test]
    fn pack_then_extract_restores_tree(files in proptest::collection::btree_map(
        proptest::collection::vec(name(), 1..4).prop_map(|v| v.join("/")),
        proptest::collection::vec(any::<u8>(), 0..5000), 1..12)) {
        let src = tempfile::tempdir().unwrap();
        let root = src.path().join("tree");
        for (p, data) in &files {
            let full = root.join(p);
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            // A path may collide with a directory created for a longer path; skip those.
            if full.is_dir() { continue; }
            std::fs::write(&full, data).unwrap();
        }
        let mut tar = Vec::new();
        let (report, _) = pack(&root, &mut tar).unwrap();
        let out = tempfile::tempdir().unwrap();
        let rep = extract(&tar[..], out.path(), &Limits::default(), false).unwrap();
        prop_assert_eq!(rep.files, report.meta.files.len());
        for f in &report.meta.files {
            let rel = f.path.strip_prefix("tree/").unwrap();
            let got = std::fs::read(out.path().join("tree").join(rel)).unwrap();
            prop_assert_eq!(sealdrop_core::hashing::sha256_hex(&got), f.sha256.clone());
        }
    }
}
