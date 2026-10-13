use std::collections::BTreeSet;

use proptest::prelude::*;
use sealdrop_core::extract::{extract, Limits};
use sealdrop_core::pack::pack;

fn name() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9_-]{0,12}".prop_filter("reserved", |s| {
        !["con", "prn", "aux", "nul"].contains(&s.as_str())
    })
}

proptest! {
    #![proptest_config(ProptestConfig { failure_persistence: None, ..ProptestConfig::with_cases(24) })]
    #[test]
    fn pack_then_extract_restores_tree(files in proptest::collection::btree_map(
        proptest::collection::vec(name(), 1..4).prop_map(|v| v.join("/")),
        proptest::collection::vec(any::<u8>(), 0..5000), 1..12)) {
        // A key that is a path-prefix of another key would be both a file and a directory;
        // drop it up front so the written tree is exactly the set of kept keys.
        let written: Vec<(&String, &Vec<u8>)> = files
            .iter()
            .filter(|(k, _)| !files.keys().any(|o| o.starts_with(&format!("{k}/"))))
            .collect();
        prop_assert!(!written.is_empty());

        let src = tempfile::tempdir().unwrap();
        let root = src.path().join("tree");
        for (p, data) in &written {
            let full = root.join(p);
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(&full, data).unwrap();
        }
        let mut tar = Vec::new();
        let (report, _) = pack(&root, &mut tar).unwrap();
        let out = tempfile::tempdir().unwrap();
        let rep = extract(&tar[..], out.path(), &Limits::default(), false).unwrap();

        // (a) the packed file set is exactly the generated one.
        let packed: BTreeSet<String> = report.meta.files.iter().map(|f| f.path.clone()).collect();
        let expected: BTreeSet<String> = written.iter().map(|(k, _)| format!("tree/{k}")).collect();
        prop_assert_eq!(packed, expected);
        // (c) extraction restored that many files.
        prop_assert_eq!(rep.files, written.len());
        // (b) every extracted file is byte-identical to the generated data.
        for (k, data) in &written {
            let got = std::fs::read(out.path().join("tree").join(k)).unwrap();
            prop_assert_eq!(&got, *data);
        }
        // Extra: the recorded hashes match the extracted bytes.
        for f in &report.meta.files {
            let rel = f.path.strip_prefix("tree/").unwrap();
            let got = std::fs::read(out.path().join("tree").join(rel)).unwrap();
            prop_assert_eq!(sealdrop_core::hashing::sha256_hex(&got), f.sha256.clone());
        }
    }
}
