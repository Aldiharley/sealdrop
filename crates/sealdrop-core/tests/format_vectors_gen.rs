//! Regenerates `spec/vectors/`. Run with:
//!   SEALDROP_VECTORS_FORCE=1 cargo test -p sealdrop-core --features test-support --test format_vectors_gen -- --ignored regenerate_format_vectors
//! Existing vector directories are kept unless SEALDROP_VECTORS_FORCE=1. The committed keys
//! under `spec/vectors/keys/` are always reused (each is generated once, when missing).
//!
//! Needs `test-support` for the deposit intercept: the timed-release vectors are sealed
//! against the production-valid `https://release.invalid` (RFC 6761: never resolves) with
//! no HTTP, and record `keys/service.pub` as the service key.
#![cfg(feature = "test-support")]

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use age::secrecy::SecretString;
use base64::prelude::{Engine, BASE64_STANDARD_NO_PAD};
use sealdrop_core::keys::KeyStore;
use sealdrop_core::passphrase::WordList;
use sealdrop_core::progress::NoProgress;
use sealdrop_core::seal::{seal, Kdf, Mode, ReleaseConfig, SealRequest, SealResult};
use serde_json::{json, Value};

/// The bundle's real file names, exactly as `seal` names them for the input `report`
/// (section 5.1), so section 5.4 step 5 (`ciphertext.file` equals the package name) holds.
const PKG: &str = "report.sealdrop.age";
const MAN: &str = "report.manifest.json";
const SIG: &str = "report.manifest.json.minisig";

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors")
}

fn fixture(dir: &Path) -> PathBuf {
    let p = dir.join("report");
    fs::create_dir_all(p.join("sub")).unwrap();
    fs::write(p.join("a.txt"), b"alpha\n").unwrap();
    fs::write(p.join("sub/b.bin"), (0u8..=255).collect::<Vec<u8>>()).unwrap();
    p
}

/// Writes a secret test key file with mode 0600 on Unix (the layout of the store's
/// `identity.txt`).
fn write_secret(path: &Path, contents: &str) {
    fs::write(path, contents).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

/// The committed post-quantum test identity `keys/pq-identity.txt`, generated once.
fn pq_identity(k: &Path) -> sealdrop_core::pq::Identity {
    let path = k.join("pq-identity.txt");
    if !path.exists() {
        let id = sealdrop_core::pq::Identity::generate();
        let created = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
        write_secret(
            &path,
            &format!(
                "# created: {created}
# public key: {}
{id}
",
                id.to_public()
            ),
        );
    }
    sealdrop_core::pq::Identity::from_str(&pq_identity_line()).unwrap()
}

/// The `AGE-SECRET-KEY-PQ-1…` line of `keys/pq-identity.txt`.
fn pq_identity_line() -> String {
    let t = fs::read_to_string(root().join("keys/pq-identity.txt")).unwrap();
    t.lines()
        .find(|l| l.starts_with("AGE-SECRET-KEY-PQ-1"))
        .unwrap()
        .to_string()
}

fn keys() -> (KeyStore, minisign::KeyPair, sealdrop_core::pq::Identity) {
    let k = root().join("keys");
    fs::create_dir_all(&k).unwrap();
    let ks = KeyStore::open(k.join("store"));
    if !ks.exists() {
        ks.generate(false, sealdrop_core::keys::IdentityKind::X25519)
            .unwrap();
    }
    let sk_path = k.join("service.key");
    if !sk_path.exists() {
        let kp = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
        fs::write(
            &sk_path,
            kp.sk
                .to_box(Some("spec vectors service key"))
                .unwrap()
                .into_string(),
        )
        .unwrap();
        fs::write(k.join("service.pub"), kp.pk.to_box().unwrap().into_string()).unwrap();
    }
    let sk = minisign::SecretKeyBox::from_string(&fs::read_to_string(&sk_path).unwrap())
        .unwrap()
        .into_unencrypted_secret_key()
        .unwrap();
    let pk =
        minisign::PublicKeyBox::from_string(&fs::read_to_string(k.join("service.pub")).unwrap())
            .unwrap()
            .into_public_key()
            .unwrap();
    let pq = pq_identity(&k);
    (ks, minisign::KeyPair { pk, sk }, pq)
}

fn want(name: &str) -> Option<PathBuf> {
    let d = root().join(name);
    if d.join("vector.json").exists() && std::env::var("SEALDROP_VECTORS_FORCE").is_err() {
        return None;
    }
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    Some(d)
}

fn write_json(d: &Path, v: Value) {
    fs::write(
        d.join("vector.json"),
        serde_json::to_vec_pretty(&v).unwrap(),
    )
    .unwrap();
}

fn files_json(m: &sealdrop_core::pack::Meta) -> Value {
    json!(m
        .files
        .iter()
        .map(|f| json!({"path": f.path, "size": f.size, "sha256": f.sha256}))
        .collect::<Vec<_>>())
}

/// Seals the fixture with `mode`, copies the three bundle files into `d`, and returns the
/// seal result plus the `expected` object for a successful open.
fn seal_into(
    ks: &KeyStore,
    d: &Path,
    mode: Mode,
    armor: bool,
    release: Option<ReleaseConfig>,
) -> (SealResult, Value) {
    let tmp = tempfile::tempdir().unwrap();
    let input = fixture(tmp.path());
    let res = seal(
        ks,
        SealRequest {
            input,
            out_dir: tmp.path().join("out"),
            mode,
            include_self: false,
            allow_unrecoverable: false,
            armor,
            classification: Some("spec-vector".into()),
            expires: None,
            release,
        },
        &NoProgress,
    )
    .unwrap();
    assert_eq!(res.package.file_name().unwrap(), PKG);
    fs::copy(&res.package, d.join(PKG)).unwrap();
    fs::copy(&res.manifest, d.join(MAN)).unwrap();
    fs::copy(&res.signature, d.join(SIG)).unwrap();
    let expected = json!({
        "package_id": res.manifest_doc.package_id,
        "plaintext_tar_sha256": res.pack.tar_sha256,
        "files": files_json(&res.pack.meta),
    });
    (res, expected)
}

fn identity_line(ks: &KeyStore) -> String {
    let t = fs::read_to_string(ks.dir().join("identity.txt")).unwrap();
    t.lines()
        .find(|l| l.starts_with("AGE-SECRET-KEY-1"))
        .unwrap()
        .to_string()
}

#[test]
#[ignore]
fn regenerate_format_vectors() {
    let (ks, service, pq_identity) = keys();
    let me = sealdrop_core::crypt::Recipient::parse(&ks.recipient_string().unwrap()).unwrap();
    let signer = ks.signing_public_string().unwrap();
    let bundle_files = json!({
        "package": PKG,
        "manifest": MAN,
        "signature": SIG
    });

    for (name, armor) in [("recipient-x25519", false), ("armored-x25519", true)] {
        if let Some(d) = want(name) {
            let (_, expected) = seal_into(&ks, &d, Mode::Recipients(vec![me.clone()]), armor, None);
            write_json(
                &d,
                json!({"name": name, "expect": "success", "stock_age": "opens",
                "inputs": {"identity": identity_line(&ks), "signer_key": signer},
                "expected": expected, "files": bundle_files,
                "comment": "§4 X25519 recipient; decryptable by stock age with -i keys/store/identity.txt"}),
            );
        }
    }
    if let Some(d) = want("recipient-pq") {
        let pq =
            sealdrop_core::crypt::Recipient::parse(&pq_identity.to_public().to_string()).unwrap();
        assert_eq!(pq.kind(), "pq");
        let (_, expected) = seal_into(&ks, &d, Mode::Recipients(vec![pq]), false, None);
        write_json(
            &d,
            json!({"name": "recipient-pq", "expect": "success", "stock_age": "opens",
            "min_age": "1.3.0",
            "inputs": {"identity": pq_identity_line(), "signer_key": signer},
            "expected": expected, "files": bundle_files,
            "comment": "§4 pq recipient (mlkem768x25519); stock age ≥ 1.3 opens it"}),
        );
    }
    if let Some(d) = want("passphrase-scrypt") {
        let (res, expected) = seal_into(
            &ks,
            &d,
            Mode::Passphrase {
                list: WordList::Eff,
                words: 6,
                kdf: Kdf::Scrypt { log_n: 12 },
            },
            false,
            None,
        );
        write_json(
            &d,
            json!({"name": "passphrase-scrypt", "expect": "success", "stock_age": "opens-interactive",
            "inputs": {"passphrase": res.passphrase.as_ref().unwrap().joined().to_string(), "signer_key": signer},
            "expected": expected, "files": bundle_files,
            "comment": "§4 scrypt logN 12 (test cost); stock age opens it when the passphrase is typed"}),
        );
    }
    if let Some(d) = want("passphrase-argon2id-compat") {
        let (res, expected) = seal_into(
            &ks,
            &d,
            Mode::Passphrase {
                list: WordList::Eff,
                words: 6,
                kdf: Kdf::Argon2id(sealdrop_core::argon2id::Profile::Compat),
            },
            false,
            None,
        );
        write_json(
            &d,
            json!({"name": "passphrase-argon2id-compat", "expect": "success", "stock_age": "rejects",
            "inputs": {"passphrase": res.passphrase.as_ref().unwrap().joined().to_string(), "signer_key": signer},
            "expected": expected, "files": bundle_files,
            "comment": "§4.1 sealdrop-argon2id stanza, compat profile; stock age reports no identity matched"}),
        );
    }
    for (name, mode) in [
        ("timed-release-x25519", Mode::Recipients(vec![me.clone()])),
        (
            "timed-release-passphrase",
            Mode::Passphrase {
                list: WordList::Eff,
                words: 6,
                kdf: Kdf::Scrypt { log_n: 12 },
            },
        ),
    ] {
        if let Some(d) = want(name) {
            let rc = ReleaseConfig {
                service: "https://release.invalid".into(),
                token: "unused".into(),
                window_secs: 600,
            };
            sealdrop_core::seal::test_support::intercept_deposits(&service.pk.to_base64());
            let (res, expected) = seal_into(&ks, &d, mode, false, Some(rc));
            sealdrop_core::seal::test_support::clear_intercept();
            let k = sealdrop_core::seal::test_support::last_memory_deposit().unwrap();
            let mut inputs =
                json!({"k_release": BASE64_STANDARD_NO_PAD.encode(*k), "signer_key": signer});
            if let Some(p) = &res.passphrase {
                inputs["passphrase"] = json!(p.joined().to_string());
            } else {
                inputs["identity"] = json!(identity_line(&ks));
            }
            write_json(
                &d,
                json!({"name": name, "expect": "success", "stock_age": "rejects",
                "inputs": inputs, "expected": expected, "files": bundle_files,
                "comment": "§4.2 sealdrop-release stanza for service https://release.invalid; K_release is what the service would return (harnesses supply it, no network)"}),
            );
        }
    }
    // Argon2id decoder bounds: encode with out-of-range t / p (cheap at tiny memory).
    for (name, params, why) in [
        (
            "argon2id-reject-t-too-large",
            sealdrop_core::argon2id::Params {
                t: 11,
                m_kib: 8192,
                p: 1,
            },
            "§4.1 decode bounds: t=11 exceeds the decoder bound of 10",
        ),
        (
            "argon2id-reject-p-too-large",
            sealdrop_core::argon2id::Params {
                t: 1,
                m_kib: 8192,
                p: 9,
            },
            "§4.1 decode bounds: p=9 exceeds the decoder bound of 8",
        ),
    ] {
        if let Some(d) = want(name) {
            let tmp = tempfile::tempdir().unwrap();
            let input = fixture(tmp.path());
            let mut tar = Vec::new();
            let (report, _) = sealdrop_core::pack::pack(&input, &mut tar).unwrap();
            let pass = SecretString::from("spec vector passphrase".to_string());
            let r: Vec<Box<dyn age::Recipient + Send>> = vec![Box::new(
                sealdrop_core::argon2id::Recipient::with_params(pass, params),
            )];
            let mut w = sealdrop_core::crypt::encrypt_writer(
                fs::File::create(d.join(PKG)).unwrap(),
                &r,
                false,
            )
            .unwrap();
            w.write_all(&tar).unwrap();
            w.finish().unwrap();
            write_json(
                &d,
                json!({"name": name, "expect": "header failure", "stock_age": "rejects",
                "inputs": {"passphrase": "spec vector passphrase"},
                "expected": {"plaintext_tar_sha256": report.tar_sha256},
                "files": {"package": PKG}, "comment": why}),
            );
        }
    }
    // Manifest/ciphertext tamper vectors derived from a fresh recipient package.
    // `stock_age`: stock age never looks at the manifest, so it opens the two manifest
    // vectors; the flipped ciphertext byte fails age's own payload authentication.
    for (name, mutate, stock_age, why) in [
        (
            "manifest-tampered",
            0u8,
            "opens",
            "§5.3 one signed byte of manifest.json changed (classification case)",
        ),
        (
            "manifest-wrong-comment",
            1u8,
            "opens",
            "§5.3 manifest re-signed by the right key but with trusted comment 'sealdrop manifest wrong'",
        ),
        (
            "ciphertext-tampered",
            2u8,
            "rejects",
            "§5.4 one byte of the package flipped; signature still valid, ciphertext hash mismatch",
        ),
    ] {
        if let Some(d) = want(name) {
            let (_, expected) =
                seal_into(&ks, &d, Mode::Recipients(vec![me.clone()]), false, None);
            match mutate {
                0 => {
                    let orig = fs::read_to_string(d.join(MAN)).unwrap();
                    let m = orig.replace("\"spec-vector\"", "\"Spec-vector\"");
                    assert_ne!(orig, m, "classification not found in manifest");
                    fs::write(d.join(MAN), m).unwrap();
                }
                1 => {
                    let bytes = fs::read(d.join(MAN)).unwrap();
                    let sig = minisign::sign(
                        Some(&ks.signing_public().unwrap()),
                        &ks.signing_key().unwrap(),
                        std::io::Cursor::new(&bytes),
                        Some("sealdrop manifest wrong"),
                        None,
                    )
                    .unwrap();
                    fs::write(d.join(SIG), sig.into_string()).unwrap();
                }
                _ => {
                    let mut b = fs::read(d.join(PKG)).unwrap();
                    let i = b.len() - 10;
                    b[i] ^= 1;
                    fs::write(d.join(PKG), b).unwrap();
                }
            }
            write_json(
                &d,
                json!({"name": name, "expect": "verify failure", "stock_age": stock_age,
                "inputs": {"identity": identity_line(&ks), "signer_key": signer},
                "expected": expected, "files": bundle_files, "comment": why}),
            );
        }
    }
    // A manifest whose key commitment does not match the file key, re-signed correctly:
    // verification (section 5.4 steps 1 to 6) passes, opening fails at step 7.
    if let Some(d) = want("commitment-mismatch") {
        let (res, expected) = seal_into(&ks, &d, Mode::Recipients(vec![me.clone()]), false, None);
        let real = res.manifest_doc.key_commitment.clone().unwrap();
        let orig = fs::read_to_string(d.join(MAN)).unwrap();
        let needle = format!("\"key_commitment\": \"{real}\"");
        assert_eq!(orig.matches(&needle).count(), 1, "key_commitment not found");
        let m = orig.replace(
            &needle,
            &format!("\"key_commitment\": \"{}\"", "0".repeat(64)),
        );
        fs::write(d.join(MAN), &m).unwrap();
        let sig = minisign::sign(
            Some(&ks.signing_public().unwrap()),
            &ks.signing_key().unwrap(),
            std::io::Cursor::new(m.as_bytes()),
            Some(&format!(
                "sealdrop manifest {}",
                res.manifest_doc.package_id
            )),
            None,
        )
        .unwrap();
        fs::write(d.join(SIG), sig.into_string()).unwrap();
        write_json(
            &d,
            json!({"name": "commitment-mismatch", "expect": "verify failure", "stock_age": "opens",
            "inputs": {"identity": identity_line(&ks), "signer_key": signer},
            "expected": expected, "files": bundle_files,
            "comment": "§5.4 step 7: signature valid, ciphertext hash valid, key_commitment does not match the file key"}),
        );
    }
    // Raw tar rejects (the extractor must refuse before writing any file).
    tar_reject_vectors();
    // Receipts.
    if let Some(d) = want("receipt-valid") {
        let r = sealdrop_core::release::Receipt {
            release_id: "3b1f8c6e-5d2a-4e9b-9c7f-1a2b3c4d5e6f".into(),
            package_sha256: "ab".repeat(32),
            first_unlock: Some("2026-10-14T09:00:00Z".into()),
            expires_at: Some("2026-10-14T09:10:00Z".into()),
            unlock_count: 1,
            service_key: service.pk.to_base64(),
            now: "2026-10-14T09:01:00Z".into(),
        };
        let s = sealdrop_core::release::sign_receipt(&r, &service.sk, &service.pk).unwrap();
        fs::write(
            d.join("receipt.json"),
            serde_json::to_vec_pretty(&s).unwrap(),
        )
        .unwrap();
        write_json(
            &d,
            json!({"name": "receipt-valid", "expect": "receipt ok", "stock_age": "n/a",
            "inputs": {"service_key": service.pk.to_base64()},
            "expected": {"release_id": r.release_id, "package_sha256": r.package_sha256},
            "files": {"receipt": "receipt.json"}, "comment": "§8 receipt signed by keys/service.key"}),
        );
    }
    if let Some(d) = want("receipt-wrong-key") {
        let r = sealdrop_core::release::Receipt {
            release_id: "3b1f8c6e-5d2a-4e9b-9c7f-1a2b3c4d5e6f".into(),
            package_sha256: "ab".repeat(32),
            first_unlock: None,
            expires_at: None,
            unlock_count: 0,
            service_key: ks.signing_public_string().unwrap(),
            now: "2026-10-14T09:01:00Z".into(),
        };
        let s = sealdrop_core::release::sign_receipt(
            &r,
            &ks.signing_key().unwrap(),
            &ks.signing_public().unwrap(),
        )
        .unwrap();
        fs::write(
            d.join("receipt.json"),
            serde_json::to_vec_pretty(&s).unwrap(),
        )
        .unwrap();
        write_json(
            &d,
            json!({"name": "receipt-wrong-key", "expect": "receipt failure", "stock_age": "n/a",
            "inputs": {"service_key": service.pk.to_base64()},
            "expected": {"release_id": r.release_id, "package_sha256": r.package_sha256},
            "files": {"receipt": "receipt.json"},
            "comment": "§8.2 internally consistent receipt signed by a key that is not the manifest's service_key"}),
        );
    }
}

fn tar_reject_vectors() {
    use tar::{Builder, EntryType, Header};
    fn meta(root: &str, files: &[(&str, &[u8])]) -> Vec<u8> {
        let files: Vec<Value> = files
            .iter()
            .map(|(p, d)| {
                json!({"path": p, "size": d.len(), "sha256": sealdrop_core::hashing::sha256_hex(d)})
            })
            .collect();
        serde_json::to_vec(&json!({"format": "sealdrop/1", "tool": "spec",
            "created": "2026-01-01T00:00:00Z", "root": root, "files": files}))
        .unwrap()
    }
    fn add(b: &mut Builder<&mut Vec<u8>>, path: &str, data: &[u8]) {
        let mut h = Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_entry_type(EntryType::Regular);
        b.append_data(&mut h, path, data).unwrap();
    }
    /// Writes `path` straight into the raw name field, bypassing the builder's own refusals.
    fn add_raw(b: &mut Builder<&mut Vec<u8>>, path: &str, data: &[u8]) {
        let mut h = Header::new_gnu();
        h.as_old_mut().name[..path.len()].copy_from_slice(path.as_bytes());
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_entry_type(EntryType::Regular);
        h.set_cksum();
        b.append(&h, data).unwrap();
    }
    fn with_meta(m: &[u8], extra: impl FnOnce(&mut Builder<&mut Vec<u8>>)) -> Vec<u8> {
        let mut out = Vec::new();
        {
            let mut b = Builder::new(&mut out);
            add(&mut b, "sealdrop/meta.json", m);
            extra(&mut b);
            b.finish().unwrap();
        }
        out
    }
    let m = meta("r", &[("r/a", b"x")]);
    let cases: Vec<(&str, Vec<u8>, &str)> = vec![
        (
            "tar-reject-traversal",
            with_meta(&m, |b| add_raw(b, "sealdrop/payload/r/../../evil", b"x")),
            "§3.4 path with .. must be rejected",
        ),
        (
            "tar-reject-symlink",
            with_meta(&m, |b| {
                let mut h = Header::new_gnu();
                h.set_entry_type(EntryType::Symlink);
                h.set_size(0);
                b.append_link(&mut h, "sealdrop/payload/r/link", "/etc/passwd")
                    .unwrap();
            }),
            "§6.2 symlink entries must be rejected",
        ),
        (
            "tar-reject-pax-size",
            with_meta(&m, |b| {
                let pax = b"9 size=5\n";
                let mut h = Header::new_ustar();
                h.set_entry_type(EntryType::XHeader);
                h.set_size(pax.len() as u64);
                b.append_data(&mut h, "PaxHeader/a", &pax[..]).unwrap();
                // A real member follows, so a lenient PAX parser still sees size= attached to it.
                add(b, "sealdrop/payload/r/a", b"x");
            }),
            "§6.1 a PAX size= override must be refused",
        ),
        (
            "tar-reject-long-name-bomb",
            {
                // A GNU long-name header declaring 2 MiB with no body behind it.
                let mut t = with_meta(&m, |_| {});
                t.truncate(t.len() - 1024);
                let mut h = Header::new_gnu();
                h.as_old_mut().name[..13].copy_from_slice(b"././@LongLink");
                h.set_size(2 << 20);
                h.set_entry_type(EntryType::GNULongName);
                h.set_cksum();
                t.extend_from_slice(h.as_bytes());
                t.extend_from_slice(&[0u8; 1024]);
                t
            },
            "§6.1 GNU long-name header declaring 2 MiB must be refused before buffering",
        ),
        (
            "tar-reject-unlisted-file",
            with_meta(&m, |b| add(b, "sealdrop/payload/r/b", b"x")),
            "§6.2 a file not listed in meta.json must be rejected",
        ),
    ];
    for (name, bytes, why) in cases {
        if let Some(d) = want(name) {
            fs::write(d.join("input.tar"), bytes).unwrap();
            write_json(
                &d,
                json!({"name": name, "expect": "extract failure", "stock_age": "n/a",
                "files": {"tar": "input.tar"}, "comment": why}),
            );
        }
    }
}
