//! Runs every vector in `spec/vectors` against the reference implementation (spec section 11).
//!
//! Needs `--features test-support`: the timed-release vectors name the service
//! `memory://spec.vectors`, which the service-URL rules (section 7.1) accept only in test
//! builds. No network is ever contacted: `K_release` comes from the vector.
#![cfg(feature = "test-support")]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use age::secrecy::SecretString;
use base64::prelude::{Engine, BASE64_STANDARD_NO_PAD};
use sealdrop_core::extract::{extract, ExtractError, Limits};
use sealdrop_core::keys::KeyStore;
use sealdrop_core::open::{open, OpenRequest};
use sealdrop_core::progress::NoProgress;
use sealdrop_core::release::{
    verify_receipt_for, MemoryFetch, ReleaseFetch, SignedReceipt, Unlock,
};
use sealdrop_core::Error;
use serde_json::Value;
use zeroize::Zeroizing;

fn vectors() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors")
}

/// Every vector directory, sorted (everything under `spec/vectors` except `keys`).
fn vector_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = fs::read_dir(vectors())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.is_dir() && p.file_name().unwrap() != "keys")
        .collect();
    dirs.sort();
    dirs
}

fn load(dir: &Path) -> Value {
    serde_json::from_slice(&fs::read(dir.join("vector.json")).expect("vector.json")).unwrap()
}

/// Serves the vector's `K_release` for any request. The unlock token is not checked here;
/// the header's own rules are exercised by the decoder.
struct VectorFetch([u8; 32]);

impl ReleaseFetch for VectorFetch {
    fn unlock(&self, _service: &str, _id: &str, _token: &str) -> sealdrop_core::Result<Unlock> {
        Ok(Unlock {
            k_release: Zeroizing::new(self.0),
            first_unlock: "2026-10-14T09:00:00Z".into(),
            expires_at: "2026-10-14T09:10:00Z".into(),
            now: "2026-10-14T09:00:01Z".into(),
        })
    }
}

/// A scratch key store holding the vectors' test identity; the committed copy is never written.
fn store_for(v: &Value, tmp: &Path) -> KeyStore {
    let src = vectors().join("keys/store");
    let dst = tmp.join("store");
    fs::create_dir_all(&dst).unwrap();
    for f in ["identity.txt", "sign.key", "sign.pub"] {
        fs::copy(src.join(f), dst.join(f)).unwrap();
    }
    let ks = KeyStore::open(&dst);
    if let Some(k) = v["inputs"]["signer_key"].as_str() {
        ks.add_trusted("vector", k).unwrap();
    }
    ks
}

fn describe<T>(r: &Result<T, Error>) -> String {
    match r {
        Ok(_) => "Ok".into(),
        Err(e) => format!("{e:?}"),
    }
}

fn run_open(dir: &Path, v: &Value, expect: &str) -> Result<(), String> {
    let tmp = tempfile::tempdir().unwrap();
    let files = &v["files"];
    let pkg_name = files["package"].as_str().ok_or("no files.package")?;
    // Present the bundle to the decoder under its real names (section 5.4 step 5).
    let work = tmp.path().join("bundle");
    fs::create_dir_all(&work).unwrap();
    let has_manifest = files["manifest"].is_string();
    for key in ["package", "manifest", "signature"] {
        if let Some(name) = files[key].as_str() {
            fs::copy(dir.join(name), work.join(name)).map_err(|e| format!("{name}: {e}"))?;
        }
    }
    let fetch: Box<dyn ReleaseFetch> = match v["inputs"]["k_release"].as_str() {
        Some(b) => {
            let raw = BASE64_STANDARD_NO_PAD
                .decode(b)
                .map_err(|e| e.to_string())?;
            let k: [u8; 32] = raw.try_into().map_err(|_| "k_release is not 32 bytes")?;
            Box::new(VectorFetch(k))
        }
        None => Box::new(MemoryFetch::expired()),
    };
    let ks = store_for(v, tmp.path());
    let out = tmp.path().join("out");
    let r = open(
        &ks,
        OpenRequest {
            package: work.join(pkg_name),
            out_dir: out.clone(),
            signer: None,
            // Vectors with no manifest (the Argon2id bound vectors) are opened unverified.
            skip_verify: !has_manifest,
            overwrite: false,
            passphrase: v["inputs"]["passphrase"]
                .as_str()
                .map(|p| SecretString::from(p.to_string())),
            limits: Limits::default(),
        },
        fetch,
        &NoProgress,
    );
    match (expect, &r) {
        ("success", Ok(rep)) => {
            let want = v["expected"]["files"]
                .as_array()
                .ok_or("no expected.files")?;
            if rep.extract.files != want.len() {
                return Err(format!(
                    "{} files restored, expected {}",
                    rep.extract.files,
                    want.len()
                ));
            }
            for f in want {
                let p = out.join(f["path"].as_str().unwrap());
                let got = fs::read(&p).map_err(|e| format!("{}: {e}", p.display()))?;
                if got.len() as u64 != f["size"].as_u64().unwrap() {
                    return Err(format!("size mismatch for {}", p.display()));
                }
                if sealdrop_core::hashing::sha256_hex(&got) != f["sha256"].as_str().unwrap() {
                    return Err(format!("sha256 mismatch for {}", p.display()));
                }
            }
            Ok(())
        }
        ("verify failure", Err(Error::Verify(_))) => Ok(()),
        ("header failure", Err(Error::Decrypt(_))) => Ok(()),
        _ => Err(format!("expected {expect}, got {}", describe(&r))),
    }
}

fn run_extract(dir: &Path, v: &Value) -> Result<(), String> {
    let tmp = tempfile::tempdir().unwrap();
    let tar = fs::read(dir.join(v["files"]["tar"].as_str().ok_or("no files.tar")?)).unwrap();
    let r = extract(&tar[..], &tmp.path().join("out"), &Limits::default(), false);
    let ok = match &r {
        Err(Error::Extract(_)) => true,
        Err(Error::Io(e)) => e
            .get_ref()
            .is_some_and(|inner| inner.downcast_ref::<ExtractError>().is_some()),
        _ => false,
    };
    if ok {
        Ok(())
    } else {
        Err(format!(
            "expected an extraction error, got {}",
            describe(&r)
        ))
    }
}

fn run_receipt(dir: &Path, v: &Value, expect: &str) -> Result<(), String> {
    let name = v["files"]["receipt"].as_str().ok_or("no files.receipt")?;
    let signed: SignedReceipt = serde_json::from_slice(&fs::read(dir.join(name)).unwrap())
        .map_err(|e| format!("receipt.json: {e}"))?;
    let r = verify_receipt_for(
        &signed,
        v["inputs"]["service_key"]
            .as_str()
            .ok_or("no service_key")?,
        v["expected"]["release_id"]
            .as_str()
            .ok_or("no release_id")?,
        v["expected"]["package_sha256"]
            .as_str()
            .ok_or("no package_sha256")?,
    );
    match (expect, r.is_ok()) {
        ("receipt ok", true) | ("receipt failure", false) => Ok(()),
        _ => Err(format!("expected {expect}, got {}", describe(&r))),
    }
}

fn run(dir: &Path) -> Result<(), String> {
    let v = load(dir);
    if v["name"].as_str() != dir.file_name().unwrap().to_str() {
        return Err("name does not equal the directory name".into());
    }
    let expect = v["expect"].as_str().ok_or("no expect")?.to_string();
    match expect.as_str() {
        "success" | "verify failure" | "header failure" => run_open(dir, &v, &expect),
        "extract failure" => run_extract(dir, &v),
        "receipt ok" | "receipt failure" => run_receipt(dir, &v, &expect),
        other => Err(format!("unknown expect {other:?}")),
    }
}

#[test]
fn all_format_vectors() {
    let dirs = vector_dirs();
    assert_eq!(dirs.len(), 18, "expected 18 vectors, found {}", dirs.len());
    let mut failures = Vec::new();
    for d in &dirs {
        let name = d.file_name().unwrap().to_string_lossy().into_owned();
        match run(d) {
            Ok(()) => eprintln!("ok    {name}"),
            Err(e) => {
                eprintln!("FAIL  {name}: {e}");
                failures.push(format!("{name}: {e}"));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "format vector failures:\n{}",
        failures.join("\n")
    );
}

fn age_available() -> bool {
    Command::new("age")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// With the Go `age` binary present, proves the `stock_age` claim of every package vector.
#[test]
fn stock_age_claims() {
    if !age_available() {
        assert!(
            std::env::var("SEALDROP_REQUIRE_AGE").as_deref() != Ok("1"),
            "SEALDROP_REQUIRE_AGE=1 but the `age` binary is not installed"
        );
        eprintln!("skipping: age not installed");
        return;
    }
    let ident = vectors().join("keys/store/identity.txt");
    let mut checked = 0;
    for d in vector_dirs() {
        let v = load(&d);
        let Some(pkg) = v["files"]["package"].as_str() else {
            continue;
        };
        let name = v["name"].as_str().unwrap();
        let claim = v["stock_age"].as_str().unwrap();
        if claim == "n/a" || claim == "opens-interactive" {
            continue;
        }
        let out = Command::new("age")
            .args(["-d", "-i"])
            .arg(&ident)
            .arg(d.join(pkg))
            .output()
            .unwrap();
        match claim {
            "opens" => {
                assert!(
                    out.status.success(),
                    "{name}: stock age failed: {}",
                    String::from_utf8_lossy(&out.stderr)
                );
                let mut ar = tar::Archive::new(&out.stdout[..]);
                let first = ar.entries().unwrap().next().unwrap().unwrap();
                assert_eq!(
                    first.path().unwrap().to_string_lossy(),
                    "sealdrop/meta.json",
                    "{name}: first tar entry"
                );
            }
            "rejects" => assert!(
                !out.status.success(),
                "{name}: stock age unexpectedly opened it"
            ),
            other => panic!("{name}: unknown stock_age {other:?}"),
        }
        eprintln!("age   {name}: {claim}");
        checked += 1;
    }
    assert!(checked > 0, "no stock_age claims were checked");
}
