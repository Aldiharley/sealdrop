//! Runs every vector in `spec/vectors` against the reference implementation (spec section 11).
//!
//! Needs no feature: the timed-release vectors name the production-valid service
//! `https://release.invalid`, and the harness answers the unlock request itself with the
//! vector's `K_release`. No network is ever contacted.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;

use age::secrecy::SecretString;
use base64::prelude::{Engine, BASE64_STANDARD_NO_PAD};
use sealdrop_core::extract::{extract, ExtractError, Limits};
use sealdrop_core::keys::KeyStore;
use sealdrop_core::open::{open, verify, OpenRequest};
use sealdrop_core::progress::NoProgress;
use sealdrop_core::release::{
    self, verify_receipt_for, MemoryFetch, ReleaseFetch, SignedReceipt, Unlock,
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

/// Serves the vector's `K_release` for any request, in place of the service (spec section 11).
/// The unlock token is not checked: a vector has no service-side `unlock_token_hash`. The
/// header's own rules (section 4.2 steps 3 to 6, including section 7.1 for the URL) are
/// exercised by the decoder before this is called.
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
/// A post-quantum `inputs.identity` replaces the store's X25519 line (a store holds exactly
/// one native identity).
fn store_for(v: &Value, tmp: &Path) -> KeyStore {
    let src = vectors().join("keys/store");
    let dst = tmp.join("store");
    fs::create_dir_all(&dst).unwrap();
    for f in ["identity.txt", "sign.key", "sign.pub"] {
        fs::copy(src.join(f), dst.join(f)).unwrap();
    }
    if let Some(i) = v["inputs"]["identity"].as_str() {
        if i.starts_with("AGE-SECRET-KEY-PQ-1") {
            fs::write(
                dst.join("identity.txt"),
                format!(
                    "{i}
"
                ),
            )
            .unwrap();
        }
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

/// The release service stand-in for a vector: its `K_release`, or (without one) a service
/// that reports the window as passed.
fn fetch_for(v: &Value) -> Result<Box<dyn ReleaseFetch>, String> {
    Ok(match v["inputs"]["k_release"].as_str() {
        Some(b) => {
            let raw = BASE64_STANDARD_NO_PAD
                .decode(b)
                .map_err(|e| e.to_string())?;
            let k: [u8; 32] = raw.try_into().map_err(|_| "k_release is not 32 bytes")?;
            Box::new(VectorFetch(k))
        }
        None => Box::new(MemoryFetch::expired()),
    })
}

/// SHA-256 of the decrypted container, obtained without `open` (no manifest, no
/// extraction): plain age decryption with the vector's identity or passphrase, and its
/// `K_release` for a timed package.
fn decrypted_tar_sha256(package: &Path, v: &Value) -> Result<String, String> {
    let mut inner: Vec<Box<dyn age::Identity>> = Vec::new();
    if let Some(i) = v["inputs"]["identity"].as_str() {
        if i.starts_with("AGE-SECRET-KEY-PQ-1") {
            inner.push(Box::new(sealdrop_core::pq::Identity::from_str(i)?));
        } else {
            inner.push(Box::new(age::x25519::Identity::from_str(i)?));
        }
    }
    if let Some(p) = v["inputs"]["passphrase"].as_str() {
        let pass = SecretString::from(p.to_string());
        inner.push(Box::new(sealdrop_core::crypt::scrypt_identity(
            pass.clone(),
        )));
        inner.push(Box::new(sealdrop_core::argon2id::Identity::new(pass)));
    }
    let ids: Vec<Box<dyn age::Identity>> =
        vec![Box::new(release::Identity::new(inner, fetch_for(v)?))];
    let file = fs::File::open(package).map_err(|e| e.to_string())?;
    let mut r = sealdrop_core::crypt::decrypt_reader(file, &ids).map_err(|e| e.to_string())?;
    let (sha, _) = sealdrop_core::hashing::sha256_reader(&mut r).map_err(|e| e.to_string())?;
    Ok(sha)
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
    let fetch = fetch_for(v)?;
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
            // The known-answer container hash, from a decryption independent of `open`.
            let want_tar = v["expected"]["plaintext_tar_sha256"]
                .as_str()
                .ok_or("no expected.plaintext_tar_sha256")?;
            let got_tar = decrypted_tar_sha256(&work.join(pkg_name), v)?;
            if got_tar != want_tar {
                return Err(format!(
                    "decrypted container sha256 {got_tar}, expected {want_tar}"
                ));
            }
            // A timed manifest records a real service key (sections 5.2 and 7.2).
            if let Some(rel) = rep
                .verify
                .as_ref()
                .and_then(|r| r.manifest.release.as_ref())
            {
                minisign::PublicKey::from_base64(&rel.service_key)
                    .map_err(|e| format!("release.service_key: {e}"))?;
            }
            Ok(())
        }
        // Section 5.4 step 7: the commitment vector verifies (steps 1 to 6) and fails only
        // when `open` checks the unwrapped file key.
        ("verify failure", Err(Error::Verify(m))) if v["name"] == "commitment-mismatch" => {
            if !m.contains("key commitment") {
                return Err(format!("expected a key commitment failure, got {m:?}"));
            }
            verify(&ks, &work.join(pkg_name), None)
                .map(|_| ())
                .map_err(|e| format!("verify alone must pass for this vector, got {e:?}"))
        }
        ("verify failure", Err(Error::Verify(_))) => Ok(()),
        // Section 2.3: `header failure` is a header error or an excessive-work error only.
        (
            "header failure",
            Err(Error::Decrypt(
                age::DecryptError::InvalidHeader | age::DecryptError::ExcessiveWork { .. },
            )),
        ) => Ok(()),
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
    // Section 11: `n/a` means exactly "no package to try".
    let stock_age = v["stock_age"].as_str().ok_or("no stock_age")?;
    let has_package = v["files"]["package"].is_string();
    if (stock_age == "n/a") == has_package {
        return Err(format!(
            "stock_age is {stock_age:?} but the vector {} a package",
            if has_package { "has" } else { "has no" }
        ));
    }
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
    assert_eq!(dirs.len(), 20, "expected 20 vectors, found {}", dirs.len());
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

/// The installed `age` version as (major, minor, patch), from `age --version` (`v1.3.2`);
/// `None` when the binary is missing.
fn age_version() -> Option<(u64, u64, u64)> {
    let out = Command::new("age").arg("--version").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    // Unparseable output (a development build) counts as new enough.
    Some(parse_version(text.trim()).unwrap_or((u64::MAX, 0, 0)))
}

/// Parses `v1.3.2` or `1.3.0` (any suffix after the patch number is ignored).
fn parse_version(s: &str) -> Option<(u64, u64, u64)> {
    let s = s.strip_prefix('v').unwrap_or(s);
    let mut it = s.splitn(3, '.');
    let major = it.next()?.parse().ok()?;
    let minor = it.next()?.parse().ok()?;
    let patch = it.next()?;
    let digits: String = patch.chars().take_while(char::is_ascii_digit).collect();
    Some((major, minor, digits.parse().ok()?))
}

#[test]
fn version_parsing() {
    assert_eq!(parse_version("v1.3.2"), Some((1, 3, 2)));
    assert_eq!(parse_version("1.3.0"), Some((1, 3, 0)));
    assert_eq!(parse_version("v1.2.1-rc.1"), Some((1, 2, 1)));
    assert_eq!(parse_version("(devel)"), None);
    assert!(parse_version("v1.2.1") < parse_version("1.3.0"));
}

/// With the Go `age` binary present, proves the `stock_age` claim of every package vector.
#[test]
fn stock_age_claims() {
    let Some(have) = age_version() else {
        assert!(
            std::env::var("SEALDROP_REQUIRE_AGE").as_deref() != Ok("1"),
            "SEALDROP_REQUIRE_AGE=1 but the `age` binary is not installed"
        );
        eprintln!("skipping: age not installed");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
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
        if let Some(min) = v["min_age"].as_str() {
            let want = parse_version(min).unwrap_or_else(|| panic!("{name}: bad min_age {min:?}"));
            if have < want {
                eprintln!("skip  {name}: needs age >= {min}, found {have:?}");
                continue;
            }
        }
        // The vector's own identity (X25519 or post-quantum), else the store's.
        let ident = match v["inputs"]["identity"].as_str() {
            Some(i) => {
                let p = tmp.path().join(format!("{name}.key"));
                fs::write(
                    &p,
                    format!(
                        "{i}
"
                    ),
                )
                .unwrap();
                p
            }
            None => vectors().join("keys/store/identity.txt"),
        };
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
                assert_eq!(
                    sealdrop_core::hashing::sha256_hex(&out.stdout),
                    v["expected"]["plaintext_tar_sha256"].as_str().unwrap(),
                    "{name}: stock age did not output the expected container"
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
