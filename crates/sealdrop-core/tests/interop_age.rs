//! Interop with the reference Go implementation (spec goal 2). Skips if `age` is not on PATH.

use std::process::Command;

use sealdrop_core::keys::KeyStore;
use sealdrop_core::passphrase::WordList;
use sealdrop_core::progress::NoProgress;
use sealdrop_core::seal::{seal, Kdf, Mode, SealRequest};

/// Returns false (after logging) when `age` is missing, unless `SEALDROP_REQUIRE_AGE=1`, in
/// which case a missing binary is a hard failure (CI sets it so interop can never silently skip).
fn age_available() -> bool {
    let ok = age_on_path();
    if !ok && std::env::var("SEALDROP_REQUIRE_AGE").as_deref() == Ok("1") {
        panic!("SEALDROP_REQUIRE_AGE=1 but the reference `age` binary is not on PATH");
    }
    ok
}

/// Same contract as `age_available`, for the reference `age-keygen` binary.
fn age_keygen_available() -> bool {
    let ok = Command::new("age-keygen")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !ok && std::env::var("SEALDROP_REQUIRE_AGE").as_deref() == Ok("1") {
        panic!("SEALDROP_REQUIRE_AGE=1 but the reference `age-keygen` binary is not on PATH");
    }
    ok
}

fn age_on_path() -> bool {
    Command::new("age")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn fixture(dir: &std::path::Path) -> std::path::PathBuf {
    let p = dir.join("docs");
    std::fs::create_dir_all(&p).unwrap();
    std::fs::write(p.join("hello.txt"), b"interop").unwrap();
    p
}

#[test]
fn stock_age_decrypts_recipient_mode_and_tar_extracts() {
    if !age_available() {
        eprintln!("skipping: age not installed");
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let ks = KeyStore::open(d.path().join("ks"));
    ks.generate(false, sealdrop_core::keys::IdentityKind::X25519)
        .unwrap();
    let me = sealdrop_core::crypt::Recipient::parse(&ks.recipient_string().unwrap()).unwrap();
    let res = seal(
        &ks,
        SealRequest {
            input: fixture(d.path()),
            out_dir: d.path().join("out"),
            mode: Mode::Recipients(vec![me]),
            include_self: true,
            allow_unrecoverable: false,
            armor: false,
            classification: None,
            expires: None,
            release: None,
        },
        &NoProgress,
    )
    .unwrap();
    let ident = d.path().join("ks/identity.txt");
    let out = Command::new("age")
        .args(["-d", "-i"])
        .arg(&ident)
        .arg(&res.package)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "age -d failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mut ar = tar::Archive::new(&out.stdout[..]);
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
    assert_eq!(names[0], "sealdrop/meta.json");
    assert!(names.iter().any(|n| n == "sealdrop/payload/docs/hello.txt"));

    // The stock-age output is a real tar: unpack it and check the payload bytes.
    let dest = tempfile::tempdir().unwrap();
    tar::Archive::new(&out.stdout[..])
        .unpack(dest.path())
        .unwrap();
    assert_eq!(
        std::fs::read(dest.path().join("sealdrop/payload/docs/hello.txt")).unwrap(),
        b"interop"
    );
}

/// Scrypt-mode packages are checked with the `age` crate only, NOT with the stock Go `age`
/// CLI: that CLI reads a passphrase only from a terminal and has no non-interactive input,
/// so it cannot be driven from a test. This is the same implementation that wrote the
/// file, so it shows format conformance of the library, not independent interop; the two
/// recipient-mode tests are the stock-age interop evidence.
#[test]
fn scrypt_mode_opens_with_the_age_crate_not_the_go_cli() {
    let d = tempfile::tempdir().unwrap();
    let ks = KeyStore::open(d.path().join("ks"));
    ks.generate(false, sealdrop_core::keys::IdentityKind::X25519)
        .unwrap();
    let res = seal(
        &ks,
        SealRequest {
            input: fixture(d.path()),
            out_dir: d.path().join("out"),
            mode: Mode::Passphrase {
                list: WordList::Eff,
                words: 6,
                kdf: Kdf::Scrypt { log_n: 12 },
            },
            include_self: false,
            allow_unrecoverable: false,
            armor: true,
            classification: None,
            expires: None,
            release: None,
        },
        &NoProgress,
    )
    .unwrap();
    let pass = res.passphrase.unwrap().joined();
    // The reference CLI reads passphrases only from a terminal (no non-interactive flag), so
    // it cannot be driven here; the recipient-mode test above already proves CLI interop. Assert
    // the armored header shape and decrypt through the age crate's scrypt identity, which
    // implements the same format.
    let text = std::fs::read_to_string(&res.package).unwrap();
    assert!(text.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"));
    let ids: Vec<Box<dyn age::Identity>> = vec![Box::new(sealdrop_core::crypt::scrypt_identity(
        age::secrecy::SecretString::from(pass.to_string()),
    ))];
    let mut r =
        sealdrop_core::crypt::decrypt_reader(std::fs::File::open(&res.package).unwrap(), &ids)
            .unwrap();
    let mut out = Vec::new();
    std::io::Read::read_to_end(&mut r, &mut out).unwrap();
    assert!(out.len() > 512);
}

#[test]
fn stock_age_rejects_argon2id_package() {
    if !age_available() {
        eprintln!("skipping: age not installed");
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let ks = KeyStore::open(d.path().join("ks"));
    ks.generate(false, sealdrop_core::keys::IdentityKind::X25519)
        .unwrap();
    let res = seal(
        &ks,
        SealRequest {
            input: fixture(d.path()),
            out_dir: d.path().join("out"),
            mode: Mode::Passphrase {
                list: WordList::Eff,
                words: 6,
                kdf: Kdf::Argon2id(sealdrop_core::argon2id::Profile::Compat),
            },
            include_self: false,
            allow_unrecoverable: false,
            armor: false,
            classification: None,
            expires: None,
            release: None,
        },
        &NoProgress,
    )
    .unwrap();
    let ident = d.path().join("ks/identity.txt");
    let out = Command::new("age")
        .args(["-d", "-i"])
        .arg(&ident)
        .arg(&res.package)
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    println!("stock age stderr for argon2id package: {err}");
    assert!(
        !out.status.success(),
        "stock age must not decrypt an argon2id package"
    );
    assert!(
        !err.trim().is_empty(),
        "stock age must explain the failure on stderr"
    );
}

/// Go age decrypts a sealdrop package sealed to a sealdrop-generated PQ identity.
#[test]
fn stock_age_decrypts_pq_recipient_package() {
    if !age_available() {
        eprintln!("skipping: age not installed");
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let ks = KeyStore::open(d.path().join("ks"));
    ks.generate(false, sealdrop_core::keys::IdentityKind::Pq)
        .unwrap();
    let me = sealdrop_core::crypt::Recipient::parse(&ks.recipient_string().unwrap()).unwrap();
    assert_eq!(me.kind(), "pq");
    let res = seal(
        &ks,
        SealRequest {
            input: fixture(d.path()),
            out_dir: d.path().join("out"),
            mode: Mode::Recipients(vec![me]),
            include_self: false,
            allow_unrecoverable: false,
            armor: false,
            classification: None,
            expires: None,
            release: None,
        },
        &NoProgress,
    )
    .unwrap();
    let tar = d.path().join("plain.tar");
    let out = Command::new("age")
        .arg("-d")
        .arg("-i")
        .arg(ks.dir().join("identity.txt"))
        .arg("-o")
        .arg(&tar)
        .arg(&res.package)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "age -d failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let (sha, _) = sealdrop_core::hashing::sha256_file(&tar).unwrap();
    assert_eq!(sha, res.pack.tar_sha256);
    // age-keygen derives the same recipient from our identity file.
    if age_keygen_available() {
        let y = Command::new("age-keygen")
            .arg("-y")
            .arg(ks.dir().join("identity.txt"))
            .output()
            .unwrap();
        assert!(
            y.status.success(),
            "age-keygen -y failed: {}",
            String::from_utf8_lossy(&y.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&y.stdout).trim(),
            ks.recipient_string().unwrap()
        );
    } else {
        eprintln!("skipping recipient check: age-keygen not installed");
    }
}

/// sealdrop opens a file Go age encrypted to a sealdrop PQ recipient (the raw age layer).
#[test]
fn sealdrop_decrypts_what_stock_age_encrypted_to_pq() {
    if !age_available() {
        eprintln!("skipping: age not installed");
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let id = sealdrop_core::pq::Identity::generate();
    let ct = d.path().join("x.age");
    std::fs::write(d.path().join("x.txt"), b"from go age").unwrap();
    let out = Command::new("age")
        .arg("-r")
        .arg(id.to_public().to_string())
        .arg("-o")
        .arg(&ct)
        .arg(d.path().join("x.txt"))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "age -e failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let ids: Vec<Box<dyn age::Identity>> = vec![Box::new(id)];
    let mut pt = Vec::new();
    std::io::Read::read_to_end(
        &mut sealdrop_core::crypt::decrypt_reader(std::fs::File::open(&ct).unwrap(), &ids).unwrap(),
        &mut pt,
    )
    .unwrap();
    assert_eq!(pt, b"from go age");
}
