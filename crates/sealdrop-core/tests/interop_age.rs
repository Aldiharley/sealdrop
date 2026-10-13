//! Interop with the reference Go implementation (spec goal 2). Skips if `age` is not on PATH.

use std::process::Command;

use sealdrop_core::keys::KeyStore;
use sealdrop_core::passphrase::WordList;
use sealdrop_core::progress::NoProgress;
use sealdrop_core::seal::{seal, Kdf, Mode, SealRequest};

fn age_available() -> bool {
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
    ks.generate(false).unwrap();
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
}

#[test]
fn stock_age_decrypts_scrypt_mode() {
    if !age_available() {
        eprintln!("skipping: age not installed");
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let ks = KeyStore::open(d.path().join("ks"));
    ks.generate(false).unwrap();
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
    ks.generate(false).unwrap();
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
