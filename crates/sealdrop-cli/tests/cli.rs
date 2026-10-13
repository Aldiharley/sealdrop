use assert_cmd::Command;
use predicates::prelude::*;
use std::path::Path;

fn cmd(home: &Path) -> Command {
    let mut c = Command::cargo_bin("sealdrop").unwrap();
    c.env("SEALDROP_HOME", home).env("NO_COLOR", "1");
    c
}

fn fixture(dir: &Path) -> std::path::PathBuf {
    let p = dir.join("report");
    std::fs::create_dir_all(p.join("sub")).unwrap();
    std::fs::write(p.join("a.pdf"), b"%PDF").unwrap();
    std::fs::write(p.join("sub/b.html"), b"<p>x</p>").unwrap();
    p
}

#[test]
fn keygen_recipient_seal_verify_open() {
    let d = tempfile::tempdir().unwrap();
    let home = d.path().join("home");
    cmd(&home)
        .arg("keygen")
        .assert()
        .success()
        .stdout(predicate::str::contains("age1"));
    cmd(&home).arg("keygen").assert().failure().code(1);
    let out = cmd(&home).arg("recipient").output().unwrap();
    let rec = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .trim()
        .to_string();
    assert!(rec.starts_with("age1"));

    let input = fixture(d.path());
    let outdir = d.path().join("bundle");
    cmd(&home)
        .args(["seal"])
        .arg(&input)
        .args(["-r", &rec, "-o"])
        .arg(&outdir)
        .assert()
        .success()
        .stdout(predicate::str::contains("report.sealdrop.age"));
    let pkg = outdir.join("report.sealdrop.age");
    assert!(outdir.join("report.manifest.json.minisig").exists());

    cmd(&home)
        .arg("verify")
        .arg(&pkg)
        .assert()
        .success()
        .stdout(predicate::str::contains("OK"));
    let restored = d.path().join("restored");
    cmd(&home)
        .arg("open")
        .arg(&pkg)
        .arg("-o")
        .arg(&restored)
        .assert()
        .success();
    assert_eq!(
        std::fs::read(restored.join("report/sub/b.html")).unwrap(),
        b"<p>x</p>"
    );

    // Tamper -> verify exits 2, and open refuses (verification runs before any decryption).
    let mut bytes = std::fs::read(&pkg).unwrap();
    let i = bytes.len() - 3;
    bytes[i] ^= 0xff;
    std::fs::write(&pkg, bytes).unwrap();
    cmd(&home)
        .arg("verify")
        .arg(&pkg)
        .assert()
        .failure()
        .code(2);
    cmd(&home)
        .arg("open")
        .arg(&pkg)
        .arg("-o")
        .arg(d.path().join("r2"))
        .assert()
        .failure()
        .code(2);
}

#[test]
fn passphrase_mode_prints_words_and_opens_with_stdin() {
    let d = tempfile::tempdir().unwrap();
    let home = d.path().join("home");
    cmd(&home).arg("keygen").assert().success();
    let input = fixture(d.path());
    let outdir = d.path().join("b");
    let out = cmd(&home)
        .arg("seal")
        .arg(&input)
        .args(["--passphrase", "--kdf-profile", "test", "-o"])
        .arg(&outdir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).unwrap();
    let words_line = text.lines().find(|l| l.starts_with("passphrase:")).unwrap();
    let pass = words_line
        .trim_start_matches("passphrase:")
        .trim()
        .to_string();
    assert_eq!(pass.split(' ').count(), 6);
    assert!(text.contains("77.5 bits"));
    cmd(&home)
        .arg("open")
        .arg(outdir.join("report.sealdrop.age"))
        .arg("-o")
        .arg(d.path().join("r"))
        .arg("--passphrase-stdin")
        .write_stdin(format!("{pass}\n"))
        .assert()
        .success();
    cmd(&home)
        .arg("open")
        .arg(outdir.join("report.sealdrop.age"))
        .arg("-o")
        .arg(d.path().join("r3"))
        .arg("--passphrase-stdin")
        .write_stdin("wrong words here now ok yes\n")
        .assert()
        .failure()
        .code(1);
}
/// A well-formed (valid checksum) hardware-key recipient, as a YubiKey plugin would print it.
fn yubikey_recipient() -> String {
    let hrp = bech32::Hrp::parse("age1yubikey").unwrap();
    bech32::encode::<bech32::Bech32>(hrp, &[3u8; 32]).unwrap()
}

#[test]
fn policy_refusals_exit_3() {
    let d = tempfile::tempdir().unwrap();
    let home = d.path().join("home");
    cmd(&home).arg("keygen").assert().success();
    let input = fixture(d.path());
    let out = cmd(&home).arg("recipient").output().unwrap();
    let rec = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .trim()
        .to_string();
    cmd(&home)
        .arg("seal")
        .arg(&input)
        .args(["--passphrase", "-r", &rec, "-o"])
        .arg(d.path().join("x"))
        .assert()
        .failure()
        .code(3);
    cmd(&home)
        .arg("seal")
        .arg(&input)
        .args(["-r", &yubikey_recipient(), "--no-self", "-o"])
        .arg(d.path().join("y"))
        .assert()
        .failure()
        .code(3);
    cmd(&home)
        .arg("seal")
        .arg(&input)
        .arg("-o")
        .arg(d.path().join("z"))
        .assert()
        .failure()
        .code(3);
}

#[test]
fn trust_store_and_unknown_signer() {
    let d = tempfile::tempdir().unwrap();
    let alice = d.path().join("alice");
    let bob = d.path().join("bob");
    cmd(&alice).arg("keygen").assert().success();
    cmd(&bob).arg("keygen").assert().success();
    let rec = String::from_utf8(cmd(&bob).arg("recipient").output().unwrap().stdout)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .trim()
        .to_string();
    let signer = String::from_utf8(cmd(&alice).arg("recipient").output().unwrap().stdout)
        .unwrap()
        .lines()
        .nth(1)
        .unwrap()
        .trim()
        .to_string();
    let outdir = d.path().join("b");
    cmd(&alice)
        .arg("seal")
        .arg(fixture(d.path()))
        .args(["-r", &rec, "-o"])
        .arg(&outdir)
        .assert()
        .success();
    let pkg = outdir.join("report.sealdrop.age");
    cmd(&bob)
        .arg("verify")
        .arg(&pkg)
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("trust add"))
        .stderr(predicate::str::contains(&signer));
    cmd(&bob)
        .args(["trust", "add", "alice", &signer])
        .assert()
        .success();
    cmd(&bob)
        .args(["trust", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("alice"));
    cmd(&bob)
        .arg("verify")
        .arg(&pkg)
        .assert()
        .success()
        .stdout(predicate::str::contains("alice"));
    cmd(&bob)
        .arg("open")
        .arg(&pkg)
        .arg("-o")
        .arg(d.path().join("r"))
        .assert()
        .success();
}

/// Starts the real key-release service on a loopback port in a background thread and
/// returns `(base_url, deposit_token)`. The runtime lives for the whole test process.
fn start_release_service() -> (String, String) {
    use sealdrop_release::app::{build, AppState};
    use sealdrop_release::clock::SystemClock;
    use sealdrop_release::db::Db;
    let db = Db::open_memory().unwrap();
    let token = db.create_token("cli-tests").unwrap();
    let kp = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
    let state = AppState::new(db, std::sync::Arc::new(SystemClock), kp, 1000);
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            tx.send(port).unwrap();
            let app = build(state).into_make_service_with_connect_info::<std::net::SocketAddr>();
            axum::serve(listener, app).await.unwrap();
        });
    });
    let port = rx.recv().unwrap();
    (format!("http://127.0.0.1:{port}"), token)
}

#[test]
fn timed_release_end_to_end_against_real_service() {
    let (service, token) = start_release_service();
    let d = tempfile::tempdir().unwrap();
    let home = d.path().join("home");
    cmd(&home).arg("keygen").assert().success();
    let rec = String::from_utf8(cmd(&home).arg("recipient").output().unwrap().stdout)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .trim()
        .to_string();
    let outdir = d.path().join("b");
    cmd(&home)
        .arg("seal")
        .arg(fixture(d.path()))
        .args([
            "-r",
            &rec,
            "--expire-after",
            "10m",
            "--release-service",
            &service,
            "-o",
        ])
        .arg(&outdir)
        .env("SEALDROP_RELEASE_TOKEN", &token)
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Timed release: 10m after first open, enforced by",
        ))
        .stdout(predicate::str::contains(
            "This does not protect the contents once decrypted.",
        ));
    let m = std::fs::read_to_string(outdir.join("report.manifest.json")).unwrap();
    assert!(m.contains("\"window_secs\": 600"));
    assert!(m.contains("\"service_key\": \"RW"));
    cmd(&home)
        .arg("open")
        .arg(outdir.join("report.sealdrop.age"))
        .arg("-o")
        .arg(d.path().join("r"))
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Expiry applies to the encrypted package only; nothing can recall a file after it has been decrypted.",
        ))
        .stdout(predicate::str::contains(format!(
            "This package uses timed release: 10m after first open, enforced by {service}"
        )))
        .stdout(predicate::str::contains(
            "Opening it starts or continues the window on the service's clock.",
        ));
    // Re-open inside the window is allowed.
    cmd(&home)
        .arg("open")
        .arg(outdir.join("report.sealdrop.age"))
        .arg("-o")
        .arg(d.path().join("r2"))
        .assert()
        .success();
    // Sender fetches and verifies the pinned receipt.
    let fetched = cmd(&home)
        .args(["receipt", "fetch"])
        .arg(outdir.join("report.manifest.json"))
        .env("SEALDROP_RELEASE_TOKEN", &token)
        .assert()
        .success()
        .stdout(predicate::str::contains("unlock count: 2"));
    assert_no_token(fetched.get_output(), &token);
    assert!(outdir.join("report.receipt.json").exists());
    let verified = cmd(&home)
        .args(["receipt", "verify"])
        .arg(outdir.join("report.receipt.json"))
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "OK (key not pinned): receipt signature valid",
        ));
    assert_no_token(verified.get_output(), &token);
    // Pinning the key from the manifest drops the "not pinned" caveat.
    let key = m
        .split("\"service_key\": \"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_string();
    cmd(&home)
        .args(["receipt", "verify"])
        .arg(outdir.join("report.receipt.json"))
        .args(["--service-key", &key])
        .assert()
        .success()
        .stdout(predicate::str::contains("OK: receipt signature valid"));
    // --skip-verify on a timed package never echoes the unverified header as fact.
    cmd(&home)
        .arg("open")
        .arg(outdir.join("report.sealdrop.age"))
        .args(["--skip-verify", "-o"])
        .arg(d.path().join("r4"))
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "(unverified header; window unknown)",
        ))
        .stdout(predicate::str::contains(
            "signature NOT verified (--skip-verify)",
        ));
    // `receipt fetch` refuses to send the token anywhere if the package no longer matches
    // its signed manifest (tamper the package, not the signed manifest).
    let outdir3 = d.path().join("b3");
    cmd(&home)
        .arg("seal")
        .arg(fixture(d.path()))
        .args([
            "-r",
            &rec,
            "--expire-after",
            "10m",
            "--release-service",
            &service,
            "-o",
        ])
        .arg(&outdir3)
        .env("SEALDROP_RELEASE_TOKEN", &token)
        .assert()
        .success();
    let pkg3 = outdir3.join("report.sealdrop.age");
    let mut bytes = std::fs::read(&pkg3).unwrap();
    let i = bytes.len() - 3;
    bytes[i] ^= 0xff;
    std::fs::write(&pkg3, bytes).unwrap();
    let refused = cmd(&home)
        .args(["receipt", "fetch"])
        .arg(outdir3.join("report.manifest.json"))
        .env("SEALDROP_RELEASE_TOKEN", &token)
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("does not match"));
    assert_no_token(refused.get_output(), &token);
    assert!(!outdir3.join("report.receipt.json").exists());
    // A file that is not a `.manifest.json` is rejected with a clear message.
    let not_manifest = d.path().join("notes.txt");
    std::fs::write(&not_manifest, b"x").unwrap();
    let bad = cmd(&home)
        .args(["receipt", "fetch"])
        .arg(&not_manifest)
        .env("SEALDROP_RELEASE_TOKEN", &token)
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("<name>.manifest.json"));
    assert_no_token(bad.get_output(), &token);
    // A 1-second window expires: seal, open once, wait, open again -> exit 2.
    let outdir2 = d.path().join("b2");
    cmd(&home)
        .arg("seal")
        .arg(fixture(d.path()))
        .args([
            "-r",
            &rec,
            "--expire-after",
            "1s",
            "--release-service",
            &service,
            "-o",
        ])
        .arg(&outdir2)
        .env("SEALDROP_RELEASE_TOKEN", &token)
        .assert()
        .success();
    cmd(&home)
        .arg("open")
        .arg(outdir2.join("report.sealdrop.age"))
        .arg("-o")
        .arg(d.path().join("e1"))
        .assert()
        .success();
    std::thread::sleep(std::time::Duration::from_millis(2100));
    cmd(&home)
        .arg("open")
        .arg(outdir2.join("report.sealdrop.age"))
        .arg("-o")
        .arg(d.path().join("e2"))
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("expired"));
}

#[test]
fn timed_release_with_passphrase_prompts_and_never_unlocks_without_it() {
    let (service, token) = start_release_service();
    let d = tempfile::tempdir().unwrap();
    let home = d.path().join("home");
    cmd(&home).arg("keygen").assert().success();
    let outdir = d.path().join("b");
    let out = cmd(&home)
        .arg("seal")
        .arg(fixture(d.path()))
        .args([
            "--passphrase",
            "--kdf-profile",
            "test",
            "--expire-after",
            "10m",
            "--release-service",
            &service,
            "-o",
        ])
        .arg(&outdir)
        .env("SEALDROP_RELEASE_TOKEN", &token)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).unwrap();
    let pass = text
        .lines()
        .find_map(|l| l.strip_prefix("passphrase:"))
        .unwrap()
        .trim()
        .to_string();
    let pkg = outdir.join("report.sealdrop.age");

    // No passphrase given: the CLI prompts (the header alone cannot show it), stdin is
    // empty, and nothing reaches the service.
    cmd(&home)
        .arg("open")
        .arg(&pkg)
        .arg("-o")
        .arg(d.path().join("r0"))
        .write_stdin("")
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("passphrase"));
    cmd(&home)
        .args(["receipt", "fetch"])
        .arg(outdir.join("report.manifest.json"))
        .env("SEALDROP_RELEASE_TOKEN", &token)
        .assert()
        .success()
        .stdout(predicate::str::contains("not yet opened"));

    // With the passphrase on stdin it opens through the service.
    cmd(&home)
        .arg("open")
        .arg(&pkg)
        .arg("-o")
        .arg(d.path().join("r"))
        .arg("--passphrase-stdin")
        .write_stdin(format!("{pass}\n"))
        .assert()
        .success()
        .stdout(predicate::str::contains("first opened"));
    assert_eq!(
        std::fs::read(d.path().join("r/report/sub/b.html")).unwrap(),
        b"<p>x</p>"
    );
    cmd(&home)
        .args(["receipt", "fetch"])
        .arg(outdir.join("report.manifest.json"))
        .env("SEALDROP_RELEASE_TOKEN", &token)
        .assert()
        .success()
        .stdout(predicate::str::contains("unlock count: 1"));
}

#[test]
fn seal_dot_uses_the_real_folder_name() {
    let d = tempfile::tempdir().unwrap();
    let home = d.path().join("home");
    cmd(&home).arg("keygen").assert().success();
    let rec = String::from_utf8(cmd(&home).arg("recipient").output().unwrap().stdout)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .trim()
        .to_string();
    let input = fixture(d.path());
    let outdir = d.path().join("out");
    cmd(&home)
        .current_dir(&input)
        .args(["seal", ".", "-r", &rec, "-o"])
        .arg(&outdir)
        .assert()
        .success();
    assert!(outdir.join("report.sealdrop.age").exists());
}

fn assert_no_token(out: &std::process::Output, token: &str) {
    for stream in [&out.stdout, &out.stderr] {
        assert!(
            !String::from_utf8_lossy(stream).contains(token),
            "the deposit token leaked into command output"
        );
    }
}

#[test]
fn usage_errors_exit_1_and_help_exits_0() {
    let d = tempfile::tempdir().unwrap();
    let home = d.path().join("home");
    // Exit 2 means "verification failed", so a usage error must not use it.
    cmd(&home)
        .args(["seal", "--no-such-flag"])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("--no-such-flag"));
    cmd(&home).arg("no-such-command").assert().failure().code(1);
    cmd(&home).assert().failure().code(1);
    cmd(&home)
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Usage: sealdrop"));
    cmd(&home)
        .args(["seal", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--passphrase"));
    cmd(&home)
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("sealdrop"));
}

#[test]
fn passphrase_only_flags_need_passphrase() {
    let d = tempfile::tempdir().unwrap();
    let home = d.path().join("home");
    cmd(&home).arg("keygen").assert().success();
    let rec = String::from_utf8(cmd(&home).arg("recipient").output().unwrap().stdout)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .trim()
        .to_string();
    let input = fixture(d.path());
    for (n, flags) in [
        ("--argon2id", vec!["--argon2id"]),
        ("--kdf-profile", vec!["--kdf-profile", "high"]),
        ("--words", vec!["--words", "bip39"]),
        ("--word-count", vec!["--word-count", "8"]),
        ("--qr", vec!["--qr"]),
    ] {
        cmd(&home)
            .arg("seal")
            .arg(&input)
            .args(["-r", &rec, "-o"])
            .arg(d.path().join("never"))
            .args(&flags)
            .assert()
            .failure()
            .code(1)
            .stderr(predicate::str::contains(format!(
                "{n} requires --passphrase"
            )));
    }
    assert!(!d.path().join("never").exists());
}

#[test]
fn bad_windows_are_errors_not_panics() {
    let d = tempfile::tempdir().unwrap();
    let home = d.path().join("home");
    cmd(&home).arg("keygen").assert().success();
    let rec = String::from_utf8(cmd(&home).arg("recipient").output().unwrap().stdout)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .trim()
        .to_string();
    for w in ["10\u{e9}", "\u{e9}", "m", "0s", "10"] {
        cmd(&home)
            .arg("seal")
            .arg(fixture(d.path()))
            .args([
                "-r",
                &rec,
                "--release-service",
                "https://x.example",
                "--expire-after",
                w,
                "-o",
            ])
            .arg(d.path().join("never"))
            .env("SEALDROP_RELEASE_TOKEN", "t")
            .assert()
            .failure()
            .code(1)
            .stderr(predicate::str::contains("window"));
    }
}

#[test]
fn empty_passphrase_stdin_is_an_error() {
    let d = tempfile::tempdir().unwrap();
    let home = d.path().join("home");
    cmd(&home).arg("keygen").assert().success();
    let out = cmd(&home)
        .arg("seal")
        .arg(fixture(d.path()))
        .args(["--passphrase", "--kdf-profile", "test", "-o"])
        .arg(d.path().join("b"))
        .output()
        .unwrap();
    assert!(out.status.success());
    let pkg = d.path().join("b/report.sealdrop.age");
    for input in ["", "\n"] {
        cmd(&home)
            .arg("open")
            .arg(&pkg)
            .arg("-o")
            .arg(d.path().join("r"))
            .arg("--passphrase-stdin")
            .write_stdin(input)
            .assert()
            .failure()
            .code(1)
            .stderr(predicate::str::contains("no passphrase on stdin"));
    }
}

#[test]
fn skip_verify_says_so() {
    let d = tempfile::tempdir().unwrap();
    let home = d.path().join("home");
    cmd(&home).arg("keygen").assert().success();
    let rec = String::from_utf8(cmd(&home).arg("recipient").output().unwrap().stdout)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .trim()
        .to_string();
    let outdir = d.path().join("b");
    cmd(&home)
        .arg("seal")
        .arg(fixture(d.path()))
        .args(["-r", &rec, "-o"])
        .arg(&outdir)
        .assert()
        .success();
    cmd(&home)
        .arg("open")
        .arg(outdir.join("report.sealdrop.age"))
        .args(["--skip-verify", "-o"])
        .arg(d.path().join("r"))
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "signature NOT verified (--skip-verify)",
        ));
}
