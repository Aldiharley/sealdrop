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

    // Tamper -> verify exits 2, open refuses, open --skip-verify fails on MAC.
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
        .stderr(predicate::str::contains("trust add"));
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
        .stdout(predicate::str::contains("Timed release: 10m"));
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
            "Expiry applies to the encrypted package only",
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
    cmd(&home)
        .args(["receipt", "fetch"])
        .arg(outdir.join("report.manifest.json"))
        .env("SEALDROP_RELEASE_TOKEN", &token)
        .assert()
        .success()
        .stdout(predicate::str::contains("unlock count: 2"));
    assert!(outdir.join("report.receipt.json").exists());
    cmd(&home)
        .args(["receipt", "verify"])
        .arg(outdir.join("report.receipt.json"))
        .assert()
        .success();
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
