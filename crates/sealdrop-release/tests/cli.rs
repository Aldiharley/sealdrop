use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sealdrop-release"))
}

#[test]
fn keygen_refuses_to_overwrite_without_force() {
    let dir = tempfile::tempdir().unwrap();
    let run = |force: bool| {
        let mut c = bin();
        c.arg("keygen").arg("--dir").arg(dir.path());
        if force {
            c.arg("--force");
        }
        c.output().unwrap()
    };
    let first = run(false);
    assert!(first.status.success(), "{first:?}");
    let key_before = std::fs::read_to_string(dir.path().join("service.key")).unwrap();

    let second = run(false);
    assert!(!second.status.success(), "second keygen must fail");
    let stderr = String::from_utf8_lossy(&second.stderr);
    assert!(
        stderr.contains("already exists") && stderr.contains("--force"),
        "{stderr}"
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join("service.key")).unwrap(),
        key_before,
        "existing key must be untouched"
    );

    let forced = run(true);
    assert!(forced.status.success(), "{forced:?}");
    assert_ne!(
        std::fs::read_to_string(dir.path().join("service.key")).unwrap(),
        key_before
    );
}

#[cfg(unix)]
#[test]
fn secret_files_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let mode = |name: &str| {
        std::fs::metadata(dir.path().join(name))
            .unwrap()
            .permissions()
            .mode()
            & 0o777
    };
    assert!(bin()
        .arg("keygen")
        .arg("--dir")
        .arg(dir.path())
        .status()
        .unwrap()
        .success());
    assert_eq!(mode("service.key"), 0o600);
    assert_eq!(mode("service.pub"), 0o600);
    assert!(bin()
        .arg("keygen")
        .arg("--dir")
        .arg(dir.path())
        .arg("--force")
        .status()
        .unwrap()
        .success());
    assert_eq!(mode("service.key"), 0o600);

    let db = dir.path().join("releases.db");
    let out = bin()
        .args(["token", "new", "alice", "--db"])
        .arg(&db)
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(mode("releases.db"), 0o600);
}

#[test]
fn serve_rejects_out_of_range_retention() {
    for bad in ["0", "3651", "-1"] {
        let out = bin()
            .args(["serve", "--retention-days", bad])
            .output()
            .unwrap();
        assert!(!out.status.success(), "{bad}");
    }
}
