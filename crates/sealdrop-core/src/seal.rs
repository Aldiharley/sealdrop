//! Seal orchestration (spec 6): pack -> encrypt -> deposit -> manifest -> sign.

use std::fs::{File, OpenOptions};
use std::io::BufWriter;
use std::path::{Path, PathBuf};

use age::secrecy::SecretString;

use crate::crypt::{self, Recipient};
use crate::keys::KeyStore;
use crate::manifest::{
    self, CiphertextInfo, Manifest, RecipientInfo, ReleaseInfo, MANIFEST_FORMAT, NOTES,
};
use crate::pack::{pack, PackReport};
use crate::passphrase::{generate, Passphrase, WordList};
use crate::policy;
use crate::progress::{Progress, ProgressEvent};
use crate::release::{self, Deposit};
use crate::{Error, Result, TOOL};

pub enum Kdf {
    Scrypt { log_n: u8 },
    Argon2id(crate::argon2id::Profile),
}

pub enum Mode {
    Recipients(Vec<Recipient>),
    Passphrase {
        list: WordList,
        words: usize,
        kdf: Kdf,
    },
}

pub struct ReleaseConfig {
    pub service: String,
    pub token: String,
    pub window_secs: u64,
}

pub struct SealRequest {
    pub input: PathBuf,
    pub out_dir: PathBuf,
    pub mode: Mode,
    pub include_self: bool,
    pub allow_unrecoverable: bool,
    pub armor: bool,
    pub classification: Option<String>,
    pub expires: Option<String>,
    pub release: Option<ReleaseConfig>,
}

pub struct SealResult {
    pub package: PathBuf,
    pub manifest: PathBuf,
    pub signature: PathBuf,
    pub manifest_doc: Manifest,
    pub passphrase: Option<Passphrase>,
    pub pack: PackReport,
    /// Why the sender's own identity was left out of the package, if it was.
    pub self_omitted: Option<String>,
}

/// `<name>.sealdrop.age` -> (`<name>.manifest.json`, `<name>.manifest.json.minisig`).
pub fn bundle_paths(package: &Path) -> (PathBuf, PathBuf) {
    let file = package
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let stem = file.strip_suffix(".sealdrop.age").unwrap_or(&file);
    let dir = package.parent().map(Path::to_path_buf).unwrap_or_default();
    let m = dir.join(format!("{stem}.manifest.json"));
    let s = dir.join(format!("{stem}.manifest.json.minisig"));
    (m, s)
}

/// Test seams. `memory://`: remembers the last deposit made against the in-process
/// service so tests can construct a `MemoryFetch` that serves it. Deposit intercept: while
/// set, every deposit (to any service URL) skips HTTP, is remembered the same way, and
/// returns the given service key, so a test can seal against a production-valid URL.
/// Compiled only for tests and the `test-support` feature, so production builds have
/// neither shortcut.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod test_support {
    use std::cell::RefCell;
    use zeroize::Zeroizing;
    // Per-thread, so parallel tests that each seal and then read cannot see each other's key.
    thread_local! {
        static LAST: RefCell<Option<Zeroizing<[u8; 32]>>> = const { RefCell::new(None) };
        static INTERCEPT: RefCell<Option<String>> = const { RefCell::new(None) };
    }
    pub fn remember(k: &Zeroizing<[u8; 32]>) {
        LAST.with(|l| *l.borrow_mut() = Some(k.clone()));
    }
    pub fn last_memory_deposit() -> Option<Zeroizing<[u8; 32]>> {
        LAST.with(|l| l.borrow().clone())
    }
    /// From now on (on this thread), deposits skip HTTP and return `service_key`.
    pub fn intercept_deposits(service_key: &str) {
        INTERCEPT.with(|i| *i.borrow_mut() = Some(service_key.to_string()));
    }
    /// Ends `intercept_deposits`: deposits go to the service again.
    pub fn clear_intercept() {
        INTERCEPT.with(|i| *i.borrow_mut() = None);
    }
    pub(crate) fn intercepted() -> Option<String> {
        INTERCEPT.with(|i| i.borrow().clone())
    }
}

/// Removes the files it guards on drop unless disarmed, so that no failure after the
/// package file is created leaves a partial or unopenable bundle behind.
struct Cleanup {
    paths: Vec<PathBuf>,
    armed: bool,
}

impl Cleanup {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        if self.armed {
            for p in &self.paths {
                let _ = std::fs::remove_file(p);
            }
        }
    }
}

/// Creates a new file, refusing to touch an existing one.
fn create_new(path: &Path) -> Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::AlreadyExists => Error::Exists(path.to_path_buf()),
            _ => Error::Io(e),
        })
}

/// Deposits the release key and returns the service key. Under test, an active deposit
/// intercept or a `memory://` service is simulated in-process; in every other build there
/// is no intercept, and `memory://` falls through to the real client, which has no
/// transport for it and fails.
#[cfg(any(test, feature = "test-support"))]
fn deposit_key(service: &str, token: &str, d: &Deposit, package_sha256: &str) -> Result<String> {
    if let Some(service_key) = test_support::intercepted() {
        test_support::remember(&d.k_release);
        return Ok(service_key);
    }
    if service.starts_with("memory://") {
        test_support::remember(&d.k_release);
        return Ok("memory".to_string());
    }
    release::deposit(service, token, d, package_sha256)
}

#[cfg(not(any(test, feature = "test-support")))]
fn deposit_key(service: &str, token: &str, d: &Deposit, package_sha256: &str) -> Result<String> {
    release::deposit(service, token, d, package_sha256)
}

pub fn seal(store: &KeyStore, req: SealRequest, progress: &dyn Progress) -> Result<SealResult> {
    let passphrase_mode = matches!(req.mode, Mode::Passphrase { .. });
    let mut specs: Vec<Recipient> = Vec::new();
    if let Mode::Recipients(given) = &req.mode {
        for r in given {
            if !specs.iter().any(|s| s.to_string() == r.to_string()) {
                specs.push(r.clone());
            }
        }
    }
    // Passphrase and timed-release packages hold exactly what the caller chose; self is
    // only added to plain recipient packages.
    let mut self_omitted: Option<String> = None;
    if req.include_self && !passphrase_mode && req.release.is_none() {
        let me = Recipient::parse(&store.recipient_string()?)?;
        let given_pq = !specs.is_empty()
            && specs
                .iter()
                .all(|r| policy::is_post_quantum_kind(&r.kind()));
        let me_pq = policy::is_post_quantum_kind(&me.kind());
        if !specs.is_empty() && given_pq != me_pq {
            self_omitted = Some(if given_pq {
                "your own identity is classical (x25519), so it was not added to this post-quantum package; create a post-quantum identity with `keygen --pq` to include yourself".into()
            } else {
                "your own identity is post-quantum, so it was not added to this classical package; the recipients would otherwise be mixed".into()
            });
        } else if !specs.iter().any(|r| r.to_string() == me.to_string()) {
            specs.push(me);
        }
    }
    policy::check_recipients(&specs, passphrase_mode, req.allow_unrecoverable)?;

    // Inner recipients.
    let mut passphrase: Option<Passphrase> = None;
    let inner: Vec<Box<dyn age::Recipient + Send>> = match &req.mode {
        Mode::Recipients(_) => crypt::to_age_recipients(&specs)?,
        Mode::Passphrase { list, words, kdf } => {
            let p = generate(*list, *words);
            let secret: SecretString = p.as_secret();
            passphrase = Some(p);
            match kdf {
                Kdf::Scrypt { log_n } => {
                    vec![Box::new(crypt::scrypt_recipient(secret, *log_n)?)]
                }
                Kdf::Argon2id(profile) => {
                    vec![Box::new(crate::argon2id::Recipient::new(secret, *profile))]
                }
            }
        }
    };

    // Optional timed-release wrap. `Recipient::new` is infallible, so the operator-supplied
    // URL is validated here, and the validated form is used everywhere below.
    let mut deposit: Option<(Deposit, String)> = None;
    let recipients: Vec<Box<dyn age::Recipient + Send>> = if let Some(rc) = &req.release {
        if rc.window_secs == 0 {
            return Err(Error::Other(
                "release window must be at least 1 second".into(),
            ));
        }
        let service = release::validate_service_url(&rc.service)?;
        let d = Deposit::new(rc.window_secs);
        let r = release::Recipient::new(inner, &d, &service);
        deposit = Some((d, service));
        vec![Box::new(r)]
    } else {
        inner
    };

    // Paths.
    std::fs::create_dir_all(&req.out_dir)?;
    // Refuse to write the bundle inside the folder being packed (it would pack itself).
    let input_abs = std::fs::canonicalize(&req.input)?;
    let out_abs = std::fs::canonicalize(&req.out_dir)?;
    if input_abs.is_dir() && out_abs.starts_with(&input_abs) {
        return Err(Error::Other(
            "output folder must not be inside the input folder".into(),
        ));
    }
    let name = req
        .input
        .file_name()
        .ok_or_else(|| Error::Other("input has no name".into()))?
        .to_string_lossy()
        .into_owned();
    let package = req.out_dir.join(format!("{name}.sealdrop.age"));
    let (manifest_path, sig_path) = bundle_paths(&package);
    for p in [&package, &manifest_path, &sig_path] {
        if p.exists() {
            return Err(Error::Exists(p.clone()));
        }
    }

    // From here on a failure removes everything this call created.
    progress.on(ProgressEvent::Packing {
        path: req.input.display().to_string(),
    });
    let file = BufWriter::new(create_new(&package)?);
    let mut cleanup = Cleanup {
        paths: vec![package.clone()],
        armed: true,
    };

    // Pack through the encryptor; `pack` hands the writer back so we can finish it.
    // `Committing` captures the file key age generates, for the manifest's key_commitment.
    let committing = crypt::Committing::new(recipients);
    let commitment = committing.handle();
    let outer: Vec<Box<dyn age::Recipient + Send>> = vec![Box::new(committing)];
    let writer = crypt::encrypt_writer(file, &outer, req.armor)?;
    let (pack_report, writer) = pack(&req.input, writer)?;
    let buf = writer.finish()?;
    buf.into_inner().map_err(|e| Error::Io(e.into_error()))?;
    let key_commitment = commitment
        .commitment_hex()
        .ok_or_else(|| Error::Other("file key was not captured".into()))?;
    let (ct_sha, ct_size) = crate::hashing::sha256_file(&package)?;
    progress.on(ProgressEvent::Encrypted { bytes: ct_size });

    // Deposit before the manifest exists, because the manifest records the service key
    // the deposit call returns. If the deposit fails the guard removes the package:
    // nothing unopenable may be left behind.
    let mut release_info: Option<ReleaseInfo> = None;
    if let (Some((d, service)), Some(rc)) = (&deposit, &req.release) {
        progress.on(ProgressEvent::Contacting {
            service: service.clone(),
        });
        let service_key = deposit_key(service, &rc.token, d, &ct_sha)?;
        release_info = Some(ReleaseInfo {
            service: service.clone(),
            release_id: d.release_id.clone(),
            window_secs: d.window_secs,
            service_key,
        });
    }

    // Manifest.
    let recipients_info: Vec<RecipientInfo> = match &req.mode {
        Mode::Passphrase { kdf, .. } => {
            let kind = match kdf {
                Kdf::Scrypt { .. } => "scrypt",
                Kdf::Argon2id(_) => "argon2id",
            };
            vec![RecipientInfo {
                kind: kind.into(),
                fingerprint: String::new(),
            }]
        }
        Mode::Recipients(_) => specs
            .iter()
            .map(|r| RecipientInfo {
                kind: r.kind(),
                fingerprint: r.fingerprint(),
            })
            .collect(),
    };
    let package_id = uuid::Uuid::new_v4().to_string();
    let doc = Manifest {
        format: MANIFEST_FORMAT.into(),
        package_id: package_id.clone(),
        tool: TOOL.into(),
        created: chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        ciphertext: CiphertextInfo {
            file: format!("{name}.sealdrop.age"),
            size: ct_size,
            sha256: ct_sha,
        },
        plaintext_tar_sha256: pack_report.tar_sha256.clone(),
        key_commitment: Some(key_commitment),
        recipients: recipients_info,
        signer: store.signing_public_string()?,
        classification: req.classification.clone(),
        expires: req.expires.clone(),
        release: release_info,
        notes: NOTES.into(),
    };
    let bytes = doc.to_json()?;
    let sig = manifest::sign(
        &bytes,
        &store.signing_key()?,
        &store.signing_public()?,
        &package_id,
    )?;
    // Each file joins the guard only once this call has created it.
    create_new(&manifest_path)?;
    cleanup.paths.push(manifest_path.clone());
    std::fs::write(&manifest_path, &bytes)?;
    create_new(&sig_path)?;
    cleanup.paths.push(sig_path.clone());
    std::fs::write(&sig_path, sig.into_string())?;
    cleanup.disarm();
    progress.on(ProgressEvent::Done);
    Ok(SealResult {
        package,
        manifest: manifest_path,
        signature: sig_path,
        manifest_doc: doc,
        passphrase,
        pack: pack_report,
        self_omitted,
    })
}
