//! Tauri command layer over `sealdrop-core` (design brief section 11).
//!
//! All file and network work happens here; the WebView only calls these commands.
//! Every command returns `Result<T, String>`; absent optional values serialize as `null`.
//!
//! Secrets: passphrases, the deposit token and release keys never reach a log, a `Debug`
//! impl or a `progress` event payload. The request/response structs that carry a secret
//! (`OpenArgs`, `SealOut`) deliberately do not derive `Debug`.
//!
//! The heavy commands are `async` and run their work on a blocking thread, so a slow key
//! derivation (scrypt, Argon2id) or a network call never freezes the window.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use age::secrecy::SecretString;
use sealdrop_core::keys::{KeyStore, Settings};
use sealdrop_core::progress::{Progress, ProgressEvent};
use sealdrop_core::text::sanitize;
use sealdrop_core::Error;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};
use zeroize::Zeroizing;

type CmdResult<T> = Result<T, String>;

/// Largest manifest or receipt file we read when peeking at one (the core caps manifests at
/// the same size).
const MAX_JSON_FILE: u64 = 1024 * 1024;

// ---------------------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------------------

fn store() -> KeyStore {
    match std::env::var_os("SEALDROP_HOME") {
        Some(p) => KeyStore::open(PathBuf::from(p)),
        None => KeyStore::open(KeyStore::default_dir()),
    }
}

fn s<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

/// Finds the sealdrop error inside an error chain, looking through the `io::Error` that age
/// uses to carry a failure raised while decrypting (an expired timed-release package
/// surfaces that way). Mirrors the CLI's classification.
fn classify<'a>(e: &'a (dyn std::error::Error + 'static)) -> Option<&'a Error> {
    if let Some(err) = e.downcast_ref::<Error>() {
        if let Error::Decrypt(age::DecryptError::Io(io)) = err {
            if let Some(inner) = io.get_ref().and_then(|i| classify(i)) {
                return Some(inner);
            }
        }
        return Some(err);
    }
    if let Some(io) = e.downcast_ref::<std::io::Error>() {
        if let Some(inner) = io.get_ref().and_then(|i| classify(i)) {
            return Some(inner);
        }
    }
    None
}

/// The message shown to the user for a core error.
fn err_msg(e: &Error) -> String {
    match classify(e) {
        Some(Error::ReleaseExpired) => {
            "this package has expired at the release service and can no longer be opened".into()
        }
        _ => strip_cli_hint(e.to_string()),
    }
}

/// The core's "signer ... is not trusted" message ends with a `sealdrop trust add ...`
/// command line. The app offers "Trust this signer" itself, so drop the CLI advice.
fn strip_cli_hint(msg: String) -> String {
    match msg.find("; add it with `sealdrop trust add") {
        Some(i) => msg[..i].to_string(),
        None => msg,
    }
}

/// Paths come from native dialogs and drag-and-drop, which always give absolute paths;
/// anything else is refused rather than resolved against an unknown working directory.
fn abs(p: &str) -> CmdResult<PathBuf> {
    let p = PathBuf::from(p);
    if p.is_absolute() {
        Ok(p)
    } else {
        Err("path must be absolute".into())
    }
}

fn ce(e: Error) -> String {
    err_msg(&e)
}

/// The deposit token: environment first (same as the CLI), then the saved settings.
fn release_token(settings: &Settings) -> CmdResult<String> {
    std::env::var("SEALDROP_RELEASE_TOKEN")
        .ok()
        .filter(|t| !t.is_empty())
        .or_else(|| settings.release_token.clone().filter(|t| !t.is_empty()))
        .ok_or_else(|| "Set the release deposit token in Settings first".to_string())
}

/// `remaining = expires_at - now`, both RFC 3339, `now` being the service clock sample that
/// came with the response. Whole seconds, never negative; `None` if either does not parse
/// (for example a receipt signed before 0.2 carries no `now`).
pub fn remaining_secs(expires_at: &str, now: &str) -> Option<i64> {
    let expires = chrono::DateTime::parse_from_rfc3339(expires_at).ok()?;
    let now = chrono::DateTime::parse_from_rfc3339(now).ok()?;
    Some((expires - now).num_seconds().max(0))
}

/// True for the core's "signer ... is not trusted" verification failure.
pub fn is_untrusted_msg(msg: &str) -> bool {
    msg.contains("is not trusted")
}

fn read_small(path: &Path) -> CmdResult<Vec<u8>> {
    let len = std::fs::metadata(path).map_err(s)?.len();
    if len > MAX_JSON_FILE {
        return Err(format!("{} is too large", path.display()));
    }
    std::fs::read(path).map_err(s)
}

/// Reads the `signer` out of the manifest beside `package` WITHOUT verifying anything, and
/// only returns it if it is a well-formed signer key that the failure message really named.
/// The value is untrusted input that the user is then asked to accept or reject.
fn untrusted_signer(package: &Path, msg: &str) -> Option<String> {
    let (manifest_path, _) = sealdrop_core::seal::bundle_paths(package);
    let bytes = read_small(&manifest_path).ok()?;
    let doc = sealdrop_core::manifest::Manifest::from_json(&bytes).ok()?;
    minisign::PublicKey::from_base64(&doc.signer).ok()?;
    msg.starts_with(&format!("signer {} is not trusted", doc.signer))
        .then_some(doc.signer)
}

/// The process's temporary viewing root: a randomly named, owner-only folder (never a
/// predictable name in a shared temp folder), created on first use and deleted when the
/// `TempDir` is dropped.
static VIEW_ROOT: Mutex<Option<tempfile::TempDir>> = Mutex::new(None);

fn fresh_root() -> CmdResult<tempfile::TempDir> {
    tempfile::Builder::new()
        .prefix("sealdrop-view-")
        .tempdir()
        .map_err(s)
}

/// The current viewing root, if one has been created and not yet removed (tests only).
#[cfg(test)]
fn view_root() -> Option<PathBuf> {
    let g = VIEW_ROOT.lock().ok()?;
    g.as_ref().map(|d| d.path().to_path_buf())
}

/// Removes this process's temporary viewing folders. Best effort.
pub fn remove_view_dir() {
    if let Ok(mut g) = VIEW_ROOT.lock() {
        drop(g.take());
    }
}

/// Creates one owner-only folder; an existing path is an error (no `recursive`).
fn make_private_dir(d: &Path) -> CmdResult<()> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(d).map_err(s)
}

fn new_view_dir() -> CmdResult<PathBuf> {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let mut g = VIEW_ROOT
        .lock()
        .map_err(|_| "viewing folder lock poisoned")?;
    if g.is_none() {
        *g = Some(fresh_root()?);
    }
    let root = g.as_ref().map(|d| d.path().to_path_buf()).unwrap();
    let d = root.join(SEQ.fetch_add(1, Ordering::SeqCst).to_string());
    make_private_dir(&d)?;
    Ok(d)
}

/// Forwards core progress to the WebView as `progress { kind, detail }`.
struct EmitProgress(AppHandle);

fn progress_parts(e: ProgressEvent) -> (&'static str, String) {
    match e {
        ProgressEvent::Packing { path } => ("packing", path),
        ProgressEvent::Encrypted { bytes } => ("encrypted", bytes.to_string()),
        ProgressEvent::Contacting { service } => ("contacting", sanitize(&service)),
        ProgressEvent::Verifying => ("verifying", String::new()),
        ProgressEvent::Extracting { path } => ("extracting", path),
        ProgressEvent::Done => ("done", String::new()),
    }
}

impl Progress for EmitProgress {
    fn on(&self, e: ProgressEvent) {
        let (kind, detail) = progress_parts(e);
        let _ = self.0.emit(
            "progress",
            serde_json::json!({ "kind": kind, "detail": detail }),
        );
    }
}

async fn blocking<T, F>(f: F) -> CmdResult<T>
where
    T: Send + 'static,
    F: FnOnce() -> CmdResult<T> + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|e| format!("background task failed: {e}"))?
}

// ---------------------------------------------------------------------------------------
// identity
// ---------------------------------------------------------------------------------------

#[derive(Serialize)]
pub struct IdentityInfo {
    pub exists: bool,
    pub recipient: Option<String>,
    pub signer: Option<String>,
    pub dir: String,
    /// `"x25519"` or `"pq"`; `None` when there is no identity yet.
    pub kind: Option<String>,
}

fn identity_info(ks: &KeyStore) -> IdentityInfo {
    IdentityInfo {
        exists: ks.exists(),
        recipient: ks.recipient_string().ok(),
        signer: ks.signing_public_string().ok(),
        dir: ks.dir().display().to_string(),
        kind: ks.identity_kind().ok().map(|k| k.as_str().to_string()),
    }
}

#[tauri::command]
pub fn get_identity() -> CmdResult<IdentityInfo> {
    Ok(identity_info(&store()))
}

#[tauri::command]
pub fn generate_identity(force: bool, pq: bool) -> CmdResult<IdentityInfo> {
    use sealdrop_core::keys::IdentityKind;
    let ks = store();
    let kind = if pq {
        IdentityKind::Pq
    } else {
        IdentityKind::X25519
    };
    ks.generate(force, kind).map_err(ce)?;
    Ok(identity_info(&ks))
}

// ---------------------------------------------------------------------------------------
// recipients
// ---------------------------------------------------------------------------------------

#[derive(Serialize, Debug, PartialEq, Eq)]
pub struct RecipientCheck {
    pub kind: String,
    pub fingerprint: String,
    pub plugin: Option<String>,
    pub allowed: bool,
}

pub fn recipient_check(input: &str) -> CmdResult<RecipientCheck> {
    let r = sealdrop_core::crypt::Recipient::parse(input).map_err(ce)?;
    let plugin = r.plugin_name();
    let allowed = plugin
        .as_deref()
        .map(sealdrop_core::policy::plugin_allowed)
        .unwrap_or(true);
    Ok(RecipientCheck {
        kind: r.kind(),
        fingerprint: r.fingerprint(),
        plugin,
        allowed,
    })
}

/// Pure parse: makes no network call and runs no plugin.
#[tauri::command]
pub fn parse_recipient(s: String) -> CmdResult<RecipientCheck> {
    recipient_check(&s)
}

// ---------------------------------------------------------------------------------------
// seal
// ---------------------------------------------------------------------------------------

fn default_true() -> bool {
    true
}
fn default_eff() -> String {
    "eff".into()
}
fn default_profile() -> String {
    "default".into()
}

#[derive(Deserialize)]
pub struct SealArgs {
    pub input: String,
    pub out_dir: String,
    #[serde(default)]
    pub recipients: Vec<String>,
    #[serde(default)]
    pub passphrase: bool,
    /// "eff" | "bip39"
    #[serde(default = "default_eff")]
    pub words: String,
    #[serde(default)]
    pub argon2id: bool,
    /// "default" | "high"
    #[serde(default = "default_profile")]
    pub kdf_profile: String,
    #[serde(default)]
    pub armor: bool,
    #[serde(default)]
    pub classification: Option<String>,
    #[serde(default)]
    pub expires: Option<String>,
    #[serde(default)]
    pub allow_unrecoverable: bool,
    #[serde(default = "default_true")]
    pub include_self: bool,
    #[serde(default)]
    pub expire_after_secs: Option<u64>,
}

#[derive(Serialize, Debug, PartialEq, Eq)]
pub struct ReleaseOut {
    pub service: String,
    pub window_secs: u64,
}

/// The service URL is the sender's text: React renders it as text, and it is sanitized here
/// too (same rule as the CLI) so no control or bidi character reaches the UI.
fn release_out(r: sealdrop_core::manifest::ReleaseInfo) -> ReleaseOut {
    ReleaseOut {
        service: sanitize(&r.service),
        window_secs: r.window_secs,
    }
}

/// Holds the generated passphrase in passphrase mode, so it has no `Debug`.
#[derive(Serialize)]
pub struct SealOut {
    pub package: String,
    pub manifest: String,
    pub package_id: String,
    pub ciphertext_sha256: String,
    pub files: usize,
    pub bytes: u64,
    pub passphrase: Option<String>,
    pub entropy_bits: Option<f64>,
    pub release: Option<ReleaseOut>,
    /// Why the sender's own identity was left out of the package, if it was.
    pub self_omitted: Option<String>,
    /// True when every recipient of the package is a post-quantum kind.
    pub post_quantum: bool,
}

fn seal_impl(ks: &KeyStore, req: SealArgs, progress: &dyn Progress) -> CmdResult<SealOut> {
    use sealdrop_core::argon2id::Profile;
    use sealdrop_core::crypt::{Recipient, SCRYPT_HIGH_LOG_N};
    use sealdrop_core::passphrase::WordList;
    use sealdrop_core::policy::PolicyError;
    use sealdrop_core::seal::{seal, Kdf, Mode, ReleaseConfig, SealRequest};

    let settings = ks.settings().map_err(ce)?;
    let high = match req.kdf_profile.as_str() {
        "default" => false,
        "high" => true,
        other => return Err(format!("unknown key-derivation profile `{other}`")),
    };
    let list = match req.words.as_str() {
        "eff" => WordList::Eff,
        "bip39" => WordList::Bip39,
        other => return Err(format!("unknown word list `{other}`")),
    };

    // Recipients and a passphrase are mutually exclusive, and one of them is required.
    let mut recipients = Vec::new();
    for r in &req.recipients {
        recipients.push(Recipient::parse(r).map_err(ce)?);
    }
    if req.passphrase && !recipients.is_empty() {
        return Err(ce(Error::Policy(PolicyError::PassphraseMustBeAlone)));
    }
    if !req.passphrase && recipients.is_empty() {
        return Err(ce(Error::Policy(PolicyError::NoRecipients)));
    }

    let mode = if req.passphrase {
        let kdf = if req.argon2id {
            Kdf::Argon2id(if high {
                Profile::Desktop
            } else {
                Profile::Compat
            })
        } else {
            Kdf::Scrypt {
                log_n: if high {
                    SCRYPT_HIGH_LOG_N
                } else {
                    settings.scrypt_log_n
                },
            }
        };
        Mode::Passphrase {
            list,
            words: 0,
            kdf,
        }
    } else {
        Mode::Recipients(recipients)
    };

    let release = match req.expire_after_secs {
        Some(0) => return Err("the timed-release window must be at least 1 second".into()),
        Some(window_secs) => Some(ReleaseConfig {
            service: settings
                .release_service
                .clone()
                .filter(|u| !u.trim().is_empty())
                .ok_or("Set the release service URL in Settings first")?,
            token: release_token(&settings)?,
            window_secs,
        }),
        None => None,
    };

    // The core takes the package name from the last path component, so resolve `.`, `..`
    // and relative paths first.
    let input = std::fs::canonicalize(abs(&req.input)?)
        .map_err(|e| format!("cannot read {}: {e}", req.input))?;
    let out_dir = abs(&req.out_dir)?;

    let res = seal(
        ks,
        SealRequest {
            input,
            out_dir,
            mode,
            include_self: req.include_self,
            allow_unrecoverable: req.allow_unrecoverable,
            armor: req.armor,
            classification: req.classification.filter(|c| !c.trim().is_empty()),
            expires: req.expires.filter(|e| !e.trim().is_empty()),
            release,
        },
        progress,
    )
    .map_err(ce)?;

    Ok(SealOut {
        package: res.package.display().to_string(),
        manifest: res.manifest.display().to_string(),
        package_id: res.manifest_doc.package_id.clone(),
        ciphertext_sha256: res.manifest_doc.ciphertext.sha256.clone(),
        files: res.pack.meta.files.len(),
        bytes: res.pack.total_bytes,
        passphrase: res.passphrase.as_ref().map(|p| p.joined().to_string()),
        entropy_bits: res.passphrase.as_ref().map(|p| p.entropy_bits),
        post_quantum: sealdrop_core::open::post_quantum_kinds(&res.manifest_doc.recipients),
        release: res.manifest_doc.release.map(release_out),
        self_omitted: res.self_omitted,
    })
}

#[tauri::command]
pub async fn seal(app: AppHandle, req: SealArgs) -> CmdResult<SealOut> {
    blocking(move || seal_impl(&store(), req, &EmitProgress(app))).await
}

// ---------------------------------------------------------------------------------------
// probe
// ---------------------------------------------------------------------------------------

#[derive(Serialize)]
pub struct ProbeRelease {
    pub service: String,
    pub release_id: String,
}

#[derive(Serialize)]
pub struct ProbeOut {
    /// True when opening needs a passphrase: a passphrase stanza in the header, or a timed
    /// package whose manifest says the key inside is a passphrase.
    pub needs_passphrase: bool,
    /// `recipients[0].kind` from the manifest beside the package, read WITHOUT verifying
    /// it: it only decides whether to show the passphrase field. The core makes the real
    /// check (before any network call) when the package is opened.
    pub inner_kind: Option<String>,
    pub timed_release: Option<ProbeRelease>,
}

fn probe_impl(path: &Path) -> CmdResult<ProbeOut> {
    use sealdrop_core::open::{is_passphrase_kind, unverified_inner_kind};
    let p = sealdrop_core::probe::probe(path).map_err(ce)?;
    let inner_kind = unverified_inner_kind(path);
    let timed_passphrase =
        p.release.is_some() && inner_kind.as_deref().is_some_and(is_passphrase_kind);
    Ok(ProbeOut {
        needs_passphrase: p.needs_passphrase || timed_passphrase,
        inner_kind,
        // The header is not signed: the service shown here is a claim until `verify`.
        timed_release: p.release.map(|r| ProbeRelease {
            service: sanitize(&r.service),
            release_id: sanitize(&r.release_id),
        }),
    })
}

#[tauri::command]
pub async fn probe(path: String) -> CmdResult<ProbeOut> {
    blocking(move || probe_impl(&abs(&path)?)).await
}

// ---------------------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------------------

#[derive(Serialize, Debug, PartialEq, Eq)]
pub struct RecipientOut {
    pub kind: String,
    pub fingerprint: String,
}

#[derive(Serialize, Debug, PartialEq, Eq, Default)]
pub struct VerifyOut {
    pub ok: bool,
    pub untrusted_signer: Option<String>,
    pub package_id: Option<String>,
    pub signer: Option<String>,
    pub trusted_as: Option<String>,
    pub created: Option<String>,
    pub classification: Option<String>,
    pub expires: Option<String>,
    pub recipients: Option<Vec<RecipientOut>>,
    pub release: Option<ReleaseOut>,
    pub ciphertext_sha256: Option<String>,
    /// Every signed recipient is post-quantum; `None` when the package was not verified.
    pub post_quantum: Option<bool>,
}

fn verify_impl(ks: &KeyStore, path: &Path, signer: Option<&str>) -> CmdResult<VerifyOut> {
    match sealdrop_core::open::verify(ks, path, signer) {
        Ok(v) => {
            let m = v.manifest;
            Ok(VerifyOut {
                ok: true,
                untrusted_signer: None,
                package_id: Some(m.package_id),
                signer: Some(v.signer),
                trusted_as: v.trusted_as,
                created: Some(m.created),
                classification: m.classification,
                expires: m.expires,
                recipients: Some(
                    m.recipients
                        .into_iter()
                        .map(|r| RecipientOut {
                            kind: r.kind,
                            fingerprint: r.fingerprint,
                        })
                        .collect(),
                ),
                release: m.release.map(release_out),
                ciphertext_sha256: Some(m.ciphertext.sha256),
                post_quantum: Some(v.post_quantum),
            })
        }
        Err(Error::Verify(msg)) if is_untrusted_msg(&msg) => {
            match untrusted_signer(path, &msg) {
                Some(key) => Ok(VerifyOut {
                    ok: false,
                    untrusted_signer: Some(key),
                    ..Default::default()
                }),
                // Not the genuine "unknown signer" case: report the failure as it is.
                None => Err(err_msg(&Error::Verify(msg))),
            }
        }
        Err(e) => Err(ce(e)),
    }
}

#[tauri::command]
pub async fn verify(path: String, signer: Option<String>) -> CmdResult<VerifyOut> {
    let signer = signer.filter(|k| !k.trim().is_empty());
    blocking(move || verify_impl(&store(), &abs(&path)?, signer.as_deref())).await
}

// ---------------------------------------------------------------------------------------
// open
// ---------------------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct OpenArgs {
    #[serde(alias = "path")]
    pub package: String,
    #[serde(default)]
    pub out_dir: Option<String>,
    #[serde(default)]
    pub temp: bool,
    /// Secret: wiped on drop, turned into a `SecretString` for the core; never logged.
    #[serde(default)]
    pub passphrase: Option<Zeroizing<String>>,
    #[serde(default)]
    pub signer: Option<String>,
    #[serde(default)]
    pub skip_verify: bool,
    #[serde(default)]
    pub overwrite: bool,
}

#[derive(Serialize, Debug, PartialEq, Eq)]
pub struct OpenOut {
    pub root: String,
    pub files: usize,
    pub bytes: u64,
    pub signer: Option<String>,
    pub trusted_as: Option<String>,
    pub verified: bool,
    pub first_unlock: Option<String>,
    pub expires_at: Option<String>,
    pub remaining_secs: Option<i64>,
    /// Every signed recipient is post-quantum; `None` when verification was skipped.
    pub post_quantum: Option<bool>,
}

fn open_impl(
    ks: &KeyStore,
    req: OpenArgs,
    fetch: Box<dyn sealdrop_core::release::ReleaseFetch>,
    progress: &dyn Progress,
) -> CmdResult<OpenOut> {
    use sealdrop_core::open::{open, OpenRequest};

    let package = abs(&req.package)?;
    let signer = req.signer.filter(|k| !k.trim().is_empty());

    // Timed package: the header is unsigned, so unless verification was skipped, check it
    // against the signed manifest first. The unlock token then only ever goes to the
    // service the sender signed.
    if !req.skip_verify {
        let p = sealdrop_core::probe::probe(&package).map_err(ce)?;
        if let Some(h) = &p.release {
            let v = sealdrop_core::open::verify(ks, &package, signer.as_deref()).map_err(ce)?;
            let r = v.manifest.release.as_ref().ok_or_else(|| {
                "the package asks for timed release but the signed manifest does not".to_string()
            })?;
            if r.service != h.service || r.release_id != h.release_id {
                return Err(
                    "the package's timed-release service does not match the signed manifest".into(),
                );
            }
        }
    }

    let (out_dir, temp_dir) = if req.temp {
        let d = new_view_dir()?;
        (d.clone(), Some(d))
    } else {
        let dir = req
            .out_dir
            .filter(|d| !d.trim().is_empty())
            .ok_or("choose a destination folder")?;
        (abs(&dir)?, None)
    };

    let rep = open(
        ks,
        OpenRequest {
            package,
            out_dir,
            signer,
            skip_verify: req.skip_verify,
            overwrite: req.overwrite,
            passphrase: req
                .passphrase
                .filter(|p| !p.is_empty())
                .map(|p| SecretString::from(p.as_str())),
            limits: Default::default(),
        },
        fetch,
        progress,
    );
    let rep = match rep {
        Ok(r) => r,
        Err(e) => {
            // Don't leave a half-restored viewing folder behind.
            if let Some(d) = temp_dir {
                let _ = std::fs::remove_dir_all(d);
            }
            return Err(ce(e));
        }
    };

    let remaining = rep
        .release
        .as_ref()
        .and_then(|u| remaining_secs(&u.expires_at, &u.now));
    Ok(OpenOut {
        root: rep.extract.root.display().to_string(),
        files: rep.extract.files,
        bytes: rep.extract.bytes,
        signer: rep.verify.as_ref().map(|v| v.signer.clone()),
        verified: rep.verify.is_some(),
        post_quantum: rep.verify.as_ref().map(|v| v.post_quantum),
        trusted_as: rep.verify.and_then(|v| v.trusted_as),
        first_unlock: rep.release.as_ref().map(|u| u.first_unlock.clone()),
        expires_at: rep.release.map(|u| u.expires_at),
        remaining_secs: remaining,
    })
}

#[tauri::command]
pub async fn open_package(app: AppHandle, req: OpenArgs) -> CmdResult<OpenOut> {
    blocking(move || {
        open_impl(
            &store(),
            req,
            Box::new(sealdrop_core::release::HttpFetch),
            &EmitProgress(app),
        )
    })
    .await
}

// ---------------------------------------------------------------------------------------
// trusted signers and settings
// ---------------------------------------------------------------------------------------

#[derive(Serialize)]
pub struct Trusted {
    pub name: String,
    pub key: String,
}

#[tauri::command]
pub fn list_trusted() -> CmdResult<Vec<Trusted>> {
    Ok(store()
        .trusted()
        .map_err(ce)?
        .into_iter()
        .map(|(name, pk)| Trusted {
            name,
            key: pk.to_base64(),
        })
        .collect())
}

#[tauri::command]
pub fn add_trusted(name: String, key: String) -> CmdResult<()> {
    store().add_trusted(&name, key.trim()).map_err(ce)
}

#[tauri::command]
pub fn remove_trusted(name: String) -> CmdResult<()> {
    store().remove_trusted(&name).map_err(ce)
}

#[tauri::command]
pub fn get_settings() -> CmdResult<Settings> {
    store().settings().map_err(ce)
}

fn normalize_settings(mut st: Settings) -> CmdResult<Settings> {
    use sealdrop_core::crypt::{SCRYPT_DEFAULT_LOG_N, SCRYPT_HIGH_LOG_N};
    if st.scrypt_log_n != SCRYPT_DEFAULT_LOG_N && st.scrypt_log_n != SCRYPT_HIGH_LOG_N {
        return Err(format!(
            "scrypt_log_n must be {SCRYPT_DEFAULT_LOG_N} (Standard) or {SCRYPT_HIGH_LOG_N} (High)"
        ));
    }
    st.release_service = st
        .release_service
        .map(|u| u.trim().to_string())
        .filter(|u| !u.is_empty());
    if let Some(u) = &st.release_service {
        sealdrop_core::release::validate_service_url(u).map_err(ce)?;
    }
    st.release_token = st
        .release_token
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty());
    Ok(st)
}

#[tauri::command]
pub fn set_settings(settings: Settings) -> CmdResult<()> {
    let st = normalize_settings(settings)?;
    store().save_settings(&st).map_err(ce)
}

// ---------------------------------------------------------------------------------------
// receipts
// ---------------------------------------------------------------------------------------

#[derive(Serialize, Debug, PartialEq, Eq)]
pub struct ReceiptOut {
    pub release_id: String,
    pub first_unlock: Option<String>,
    pub expires_at: Option<String>,
    pub remaining_secs: Option<i64>,
    pub unlock_count: u64,
    pub service_key: String,
    pub pinned: bool,
    pub saved_to: String,
}

fn receipt_out(r: sealdrop_core::release::Receipt, pinned: bool, saved_to: String) -> ReceiptOut {
    let remaining = r
        .expires_at
        .as_deref()
        .and_then(|e| remaining_secs(e, &r.now));
    ReceiptOut {
        release_id: r.release_id,
        first_unlock: r.first_unlock,
        expires_at: r.expires_at,
        remaining_secs: remaining,
        unlock_count: r.unlock_count,
        service_key: r.service_key,
        pinned,
        saved_to,
    }
}

#[tauri::command]
pub async fn receipt_fetch(manifest_path: String) -> CmdResult<ReceiptOut> {
    blocking(move || {
        use sealdrop_core::release::{fetch_receipt, verify_receipt_for};

        let ks = store();
        let manifest = abs(&manifest_path)?;
        let name = manifest
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let stem = name
            .strip_suffix(".manifest.json")
            .ok_or("expected a file named <name>.manifest.json")?;
        // Verify the manifest (signature, trusted signer, ciphertext hash) before the
        // deposit token goes to the service it names.
        let package = manifest.with_file_name(format!("{stem}.sealdrop.age"));
        let v = sealdrop_core::open::verify(&ks, &package, None).map_err(ce)?;
        let m = v.manifest;
        let r = m
            .release
            .as_ref()
            .ok_or("this package has no timed release")?;
        let token = release_token(&ks.settings().map_err(ce)?)?;
        let signed = fetch_receipt(&r.service, &token, &r.release_id).map_err(ce)?;
        // Pinned to the service key recorded at seal time; never trust-on-first-use.
        let rec = verify_receipt_for(&signed, &r.service_key, &r.release_id, &m.ciphertext.sha256)
            .map_err(ce)?;
        let out = manifest.with_file_name(format!("{stem}.receipt.json"));
        std::fs::write(&out, serde_json::to_vec_pretty(&signed).map_err(s)?).map_err(s)?;
        Ok(receipt_out(rec, true, out.display().to_string()))
    })
    .await
}

fn receipt_verify_impl(receipt_path: &Path, service_key: Option<&str>) -> CmdResult<ReceiptOut> {
    let signed: sealdrop_core::release::SignedReceipt =
        serde_json::from_slice(&read_small(receipt_path)?)
            .map_err(|e| format!("not a receipt file: {e}"))?;
    let r = sealdrop_core::release::verify_receipt(&signed, service_key).map_err(ce)?;
    Ok(receipt_out(r, service_key.is_some(), String::new()))
}

#[tauri::command]
pub async fn receipt_verify(
    receipt_path: String,
    service_key: Option<String>,
) -> CmdResult<ReceiptOut> {
    let key = service_key
        .map(|k| k.trim().to_string())
        .filter(|k| !k.is_empty());
    blocking(move || receipt_verify_impl(&abs(&receipt_path)?, key.as_deref())).await
}

// ---------------------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sealdrop_core::progress::NoProgress;
    use sealdrop_core::release::{
        sign_receipt, Deposit, MemoryFetch, Receipt, ReleaseFetch, Unlock,
    };

    fn fast_store(dir: &Path) -> KeyStore {
        let ks = KeyStore::open(dir);
        ks.generate(false, sealdrop_core::keys::IdentityKind::X25519)
            .unwrap();
        // Tests only: a cheap scrypt cost. The commands themselves accept 18 or 20.
        ks.save_settings(&Settings {
            scrypt_log_n: 10,
            ..Settings::default()
        })
        .unwrap();
        ks
    }

    fn seal_args(input: &Path, out: &Path) -> SealArgs {
        SealArgs {
            input: input.display().to_string(),
            out_dir: out.display().to_string(),
            recipients: vec![],
            passphrase: true,
            words: "eff".into(),
            argon2id: false,
            kdf_profile: "default".into(),
            armor: false,
            classification: None,
            expires: None,
            allow_unrecoverable: false,
            include_self: true,
            expire_after_secs: None,
        }
    }

    fn open_args(package: &str, out: Option<&Path>, temp: bool, pass: Option<&str>) -> OpenArgs {
        OpenArgs {
            package: package.into(),
            out_dir: out.map(|o| o.display().to_string()),
            temp,
            passphrase: pass.map(|p| Zeroizing::new(p.to_string())),
            signer: None,
            skip_verify: false,
            overwrite: false,
        }
    }

    #[test]
    fn remaining_secs_is_expiry_minus_service_now() {
        assert_eq!(
            remaining_secs("2026-10-13T09:10:00Z", "2026-10-13T09:00:00Z"),
            Some(600)
        );
        assert_eq!(
            remaining_secs("2026-10-13T09:10:00Z", "2026-10-13T09:09:59Z"),
            Some(1)
        );
        // Offsets are honoured, not read as local time.
        assert_eq!(
            remaining_secs("2026-10-13T11:10:00+02:00", "2026-10-13T09:00:00Z"),
            Some(600)
        );
    }

    #[test]
    fn remaining_secs_clamps_at_zero_and_rejects_garbage() {
        assert_eq!(
            remaining_secs("2026-10-13T09:10:00Z", "2026-10-13T09:10:00Z"),
            Some(0)
        );
        assert_eq!(
            remaining_secs("2026-10-13T09:10:00Z", "2026-10-13T10:00:00Z"),
            Some(0)
        );
        assert_eq!(remaining_secs("2026-10-13T09:10:00Z", ""), None);
        assert_eq!(remaining_secs("soon", "2026-10-13T09:10:00Z"), None);
    }

    #[test]
    fn untrusted_message_detection() {
        assert!(is_untrusted_msg(
            "signer RWQabc is not trusted; add it with `sealdrop trust add <name> RWQabc` or pass --signer"
        ));
        assert!(!is_untrusted_msg(
            "ciphertext hash does not match the signed manifest"
        ));
        assert!(!is_untrusted_msg(
            "manifest signer X does not match --signer"
        ));
    }

    #[test]
    fn recipient_check_maps_pq_kind() {
        let s = sealdrop_core::pq::Identity::generate()
            .to_public()
            .to_string();
        let c = recipient_check(&s).unwrap();
        assert_eq!(c.kind, "pq");
        assert_eq!(c.plugin, None);
        assert!(c.allowed);
    }

    #[test]
    fn generate_identity_kinds_and_pq_status() {
        let dir = tempfile::tempdir().unwrap();
        let ks = KeyStore::open(dir.path());
        ks.generate(false, sealdrop_core::keys::IdentityKind::Pq)
            .unwrap();
        let info = identity_info(&ks);
        assert_eq!(info.kind.as_deref(), Some("pq"));
        assert!(info.recipient.unwrap().starts_with("age1pq1"));

        let empty = tempfile::tempdir().unwrap();
        assert_eq!(identity_info(&KeyStore::open(empty.path())).kind, None);
        let x = fast_store(&empty.path().join("x"));
        assert_eq!(identity_info(&x).kind.as_deref(), Some("x25519"));
    }

    #[test]
    fn recipient_check_maps_kind_plugin_and_allowed() {
        let id = age::x25519::Identity::generate().to_public().to_string();
        let c = recipient_check(&id).unwrap();
        assert_eq!(c.kind, "x25519");
        assert_eq!(c.plugin, None);
        assert!(c.allowed);
        assert_eq!(c.fingerprint.len(), 16);

        let plugin = |name: &str| {
            bech32::encode::<bech32::Bech32>(
                bech32::Hrp::parse(&format!("age1{name}")).unwrap(),
                &[1u8; 32],
            )
            .unwrap()
        };
        let c = recipient_check(&plugin("yubikey")).unwrap();
        assert_eq!(c.kind, "plugin:yubikey");
        assert_eq!(c.plugin.as_deref(), Some("yubikey"));
        assert!(c.allowed);

        let c = recipient_check(&plugin("evilplugin")).unwrap();
        assert_eq!(c.plugin.as_deref(), Some("evilplugin"));
        assert!(!c.allowed);

        assert!(recipient_check("age1notvalid").is_err());
        assert!(recipient_check("hello").is_err());
    }

    #[test]
    fn progress_kinds_match_the_contract() {
        let kinds: Vec<_> = [
            ProgressEvent::Packing { path: "p".into() },
            ProgressEvent::Encrypted { bytes: 7 },
            ProgressEvent::Contacting {
                service: "h".into(),
            },
            ProgressEvent::Verifying,
            ProgressEvent::Extracting { path: "x".into() },
            ProgressEvent::Done,
        ]
        .into_iter()
        .map(progress_parts)
        .collect();
        assert_eq!(
            kinds.iter().map(|k| k.0).collect::<Vec<_>>(),
            [
                "packing",
                "encrypted",
                "contacting",
                "verifying",
                "extracting",
                "done"
            ]
        );
        assert_eq!(kinds[1].1, "7");
        assert_eq!(
            progress_parts(ProgressEvent::Contacting {
                service: "https://r\u{1b}[2J.example".into()
            })
            .1,
            "https://r?[2J.example"
        );
        // Manifest service URLs reach the WebView sanitized too.
        let r = release_out(sealdrop_core::manifest::ReleaseInfo {
            service: "https://r.example\u{202E}lmth.exe\u{7}".into(),
            release_id: "id".into(),
            window_secs: 60,
            service_key: String::new(),
        });
        assert_eq!(r.service, "https://r.example?lmth.exe?");
    }

    #[test]
    fn settings_validation() {
        let ok = normalize_settings(Settings {
            release_service: Some("  https://r.example/ ".into()),
            release_token: Some(" ".into()),
            scrypt_log_n: 20,
            armor: true,
            argon2id: false,
        })
        .unwrap();
        assert_eq!(ok.release_service.as_deref(), Some("https://r.example/"));
        assert_eq!(ok.release_token, None);
        assert!(normalize_settings(Settings {
            scrypt_log_n: 19,
            ..Settings::default()
        })
        .is_err());
        assert!(normalize_settings(Settings {
            release_service: Some("http://evil.example".into()),
            ..Settings::default()
        })
        .is_err());
        // Empty service string means "unset".
        let unset = normalize_settings(Settings {
            release_service: Some("".into()),
            ..Settings::default()
        })
        .unwrap();
        assert_eq!(unset.release_service, None);
    }

    #[test]
    fn seal_verify_untrusted_then_trusted_then_open() {
        let d = tempfile::tempdir().unwrap();
        let sender = fast_store(&d.path().join("sender"));
        let receiver = KeyStore::open(d.path().join("receiver")); // no identity at all
        let input = d.path().join("report");
        std::fs::create_dir_all(&input).unwrap();
        std::fs::write(input.join("a.txt"), b"hello").unwrap();
        let out = d.path().join("out");

        let sealed = seal_impl(&sender, seal_args(&input, &out), &NoProgress).unwrap();
        assert_eq!(sealed.files, 1);
        assert_eq!(sealed.bytes, 5);
        assert!(sealed.release.is_none());
        assert!(!sealed.post_quantum);
        assert_eq!(sealed.self_omitted, None);
        let pass = sealed.passphrase.clone().expect("passphrase mode");
        assert!(sealed.entropy_bits.unwrap() > 70.0);

        // Receiver does not trust the sender yet.
        let v = verify_impl(&receiver, Path::new(&sealed.package), None).unwrap();
        assert!(!v.ok);
        assert_eq!(
            v.untrusted_signer.as_deref(),
            Some(sender.signing_public_string().unwrap().as_str())
        );
        assert_eq!(v.package_id, None);
        assert_eq!(v.post_quantum, None);

        // Passing the expected key verifies without trusting.
        let key = sender.signing_public_string().unwrap();
        let v = verify_impl(&receiver, Path::new(&sealed.package), Some(&key)).unwrap();
        assert!(v.ok);
        assert_eq!(v.untrusted_signer, None);
        assert_eq!(v.trusted_as, None);

        receiver.add_trusted("alice", &key).unwrap();
        let v = verify_impl(&receiver, Path::new(&sealed.package), None).unwrap();
        assert!(v.ok);
        assert_eq!(v.trusted_as.as_deref(), Some("alice"));
        assert_eq!(v.package_id.as_deref(), Some(sealed.package_id.as_str()));
        assert_eq!(
            v.ciphertext_sha256.as_deref(),
            Some(sealed.ciphertext_sha256.as_str())
        );
        assert_eq!(v.recipients.as_ref().unwrap().len(), 1);
        assert_eq!(v.post_quantum, Some(false));

        // Open to a chosen folder.
        let dest = d.path().join("dest");
        let rep = open_impl(
            &receiver,
            open_args(&sealed.package, Some(&dest), false, Some(&pass)),
            Box::new(MemoryFetch::expired()),
            &NoProgress,
        )
        .unwrap();
        assert!(rep.verified);
        assert_eq!(rep.trusted_as.as_deref(), Some("alice"));
        assert_eq!(rep.files, 1);
        assert_eq!(rep.remaining_secs, None);
        assert_eq!(rep.post_quantum, Some(false));
        assert_eq!(
            std::fs::read(Path::new(&rep.root).join("a.txt")).unwrap(),
            b"hello"
        );

        // Wrong passphrase fails and a temporary open leaves nothing behind.
        let bad = open_impl(
            &receiver,
            open_args(&sealed.package, None, true, Some("wrong wrong wrong")),
            Box::new(MemoryFetch::expired()),
            &NoProgress,
        );
        assert!(bad.is_err());
        let root = view_root().expect("a temporary open created the root");
        let leftovers = std::fs::read_dir(&root).map(|d| d.count()).unwrap_or(0);
        assert_eq!(leftovers, 0, "a failed temporary open must not leave files");

        // Skip verification: `verified` is false and no signer is reported.
        let mut args = open_args(&sealed.package, None, true, Some(&pass));
        args.skip_verify = true;
        let rep = open_impl(&sender, args, Box::new(MemoryFetch::expired()), &NoProgress).unwrap();
        assert!(!rep.verified);
        assert_eq!(rep.signer, None);
        assert_eq!(rep.post_quantum, None);
        assert!(Path::new(&rep.root).starts_with(&root));
        assert_eq!(
            std::fs::read(Path::new(&rep.root).join("a.txt")).unwrap(),
            b"hello"
        );
        remove_view_dir();
        assert!(view_root().is_none());
        assert!(!root.exists());
    }

    #[test]
    fn pq_package_reports_post_quantum_and_self_omitted() {
        let d = tempfile::tempdir().unwrap();
        let input = d.path().join("report");
        std::fs::create_dir_all(&input).unwrap();
        std::fs::write(input.join("a.txt"), b"hello").unwrap();

        // A post-quantum sender sealing to itself: every recipient is post-quantum.
        let pq = KeyStore::open(d.path().join("pq"));
        pq.generate(false, sealdrop_core::keys::IdentityKind::Pq)
            .unwrap();
        let mut args = seal_args(&input, &d.path().join("out-pq"));
        args.passphrase = false;
        args.recipients = vec![pq.recipient_string().unwrap()];
        let sealed = seal_impl(&pq, args, &NoProgress).unwrap();
        assert!(sealed.post_quantum);
        assert_eq!(sealed.self_omitted, None);

        let key = pq.signing_public_string().unwrap();
        let v = verify_impl(&pq, Path::new(&sealed.package), Some(&key)).unwrap();
        assert!(v.ok);
        assert_eq!(v.post_quantum, Some(true));
        assert_eq!(v.recipients.as_ref().unwrap()[0].kind, "pq");

        let mut oargs = open_args(&sealed.package, Some(&d.path().join("dest")), false, None);
        oargs.signer = Some(key);
        let rep = open_impl(&pq, oargs, Box::new(MemoryFetch::expired()), &NoProgress).unwrap();
        assert!(rep.verified);
        assert_eq!(rep.post_quantum, Some(true));

        // A classical sender sealing to a post-quantum recipient is left out, with a note.
        let classical = fast_store(&d.path().join("classical"));
        let mut args = seal_args(&input, &d.path().join("out-mixed"));
        args.passphrase = false;
        args.recipients = vec![pq.recipient_string().unwrap()];
        let sealed = seal_impl(&classical, args, &NoProgress).unwrap();
        assert!(sealed.post_quantum);
        assert!(sealed.self_omitted.unwrap().contains("classical"));
    }

    #[test]
    fn tampered_package_is_an_error_not_untrusted() {
        let d = tempfile::tempdir().unwrap();
        let sender = fast_store(&d.path().join("sender"));
        let input = d.path().join("f.txt");
        std::fs::write(&input, b"x").unwrap();
        let sealed =
            seal_impl(&sender, seal_args(&input, &d.path().join("o")), &NoProgress).unwrap();
        let mut bytes = std::fs::read(&sealed.package).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        std::fs::write(&sealed.package, bytes).unwrap();
        let err = verify_impl(&sender, Path::new(&sealed.package), None).unwrap_err();
        assert!(err.contains("ciphertext hash"), "{err}");
    }

    #[test]
    fn untrusted_signer_requires_the_failure_to_name_the_manifest_signer() {
        let d = tempfile::tempdir().unwrap();
        let sender = fast_store(&d.path().join("sender"));
        let input = d.path().join("f.txt");
        std::fs::write(&input, b"x").unwrap();
        let sealed =
            seal_impl(&sender, seal_args(&input, &d.path().join("o")), &NoProgress).unwrap();
        let pkg = Path::new(&sealed.package);
        let key = sender.signing_public_string().unwrap();
        assert_eq!(
            untrusted_signer(pkg, &format!("signer {key} is not trusted; add it")),
            Some(key.clone())
        );
        assert_eq!(
            untrusted_signer(pkg, "signer SOMEONEELSE is not trusted"),
            None
        );
        assert_eq!(
            untrusted_signer(Path::new("/nope/x.sealdrop.age"), "x"),
            None
        );
    }

    #[test]
    fn seal_rejects_bad_combinations() {
        let d = tempfile::tempdir().unwrap();
        let ks = fast_store(&d.path().join("ks"));
        let input = d.path().join("f.txt");
        std::fs::write(&input, b"x").unwrap();
        let out = d.path().join("o");
        let me = ks.recipient_string().unwrap();

        let mut a = seal_args(&input, &out);
        a.recipients = vec![me.clone()];
        assert!(seal_impl(&ks, a, &NoProgress).is_err()); // passphrase + recipients

        let mut a = seal_args(&input, &out);
        a.passphrase = false;
        assert!(seal_impl(&ks, a, &NoProgress).is_err()); // neither

        let mut a = seal_args(&input, &out);
        a.words = "klingon".into();
        assert!(seal_impl(&ks, a, &NoProgress).is_err());

        // Timed release without settings points the user at Settings.
        let mut a = seal_args(&input, &out);
        a.expire_after_secs = Some(600);
        let e = seal_impl(&ks, a, &NoProgress).err().unwrap();
        assert!(e.contains("Settings"), "{e}");

        // Recipient mode works and has no passphrase.
        let mut a = seal_args(&input, &out);
        a.passphrase = false;
        a.recipients = vec![me];
        let ok = seal_impl(&ks, a, &NoProgress).unwrap();
        assert!(ok.passphrase.is_none() && ok.entropy_bits.is_none());
    }

    #[test]
    fn receipt_verify_reports_pinned_and_remaining() {
        let d = tempfile::tempdir().unwrap();
        let kp = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
        let rec = Receipt {
            release_id: "r1".into(),
            package_sha256: "ab".into(),
            first_unlock: Some("2026-10-13T09:00:00Z".into()),
            expires_at: Some("2026-10-13T09:10:00Z".into()),
            unlock_count: 2,
            service_key: kp.pk.to_base64(),
            now: "2026-10-13T09:04:00Z".into(),
        };
        let signed = sign_receipt(&rec, &kp.sk, &kp.pk).unwrap();
        let path = d.path().join("x.receipt.json");
        std::fs::write(&path, serde_json::to_vec_pretty(&signed).unwrap()).unwrap();

        let unpinned = receipt_verify_impl(&path, None).unwrap();
        assert!(!unpinned.pinned);
        assert_eq!(unpinned.remaining_secs, Some(360));
        assert_eq!(unpinned.saved_to, "");
        assert_eq!(unpinned.unlock_count, 2);

        let pinned = receipt_verify_impl(&path, Some(&kp.pk.to_base64())).unwrap();
        assert!(pinned.pinned);

        let other = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
        assert!(receipt_verify_impl(&path, Some(&other.pk.to_base64())).is_err());

        // A receipt that never opened has no expiry, so no countdown.
        let mut unopened = rec.clone();
        unopened.first_unlock = None;
        unopened.expires_at = None;
        assert_eq!(
            receipt_out(unopened, true, String::new()).remaining_secs,
            None
        );

        // Not a receipt at all.
        let junk = d.path().join("junk.json");
        std::fs::write(&junk, b"{}").unwrap();
        assert!(receipt_verify_impl(&junk, None).is_err());
    }

    #[test]
    fn open_reports_remaining_secs_from_the_service_clock() {
        // A fetch double whose clock sample is 4 minutes into a 10 minute window.
        struct Fixed(MemoryFetch);
        impl ReleaseFetch for Fixed {
            fn unlock(
                &self,
                service: &str,
                release_id: &str,
                token: &str,
            ) -> sealdrop_core::Result<Unlock> {
                let mut u = self.0.unlock(service, release_id, token)?;
                u.now = "2026-10-13T09:04:00Z".into();
                Ok(u)
            }
        }
        // The timed seal needs a live service (covered by the CLI e2e); here only the
        // arithmetic path through `Unlock` is exercised.
        let d = Deposit::new(600);
        let u = Fixed(MemoryFetch::serving(&d))
            .unlock("memory://x", "id", &d.unlock_token_b64())
            .unwrap();
        assert_eq!(remaining_secs(&u.expires_at, &u.now), Some(360));
    }

    /// Writes a timed-release package whose inner key is scrypt, plus an (unsigned) manifest
    /// beside it that records that, as `seal` would. Returns the package path.
    fn timed_scrypt_package(dir: &Path) -> PathBuf {
        use sealdrop_core::manifest::{CiphertextInfo, Manifest, RecipientInfo, ReleaseInfo};
        use sealdrop_core::release::{Deposit, Recipient as ReleaseRecipient};
        use std::io::Write;
        let d = Deposit::new(600);
        let inner: Vec<Box<dyn age::Recipient + Send>> = vec![Box::new(
            sealdrop_core::crypt::scrypt_recipient(SecretString::from("pass words"), 10).unwrap(),
        )];
        let service = "https://release.example";
        let recipients: Vec<Box<dyn age::Recipient + Send>> =
            vec![Box::new(ReleaseRecipient::new(inner, &d, service))];
        let package = dir.join("t.sealdrop.age");
        let f = std::fs::File::create(&package).unwrap();
        let mut w = sealdrop_core::crypt::encrypt_writer(f, &recipients, false).unwrap();
        w.write_all(b"not a tar; never decrypted here").unwrap();
        w.finish().unwrap();
        let m = Manifest {
            format: sealdrop_core::manifest::MANIFEST_FORMAT.into(),
            package_id: "11111111-2222-3333-4444-555555555555".into(),
            tool: "test".into(),
            created: "2026-10-13T09:00:00Z".into(),
            ciphertext: CiphertextInfo {
                file: "t.sealdrop.age".into(),
                size: 0,
                sha256: String::new(),
            },
            plaintext_tar_sha256: String::new(),
            key_commitment: None,
            recipients: vec![RecipientInfo {
                kind: "scrypt".into(),
                fingerprint: String::new(),
            }],
            signer: String::new(),
            classification: None,
            expires: None,
            release: Some(ReleaseInfo {
                service: service.into(),
                release_id: d.release_id.clone(),
                window_secs: 600,
                service_key: String::new(),
            }),
            notes: String::new(),
        };
        let (mpath, _) = sealdrop_core::seal::bundle_paths(&package);
        std::fs::write(mpath, m.to_json().unwrap()).unwrap();
        package
    }

    #[test]
    fn timed_passphrase_package_shows_the_field_and_never_unlocks_without_it() {
        struct NoNetwork;
        impl sealdrop_core::release::ReleaseFetch for NoNetwork {
            fn unlock(&self, _: &str, _: &str, _: &str) -> sealdrop_core::Result<Unlock> {
                panic!("the release service must not be contacted");
            }
        }
        let d = tempfile::tempdir().unwrap();
        let package = timed_scrypt_package(d.path());
        let p = probe_impl(&package).unwrap();
        assert!(p.timed_release.is_some());
        assert_eq!(p.inner_kind.as_deref(), Some("scrypt"));
        assert!(p.needs_passphrase, "the Open screen must ask for it");

        // Opening without a passphrase is refused by the core before any network call.
        let ks = KeyStore::open(d.path().join("ks"));
        ks.generate(false, sealdrop_core::keys::IdentityKind::X25519)
            .unwrap();
        let mut req = open_args(
            &package.display().to_string(),
            Some(&d.path().join("out")),
            false,
            None,
        );
        req.skip_verify = true;
        let err = open_impl(&ks, req, Box::new(NoNetwork), &NoProgress).unwrap_err();
        assert!(err.contains("needs a passphrase"), "{err}");
        assert!(!d.path().join("out").exists());

        // Without the manifest beside it nothing says which key is inside: the probe reports
        // timed with no inner kind, and the Open screen offers an optional passphrase field.
        let (mpath, _) = sealdrop_core::seal::bundle_paths(&package);
        std::fs::remove_file(mpath).unwrap();
        let p = probe_impl(&package).unwrap();
        assert!(p.timed_release.is_some());
        assert_eq!(p.inner_kind, None);
        assert!(!p.needs_passphrase);
    }

    #[test]
    fn view_root_is_random_and_new_dirs_refuse_existing_paths() {
        let a = fresh_root().unwrap();
        let b = fresh_root().unwrap();
        assert_ne!(a.path(), b.path());
        assert!(a
            .path()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("sealdrop-view-"));
        // Neither the old predictable name nor a shared pid-derived name.
        assert_ne!(
            a.path(),
            std::env::temp_dir().join(format!("sealdrop-view-{}", std::process::id()))
        );
        let sub = a.path().join("0");
        make_private_dir(&sub).unwrap();
        assert!(
            make_private_dir(&sub).is_err(),
            "an existing path must be refused"
        );
        assert!(
            make_private_dir(&a.path().join("x").join("y")).is_err(),
            "no recursive creation"
        );
    }

    #[test]
    fn relative_paths_are_refused() {
        assert!(abs("report").is_err());
        assert!(abs("./report").is_err());
        assert_eq!(abs("report").unwrap_err(), "path must be absolute");
        let d = tempfile::tempdir().unwrap();
        assert!(abs(&d.path().display().to_string()).is_ok());

        let ks = fast_store(&d.path().join("ks"));
        let mut a = seal_args(&d.path().join("f.txt"), &d.path().join("o"));
        a.input = "f.txt".into();
        assert_eq!(
            seal_impl(&ks, a, &NoProgress).err().unwrap(),
            "path must be absolute"
        );
        let mut a = seal_args(d.path(), &d.path().join("o"));
        a.out_dir = "o".into();
        assert_eq!(
            seal_impl(&ks, a, &NoProgress).err().unwrap(),
            "path must be absolute"
        );
        let args = open_args("pkg.sealdrop.age", Some(d.path()), false, None);
        let e = open_impl(&ks, args, Box::new(MemoryFetch::expired()), &NoProgress)
            .err()
            .unwrap();
        assert_eq!(e, "path must be absolute");
    }

    #[test]
    fn cli_hint_is_stripped_from_untrusted_errors() {
        let msg = "verification failed: signer RWQabc is not trusted; add it with `sealdrop trust add <name> RWQabc` or pass --signer".to_string();
        assert_eq!(
            strip_cli_hint(msg),
            "verification failed: signer RWQabc is not trusted"
        );
        assert_eq!(strip_cli_hint("other failure".into()), "other failure");
        let e = Error::Verify(
            "signer K is not trusted; add it with `sealdrop trust add <name> K` or pass --signer"
                .into(),
        );
        assert!(!err_msg(&e).contains("sealdrop trust add"));
    }
}
