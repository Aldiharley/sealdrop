use std::io::BufRead;
use std::path::PathBuf;

use age::secrecy::SecretString;
use clap::Args as ClapArgs;
use sealdrop_core::open::{open, OpenRequest};
use sealdrop_core::release::{self, HttpFetch};
use sealdrop_core::Error;
use zeroize::Zeroizing;

use super::{key_display, sanitize};

#[derive(ClapArgs)]
pub struct Args {
    /// The .sealdrop.age package (its .manifest.json and .minisig must sit beside it)
    pub package: PathBuf,
    /// Folder to restore into (created if missing)
    #[arg(short = 'o', long, default_value = ".")]
    pub out: PathBuf,
    /// Expected signer key (base64 minisign public key), for a signer you have not trusted
    #[arg(long)]
    pub signer: Option<String>,
    /// Skip signature and hash verification (decryption still authenticates the data)
    #[arg(long)]
    pub skip_verify: bool,
    /// Replace files that already exist in the output folder
    #[arg(long)]
    pub overwrite: bool,
    /// Read the passphrase from the first line of stdin instead of the hidden prompt
    #[arg(long)]
    pub passphrase_stdin: bool,
}

pub fn run(a: Args) -> anyhow::Result<()> {
    let ks = crate::store();
    let p = sealdrop_core::probe::probe(&a.package)?;
    // Kind of the key inside a timed package (its header cannot show a passphrase stanza):
    // from the verified manifest, or under --skip-verify from the unverified one, which only
    // decides whether to prompt; the core makes the same check before any network call.
    let mut inner_kind: Option<String> = None;
    if let Some(h) = &p.release {
        if a.skip_verify {
            inner_kind = sealdrop_core::open::unverified_inner_kind(&a.package);
            // Nothing in the header is signed, so never echo it raw: print only values that
            // pass the same validation the network code applies.
            let service = release::validate_service_url(&h.service)
                .unwrap_or_else(|_| "<invalid service URL>".into());
            let id = match release::validate_release_id(&h.release_id) {
                Ok(()) => format!(" (release {})", h.release_id),
                Err(_) => String::new(),
            };
            out!(
                "This package claims timed release via {service}{id} (unverified header; window unknown)."
            );
        } else {
            // Verify first (the manifest is signed, the header is not) so the window and
            // service shown are the sender's. `open` verifies again below: the file is hashed twice.
            let v = sealdrop_core::open::verify(&ks, &a.package, a.signer.as_deref())?;
            let r = v.manifest.release.as_ref().ok_or_else(|| {
                Error::Verify(
                    "the package asks for timed release but the signed manifest does not".into(),
                )
            })?;
            if r.service != h.service || r.release_id != h.release_id {
                return Err(Error::Verify(
                    "the package's timed-release service does not match the signed manifest".into(),
                )
                .into());
            }
            inner_kind = v.manifest.recipients.first().map(|r| r.kind.clone());
            out!(
                "This package uses timed release: {} after first open, enforced by {}",
                super::human(r.window_secs),
                sanitize(&r.service)
            );
        }
        out!("Opening it starts or continues the window on the service's clock.");
    }
    let prompt = if p.needs_passphrase {
        Prompt::Required
    } else {
        needs_prompt(
            p.release.is_some(),
            inner_kind.as_deref(),
            ks.has_identity(),
        )
    };
    let passphrase = if a.passphrase_stdin {
        Some(read_line_secret()?)
    } else {
        match prompt {
            Prompt::Required => Some(read_secret_prompt("passphrase: ")?),
            Prompt::Optional => {
                read_secret_prompt_optional("Passphrase (leave empty to use your key): ")?
            }
            Prompt::None => None,
        }
    };
    let rep = open(
        &ks,
        OpenRequest {
            package: a.package,
            out_dir: a.out,
            signer: a.signer,
            skip_verify: a.skip_verify,
            overwrite: a.overwrite,
            passphrase,
            limits: Default::default(),
        },
        Box::new(HttpFetch),
        &super::StderrProgress,
    )?;
    out!(
        "restored: {} ({} files, {} bytes)",
        sanitize(&rep.extract.root.display().to_string()),
        rep.extract.files,
        rep.extract.bytes
    );
    match &rep.verify {
        Some(v) => {
            out!(
                "verified: signer {}{}",
                key_display(&v.signer),
                v.trusted_as
                    .as_ref()
                    .map(|n| format!(" ({})", sanitize(n)))
                    .unwrap_or_default()
            );
            out!(
                "post-quantum: {}",
                if v.post_quantum { "yes" } else { "no" }
            );
        }
        None => out!("signature NOT verified (--skip-verify)"),
    }
    if let Some(u) = &rep.release {
        out!(
            "first opened {} - expires {} (service clock)",
            sanitize(&u.first_unlock),
            sanitize(&u.expires_at)
        );
        out!("Expiry applies to the encrypted package only; nothing can recall a file after it has been decrypted.");
    }
    Ok(())
}

/// Whether `open` asks for a passphrase.
#[derive(Debug, PartialEq, Eq)]
pub enum Prompt {
    /// The package needs one: ask, and refuse an empty answer.
    Required,
    /// It may need one: ask, and an empty answer means "use my key".
    Optional,
    None,
}

/// The prompt for a package whose header shows no passphrase stanza. `inner_kind` is the
/// manifest's `recipients[0].kind` (verified, or unverified under `--skip-verify`), `None`
/// when there is no manifest to read. Only a timed package can hide a passphrase stanza
/// (inside its release stanza); without a manifest nothing says which key is inside, so the
/// prompt is optional, or required when there is no identity to fall back on.
pub fn needs_prompt(timed: bool, inner_kind: Option<&str>, has_identity: bool) -> Prompt {
    if !timed {
        return Prompt::None;
    }
    match inner_kind {
        Some(k) if sealdrop_core::open::is_passphrase_kind(k) => Prompt::Required,
        Some(_) => Prompt::None,
        None if has_identity => Prompt::Optional,
        None => Prompt::Required,
    }
}

/// Reads a passphrase without echo when stdin is a terminal; otherwise reads one line and
/// says that the input was not hidden.
fn read_secret_prompt(prompt: &str) -> anyhow::Result<SecretString> {
    if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        let s = Zeroizing::new(rpassword::prompt_password(prompt)?);
        anyhow::ensure!(!s.trim().is_empty(), "empty passphrase");
        return Ok(SecretString::from(s.trim().to_string()));
    }
    eprint!("{prompt}(input is not a terminal, so it is read as a line) ");
    read_line_secret()
}

/// Like `read_secret_prompt`, but an empty answer means "none".
fn read_secret_prompt_optional(prompt: &str) -> anyhow::Result<Option<SecretString>> {
    if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        let s = Zeroizing::new(rpassword::prompt_password(prompt)?);
        let t = s.trim();
        return Ok((!t.is_empty()).then(|| SecretString::from(t.to_string())));
    }
    eprint!("{prompt}(input is not a terminal, so it is read as a line) ");
    read_line_optional()
}

/// Reads one line from stdin; an empty line (or end of input) is `None`.
fn read_line_optional() -> anyhow::Result<Option<SecretString>> {
    let mut line = Zeroizing::new(String::new());
    std::io::stdin().lock().read_line(&mut line)?;
    let pass = line.trim_end_matches(['\r', '\n']);
    Ok((!pass.is_empty()).then(|| SecretString::from(pass.to_string())))
}

/// Reads one line from stdin without keeping a plain copy of it around.
fn read_line_secret() -> anyhow::Result<SecretString> {
    let mut line = Zeroizing::new(String::new());
    std::io::stdin().lock().read_line(&mut line)?;
    let pass = line.trim_end_matches(['\r', '\n']);
    anyhow::ensure!(!pass.is_empty(), "no passphrase on stdin");
    Ok(SecretString::from(pass.to_string()))
}

#[cfg(test)]
mod tests {
    use super::{needs_prompt, Prompt};

    #[test]
    fn prompt_decision() {
        // Not timed: the header shows any passphrase stanza; nothing to add.
        assert_eq!(needs_prompt(false, None, true), Prompt::None);
        assert_eq!(needs_prompt(false, Some("scrypt"), true), Prompt::None);
        // Timed, manifest says passphrase: required, identity or not.
        for kind in ["scrypt", "argon2id"] {
            assert_eq!(needs_prompt(true, Some(kind), true), Prompt::Required);
            assert_eq!(needs_prompt(true, Some(kind), false), Prompt::Required);
        }
        // Timed, manifest says a key: no prompt.
        assert_eq!(needs_prompt(true, Some("x25519"), true), Prompt::None);
        // Timed, no manifest: optional with an identity to fall back on, else required.
        assert_eq!(needs_prompt(true, None, true), Prompt::Optional);
        assert_eq!(needs_prompt(true, None, false), Prompt::Required);
    }
}
