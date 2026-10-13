use std::io::BufRead;
use std::path::PathBuf;

use age::secrecy::SecretString;
use clap::Args as ClapArgs;
use sealdrop_core::open::{open, OpenRequest};
use sealdrop_core::release::{self, HttpFetch};
use sealdrop_core::Error;
use zeroize::Zeroizing;

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
    /// Read the passphrase from the first line of stdin instead of prompting
    /// (the interactive prompt shows what you type; use --passphrase-stdin to pipe it)
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
            println!(
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
            println!(
                "This package uses timed release: {} after first open, enforced by {}",
                super::human(r.window_secs),
                r.service
            );
        }
        println!("Opening it starts or continues the window on the service's clock.");
    }
    let passphrase = if a.passphrase_stdin {
        Some(read_line_secret()?)
    } else if p.needs_passphrase
        || inner_kind
            .as_deref()
            .is_some_and(sealdrop_core::open::is_passphrase_kind)
    {
        eprint!("passphrase (typing is shown; use --passphrase-stdin to pipe it): ");
        Some(read_line_secret()?)
    } else {
        None
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
    println!(
        "restored: {} ({} files, {} bytes)",
        rep.extract.root.display(),
        rep.extract.files,
        rep.extract.bytes
    );
    match &rep.verify {
        Some(v) => println!(
            "verified: signer {}{}",
            v.signer,
            v.trusted_as
                .as_ref()
                .map(|n| format!(" ({n})"))
                .unwrap_or_default()
        ),
        None => println!("signature NOT verified (--skip-verify)"),
    }
    if let Some(u) = &rep.release {
        println!(
            "first opened {} - expires {} (service clock)",
            u.first_unlock, u.expires_at
        );
        println!("Expiry applies to the encrypted package only; nothing can recall a file after it has been decrypted.");
    }
    Ok(())
}

/// Reads one line from stdin without keeping a plain copy of it around.
fn read_line_secret() -> anyhow::Result<SecretString> {
    let mut line = Zeroizing::new(String::new());
    std::io::stdin().lock().read_line(&mut line)?;
    let pass = line.trim_end_matches(['\r', '\n']);
    anyhow::ensure!(!pass.is_empty(), "no passphrase on stdin");
    Ok(SecretString::from(pass.to_string()))
}
