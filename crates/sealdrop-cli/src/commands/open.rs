use std::io::BufRead;
use std::path::PathBuf;

use age::secrecy::SecretString;
use clap::Args as ClapArgs;
use sealdrop_core::open::{open, OpenRequest};
use sealdrop_core::release::HttpFetch;
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
    if let Some(r) = &p.release {
        println!(
            "This package uses timed release via {} (release {}).",
            r.service, r.release_id
        );
        println!("Opening it starts or continues the window on the service's clock.");
    }
    let passphrase = if a.passphrase_stdin {
        Some(read_line_secret()?)
    } else if p.needs_passphrase {
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
    if let Some(v) = &rep.verify {
        println!(
            "verified: signer {}{}",
            v.signer,
            v.trusted_as
                .as_ref()
                .map(|n| format!(" ({n})"))
                .unwrap_or_default()
        );
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
    Ok(SecretString::from(
        line.trim_end_matches(['\r', '\n']).to_string(),
    ))
}
