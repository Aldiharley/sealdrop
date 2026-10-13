use std::path::PathBuf;

use clap::Args as ClapArgs;

use super::{key_display, sanitize};

#[derive(ClapArgs)]
pub struct Args {
    /// The .sealdrop.age package (its .manifest.json and .minisig must sit beside it)
    pub package: PathBuf,
    /// Expected signer key (base64 minisign public key), for a signer you have not trusted
    #[arg(long)]
    pub signer: Option<String>,
}

pub fn run(a: Args) -> anyhow::Result<()> {
    let ks = crate::store();
    let v = sealdrop_core::open::verify(&ks, &a.package, a.signer.as_deref())?;
    // Every manifest value is the sender's text: shown only through `sanitize`.
    let m = &v.manifest;
    out!("OK: signature valid, ciphertext hash matches");
    out!("package id: {}", sanitize(&m.package_id));
    out!(
        "signer: {}{}",
        key_display(&v.signer),
        v.trusted_as
            .as_ref()
            .map(|n| format!(" ({})", sanitize(n)))
            .unwrap_or_default()
    );
    out!("created: {}", sanitize(&m.created));
    if let Some(c) = &m.classification {
        out!("classification: {}", sanitize(c));
    }
    if let Some(e) = &m.expires {
        out!("advisory expiry: {} (not enforced)", sanitize(e));
    }
    if let Some(r) = &m.release {
        out!(
            "timed release: {} after first open via {}",
            super::human(r.window_secs),
            sanitize(&r.service)
        );
    }
    for r in &m.recipients {
        out!(
            "recipient: {} {}",
            sanitize(&r.kind),
            sanitize(&r.fingerprint)
        );
    }
    Ok(())
}
