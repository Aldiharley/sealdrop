use std::path::PathBuf;

use clap::Args as ClapArgs;

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
    out!("OK: signature valid, ciphertext hash matches");
    out!("package id: {}", v.manifest.package_id);
    out!(
        "signer: {}{}",
        v.signer,
        v.trusted_as.map(|n| format!(" ({n})")).unwrap_or_default()
    );
    out!("created: {}", v.manifest.created);
    if let Some(c) = &v.manifest.classification {
        out!("classification: {c}");
    }
    if let Some(e) = &v.manifest.expires {
        out!("advisory expiry: {e} (not enforced)");
    }
    if let Some(r) = &v.manifest.release {
        out!(
            "timed release: {} after first open via {}",
            super::human(r.window_secs),
            r.service
        );
    }
    for r in &v.manifest.recipients {
        out!("recipient: {} {}", r.kind, r.fingerprint);
    }
    Ok(())
}
