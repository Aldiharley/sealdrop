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
    println!("OK: signature valid, ciphertext hash matches");
    println!("package id: {}", v.manifest.package_id);
    println!(
        "signer: {}{}",
        v.signer,
        v.trusted_as.map(|n| format!(" ({n})")).unwrap_or_default()
    );
    println!("created: {}", v.manifest.created);
    if let Some(c) = &v.manifest.classification {
        println!("classification: {c}");
    }
    if let Some(e) = &v.manifest.expires {
        println!("advisory expiry: {e} (not enforced)");
    }
    if let Some(r) = &v.manifest.release {
        println!(
            "timed release: {} after first open via {}",
            super::human(r.window_secs),
            r.service
        );
    }
    for r in &v.manifest.recipients {
        println!("recipient: {} {}", r.kind, r.fingerprint);
    }
    Ok(())
}
