use std::path::PathBuf;

use clap::Subcommand;
use sealdrop_core::release::{
    fetch_receipt, verify_receipt, verify_receipt_for, Receipt, SignedReceipt,
};

#[derive(Subcommand)]
pub enum Cmd {
    /// Fetch, verify and save the receipt for a sealed package (sender side)
    ///
    /// The manifest and its package must sit together (as `seal` wrote them): the manifest
    /// is verified before your deposit token is sent to the service it names. The token
    /// comes from SEALDROP_RELEASE_TOKEN or settings.release_token.
    Fetch {
        /// The <name>.manifest.json written by `seal`
        manifest: PathBuf,
    },
    /// Verify a saved receipt file
    Verify {
        /// A <name>.receipt.json saved by `receipt fetch`
        receipt: PathBuf,
        /// Require this service key (the `service_key` in the manifest); without it the
        /// receipt is only checked against the key it carries
        #[arg(long)]
        service_key: Option<String>,
    },
}

pub fn run(cmd: Cmd) -> anyhow::Result<()> {
    let ks = crate::store();
    match cmd {
        Cmd::Fetch { manifest } => {
            let name = manifest
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let stem = name
                .strip_suffix(".manifest.json")
                .ok_or_else(|| anyhow::anyhow!("expected a file named <name>.manifest.json"))?;
            // Verify the manifest (signature, trusted signer, ciphertext hash) before trusting
            // the service URL in it with the deposit token.
            let package = manifest.with_file_name(format!("{stem}.sealdrop.age"));
            let v = sealdrop_core::open::verify(&ks, &package, None)?;
            let m = v.manifest;
            let r = m
                .release
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("manifest has no timed release"))?;
            let token = super::release_token(&ks.settings()?)?;
            let signed = fetch_receipt(&r.service, &token, &r.release_id)?;
            // Pinned to the service key recorded at seal time; never trust-on-first-use.
            let receipt =
                verify_receipt_for(&signed, &r.service_key, &r.release_id, &m.ciphertext.sha256)?;
            let out = manifest.with_file_name(format!("{stem}.receipt.json"));
            std::fs::write(&out, serde_json::to_vec_pretty(&signed)?)?;
            print(&receipt)?;
            out!("saved: {}", out.display());
        }
        Cmd::Verify {
            receipt,
            service_key,
        } => {
            let signed: SignedReceipt = serde_json::from_slice(&std::fs::read(receipt)?)?;
            let r = verify_receipt(&signed, service_key.as_deref())?;
            if service_key.is_some() {
                out!("OK: receipt signature valid");
            } else {
                out!("OK (key not pinned): receipt signature valid");
            }
            print(&r)?;
            if service_key.is_none() {
                out!(
                    "note: checked against the key inside the receipt only; pass --service-key <key from the manifest> to prove which service signed it"
                );
            }
        }
    }
    Ok(())
}

fn print(r: &Receipt) -> anyhow::Result<()> {
    out!("release: {}", r.release_id);
    out!("package sha256: {}", r.package_sha256);
    match &r.first_unlock {
        Some(t) => out!(
            "first opened: {t} (service clock), expires {}",
            r.expires_at.as_deref().unwrap_or("?")
        ),
        None => out!("not yet opened"),
    }
    out!("unlock count: {}", r.unlock_count);
    out!("service key: {}", r.service_key);
    Ok(())
}
