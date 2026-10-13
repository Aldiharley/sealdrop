use std::path::PathBuf;

use clap::{Args as ClapArgs, ValueEnum};
use sealdrop_core::argon2id::Profile;
use sealdrop_core::crypt::{Recipient, SCRYPT_HIGH_LOG_N};
use sealdrop_core::passphrase::WordList;
use sealdrop_core::policy::PolicyError;
use sealdrop_core::seal::{seal, Kdf, Mode, ReleaseConfig, SealRequest};
use sealdrop_core::Error;

#[derive(Clone, Copy, ValueEnum)]
pub enum Words {
    /// EFF large list (7776 words, 12.9 bits each; minimum 6 words)
    Eff,
    /// BIP-39 English list (2048 words, 11 bits each; minimum 10 words)
    Bip39,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum KdfProfile {
    /// Standard strength (the key-store setting, normally scrypt 2^18)
    Default,
    /// Slower and stronger (scrypt 2^20; Argon2id desktop profile)
    High,
    /// Fast parameters for automated tests only; do not use for real files
    #[value(hide = true)]
    Test,
}

#[derive(ClapArgs)]
pub struct Args {
    /// File or folder to seal
    pub input: PathBuf,
    /// Recipient (age1..., age1pq..., or age1<plugin>1...). Repeatable.
    #[arg(short = 'r', long = "recipient")]
    pub recipients: Vec<String>,
    /// Generate a passphrase instead of using recipients (it is printed once, to stdout)
    #[arg(long)]
    pub passphrase: bool,
    /// Word list for --passphrase (default: eff)
    #[arg(long, value_enum)]
    pub words: Option<Words>,
    /// Passphrase length in words (default and minimum: 6 for EFF, 10 for BIP-39)
    #[arg(long)]
    pub word_count: Option<usize>,
    /// Use the non-standard Argon2id stanza (files will not open in stock age)
    #[arg(long)]
    pub argon2id: bool,
    /// Key-derivation strength for --passphrase (default: default)
    #[arg(long, value_enum)]
    pub kdf_profile: Option<KdfProfile>,
    /// Write ASCII-armored output instead of binary
    #[arg(long)]
    pub armor: bool,
    /// Free-text classification recorded in the signed manifest
    #[arg(long)]
    pub classification: Option<String>,
    /// Advisory expiry date (YYYY-MM-DD); not enforced by any software
    #[arg(long)]
    pub expires: Option<String>,
    /// Allow hardware-key-only recipients with no recovery recipient
    #[arg(long)]
    pub allow_unrecoverable: bool,
    /// Do not add your own recipient
    #[arg(long)]
    pub no_self: bool,
    /// Folder for the package, manifest and signature (created if missing)
    #[arg(short = 'o', long, default_value = ".")]
    pub out: PathBuf,
    /// Print the passphrase as a QR code too
    #[arg(long)]
    pub qr: bool,
    /// Timed release: window after first open, e.g. 90s, 10m, 6h, 3d
    #[arg(long, value_name = "WINDOW")]
    pub expire_after: Option<String>,
    /// Release service base URL (or settings.release_service); the deposit token comes
    /// from SEALDROP_RELEASE_TOKEN or settings.release_token
    #[arg(long, value_name = "URL")]
    pub release_service: Option<String>,
}

pub fn run(a: Args) -> anyhow::Result<()> {
    let ks = crate::store();
    let settings = ks.settings()?;

    if !a.passphrase {
        for (given, flag) in [
            (a.argon2id, "--argon2id"),
            (a.kdf_profile.is_some(), "--kdf-profile"),
            (a.words.is_some(), "--words"),
            (a.word_count.is_some(), "--word-count"),
            (a.qr, "--qr"),
        ] {
            anyhow::ensure!(!given, "{flag} requires --passphrase");
        }
    }

    let mut recipients = Vec::new();
    for r in &a.recipients {
        recipients.push(Recipient::parse(r)?);
    }
    // Recipients and a passphrase are mutually exclusive, and one of them is required.
    // (The core would otherwise ignore recipients in passphrase mode, or seal to yourself only.)
    if a.passphrase && !recipients.is_empty() {
        return Err(Error::Policy(PolicyError::PassphraseMustBeAlone).into());
    }
    if !a.passphrase && recipients.is_empty() {
        return Err(anyhow::Error::new(Error::Policy(PolicyError::NoRecipients))
            .context("give at least one -r <recipient>, or use --passphrase"));
    }

    let kdf_profile = a.kdf_profile.unwrap_or(KdfProfile::Default);
    let use_argon2id = a.argon2id || settings.argon2id;
    let mode = if a.passphrase {
        let kdf = if use_argon2id {
            Kdf::Argon2id(match kdf_profile {
                KdfProfile::High => Profile::Desktop,
                _ => Profile::Compat,
            })
        } else {
            Kdf::Scrypt {
                log_n: match kdf_profile {
                    KdfProfile::Default => settings.scrypt_log_n,
                    KdfProfile::High => SCRYPT_HIGH_LOG_N,
                    KdfProfile::Test => 10,
                },
            }
        };
        let list = match a.words.unwrap_or(Words::Eff) {
            Words::Eff => WordList::Eff,
            Words::Bip39 => WordList::Bip39,
        };
        Mode::Passphrase {
            list,
            words: a.word_count.unwrap_or(0),
            kdf,
        }
    } else {
        Mode::Recipients(recipients)
    };

    let release = match &a.expire_after {
        Some(w) => {
            let window_secs = super::parse_window(w)?;
            let service = a
                .release_service
                .clone()
                .or_else(|| settings.release_service.clone())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "--expire-after needs --release-service or settings.release_service"
                    )
                })?;
            let token = super::release_token(&settings)?;
            Some(ReleaseConfig {
                service,
                token,
                window_secs,
            })
        }
        None => None,
    };

    // The core takes the package name from the last path component, so resolve `.`, `..` and
    // relative paths first.
    let input = std::fs::canonicalize(&a.input)
        .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", a.input.display()))?;

    let res = seal(
        &ks,
        SealRequest {
            input,
            out_dir: a.out.clone(),
            mode,
            include_self: !a.no_self,
            allow_unrecoverable: a.allow_unrecoverable,
            armor: a.armor || settings.armor,
            classification: a.classification.clone(),
            expires: a.expires.clone(),
            release,
        },
        &super::StderrProgress,
    )?;

    out!("sealed: {}", res.package.display());
    out!("manifest: {}", res.manifest.display());
    out!("signature: {}", res.signature.display());
    out!("package id: {}", res.manifest_doc.package_id);
    out!("ciphertext sha256: {}", res.manifest_doc.ciphertext.sha256);
    if let Some(r) = &res.manifest_doc.release {
        out!(
            "Timed release: {} after first open, enforced by {}",
            super::human(r.window_secs),
            r.service
        );
        out!("This does not protect the contents once decrypted.");
    }
    if let Some(p) = &res.passphrase {
        out!("passphrase: {}", *p.joined());
        out!(
            "entropy: {:.1} bits - send it on a different channel from the file",
            p.entropy_bits
        );
        if a.qr {
            let code = qrcode::QrCode::new(p.joined().as_bytes())?;
            out!(
                "{}",
                code.render::<qrcode::render::unicode::Dense1x2>()
                    .quiet_zone(true)
                    .build()
            );
        }
        if use_argon2id {
            out!("note: Argon2id mode is non-standard; this file will not open in stock age tools");
        }
    }
    Ok(())
}
