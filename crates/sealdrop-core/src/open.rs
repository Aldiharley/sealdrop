//! Verify and open (spec 6, 7, 8): verify manifest and ciphertext hash before decrypting.

use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};

use age::secrecy::SecretString;

use crate::crypt;
use crate::extract::{extract, ExtractReport, Limits};
use crate::keys::KeyStore;
use crate::manifest::{self, Manifest};
use crate::probe::probe;
use crate::progress::{Progress, ProgressEvent};
use crate::release::{self, ReleaseFetch, Unlock};
use crate::seal::bundle_paths;
use crate::{Error, Result};

pub struct VerifyReport {
    pub manifest: Manifest,
    pub signer: String,
    pub trusted_as: Option<String>,
    pub ciphertext_ok: bool,
}

fn resolve_signer(
    store: &KeyStore,
    manifest_signer: &str,
    explicit: Option<&str>,
) -> Result<(minisign::PublicKey, Option<String>)> {
    if let Some(s) = explicit {
        if s != manifest_signer {
            return Err(Error::Verify(format!(
                "manifest signer {manifest_signer} does not match --signer"
            )));
        }
        return Ok((
            minisign::PublicKey::from_base64(s).map_err(|e| Error::Verify(e.to_string()))?,
            None,
        ));
    }
    if let Ok(own) = store.signing_public_string() {
        if own == manifest_signer {
            return Ok((store.signing_public()?, Some("self".into())));
        }
    }
    for (name, pk) in store.trusted()? {
        if pk.to_base64() == manifest_signer {
            return Ok((pk, Some(name)));
        }
    }
    Err(Error::Verify(format!(
        "signer {manifest_signer} is not trusted; add it with `sealdrop trust add <name> {manifest_signer}` or pass --signer"
    )))
}

/// Checks the signed manifest and the ciphertext hash. Never decrypts anything.
pub fn verify(store: &KeyStore, package: &Path, signer: Option<&str>) -> Result<VerifyReport> {
    let (mpath, spath) = bundle_paths(package);
    let bytes = std::fs::read(&mpath)
        .map_err(|_| Error::Verify(format!("manifest not found: {}", mpath.display())))?;
    let sig_text = std::fs::read_to_string(&spath)
        .map_err(|_| Error::Verify(format!("signature not found: {}", spath.display())))?;
    let doc = Manifest::from_json(&bytes)?;
    let (pk, trusted_as) = resolve_signer(store, &doc.signer, signer)?;
    let sig =
        minisign::SignatureBox::from_string(&sig_text).map_err(|e| Error::Verify(e.to_string()))?;
    manifest::verify(&bytes, &sig, &pk)?;
    // Bind the signature to this manifest's package id (the trusted comment is signed).
    let expected_comment = format!("sealdrop manifest {}", doc.package_id);
    if sig
        .trusted_comment()
        .map_err(|e| Error::Verify(e.to_string()))?
        != expected_comment
    {
        return Err(Error::Verify(
            "signature trusted comment does not name this package".into(),
        ));
    }
    // The manifest's file name must be the package's bare file name (never a path).
    let package_name = package
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    if doc.ciphertext.file.contains(['/', '\\']) || doc.ciphertext.file != package_name {
        return Err(Error::Verify(
            "manifest ciphertext.file does not match the package file name".into(),
        ));
    }
    let (sha, size) = crate::hashing::sha256_file(package)?;
    if sha != doc.ciphertext.sha256 || size != doc.ciphertext.size {
        return Err(Error::Verify(
            "ciphertext hash does not match the signed manifest".into(),
        ));
    }
    Ok(VerifyReport {
        signer: doc.signer.clone(),
        manifest: doc,
        trusted_as,
        ciphertext_ok: true,
    })
}

pub struct OpenRequest {
    pub package: PathBuf,
    pub out_dir: PathBuf,
    pub signer: Option<String>,
    pub skip_verify: bool,
    pub overwrite: bool,
    pub passphrase: Option<SecretString>,
    pub limits: Limits,
}

pub struct OpenReport {
    pub verify: Option<VerifyReport>,
    pub extract: ExtractReport,
    pub release: Option<Unlock>,
}

/// Verifies (unless `skip_verify`), then decrypts and extracts. Verification always runs
/// before any key material is touched or any network call is made.
pub fn open(
    store: &KeyStore,
    req: OpenRequest,
    fetch: Box<dyn ReleaseFetch>,
    progress: &dyn Progress,
) -> Result<OpenReport> {
    let verify_report = if req.skip_verify {
        None
    } else {
        progress.on(ProgressEvent::Verifying);
        Some(verify(store, &req.package, req.signer.as_deref())?)
    };
    let p = probe(&req.package)?;
    if p.needs_passphrase && req.passphrase.is_none() {
        return Err(Error::Other("this package needs a passphrase".into()));
    }

    let mut inner: Vec<Box<dyn age::Identity>> = Vec::new();
    if let Ok(id) = store.identity() {
        inner.push(Box::new(id));
    }
    if let Ok(lines) = store.plugin_identity_lines() {
        if !lines.is_empty() {
            // `plugin_identity_lines` returns zeroizing strings; borrow them as &str so no
            // plain copies are made.
            let borrowed: Vec<&str> = lines.iter().map(|l| l.as_str()).collect();
            inner.extend(crypt::plugin_identities(&borrowed)?);
        }
    }
    if let Some(pass) = &req.passphrase {
        inner.push(Box::new(crypt::scrypt_identity(pass.clone())));
        inner.push(Box::new(crate::argon2id::Identity::new(pass.clone())));
    }
    if inner.is_empty() {
        return Err(Error::KeyStore(
            "no identity available; run `sealdrop keygen` or provide a passphrase".into(),
        ));
    }
    if let Some(args) = &p.release {
        progress.on(ProgressEvent::Contacting {
            service: args.service.clone(),
        });
    }
    let wrapper = release::Identity::new(inner, fetch);
    let file = BufReader::new(File::open(&req.package)?);
    let ids: Vec<Box<dyn age::Identity + '_>> = vec![Box::new(IdentityRef(&wrapper))];
    let reader = crypt::decrypt_reader(file, &ids)?;
    progress.on(ProgressEvent::Extracting {
        path: req.out_dir.display().to_string(),
    });
    let extract_report = extract(reader, &req.out_dir, &req.limits, req.overwrite)?;
    progress.on(ProgressEvent::Done);
    Ok(OpenReport {
        verify: verify_report,
        extract: extract_report,
        release: wrapper.last_unlock(),
    })
}

/// Borrow the wrapper as an identity without moving it, so `last_unlock()` stays readable.
struct IdentityRef<'a>(&'a release::Identity);

impl age::Identity for IdentityRef<'_> {
    fn unwrap_stanza(
        &self,
        stanza: &age_core::format::Stanza,
    ) -> Option<std::result::Result<age_core::format::FileKey, age::DecryptError>> {
        age::Identity::unwrap_stanza(self.0, stanza)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KeyStore;
    use crate::passphrase::WordList;
    use crate::progress::NoProgress;
    use crate::release::{Deposit, MemoryFetch};
    use crate::seal::{seal, Kdf, Mode, SealRequest};

    fn store() -> (tempfile::TempDir, KeyStore) {
        let d = tempfile::tempdir().unwrap();
        let ks = KeyStore::open(d.path().join("ks"));
        ks.generate(false).unwrap();
        (d, ks)
    }

    fn input(dir: &std::path::Path) -> std::path::PathBuf {
        let p = dir.join("report");
        std::fs::create_dir_all(p.join("sub")).unwrap();
        std::fs::write(p.join("a.pdf"), b"%PDF-fake").unwrap();
        std::fs::write(p.join("sub/b.html"), b"<p>hi</p>").unwrap();
        p
    }

    fn req(input: std::path::PathBuf, out: std::path::PathBuf, mode: Mode) -> SealRequest {
        SealRequest {
            input,
            out_dir: out,
            mode,
            include_self: true,
            allow_unrecoverable: false,
            armor: false,
            classification: Some("confidential".into()),
            expires: None,
            release: None,
        }
    }

    fn open_req(package: std::path::PathBuf, out_dir: std::path::PathBuf) -> OpenRequest {
        OpenRequest {
            package,
            out_dir,
            signer: None,
            skip_verify: false,
            overwrite: false,
            passphrase: None,
            limits: Default::default(),
        }
    }

    fn me(ks: &KeyStore) -> crate::crypt::Recipient {
        crate::crypt::Recipient::parse(&ks.recipient_string().unwrap()).unwrap()
    }

    #[test]
    fn seal_to_self_verify_and_open() {
        let (d, ks) = store();
        let inp = input(d.path());
        let out = d.path().join("out");
        // With nobody to encrypt to (and self not implied) policy refuses.
        let mut empty = req(inp, out.clone(), Mode::Recipients(vec![]));
        empty.include_self = false;
        let r = seal(&ks, empty, &NoProgress).map(|_| ()).unwrap_err();
        assert!(matches!(
            r,
            crate::Error::Policy(crate::policy::PolicyError::NoRecipients)
        ));

        let res = seal(
            &ks,
            req(
                input(d.path()),
                out.clone(),
                Mode::Recipients(vec![me(&ks)]),
            ),
            &NoProgress,
        )
        .unwrap();
        assert!(res.package.ends_with("report.sealdrop.age"));
        assert!(res.manifest.exists() && res.signature.exists());
        assert_eq!(res.manifest_doc.recipients.len(), 1); // self deduplicated
        assert_eq!(
            res.manifest_doc.classification.as_deref(),
            Some("confidential")
        );

        let v = verify(&ks, &res.package, None).unwrap();
        assert!(v.ciphertext_ok);
        assert_eq!(v.signer, ks.signing_public_string().unwrap());
        assert_eq!(v.trusted_as.as_deref(), Some("self"));

        let opened = open(
            &ks,
            open_req(res.package.clone(), d.path().join("restored")),
            Box::new(MemoryFetch::expired()),
            &NoProgress,
        )
        .unwrap();
        assert_eq!(opened.extract.files, 2);
        assert_eq!(
            std::fs::read(d.path().join("restored/report/sub/b.html")).unwrap(),
            b"<p>hi</p>"
        );

        // Tamper one ciphertext byte: verify fails before decryption.
        let mut bytes = std::fs::read(&res.package).unwrap();
        let i = bytes.len() - 5;
        bytes[i] ^= 1;
        std::fs::write(&res.package, bytes).unwrap();
        assert!(matches!(
            verify(&ks, &res.package, None),
            Err(crate::Error::Verify(_))
        ));
        // `open` verifies first: nothing is decrypted or written.
        let blocked = d.path().join("blocked");
        let err = open(
            &ks,
            open_req(res.package.clone(), blocked.clone()),
            Box::new(MemoryFetch::expired()),
            &NoProgress,
        )
        .map(|_| ())
        .unwrap_err();
        assert!(matches!(err, crate::Error::Verify(_)), "{err}");
        assert!(!blocked.exists());
    }

    #[test]
    fn passphrase_scrypt_and_argon2id_round_trip() {
        let (d, ks) = store();
        for kdf in [
            Kdf::Scrypt { log_n: 10 },
            Kdf::Argon2id(crate::argon2id::Profile::Compat),
        ] {
            let out = d
                .path()
                .join(format!("out-{}", matches!(kdf, Kdf::Scrypt { .. })));
            let res = seal(
                &ks,
                req(
                    input(d.path()),
                    out.clone(),
                    Mode::Passphrase {
                        list: WordList::Eff,
                        words: 6,
                        kdf,
                    },
                ),
                &NoProgress,
            )
            .unwrap();
            let pass = res.passphrase.as_ref().unwrap();
            assert_eq!(pass.words.len(), 6);
            assert_eq!(res.manifest_doc.recipients.len(), 1); // self omitted
            assert_eq!(res.manifest_doc.recipients[0].fingerprint, "");
            let mut rq = open_req(res.package.clone(), out.join("x"));
            rq.passphrase = Some(pass.as_secret());
            let opened = open(&ks, rq, Box::new(MemoryFetch::expired()), &NoProgress).unwrap();
            assert_eq!(opened.extract.files, 2);

            // A passphrase package without the passphrase is refused up front.
            let err = open(
                &ks,
                open_req(res.package.clone(), out.join("y")),
                Box::new(MemoryFetch::expired()),
                &NoProgress,
            )
            .map(|_| ())
            .unwrap_err();
            assert!(err.to_string().contains("passphrase"), "{err}");
        }
    }

    #[test]
    fn timed_release_seal_uses_memory_service_in_tests() {
        let (d, ks) = store();
        let mut rq = req(
            input(d.path()),
            d.path().join("out"),
            Mode::Recipients(vec![me(&ks)]),
        );
        rq.release = Some(crate::seal::ReleaseConfig {
            service: "memory://test".into(),
            token: "t".into(),
            window_secs: 90,
        });
        let res = seal(&ks, rq, &NoProgress).unwrap();
        let rel = res.manifest_doc.release.as_ref().unwrap();
        assert_eq!(rel.window_secs, 90);
        assert_eq!(rel.service_key, "memory");
        // Timed release is a one-recipient wrap: self is not added implicitly.
        let p = crate::probe::probe(&res.package).unwrap();
        // age appends random `*-grease` stanzas to non-scrypt headers; the only real one is ours.
        let real: Vec<&String> = p.tags.iter().filter(|t| !t.ends_with("-grease")).collect();
        assert_eq!(real, vec![crate::release::TAG]);
        let args = p.release.unwrap();
        let d2 = Deposit {
            release_id: args.release_id.clone(),
            k_release: crate::seal::test_support::last_memory_deposit().unwrap(),
            unlock_token: zeroize::Zeroizing::new([0u8; 32]),
            window_secs: 90,
        };
        let mut fetch = MemoryFetch::serving(&d2);
        fetch_set_token(&mut fetch, &args.unlock_token_b64);
        let opened = open(
            &ks,
            open_req(res.package.clone(), d.path().join("r")),
            Box::new(fetch),
            &NoProgress,
        )
        .unwrap();
        assert_eq!(opened.release.unwrap().expires_at, "2026-10-13T09:10:00Z");
    }

    fn fetch_set_token(f: &mut MemoryFetch, token: &str) {
        f.set_expected_token(token);
    }

    #[test]
    fn verify_rejects_untrusted_signer_renamed_package_and_missing_bundle() {
        let (d, ks) = store();
        let res = seal(
            &ks,
            req(
                input(d.path()),
                d.path().join("out"),
                Mode::Recipients(vec![me(&ks)]),
            ),
            &NoProgress,
        )
        .unwrap();

        // A different key store does not trust this signer.
        let other = KeyStore::open(d.path().join("other"));
        other.generate(false).unwrap();
        let err = verify(&other, &res.package, None).map(|_| ()).unwrap_err();
        assert!(err.to_string().contains("not trusted"), "{err}");
        // ... until it is added to the trust list.
        other
            .add_trusted("alice", &ks.signing_public_string().unwrap())
            .unwrap();
        let v = verify(&other, &res.package, None).unwrap();
        assert_eq!(v.trusted_as.as_deref(), Some("alice"));
        // An explicit --signer that disagrees with the manifest is refused.
        let wrong = other.signing_public_string().unwrap();
        assert!(matches!(
            verify(&other, &res.package, Some(&wrong)),
            Err(crate::Error::Verify(_))
        ));

        // The signed manifest names its ciphertext file: a renamed copy must not verify.
        let renamed = d.path().join("out").join("renamed.sealdrop.age");
        std::fs::copy(&res.package, &renamed).unwrap();
        let (m, s) = crate::seal::bundle_paths(&renamed);
        std::fs::copy(&res.manifest, &m).unwrap();
        std::fs::copy(&res.signature, &s).unwrap();
        assert!(matches!(
            verify(&ks, &renamed, None),
            Err(crate::Error::Verify(_))
        ));

        // Missing manifest.
        std::fs::remove_file(&res.manifest).unwrap();
        assert!(matches!(
            verify(&ks, &res.package, None),
            Err(crate::Error::Verify(_))
        ));
    }

    #[test]
    fn open_refuses_without_any_identity_and_skip_verify_is_explicit() {
        let (d, ks) = store();
        let res = seal(
            &ks,
            req(
                input(d.path()),
                d.path().join("out"),
                Mode::Recipients(vec![me(&ks)]),
            ),
            &NoProgress,
        )
        .unwrap();
        // A key store with no keys and no passphrase cannot decrypt.
        let empty = KeyStore::open(d.path().join("empty"));
        let mut rq = open_req(res.package.clone(), d.path().join("o1"));
        rq.skip_verify = true;
        let err = open(&empty, rq, Box::new(MemoryFetch::expired()), &NoProgress)
            .map(|_| ())
            .unwrap_err();
        assert!(matches!(err, crate::Error::KeyStore(_)), "{err}");

        // Without skip_verify the same store fails at verification, before any identity use.
        let rq = open_req(res.package.clone(), d.path().join("o2"));
        let err = open(&empty, rq, Box::new(MemoryFetch::expired()), &NoProgress)
            .map(|_| ())
            .unwrap_err();
        assert!(matches!(err, crate::Error::Verify(_)), "{err}");

        // skip_verify with the real store opens and reports no verification.
        let mut rq = open_req(res.package.clone(), d.path().join("o3"));
        rq.skip_verify = true;
        let opened = open(&ks, rq, Box::new(MemoryFetch::expired()), &NoProgress).unwrap();
        assert!(opened.verify.is_none());
        assert_eq!(opened.extract.files, 2);
    }

    #[test]
    fn seal_refuses_existing_package_and_failed_deposit_leaves_nothing() {
        let (d, ks) = store();
        let out = d.path().join("out");
        seal(
            &ks,
            req(
                input(d.path()),
                out.clone(),
                Mode::Recipients(vec![me(&ks)]),
            ),
            &NoProgress,
        )
        .unwrap();
        let err = seal(
            &ks,
            req(
                input(d.path()),
                out.clone(),
                Mode::Recipients(vec![me(&ks)]),
            ),
            &NoProgress,
        )
        .map(|_| ())
        .unwrap_err();
        assert!(matches!(err, crate::Error::Exists(_)), "{err}");

        // A deposit that cannot reach its service removes the package it just wrote.
        let out2 = d.path().join("out2");
        let mut rq = req(
            input(d.path()),
            out2.clone(),
            Mode::Recipients(vec![me(&ks)]),
        );
        rq.release = Some(crate::seal::ReleaseConfig {
            service: "http://127.0.0.1:1".into(),
            token: "t".into(),
            window_secs: 60,
        });
        assert!(seal(&ks, rq, &NoProgress).is_err());
        assert!(!out2.join("report.sealdrop.age").exists());
    }
}
