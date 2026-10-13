//! Timed release (spec 5.5): nested wrap of inner recipient stanzas under a service-held
//! key, plus the HTTP client for deposit, unlock and receipts.

use std::cell::RefCell;
use std::collections::HashSet;

use age::{DecryptError, EncryptError};
use age_core::format::{FileKey, Stanza};
use base64::prelude::{Engine, BASE64_STANDARD_NO_PAD};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::hashing::sha256_hex;
use crate::{Error, Result};

/// Domain-separation tag.
pub const TAG: &str = "sealdrop-release";

#[derive(Serialize, Deserialize)]
struct InnerStanza {
    tag: String,
    args: Vec<String>,
    body: String,
}

#[derive(Serialize, Deserialize)]
struct InnerStanzas {
    stanzas: Vec<InnerStanza>,
}

/// Secrets of one timed release. Deliberately not `Debug`.
pub struct Deposit {
    pub release_id: String,
    pub k_release: Zeroizing<[u8; 32]>,
    pub unlock_token: Zeroizing<[u8; 32]>,
    pub window_secs: u64,
}

impl Deposit {
    pub fn new(window_secs: u64) -> Self {
        let mut k = Zeroizing::new([0u8; 32]);
        let mut t = Zeroizing::new([0u8; 32]);
        rand::rng().fill_bytes(k.as_mut());
        rand::rng().fill_bytes(t.as_mut());
        Self {
            release_id: uuid::Uuid::new_v4().to_string(),
            k_release: k,
            unlock_token: t,
            window_secs,
        }
    }
    pub fn unlock_token_b64(&self) -> String {
        BASE64_STANDARD_NO_PAD.encode(*self.unlock_token)
    }
    pub fn unlock_token_hash(&self) -> String {
        sha256_hex(self.unlock_token.as_ref())
    }
}

pub struct Recipient {
    inner: Vec<Box<dyn age::Recipient + Send>>,
    k_release: Zeroizing<[u8; 32]>,
    release_id: String,
    service: String,
    unlock_token_b64: String,
}

impl Recipient {
    pub fn new(
        inner: Vec<Box<dyn age::Recipient + Send>>,
        deposit: &Deposit,
        service: &str,
    ) -> Self {
        Self {
            inner,
            k_release: deposit.k_release.clone(),
            release_id: deposit.release_id.clone(),
            service: service.trim_end_matches('/').to_string(),
            unlock_token_b64: deposit.unlock_token_b64(),
        }
    }
}

impl age::Recipient for Recipient {
    fn wrap_file_key(
        &self,
        file_key: &FileKey,
    ) -> std::result::Result<(Vec<Stanza>, HashSet<String>), EncryptError> {
        let mut inner = Vec::new();
        for r in &self.inner {
            let (stanzas, _labels) = r.wrap_file_key(file_key)?;
            for s in stanzas {
                inner.push(InnerStanza {
                    tag: s.tag,
                    args: s.args,
                    body: BASE64_STANDARD_NO_PAD.encode(s.body),
                });
            }
        }
        if inner.is_empty() {
            return Err(EncryptError::MissingRecipients);
        }
        let json = Zeroizing::new(
            serde_json::to_vec(&InnerStanzas { stanzas: inner })
                .map_err(|e| EncryptError::Io(std::io::Error::other(e)))?,
        );
        let mut nonce = [0u8; 12];
        rand::rng().fill_bytes(&mut nonce);
        let aead = ChaCha20Poly1305::new(&Key::from(*self.k_release));
        let body = aead
            .encrypt(&Nonce::from(nonce), json.as_slice())
            .map_err(|_| EncryptError::Io(std::io::Error::other("aead")))?;
        let stanza = Stanza {
            tag: TAG.into(),
            args: vec![
                self.release_id.clone(),
                BASE64_STANDARD_NO_PAD.encode(self.service.as_bytes()),
                BASE64_STANDARD_NO_PAD.encode(nonce),
                self.unlock_token_b64.clone(),
            ],
            body,
        };
        let mut labels = HashSet::new();
        labels.insert(TAG.to_string());
        Ok((vec![stanza], labels))
    }
}

/// The service's answer to an unlock. Deliberately not `Debug` (holds the release key).
#[derive(Clone)]
pub struct Unlock {
    pub k_release: Zeroizing<[u8; 32]>,
    pub first_unlock: String,
    pub expires_at: String,
}

pub trait ReleaseFetch {
    fn unlock(&self, service: &str, release_id: &str, unlock_token_b64: &str) -> Result<Unlock>;
}

pub struct Identity {
    inner: Vec<Box<dyn age::Identity>>,
    fetch: Box<dyn ReleaseFetch>,
    last: RefCell<Option<Unlock>>,
}

impl Identity {
    pub fn new(inner: Vec<Box<dyn age::Identity>>, fetch: Box<dyn ReleaseFetch>) -> Self {
        Self {
            inner,
            fetch,
            last: RefCell::new(None),
        }
    }
    pub fn last_unlock(&self) -> Option<Unlock> {
        self.last.borrow().clone()
    }
}

impl age::Identity for Identity {
    fn unwrap_stanza(&self, stanza: &Stanza) -> Option<std::result::Result<FileKey, DecryptError>> {
        if stanza.tag != TAG {
            // Not timed release: delegate to inner identities directly.
            return self.inner.iter().find_map(|i| i.unwrap_stanza(stanza));
        }
        if stanza.args.len() != 4 {
            return Some(Err(DecryptError::InvalidHeader));
        }
        let service = match BASE64_STANDARD_NO_PAD
            .decode(&stanza.args[1])
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
        {
            Some(s) => s,
            None => return Some(Err(DecryptError::InvalidHeader)),
        };
        let nonce = match BASE64_STANDARD_NO_PAD.decode(&stanza.args[2]) {
            Ok(n) if n.len() == 12 => n,
            _ => return Some(Err(DecryptError::InvalidHeader)),
        };
        let unlock = match self
            .fetch
            .unlock(&service, &stanza.args[0], &stanza.args[3])
        {
            Ok(u) => u,
            Err(e) => return Some(Err(DecryptError::Io(std::io::Error::other(e.to_string())))),
        };
        let aead = ChaCha20Poly1305::new(&Key::from(*unlock.k_release));
        let mut n = [0u8; 12];
        n.copy_from_slice(&nonce);
        let json = match aead.decrypt(&Nonce::from(n), stanza.body.as_slice()) {
            Ok(j) => Zeroizing::new(j),
            Err(_) => return Some(Err(DecryptError::DecryptionFailed)),
        };
        let inner: InnerStanzas = match serde_json::from_slice(&json) {
            Ok(i) => i,
            Err(_) => return Some(Err(DecryptError::InvalidHeader)),
        };
        if inner.stanzas.len() > 64 {
            return Some(Err(DecryptError::InvalidHeader));
        }
        let stanzas: Vec<Stanza> = inner
            .stanzas
            .into_iter()
            .filter_map(|s| {
                BASE64_STANDARD_NO_PAD
                    .decode(s.body)
                    .ok()
                    .map(|body| Stanza {
                        tag: s.tag,
                        args: s.args,
                        body,
                    })
            })
            .collect();
        *self.last.borrow_mut() = Some(unlock);
        match self.inner.iter().find_map(|i| i.unwrap_stanzas(&stanzas)) {
            Some(r) => Some(r),
            None => Some(Err(DecryptError::NoMatchingKeys)),
        }
    }
}

// ---------- HTTP client ----------

#[derive(Serialize)]
struct DepositBody<'a> {
    k_release: String,
    window_secs: u64,
    unlock_token_hash: String,
    package_sha256: &'a str,
}

#[derive(Serialize)]
struct UnlockBody<'a> {
    unlock_token: &'a str,
}

#[derive(Deserialize)]
struct UnlockResponse {
    k_release: String,
    first_unlock: String,
    expires_at: String,
}

pub struct HttpFetch;

impl ReleaseFetch for HttpFetch {
    fn unlock(&self, service: &str, release_id: &str, unlock_token_b64: &str) -> Result<Unlock> {
        let url = format!(
            "{}/v1/releases/{release_id}/unlock",
            service.trim_end_matches('/')
        );
        let res = ureq::post(&url).send_json(UnlockBody {
            unlock_token: unlock_token_b64,
        });
        let mut res = match res {
            Ok(r) => r,
            Err(ureq::Error::StatusCode(410)) => return Err(Error::ReleaseExpired),
            Err(ureq::Error::StatusCode(403)) => {
                return Err(Error::Release("unlock token rejected".into()))
            }
            Err(ureq::Error::StatusCode(404)) => {
                return Err(Error::Release("release not found at service".into()))
            }
            Err(e) => return Err(Error::Release(e.to_string())),
        };
        let body: UnlockResponse = res
            .body_mut()
            .read_json()
            .map_err(|e| Error::Release(e.to_string()))?;
        let raw = Zeroizing::new(
            BASE64_STANDARD_NO_PAD
                .decode(body.k_release)
                .map_err(|_| Error::Release("bad key".into()))?,
        );
        if raw.len() != 32 {
            return Err(Error::Release("bad key length".into()));
        }
        let mut k = Zeroizing::new([0u8; 32]);
        k.copy_from_slice(&raw);
        Ok(Unlock {
            k_release: k,
            first_unlock: body.first_unlock,
            expires_at: body.expires_at,
        })
    }
}

pub fn deposit(service: &str, token: &str, d: &Deposit, package_sha256: &str) -> Result<()> {
    let url = format!(
        "{}/v1/releases/{}",
        service.trim_end_matches('/'),
        d.release_id
    );
    ureq::put(&url)
        .header("Authorization", &format!("Bearer {token}"))
        .send_json(DepositBody {
            k_release: BASE64_STANDARD_NO_PAD.encode(*d.k_release),
            window_secs: d.window_secs,
            unlock_token_hash: d.unlock_token_hash(),
            package_sha256,
        })
        .map_err(|e| Error::Release(format!("deposit failed: {e}")))?;
    Ok(())
}

// ---------- receipts ----------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Receipt {
    pub release_id: String,
    pub package_sha256: String,
    pub first_unlock: Option<String>,
    pub expires_at: Option<String>,
    pub unlock_count: u64,
    pub service_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedReceipt {
    /// Canonical JSON bytes that were signed (kept verbatim).
    pub receipt_json: String,
    /// minisign signature box text.
    pub signature: String,
}

pub fn sign_receipt(
    r: &Receipt,
    sk: &minisign::SecretKey,
    pk: &minisign::PublicKey,
) -> Result<SignedReceipt> {
    let receipt_json =
        serde_json::to_string_pretty(r).map_err(|e| Error::Release(e.to_string()))?;
    let sig = minisign::sign(
        Some(pk),
        sk,
        std::io::Cursor::new(receipt_json.as_bytes()),
        Some(&format!("sealdrop receipt {}", r.release_id)),
        None,
    )
    .map_err(|e| Error::Release(e.to_string()))?;
    Ok(SignedReceipt {
        receipt_json,
        signature: sig.into_string(),
    })
}

pub fn verify_receipt(s: &SignedReceipt, expected_service_key: Option<&str>) -> Result<Receipt> {
    let r: Receipt =
        serde_json::from_str(&s.receipt_json).map_err(|e| Error::Verify(e.to_string()))?;
    if let Some(exp) = expected_service_key {
        if exp != r.service_key {
            return Err(Error::Verify(
                "receipt signed by a different service key".into(),
            ));
        }
    }
    let pk = minisign::PublicKey::from_base64(&r.service_key)
        .map_err(|e| Error::Verify(e.to_string()))?;
    let sig = minisign::SignatureBox::from_string(&s.signature)
        .map_err(|e| Error::Verify(e.to_string()))?;
    minisign::verify(
        &pk,
        &sig,
        std::io::Cursor::new(s.receipt_json.as_bytes()),
        true,
        false,
        false,
    )
    .map_err(|e| Error::Verify(format!("receipt signature invalid: {e}")))?;
    Ok(r)
}

pub fn fetch_receipt(service: &str, token: &str, release_id: &str) -> Result<SignedReceipt> {
    let url = format!(
        "{}/v1/releases/{release_id}/receipt",
        service.trim_end_matches('/')
    );
    let mut res = ureq::get(&url)
        .header("Authorization", &format!("Bearer {token}"))
        .call()
        .map_err(|e| Error::Release(format!("receipt fetch failed: {e}")))?;
    res.body_mut()
        .read_json()
        .map_err(|e| Error::Release(e.to_string()))
}

// ---------- test double ----------

/// In-memory stand-in for the service, used by core, CLI and desktop tests.
pub struct MemoryFetch {
    key: Option<Zeroizing<[u8; 32]>>,
    expected_token: String,
}

impl MemoryFetch {
    pub fn serving(d: &Deposit) -> Self {
        Self {
            key: Some(d.k_release.clone()),
            expected_token: d.unlock_token_b64(),
        }
    }
    pub fn expired() -> Self {
        Self {
            key: None,
            expected_token: String::new(),
        }
    }
    /// Change the unlock token this double accepts.
    pub fn set_expected_token(&mut self, t: &str) {
        self.expected_token = t.to_string();
    }
}

impl ReleaseFetch for MemoryFetch {
    fn unlock(&self, _service: &str, _release_id: &str, unlock_token_b64: &str) -> Result<Unlock> {
        match &self.key {
            Some(k) if unlock_token_b64 == self.expected_token => Ok(Unlock {
                k_release: k.clone(),
                first_unlock: "2026-10-13T09:00:00Z".into(),
                expires_at: "2026-10-13T09:10:00Z".into(),
            }),
            Some(_) => Err(Error::Release("unlock token rejected".into())),
            None => Err(Error::ReleaseExpired),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::secrecy::SecretString;
    use std::io::{Read, Write};

    #[test]
    fn nested_wrap_requires_both_service_key_and_inner_identity() {
        let x = age::x25519::Identity::generate();
        let d = Deposit::new(600);
        let inner: Vec<Box<dyn age::Recipient + Send>> = vec![Box::new(x.to_public())];
        let r = Recipient::new(inner, &d, "https://release.example");
        let rs: Vec<Box<dyn age::Recipient + Send>> = vec![Box::new(r)];
        let mut w = crate::crypt::encrypt_writer(Vec::new(), &rs, false).unwrap();
        w.write_all(b"timed").unwrap();
        let ct = w.finish().unwrap();

        // Exactly one real stanza, ours: no inner (X25519) stanza leaks into the header.
        // age itself appends a random `*-grease` stanza whenever no scrypt stanza is
        // present (age-0.12.1 src/format.rs:45), so tolerate that and nothing else.
        let p = crate::probe::probe_bytes(&ct).unwrap();
        assert_eq!(p.tags.iter().filter(|t| *t == TAG).count(), 1);
        assert!(p.tags.iter().all(|t| t == TAG || t.ends_with("-grease")));
        assert!(!p.tags.iter().any(|t| t == "X25519"));
        let args = p.release.unwrap();
        assert_eq!(args.release_id, d.release_id);
        assert_eq!(args.service, "https://release.example");

        // Inner identity alone cannot open it.
        let alone: Vec<Box<dyn age::Identity>> = vec![Box::new(x.clone())];
        assert!(crate::crypt::decrypt_reader(&ct[..], &alone).is_err());

        // With the service key (from the fetch seam) it opens.
        let fetch = MemoryFetch::serving(&d);
        let id = Identity::new(vec![Box::new(x.clone())], Box::new(fetch));
        let ids: Vec<Box<dyn age::Identity>> = vec![Box::new(id)];
        let mut out = Vec::new();
        crate::crypt::decrypt_reader(&ct[..], &ids)
            .unwrap()
            .read_to_end(&mut out)
            .unwrap();
        assert_eq!(out, b"timed");

        // Wrong inner identity with the right service key still fails.
        let other = age::x25519::Identity::generate();
        let id = Identity::new(vec![Box::new(other)], Box::new(MemoryFetch::serving(&d)));
        let ids: Vec<Box<dyn age::Identity>> = vec![Box::new(id)];
        assert!(crate::crypt::decrypt_reader(&ct[..], &ids).is_err());

        // Expired service answer surfaces as an error.
        let id = Identity::new(vec![Box::new(x)], Box::new(MemoryFetch::expired()));
        let ids: Vec<Box<dyn age::Identity>> = vec![Box::new(id)];
        assert!(crate::crypt::decrypt_reader(&ct[..], &ids).is_err());
    }

    #[test]
    fn nonce_is_random_per_wrap() {
        let x = age::x25519::Identity::generate();
        let d = Deposit::new(60);
        let nonces: Vec<String> = (0..2)
            .map(|_| {
                let inner: Vec<Box<dyn age::Recipient + Send>> = vec![Box::new(x.to_public())];
                let rs: Vec<Box<dyn age::Recipient + Send>> =
                    vec![Box::new(Recipient::new(inner, &d, "https://s/"))];
                let w = crate::crypt::encrypt_writer(Vec::new(), &rs, false).unwrap();
                let ct = w.finish().unwrap();
                let args = crate::probe::probe_bytes(&ct).unwrap().release.unwrap();
                // Trailing slash on the service is normalised away.
                assert_eq!(args.service, "https://s");
                args.nonce_b64
            })
            .collect();
        assert_ne!(nonces[0], nonces[1]);
    }

    #[test]
    fn empty_inner_recipients_is_an_error() {
        let d = Deposit::new(60);
        let rs: Vec<Box<dyn age::Recipient + Send>> =
            vec![Box::new(Recipient::new(Vec::new(), &d, "https://s"))];
        assert!(crate::crypt::encrypt_writer(Vec::new(), &rs, false).is_err());
    }

    #[test]
    fn wraps_a_passphrase_inner_recipient_and_cannot_mix() {
        let pass = SecretString::from("p".to_string());
        let d = Deposit::new(5);
        let inner: Vec<Box<dyn age::Recipient + Send>> = vec![Box::new(
            crate::crypt::scrypt_recipient(pass.clone(), 10).unwrap(),
        )];
        let r = Recipient::new(inner, &d, "https://s");
        let x = age::x25519::Identity::generate();
        let mixed: Vec<Box<dyn age::Recipient + Send>> = vec![Box::new(r), Box::new(x.to_public())];
        assert!(crate::crypt::encrypt_writer(Vec::new(), &mixed, false).is_err());
    }

    #[test]
    fn receipt_signature_verifies_and_detects_tamper() {
        let kp = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
        let receipt = Receipt {
            release_id: "r1".into(),
            package_sha256: "ab".into(),
            first_unlock: Some("2026-10-13T09:00:00Z".into()),
            expires_at: Some("2026-10-13T09:10:00Z".into()),
            unlock_count: 1,
            service_key: kp.pk.to_base64(),
        };
        let signed = sign_receipt(&receipt, &kp.sk, &kp.pk).unwrap();
        let back = verify_receipt(&signed, Some(&kp.pk.to_base64())).unwrap();
        assert_eq!(back.unlock_count, 1);
        let mut bad = signed.clone();
        bad.receipt_json = bad
            .receipt_json
            .replace("\"unlock_count\": 1", "\"unlock_count\": 2");
        assert!(verify_receipt(&bad, None).is_err());
        assert!(verify_receipt(
            &signed,
            Some("RWQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        )
        .is_err());
    }
}
