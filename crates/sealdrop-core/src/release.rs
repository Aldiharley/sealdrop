//! Timed release (spec 5.5): nested wrap of inner recipient stanzas under a service-held
//! key, plus the HTTP client for deposit, unlock and receipts.

use std::cell::RefCell;
use std::collections::HashSet;
use std::time::Duration;

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

/// Maximum number of inner stanzas, enforced on both wrap and unwrap.
const MAX_INNER_STANZAS: usize = 64;
/// Maximum size of the decrypted (and of the to-be-encrypted) inner-stanza JSON.
const MAX_INNER_JSON: usize = 64 * 1024;

/// Validates a service URL that came from a file header or the user before any request is
/// built from it. Returns the URL without trailing slashes.
///
/// Accepted: `https://<host>[:port][/path]`; `http://` only for `localhost`, `127.0.0.1`
/// and `[::1]`; and, only in test builds (`cfg(test)` or the `test-support` feature), the test scheme
/// `memory://<anything>`; in every other build `memory://` is an unsupported scheme. Rejected: any `?`, `#`,
/// whitespace or control character, plus `@` and `\` (userinfo / parser-confusion tricks).
pub fn validate_service_url(s: &str) -> Result<String> {
    let bad = |why: &str| Error::Release(format!("invalid service URL: {why}"));
    if s.chars()
        .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '?' | '#' | '@' | '\\'))
    {
        return Err(bad("forbidden character"));
    }
    let (scheme, rest) = s.split_once("://").ok_or_else(|| bad("missing scheme"))?;
    let authority = rest.split('/').next().unwrap_or("");
    if authority.is_empty() {
        return Err(bad("missing host"));
    }
    // `memory://` is the in-process test transport. ureq has no transport for the scheme
    // (it rejects it), so it can never reach the network from `HttpFetch`/`deposit`.
    #[cfg(any(test, feature = "test-support"))]
    if scheme == "memory" {
        return Ok(format!("{scheme}://{}", rest.trim_end_matches('/')));
    }
    // Split host from optional :port.
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        let end = v6.find(']').ok_or_else(|| bad("unterminated IPv6 host"))?;
        let after = &v6[end + 1..];
        let port = match after {
            "" => None,
            _ => Some(after.strip_prefix(':').ok_or_else(|| bad("bad port"))?),
        };
        (&authority[..end + 2], port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        }
    };
    if host.is_empty() {
        return Err(bad("missing host"));
    }
    if let Some(p) = port {
        if p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()) {
            return Err(bad("bad port"));
        }
    }
    match scheme {
        "https" => {}
        "http" if matches!(host, "localhost" | "127.0.0.1" | "[::1]") => {}
        "http" => return Err(bad("plain http is only allowed for loopback hosts")),
        _ => return Err(bad("unsupported scheme")),
    }
    Ok(format!("{scheme}://{}", rest.trim_end_matches('/')))
}

/// Validates a release id: a lowercase hyphenated UUID.
pub fn validate_release_id(s: &str) -> Result<()> {
    match uuid::Uuid::parse_str(s) {
        Ok(u) if u.hyphenated().to_string() == s => Ok(()),
        _ => Err(Error::Release("invalid release id".into())),
    }
}

/// Shared HTTP agent. Redirects are disabled on purpose: the service URL is validated
/// (https, or loopback http), and following a 3xx from an attacker-named host could land on
/// a plain-http or internal address (for example a cloud metadata endpoint) and bypass that
/// check. With `max_redirects(0)` a 3xx is returned as-is, and every caller below requires an
/// exact success status, so a redirect is always an error.
fn agent() -> ureq::Agent {
    ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(30)))
            .max_redirects(0)
            .build(),
    )
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

/// Wraps the inner recipients' stanzas under the service-held release key.
///
/// The unlock token is carried in the header by design: anyone holding the file can start
/// the unlock window, but without an inner key or passphrase they still cannot read it.
/// `service` should have passed [`validate_service_url`] (the CLI does this before use).
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
        if inner.len() > MAX_INNER_STANZAS {
            return Err(EncryptError::Io(std::io::Error::other(
                "too many inner stanzas",
            )));
        }
        let json = Zeroizing::new(
            serde_json::to_vec(&InnerStanzas { stanzas: inner })
                .map_err(|e| EncryptError::Io(std::io::Error::other(e)))?,
        );
        if json.len() > MAX_INNER_JSON {
            return Err(EncryptError::Io(std::io::Error::other(
                "inner stanzas too large",
            )));
        }
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
    /// Service clock at the moment of the response (RFC 3339 UTC).
    pub now: String,
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
        // File-controlled values must never reach a URL unchecked.
        let service = match validate_service_url(&service) {
            Ok(s) => s,
            Err(_) => return Some(Err(DecryptError::InvalidHeader)),
        };
        if validate_release_id(&stanza.args[0]).is_err() {
            return Some(Err(DecryptError::InvalidHeader));
        }
        let nonce = match BASE64_STANDARD_NO_PAD.decode(&stanza.args[2]) {
            Ok(n) if n.len() == 12 => n,
            _ => return Some(Err(DecryptError::InvalidHeader)),
        };
        let unlock = match self
            .fetch
            .unlock(&service, &stanza.args[0], &stanza.args[3])
        {
            Ok(u) => u,
            Err(e) => return Some(Err(DecryptError::Io(std::io::Error::other(e)))),
        };
        let aead = ChaCha20Poly1305::new(&Key::from(*unlock.k_release));
        let mut n = [0u8; 12];
        n.copy_from_slice(&nonce);
        let json = match aead.decrypt(&Nonce::from(n), stanza.body.as_slice()) {
            Ok(j) => Zeroizing::new(j),
            Err(_) => return Some(Err(DecryptError::DecryptionFailed)),
        };
        if json.len() > MAX_INNER_JSON {
            return Some(Err(DecryptError::InvalidHeader));
        }
        let inner: InnerStanzas = match serde_json::from_slice(&json) {
            Ok(i) => i,
            Err(_) => return Some(Err(DecryptError::InvalidHeader)),
        };
        if inner.stanzas.len() > MAX_INNER_STANZAS {
            return Some(Err(DecryptError::InvalidHeader));
        }
        let mut stanzas: Vec<Stanza> = Vec::with_capacity(inner.stanzas.len());
        for s in inner.stanzas {
            match BASE64_STANDARD_NO_PAD.decode(s.body) {
                Ok(body) => stanzas.push(Stanza {
                    tag: s.tag,
                    args: s.args,
                    body,
                }),
                Err(_) => return Some(Err(DecryptError::InvalidHeader)),
            }
        }
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
    now: String,
}

pub struct HttpFetch;

impl ReleaseFetch for HttpFetch {
    fn unlock(&self, service: &str, release_id: &str, unlock_token_b64: &str) -> Result<Unlock> {
        let service = validate_service_url(service)?;
        validate_release_id(release_id)?;
        let url = format!("{service}/v1/releases/{release_id}/unlock");
        let res = agent().post(&url).send_json(UnlockBody {
            unlock_token: unlock_token_b64,
        });
        let mut res = match res {
            Ok(r) if r.status().as_u16() == 200 => r,
            Ok(r) => {
                return Err(Error::Release(format!(
                    "unexpected status {}",
                    r.status().as_u16()
                )))
            }
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
            now: body.now,
        })
    }
}

#[derive(Deserialize)]
struct DepositResponse {
    service_key: String,
}

/// Deposits the release key with the service. The service answers `201` with
/// `{ "service_key": "<minisign public key, base64>" }`; that key is returned so the caller
/// can record it in the manifest and later pin receipt verification to it.
pub fn deposit(service: &str, token: &str, d: &Deposit, package_sha256: &str) -> Result<String> {
    let service = validate_service_url(service)?;
    validate_release_id(&d.release_id)?;
    let url = format!("{service}/v1/releases/{}", d.release_id);
    let mut res = agent()
        .put(&url)
        .header("Authorization", &format!("Bearer {token}"))
        .send_json(DepositBody {
            k_release: BASE64_STANDARD_NO_PAD.encode(*d.k_release),
            window_secs: d.window_secs,
            unlock_token_hash: d.unlock_token_hash(),
            package_sha256,
        })
        .map_err(|e| Error::Release(format!("deposit failed: {e}")))?;
    if res.status().as_u16() != 201 {
        return Err(Error::Release(format!(
            "deposit failed: unexpected status {}",
            res.status().as_u16()
        )));
    }
    let body: DepositResponse = res
        .body_mut()
        .read_json()
        .map_err(|e| Error::Release(format!("deposit response: {e}")))?;
    minisign::PublicKey::from_base64(&body.service_key)
        .map_err(|_| Error::Release("service returned an invalid signing key".into()))?;
    Ok(body.service_key)
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
    /// Service clock when the receipt was issued (RFC 3339 UTC). Empty in receipts signed
    /// before 0.2, which carry no clock sample.
    #[serde(default)]
    pub now: String,
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

/// Verifies the receipt's signature and parses it.
///
/// With `expected_service_key = None` this checks integrity against the key embedded in the
/// receipt only (trust-on-first-use): anyone can mint a receipt under their own key.
/// Callers MUST pass the key recorded in the manifest for authenticity, and must compare
/// `release_id` / `package_sha256` against the manifest themselves, or use
/// [`verify_receipt_for`] which does all of that.
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

/// Fully pinned receipt verification: signature under `expected_service_key`, the receipt
/// names exactly this `release_id` and `package_sha256`, and the signed trusted comment is
/// `sealdrop receipt <release_id>`.
pub fn verify_receipt_for(
    s: &SignedReceipt,
    expected_service_key: &str,
    release_id: &str,
    package_sha256: &str,
) -> Result<Receipt> {
    let r = verify_receipt(s, Some(expected_service_key))?;
    if r.release_id != release_id {
        return Err(Error::Verify("receipt is for a different release".into()));
    }
    if r.package_sha256 != package_sha256 {
        return Err(Error::Verify("receipt is for a different package".into()));
    }
    let sig = minisign::SignatureBox::from_string(&s.signature)
        .map_err(|e| Error::Verify(e.to_string()))?;
    let comment = sig
        .trusted_comment()
        .map_err(|e| Error::Verify(e.to_string()))?;
    if comment != format!("sealdrop receipt {release_id}") {
        return Err(Error::Verify("receipt trusted comment mismatch".into()));
    }
    Ok(r)
}

pub fn fetch_receipt(service: &str, token: &str, release_id: &str) -> Result<SignedReceipt> {
    let service = validate_service_url(service)?;
    validate_release_id(release_id)?;
    let url = format!("{service}/v1/releases/{release_id}/receipt");
    let mut res = agent()
        .get(&url)
        .header("Authorization", &format!("Bearer {token}"))
        .call()
        .map_err(|e| Error::Release(format!("receipt fetch failed: {e}")))?;
    if res.status().as_u16() != 200 {
        return Err(Error::Release(format!(
            "receipt fetch failed: unexpected status {}",
            res.status().as_u16()
        )));
    }
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
                now: "2026-10-13T09:00:00Z".into(),
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
        match crate::crypt::decrypt_reader(&ct[..], &ids).err() {
            Some(Error::Decrypt(age::DecryptError::NoMatchingKeys)) => {}
            other => panic!("expected NoMatchingKeys, got {other:?}"),
        }

        // Expired service answer surfaces as an error.
        let id = Identity::new(vec![Box::new(x)], Box::new(MemoryFetch::expired()));
        let ids: Vec<Box<dyn age::Identity>> = vec![Box::new(id)];
        // The fetch error keeps its type, so callers can downcast `ReleaseExpired`.
        match crate::crypt::decrypt_reader(&ct[..], &ids).err() {
            Some(Error::Decrypt(age::DecryptError::Io(e))) => {
                let inner = e.get_ref().and_then(|i| i.downcast_ref::<Error>());
                assert!(matches!(inner, Some(Error::ReleaseExpired)), "{inner:?}");
            }
            other => panic!("expected wrapped ReleaseExpired, got {other:?}"),
        }
    }

    const UUID: &str = "0b1d6a52-8f0e-4c1c-9d1e-5c2b7a3f4e60";

    fn craft_stanza(json: &[u8], d: &Deposit) -> Stanza {
        let nonce = [7u8; 12];
        let aead = ChaCha20Poly1305::new(&Key::from(*d.k_release));
        let body = aead.encrypt(&Nonce::from(nonce), json).unwrap();
        Stanza {
            tag: TAG.into(),
            args: vec![
                UUID.into(),
                BASE64_STANDARD_NO_PAD.encode(b"https://s"),
                BASE64_STANDARD_NO_PAD.encode(nonce),
                d.unlock_token_b64(),
            ],
            body,
        }
    }

    #[test]
    fn rejects_non_https_service_and_bad_release_id() {
        for bad in [
            "http://evil.example",
            "ftp://x",
            "https://h/x?y",
            "https://h/x#f",
            "javascript:alert(1)",
            "https://h x",
            "https://user@evil.example",
            "https://",
            "http://127.0.0.1:notaport",
        ] {
            assert!(validate_service_url(bad).is_err(), "{bad}");
        }
        assert_eq!(
            validate_service_url("http://127.0.0.1:8787").unwrap(),
            "http://127.0.0.1:8787"
        );
        assert_eq!(
            validate_service_url("https://release.example/").unwrap(),
            "https://release.example"
        );
        assert!(validate_service_url("http://localhost:1").is_ok());
        assert!(validate_service_url("http://[::1]:8787").is_ok());
        assert!(validate_service_url("memory://svc").is_ok());
        assert!(validate_release_id(UUID).is_ok());
        for bad in [
            "not-a-uuid",
            "../../etc/passwd",
            "0B1D6A52-8F0E-4C1C-9D1E-5C2B7A3F4E60",
            "0b1d6a528f0e4c1c9d1e5c2b7a3f4e60",
            "",
        ] {
            assert!(validate_release_id(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn identity_refuses_hostile_header_values_without_fetching() {
        struct Boom;
        impl ReleaseFetch for Boom {
            fn unlock(&self, _: &str, _: &str, _: &str) -> Result<Unlock> {
                panic!("fetch must not be reached");
            }
        }
        let d = Deposit::new(60);
        let id = Identity::new(Vec::new(), Box::new(Boom));
        let mut st = craft_stanza(b"{\"stanzas\":[]}", &d);
        st.args[1] = BASE64_STANDARD_NO_PAD.encode(b"http://evil.example");
        assert!(matches!(
            age::Identity::unwrap_stanza(&id, &st),
            Some(Err(DecryptError::InvalidHeader))
        ));
        let mut st = craft_stanza(b"{\"stanzas\":[]}", &d);
        st.args[0] = "../x".into();
        assert!(matches!(
            age::Identity::unwrap_stanza(&id, &st),
            Some(Err(DecryptError::InvalidHeader))
        ));
    }

    #[test]
    fn malformed_inner_json_is_rejected() {
        let d = Deposit::new(60);
        let id = Identity::new(Vec::new(), Box::new(MemoryFetch::serving(&d)));
        // Bad base64 in an inner body is rejected, not skipped.
        let bad = br#"{"stanzas":[{"tag":"X25519","args":[],"body":"!!!"}]}"#;
        assert!(matches!(
            age::Identity::unwrap_stanza(&id, &craft_stanza(bad, &d)),
            Some(Err(DecryptError::InvalidHeader))
        ));
        // Oversized decrypted JSON is rejected before parsing.
        let big = vec![b' '; MAX_INNER_JSON + 1];
        assert!(matches!(
            age::Identity::unwrap_stanza(&id, &craft_stanza(&big, &d)),
            Some(Err(DecryptError::InvalidHeader))
        ));
        // More than 64 inner stanzas is rejected.
        let one = r#"{"tag":"X25519","args":[],"body":"AAAA"}"#;
        let many = format!(r#"{{"stanzas":[{}]}}"#, vec![one; 65].join(","));
        assert!(matches!(
            age::Identity::unwrap_stanza(&id, &craft_stanza(many.as_bytes(), &d)),
            Some(Err(DecryptError::InvalidHeader))
        ));
    }

    #[test]
    fn wrap_caps_inner_stanza_count() {
        let d = Deposit::new(60);
        let inner: Vec<Box<dyn age::Recipient + Send>> = (0..65)
            .map(|_| {
                Box::new(age::x25519::Identity::generate().to_public())
                    as Box<dyn age::Recipient + Send>
            })
            .collect();
        let rs: Vec<Box<dyn age::Recipient + Send>> =
            vec![Box::new(Recipient::new(inner, &d, "https://s"))];
        assert!(crate::crypt::encrypt_writer(Vec::new(), &rs, false).is_err());
    }

    #[test]
    fn inner_scrypt_round_trip_and_wrong_passphrase() {
        let pass = SecretString::from("correct horse".to_string());
        let d = Deposit::new(60);
        let inner: Vec<Box<dyn age::Recipient + Send>> = vec![Box::new(
            crate::crypt::scrypt_recipient(pass.clone(), 10).unwrap(),
        )];
        let rs: Vec<Box<dyn age::Recipient + Send>> = vec![Box::new(Recipient::new(
            inner,
            &d,
            "https://release.example",
        ))];
        let mut w = crate::crypt::encrypt_writer(Vec::new(), &rs, false).unwrap();
        w.write_all(b"timed pass").unwrap();
        let ct = w.finish().unwrap();

        let id = Identity::new(
            vec![Box::new(crate::crypt::scrypt_identity(pass))],
            Box::new(MemoryFetch::serving(&d)),
        );
        let ids: Vec<Box<dyn age::Identity>> = vec![Box::new(id)];
        let mut out = Vec::new();
        crate::crypt::decrypt_reader(&ct[..], &ids)
            .unwrap()
            .read_to_end(&mut out)
            .unwrap();
        assert_eq!(out, b"timed pass");

        let wrong = SecretString::from("wrong".to_string());
        let id = Identity::new(
            vec![Box::new(crate::crypt::scrypt_identity(wrong))],
            Box::new(MemoryFetch::serving(&d)),
        );
        let ids: Vec<Box<dyn age::Identity>> = vec![Box::new(id)];
        assert!(crate::crypt::decrypt_reader(&ct[..], &ids).is_err());
    }

    fn receipt_for(kp: &minisign::KeyPair, id: &str, sha: &str) -> Receipt {
        Receipt {
            release_id: id.into(),
            package_sha256: sha.into(),
            first_unlock: None,
            expires_at: None,
            unlock_count: 0,
            service_key: kp.pk.to_base64(),
            now: "2026-10-13T09:00:00Z".into(),
        }
    }

    #[test]
    fn verify_receipt_for_pins_key_release_hash_and_comment() {
        let kp = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
        let signed = sign_receipt(&receipt_for(&kp, "rid", "abc"), &kp.sk, &kp.pk).unwrap();
        let key = kp.pk.to_base64();
        assert!(verify_receipt_for(&signed, &key, "rid", "abc").is_ok());
        assert!(verify_receipt_for(&signed, &key, "other", "abc").is_err());
        assert!(verify_receipt_for(&signed, &key, "rid", "zzz").is_err());

        // Expected key differs from the signer: rejected.
        let other = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
        assert!(verify_receipt_for(&signed, &other.pk.to_base64(), "rid", "abc").is_err());

        // Trusted comment must name this release, even under the right key.
        let r = receipt_for(&kp, "rid", "abc");
        let json = serde_json::to_string_pretty(&r).unwrap();
        let sig = minisign::sign(
            Some(&kp.pk),
            &kp.sk,
            std::io::Cursor::new(json.as_bytes()),
            Some("sealdrop receipt someone-else"),
            None,
        )
        .unwrap();
        let wrong_comment = SignedReceipt {
            receipt_json: json,
            signature: sig.into_string(),
        };
        assert!(verify_receipt(&wrong_comment, Some(&key)).is_ok());
        assert!(verify_receipt_for(&wrong_comment, &key, "rid", "abc").is_err());
    }

    #[test]
    fn unpinned_verify_receipt_trusts_the_embedded_key() {
        // Documents the weakness: a receipt minted under an attacker key passes `None`.
        let attacker = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
        let forged = sign_receipt(
            &receipt_for(&attacker, "rid", "abc"),
            &attacker.sk,
            &attacker.pk,
        )
        .unwrap();
        assert!(verify_receipt(&forged, None).is_ok());
        let real = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
        assert!(verify_receipt(&forged, Some(&real.pk.to_base64())).is_err());
        assert!(verify_receipt_for(&forged, &real.pk.to_base64(), "rid", "abc").is_err());
    }

    #[test]
    fn http_client_never_follows_redirects() {
        use std::net::TcpListener;
        let target = TcpListener::bind("127.0.0.1:0").unwrap();
        target.set_nonblocking(true).unwrap();
        let tport = target.local_addr().unwrap().port();
        let front = TcpListener::bind("127.0.0.1:0").unwrap();
        let fport = front.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut c, _) = front.accept().unwrap();
            let mut buf = [0u8; 2048];
            let _ = c.read(&mut buf);
            let resp = format!(
                "HTTP/1.1 302 Found
Location: http://127.0.0.1:{tport}/x
Content-Length: 0
Connection: close

"
            );
            c.write_all(resp.as_bytes()).unwrap();
        });
        let res = HttpFetch.unlock(&format!("http://127.0.0.1:{fport}"), UUID, "dG9r");
        server.join().unwrap();
        assert!(matches!(res, Err(Error::Release(_))));
        assert!(
            target.accept().is_err(),
            "redirect target must never be contacted"
        );
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
            now: "2026-10-13T09:05:00Z".into(),
        };
        let signed = sign_receipt(&receipt, &kp.sk, &kp.pk).unwrap();
        let back = verify_receipt(&signed, Some(&kp.pk.to_base64())).unwrap();
        assert_eq!(back.unlock_count, 1);
        assert_eq!(back.now, "2026-10-13T09:05:00Z");
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
