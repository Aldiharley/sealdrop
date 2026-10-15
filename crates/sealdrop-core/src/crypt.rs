//! Thin wrapper over the `age` crate (spec 4.2, 5.1, 5.2). Nothing below the age
//! format layer is implemented here.

use std::cell::Cell;
use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::io::{BufReader, Read, Write};
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use age::armor::{ArmoredReader, ArmoredWriter, Format};
use age::secrecy::{ExposeSecret, SecretString};
use age::stream::StreamWriter;
use age_core::format::{FileKey, Stanza, FILE_KEY_BYTES};
use zeroize::Zeroizing;

use crate::hashing::sha256_hex;
use crate::{Error, Result};

pub const SCRYPT_DEFAULT_LOG_N: u8 = 18;
pub const SCRYPT_HIGH_LOG_N: u8 = 20;
pub const SCRYPT_MAX_DECRYPT_LOG_N: u8 = 22;

/// Error-safe rendering of unparseable recipient input: the input may be a secret
/// pasted into the wrong field, so only a public-looking `age1` prefix is kept.
fn redact(s: &str) -> String {
    if s.starts_with("age1") {
        let prefix: String = s.chars().take(12).collect();
        format!("{prefix}\u{2026}")
    } else {
        "(redacted)".to_string()
    }
}

/// HRP of age's native post-quantum recipients.
const PQ_RECIPIENT_HRP: &str = "age1pq";

/// The Bech32 human-readable part (the text before the last `1`), lowercased.
fn bech32_hrp(s: &str) -> Option<String> {
    s.rfind('1').map(|i| s[..i].to_ascii_lowercase())
}

/// `Pq` and `Hybrid` are large (both hold an ML-KEM public key); kept unboxed to match
/// the module interface.
#[derive(Clone)]
#[allow(clippy::large_enum_variant)]
pub enum Recipient {
    X25519(age::x25519::Recipient),
    /// age 1.3's native post-quantum type (`age1pq1…`, ML-KEM-768 + X25519); `Hybrid`
    /// below is the tagged P-256 variant.
    Pq(crate::pq::Recipient),
    Hybrid(age::tagpq::Recipient),
    Plugin(age::plugin::Recipient),
}

impl Recipient {
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        if let Ok(r) = age::x25519::Recipient::from_str(s) {
            return Ok(Self::X25519(r));
        }
        // `age1pq1…` is always the native PQ type. A malformed one is an error: falling
        // through would parse it as plugin `pq` and run any `age-plugin-pq` on PATH.
        match crate::pq::Recipient::from_str(s) {
            Ok(r) => return Ok(Self::Pq(r)),
            Err(_) if bech32_hrp(s).as_deref() == Some(PQ_RECIPIENT_HRP) => {
                return Err(Error::InvalidRecipient(redact(s)));
            }
            Err(_) => {}
        }
        if let Ok(r) = age::tagpq::Recipient::from_str(s) {
            return Ok(Self::Hybrid(r));
        }
        if let Ok(r) = age::plugin::Recipient::from_str(s) {
            return Ok(Self::Plugin(r));
        }
        Err(Error::InvalidRecipient(redact(s)))
    }

    pub fn kind(&self) -> String {
        match self {
            Self::X25519(_) => "x25519".into(),
            Self::Pq(_) => "pq".into(),
            Self::Hybrid(_) => "hybrid-pq".into(),
            Self::Plugin(p) => format!("plugin:{}", p.plugin()),
        }
    }

    pub fn plugin_name(&self) -> Option<String> {
        match self {
            Self::Plugin(p) => Some(p.plugin().to_string()),
            _ => None,
        }
    }

    /// First 16 hex chars of SHA-256 of the recipient string.
    pub fn fingerprint(&self) -> String {
        sha256_hex(self.to_string().as_bytes())[..16].to_string()
    }
}

impl fmt::Display for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::X25519(r) => write!(f, "{r}"),
            Self::Pq(r) => write!(f, "{r}"),
            Self::Hybrid(r) => write!(f, "{r}"),
            Self::Plugin(r) => write!(f, "{r}"),
        }
    }
}

/// Recipients are public keys; `Debug` shows the kind and fingerprint only.
impl fmt::Debug for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Recipient({}, {})", self.kind(), self.fingerprint())
    }
}

/// Builds a passphrase recipient. `log_n` must be in `1..=SCRYPT_MAX_DECRYPT_LOG_N` so
/// that a package we write can always be opened by our own decrypt limit.
pub fn scrypt_recipient(pass: SecretString, log_n: u8) -> Result<age::scrypt::Recipient> {
    if !(1..=SCRYPT_MAX_DECRYPT_LOG_N).contains(&log_n) {
        return Err(Error::Other(format!(
            "scrypt work factor {log_n} out of range 1..={SCRYPT_MAX_DECRYPT_LOG_N}"
        )));
    }
    let mut r = age::scrypt::Recipient::new(pass);
    r.set_work_factor(log_n);
    Ok(r)
}

pub fn scrypt_identity(pass: SecretString) -> age::scrypt::Identity {
    let mut i = age::scrypt::Identity::new(pass);
    i.set_max_work_factor(SCRYPT_MAX_DECRYPT_LOG_N);
    i
}

/// Converts parsed recipients into age recipients; plugin recipients are grouped by
/// plugin name and resolved through the plugin binary on PATH.
pub fn to_age_recipients(specs: &[Recipient]) -> Result<Vec<Box<dyn age::Recipient + Send>>> {
    let mut out: Vec<Box<dyn age::Recipient + Send>> = Vec::new();
    let mut plugins: BTreeMap<String, Vec<age::plugin::Recipient>> = BTreeMap::new();
    for s in specs {
        match s {
            Recipient::X25519(r) => out.push(Box::new(r.clone())),
            Recipient::Pq(r) => out.push(Box::new(r.clone())),
            Recipient::Hybrid(r) => out.push(Box::new(r.clone())),
            Recipient::Plugin(p) => plugins
                .entry(p.plugin().to_string())
                .or_default()
                .push(p.clone()),
        }
    }
    for (name, recips) in plugins {
        let plugin = age::plugin::RecipientPluginV1::new(&name, &recips, &[], age::NoCallbacks)
            .map_err(|e| Error::Other(format!("age-plugin-{name}: {e}")))?;
        out.push(Box::new(plugin));
    }
    Ok(out)
}

/// Builds plugin identities from `AGE-PLUGIN-...` lines.
pub fn plugin_identities(lines: &[&str]) -> Result<Vec<Box<dyn age::Identity>>> {
    let mut by_plugin: BTreeMap<String, Vec<age::plugin::Identity>> = BTreeMap::new();
    for l in lines {
        let id = age::plugin::Identity::from_str(l.trim()).map_err(|_| Error::InvalidIdentity)?;
        by_plugin
            .entry(id.plugin().to_string())
            .or_default()
            .push(id);
    }
    let mut out: Vec<Box<dyn age::Identity>> = Vec::new();
    for (name, ids) in by_plugin {
        let p = age::plugin::IdentityPluginV1::new(&name, &ids, age::NoCallbacks)
            .map_err(|e| Error::Other(format!("age-plugin-{name}: {e}")))?;
        out.push(Box::new(p));
    }
    Ok(out)
}

/// HKDF info string of the manifest `key_commitment` (spec 5.2).
pub const COMMIT_INFO: &[u8] = b"sealdrop/commit/v1";

/// Spec 5.2 `key_commitment`: HKDF-SHA-256(ikm = file key, salt = empty, info = COMMIT_INFO).
pub fn key_commitment(file_key: &FileKey) -> [u8; 32] {
    age_core::primitives::hkdf(&[], COMMIT_INFO, file_key.expose_secret())
}

/// Parses a manifest `key_commitment`: exactly 64 lowercase hex characters.
pub fn parse_commitment(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let v = hex::decode(s).ok()?;
    v.try_into().ok()
}

type CapturedKey = Arc<Mutex<Option<Zeroizing<[u8; FILE_KEY_BYTES]>>>>;

/// Read side of a [`Committing`] recipient: stays usable after the recipient itself has
/// been moved into the encryptor's recipient list.
#[derive(Clone)]
pub struct CommitmentHandle(CapturedKey);

impl CommitmentHandle {
    /// The hex `key_commitment` of the captured file key; `None` until age has called
    /// `wrap_file_key`.
    pub fn commitment_hex(&self) -> Option<String> {
        let g = self.0.lock().ok()?;
        let fk = g.as_ref()?;
        Some(hex::encode(age_core::primitives::hkdf(
            &[],
            COMMIT_INFO,
            &fk[..],
        )))
    }
}

/// Wraps the outer recipient list so `seal` can learn the file key age generated.
/// Replicates age's label rule, because age only sees this one recipient.
pub struct Committing {
    inner: Vec<Box<dyn age::Recipient + Send>>,
    captured: CapturedKey,
}

impl Committing {
    pub fn new(inner: Vec<Box<dyn age::Recipient + Send>>) -> Self {
        Self {
            inner,
            captured: Arc::new(Mutex::new(None)),
        }
    }

    /// A shared reader of the captured key, to take before boxing this recipient.
    pub fn handle(&self) -> CommitmentHandle {
        CommitmentHandle(Arc::clone(&self.captured))
    }

    pub fn commitment_hex(&self) -> Option<String> {
        self.handle().commitment_hex()
    }
}

impl age::Recipient for Committing {
    fn wrap_file_key(
        &self,
        file_key: &FileKey,
    ) -> std::result::Result<(Vec<Stanza>, HashSet<String>), age::EncryptError> {
        let mut stanzas = Vec::new();
        let mut labels: Option<HashSet<String>> = None;
        for r in &self.inner {
            let (s, l) = r.wrap_file_key(file_key)?;
            match &labels {
                None => labels = Some(l),
                Some(prev) if *prev != l => {
                    return Err(age::EncryptError::IncompatibleRecipients {
                        l_labels: prev.clone(),
                        r_labels: l,
                    })
                }
                Some(_) => {}
            }
            stanzas.extend(s);
        }
        if stanzas.is_empty() {
            return Err(age::EncryptError::MissingRecipients);
        }
        let mut g = self.captured.lock().map_err(|_| {
            age::EncryptError::Io(std::io::Error::other("file key capture lock poisoned"))
        })?;
        *g = Some(Zeroizing::new(*file_key.expose_secret()));
        Ok((stanzas, labels.unwrap_or_default()))
    }
}

/// Wraps the outer identity so `open` can refuse a file key that does not match the signed
/// manifest's `key_commitment` before age ever derives a payload key.
pub struct CommittedIdentity<'a> {
    inner: &'a dyn age::Identity,
    expected: Option<[u8; 32]>,
    mismatch: Cell<bool>,
}

impl<'a> CommittedIdentity<'a> {
    pub fn new(inner: &'a dyn age::Identity, expected: Option<[u8; 32]>) -> Self {
        Self {
            inner,
            expected,
            mismatch: Cell::new(false),
        }
    }

    /// True once an unwrapped file key failed the commitment check.
    pub fn mismatched(&self) -> bool {
        self.mismatch.get()
    }

    fn check(
        &self,
        r: Option<std::result::Result<FileKey, age::DecryptError>>,
    ) -> Option<std::result::Result<FileKey, age::DecryptError>> {
        match (&self.expected, r) {
            (Some(want), Some(Ok(fk))) => {
                use subtle::ConstantTimeEq;
                if key_commitment(&fk).ct_eq(want).into() {
                    Some(Ok(fk))
                } else {
                    self.mismatch.set(true);
                    Some(Err(age::DecryptError::InvalidHeader))
                }
            }
            (_, r) => r,
        }
    }
}

impl age::Identity for CommittedIdentity<'_> {
    fn unwrap_stanza(
        &self,
        stanza: &Stanza,
    ) -> Option<std::result::Result<FileKey, age::DecryptError>> {
        self.check(self.inner.unwrap_stanza(stanza))
    }

    fn unwrap_stanzas(
        &self,
        stanzas: &[Stanza],
    ) -> Option<std::result::Result<FileKey, age::DecryptError>> {
        self.check(self.inner.unwrap_stanzas(stanzas))
    }
}

#[must_use = "call finish() or the file is truncated"]
pub struct CipherWriter<W: Write> {
    inner: StreamWriter<ArmoredWriter<W>>,
}

impl<W: Write> Write for CipherWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

impl<W: Write> CipherWriter<W> {
    /// Completes the age stream (final chunk and armor trailer) and returns the sink.
    /// Dropping the writer without calling this leaves a truncated, undecryptable file.
    pub fn finish(self) -> Result<W> {
        let armored = self.inner.finish()?;
        Ok(armored.finish()?)
    }
}

pub fn encrypt_writer<W: Write>(
    out: W,
    recipients: &[Box<dyn age::Recipient + Send>],
    armor: bool,
) -> Result<CipherWriter<W>> {
    let enc = age::Encryptor::with_recipients(
        recipients.iter().map(|r| r.as_ref() as &dyn age::Recipient),
    )?;
    let format = if armor {
        Format::AsciiArmor
    } else {
        Format::Binary
    };
    let armored = ArmoredWriter::wrap_output(out, format)?;
    Ok(CipherWriter {
        inner: enc.wrap_output(armored)?,
    })
}

// Lenient only in the safe direction: a binary age file never starts with whitespace.
/// Drops leading ASCII whitespace (space, tab, CR, LF) from the stream, once, and then
/// passes everything through unchanged. The age crate only detects armor at the very start
/// of its input, but the armor spec allows whitespace around armored files. A binary age
/// file starts with `age-encryption.org/v1`, so skipping whitespace cannot alter one.
struct SkipLeadingWhitespace<R: Read> {
    inner: R,
    started: bool,
}

impl<R: Read> Read for SkipLeadingWhitespace<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.started || buf.is_empty() {
            return self.inner.read(buf);
        }
        loop {
            let n = self.inner.read(buf)?;
            if n == 0 {
                return Ok(0);
            }
            if let Some(i) = buf[..n]
                .iter()
                .position(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
            {
                buf.copy_within(i..n, 0);
                self.started = true;
                return Ok(n - i);
            }
        }
    }
}

pub fn decrypt_reader<'a, R: Read>(
    input: R,
    identities: &[Box<dyn age::Identity + 'a>],
) -> Result<impl Read> {
    let input = SkipLeadingWhitespace {
        inner: input,
        started: false,
    };
    let armored = ArmoredReader::new(BufReader::new(input));
    let dec = age::Decryptor::new(armored)?;
    let reader = dec.decrypt(identities.iter().map(|i| i.as_ref() as &dyn age::Identity))?;
    Ok(reader)
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::secrecy::ExposeSecret;
    use std::io::{Read, Write};

    #[test]
    fn parses_x25519_recipient_and_fingerprints() {
        let id = age::x25519::Identity::generate();
        let s = id.to_public().to_string();
        let r = Recipient::parse(&s).unwrap();
        assert_eq!(r.kind(), "x25519");
        assert_eq!(r.fingerprint().len(), 16);
        assert_eq!(r.to_string(), s);
        assert!(Recipient::parse("age1notvalid").is_err());
    }

    #[test]
    fn parses_pq_recipient_before_plugin_fallback() {
        let id = crate::pq::Identity::generate();
        let s = id.to_public().to_string();
        let r = Recipient::parse(&s).unwrap();
        assert!(matches!(r, Recipient::Pq(_)));
        assert_eq!(r.kind(), "pq");
        assert_eq!(r.plugin_name(), None);
        assert_eq!(r.to_string(), s);
        assert_eq!(r.fingerprint().len(), 16);
    }

    #[test]
    fn malformed_pq_recipient_is_an_error_not_a_plugin() {
        let hrp = bech32::Hrp::parse("age1pq").unwrap();
        // Checksum-valid, but a 32-byte payload instead of 1216.
        let short = age_core::primitives::bech32_encode(hrp, &[7u8; 32]);
        // A real recipient with its X25519 half zeroed (low order).
        let good = crate::pq::Identity::generate().to_public().to_string();
        let mut bytes: Vec<u8> =
            age_core::primitives::bech32_decode(&good, |_| (), |_| Ok(()), |_, b| Ok(b.collect()))
                .unwrap();
        let n = bytes.len();
        bytes[n - 32..].fill(0);
        let low_order = age_core::primitives::bech32_encode(hrp, &bytes);
        for s in [short.clone(), short.to_uppercase(), low_order] {
            match Recipient::parse(&s) {
                Err(Error::InvalidRecipient(_)) => {}
                other => panic!(
                    "expected InvalidRecipient, got {:?}",
                    other.map(|r| r.kind())
                ),
            }
        }
    }

    #[test]
    fn round_trips_to_pq_recipient() {
        let id = crate::pq::Identity::generate();
        let specs = vec![Recipient::parse(&id.to_public().to_string()).unwrap()];
        let recips = to_age_recipients(&specs).unwrap();
        let mut w = encrypt_writer(Vec::new(), &recips, false).unwrap();
        w.write_all(b"pq hello").unwrap();
        let ct = w.finish().unwrap();
        let ids: Vec<Box<dyn age::Identity>> = vec![Box::new(id)];
        let mut pt = Vec::new();
        decrypt_reader(&ct[..], &ids)
            .unwrap()
            .read_to_end(&mut pt)
            .unwrap();
        assert_eq!(pt, b"pq hello");
    }

    #[test]
    fn parses_plugin_recipient_name() {
        // Synthetic recipient with a valid Bech32 checksum; parsing never runs a plugin.
        let s = bech32::encode::<bech32::Bech32>(
            bech32::Hrp::parse("age1yubikey").unwrap(),
            &[1u8; 32],
        )
        .unwrap();
        let r = Recipient::parse(&s);
        match r {
            Ok(Recipient::Plugin(p)) => assert_eq!(p.plugin(), "yubikey"),
            other => panic!(
                "expected plugin recipient, got {:?}",
                other.map(|r| r.kind())
            ),
        }
    }

    #[test]
    fn round_trips_binary_and_armored_to_x25519() {
        let id = age::x25519::Identity::generate();
        let specs = vec![Recipient::parse(&id.to_public().to_string()).unwrap()];
        for armor in [false, true] {
            let recips = to_age_recipients(&specs).unwrap();
            let mut w = encrypt_writer(Vec::new(), &recips, armor).unwrap();
            w.write_all(b"hello sealdrop").unwrap();
            let ct = w.finish().unwrap();
            if armor {
                assert!(ct.starts_with(b"-----BEGIN AGE ENCRYPTED FILE-----"));
            } else {
                assert!(ct.starts_with(b"age-encryption.org/v1"));
            }
            let ids: Vec<Box<dyn age::Identity>> = vec![Box::new(id.clone())];
            let mut r = decrypt_reader(&ct[..], &ids).unwrap();
            let mut pt = Vec::new();
            r.read_to_end(&mut pt).unwrap();
            assert_eq!(pt, b"hello sealdrop");
        }
    }

    #[test]
    fn decrypts_armor_with_leading_whitespace() {
        let pass = SecretString::from("p".to_string());
        let r: Vec<Box<dyn age::Recipient + Send>> =
            vec![Box::new(scrypt_recipient(pass.clone(), 10).unwrap())];
        let mut w = encrypt_writer(Vec::new(), &r, true).unwrap();
        w.write_all(b"ws").unwrap();
        let mut ct = b"  \n\t".to_vec();
        ct.extend(w.finish().unwrap());
        let ids: Vec<Box<dyn age::Identity>> = vec![Box::new(scrypt_identity(pass))];
        let mut out = Vec::new();
        decrypt_reader(&ct[..], &ids)
            .unwrap()
            .read_to_end(&mut out)
            .unwrap();
        assert_eq!(out, b"ws");
    }

    #[test]
    fn round_trips_scrypt_and_rejects_wrong_passphrase() {
        let pass = SecretString::from("correct horse battery staple".to_string());
        let r: Vec<Box<dyn age::Recipient + Send>> =
            vec![Box::new(scrypt_recipient(pass.clone(), 10).unwrap())];
        let mut w = encrypt_writer(Vec::new(), &r, false).unwrap();
        w.write_all(b"pw").unwrap();
        let ct = w.finish().unwrap();
        let ids: Vec<Box<dyn age::Identity>> = vec![Box::new(scrypt_identity(pass.clone()))];
        let mut out = Vec::new();
        decrypt_reader(&ct[..], &ids)
            .unwrap()
            .read_to_end(&mut out)
            .unwrap();
        assert_eq!(out, b"pw");
        assert_eq!(pass.expose_secret().len(), 28);

        let wrong: Vec<Box<dyn age::Identity>> = vec![Box::new(scrypt_identity(
            SecretString::from("nope".to_string()),
        ))];
        assert!(matches!(
            decrypt_reader(&ct[..], &wrong),
            Err(Error::Decrypt(_))
        ));

        for bad in [0u8, 23, 64] {
            assert!(scrypt_recipient(pass.clone(), bad).is_err(), "log_n {bad}");
        }
        assert!(scrypt_recipient(pass.clone(), SCRYPT_MAX_DECRYPT_LOG_N).is_ok());
    }

    #[test]
    fn invalid_recipient_error_never_echoes_secret_material() {
        let id = age::x25519::Identity::generate();
        let secret = id.to_string();
        let secret = secret.expose_secret();
        let msg = match Recipient::parse(secret) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("a secret key must not parse as a recipient"),
        };
        assert!(!msg.contains("AGE-SECRET-KEY"), "{msg}");
        for w in secret.as_bytes().windows(20) {
            assert!(!msg.contains(std::str::from_utf8(w).unwrap()), "{msg}");
        }

        let msg = Recipient::parse("age1notvalid").unwrap_err().to_string();
        assert!(msg.contains("age1notvalid"), "{msg}");
        let long = Recipient::parse("age1notvalidbutlongerthantwelve")
            .unwrap_err()
            .to_string();
        assert!(long.contains("age1notvalid\u{2026}"), "{long}");
        assert!(!long.contains("longer"), "{long}");
    }

    #[test]
    fn plugin_recipient_with_absent_binary_is_a_clean_error() {
        let s = bech32::encode::<bech32::Bech32>(
            bech32::Hrp::parse("age1sealdroptest").unwrap(),
            &[2u8; 32],
        )
        .unwrap();
        let specs = vec![Recipient::parse(&s).unwrap()];
        assert_eq!(specs[0].kind(), "plugin:sealdroptest");
        assert_eq!(specs[0].plugin_name().as_deref(), Some("sealdroptest"));
        match to_age_recipients(&specs) {
            Err(Error::Other(m)) => assert!(m.contains("age-plugin-sealdroptest"), "{m}"),
            other => panic!("expected Error::Other, got ok={}", other.is_ok()),
        }
    }

    #[test]
    fn committing_recipient_captures_the_file_key_and_checks_labels() {
        use age_core::format::FileKey;
        let id = age::x25519::Identity::generate();
        let c = Committing::new(vec![Box::new(id.to_public())]);
        assert!(c.commitment_hex().is_none());
        let fk = FileKey::new(Box::new([9u8; 16]));
        let (stanzas, labels) = age::Recipient::wrap_file_key(&c, &fk).unwrap();
        assert_eq!(stanzas.len(), 1);
        assert!(labels.is_empty());
        assert_eq!(
            c.commitment_hex().unwrap(),
            hex::encode(key_commitment(&fk))
        );
        assert_eq!(
            parse_commitment(&c.commitment_hex().unwrap()).unwrap(),
            key_commitment(&fk)
        );
        assert!(parse_commitment("ABCD").is_none());
        // Mixed label sets are refused, as age itself would.
        let pq = crate::pq::Identity::generate();
        let mixed = Committing::new(vec![Box::new(id.to_public()), Box::new(pq.to_public())]);
        assert!(matches!(
            age::Recipient::wrap_file_key(&mixed, &fk),
            Err(age::EncryptError::IncompatibleRecipients { .. })
        ));
    }

    #[test]
    fn committed_identity_refuses_a_wrong_commitment() {
        use age_core::format::FileKey;
        let id = age::x25519::Identity::generate();
        let fk = FileKey::new(Box::new([3u8; 16]));
        let (stanzas, _) = age::Recipient::wrap_file_key(&id.to_public(), &fk).unwrap();
        let good = CommittedIdentity::new(&id, Some(key_commitment(&fk)));
        assert!(matches!(
            age::Identity::unwrap_stanza(&good, &stanzas[0]),
            Some(Ok(_))
        ));
        assert!(!good.mismatched());
        let bad = CommittedIdentity::new(&id, Some([0u8; 32]));
        assert!(matches!(
            age::Identity::unwrap_stanza(&bad, &stanzas[0]),
            Some(Err(_))
        ));
        assert!(bad.mismatched());
        let unchecked = CommittedIdentity::new(&id, None);
        assert!(matches!(
            age::Identity::unwrap_stanza(&unchecked, &stanzas[0]),
            Some(Ok(_))
        ));
    }

    #[test]
    fn plugin_identities_rejects_invalid_line() {
        assert!(matches!(
            plugin_identities(&["not an identity"]),
            Err(Error::InvalidIdentity)
        ));
    }
}
