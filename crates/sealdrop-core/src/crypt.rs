//! Thin wrapper over the `age` crate (spec 4.2, 5.1, 5.2). Nothing below the age
//! format layer is implemented here.

use std::collections::BTreeMap;
use std::fmt;
use std::io::{BufReader, Read, Write};
use std::str::FromStr;

use age::armor::{ArmoredReader, ArmoredWriter, Format};
use age::secrecy::SecretString;
use age::stream::StreamWriter;

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

/// `Hybrid` is large (ML-KEM public key); kept unboxed to match the module interface.
#[derive(Clone)]
#[allow(clippy::large_enum_variant)]
pub enum Recipient {
    X25519(age::x25519::Recipient),
    Hybrid(age::tagpq::Recipient),
    Plugin(age::plugin::Recipient),
}

impl Recipient {
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        if let Ok(r) = age::x25519::Recipient::from_str(s) {
            return Ok(Self::X25519(r));
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
pub fn plugin_identities(lines: &[String]) -> Result<Vec<Box<dyn age::Identity>>> {
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

pub fn decrypt_reader<'a, R: Read>(
    input: R,
    identities: &[Box<dyn age::Identity + 'a>],
) -> Result<impl Read> {
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
    fn plugin_identities_rejects_invalid_line() {
        assert!(matches!(
            plugin_identities(&["not an identity".to_string()]),
            Err(Error::InvalidIdentity)
        ));
    }
}
