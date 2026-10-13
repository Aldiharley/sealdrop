//! Identity store: age identity, minisign signing key, trusted signers, settings.

use std::fmt;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use age::secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

#[derive(Clone, Serialize, Deserialize)]
pub struct Settings {
    #[serde(default)]
    pub release_service: Option<String>,
    /// Secret: never printed by `Debug`.
    #[serde(default)]
    pub release_token: Option<String>,
    #[serde(default = "default_log_n")]
    pub scrypt_log_n: u8,
    #[serde(default)]
    pub armor: bool,
    #[serde(default)]
    pub argon2id: bool,
}

impl fmt::Debug for Settings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let token = self.release_token.as_ref().map(|_| "<redacted>");
        f.debug_struct("Settings")
            .field("release_service", &self.release_service)
            .field("release_token", &token)
            .field("scrypt_log_n", &self.scrypt_log_n)
            .field("armor", &self.armor)
            .field("argon2id", &self.argon2id)
            .finish()
    }
}

fn default_log_n() -> u8 {
    crate::crypt::SCRYPT_DEFAULT_LOG_N
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            release_service: None,
            release_token: None,
            scrypt_log_n: default_log_n(),
            armor: false,
            argon2id: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct KeyInfo {
    pub recipient: String,
    pub signer: String,
}

pub struct KeyStore {
    dir: PathBuf,
}

/// Write a file that only the owner can read. On Unix the file is created with mode 0600
/// (so there is no window where it is world-readable) and the mode is re-asserted for
/// files that already existed.
fn write_private(path: &Path, contents: &str) -> Result<()> {
    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.set_permissions(fs::Permissions::from_mode(0o600))?;
        f
    };
    #[cfg(not(unix))]
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    file.write_all(contents.as_bytes())?;
    file.flush()?;
    Ok(())
}

impl KeyStore {
    pub fn default_dir() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("sealdrop")
    }

    pub fn open(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn identity_path(&self) -> PathBuf {
        self.dir.join("identity.txt")
    }
    fn sign_key_path(&self) -> PathBuf {
        self.dir.join("sign.key")
    }
    fn sign_pub_path(&self) -> PathBuf {
        self.dir.join("sign.pub")
    }
    fn trusted_dir(&self) -> PathBuf {
        self.dir.join("trusted")
    }
    fn settings_path(&self) -> PathBuf {
        self.dir.join("settings.json")
    }

    pub fn exists(&self) -> bool {
        self.identity_path().exists() && self.sign_key_path().exists()
    }

    pub fn generate(&self, force: bool) -> Result<KeyInfo> {
        if self.exists() && !force {
            return Err(Error::KeyStore(format!(
                "identity already exists in {}; use --force to replace",
                self.dir.display()
            )));
        }
        fs::create_dir_all(&self.dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&self.dir, fs::Permissions::from_mode(0o700))?;
        }
        let id = age::x25519::Identity::generate();
        let recipient = id.to_public().to_string();
        let created = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
        let body = zeroize::Zeroizing::new(format!(
            "# created: {created}\n# public key: {recipient}\n{}\n",
            id.to_string().expose_secret()
        ));
        write_private(&self.identity_path(), &body)?;

        let kp = minisign::KeyPair::generate_unencrypted_keypair()
            .map_err(|e| Error::KeyStore(e.to_string()))?;
        let sk_box = kp
            .sk
            .to_box(Some("sealdrop signing key"))
            .map_err(|e| Error::KeyStore(e.to_string()))?;
        write_private(&self.sign_key_path(), &sk_box.into_string())?;
        let pk_box = kp.pk.to_box().map_err(|e| Error::KeyStore(e.to_string()))?;
        fs::write(self.sign_pub_path(), pk_box.into_string())?;
        Ok(KeyInfo {
            recipient,
            signer: kp.pk.to_base64(),
        })
    }

    fn identity_lines(&self) -> Result<Vec<String>> {
        let text = zeroize::Zeroizing::new(
            fs::read_to_string(self.identity_path())
                .map_err(|_| Error::KeyStore("no identity; run `sealdrop keygen`".into()))?,
        );
        Ok(text
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect())
    }

    pub fn identity(&self) -> Result<age::x25519::Identity> {
        let line = self
            .identity_lines()?
            .into_iter()
            .find(|l| l.starts_with("AGE-SECRET-KEY-1"))
            .ok_or(Error::InvalidIdentity)?;
        age::x25519::Identity::from_str(&line).map_err(|_| Error::InvalidIdentity)
    }

    /// Lines starting with `AGE-PLUGIN-` (hardware identities the user added by hand).
    pub fn plugin_identity_lines(&self) -> Result<Vec<String>> {
        Ok(self
            .identity_lines()?
            .into_iter()
            .filter(|l| l.starts_with("AGE-PLUGIN-"))
            .collect())
    }

    pub fn recipient_string(&self) -> Result<String> {
        Ok(self.identity()?.to_public().to_string())
    }

    pub fn signing_key(&self) -> Result<minisign::SecretKey> {
        let s = fs::read_to_string(self.sign_key_path())
            .map_err(|_| Error::KeyStore("no signing key".into()))?;
        minisign::SecretKeyBox::from_string(&s)
            .and_then(|b| b.into_unencrypted_secret_key())
            .map_err(|e| Error::KeyStore(e.to_string()))
    }

    pub fn signing_public(&self) -> Result<minisign::PublicKey> {
        let s = fs::read_to_string(self.sign_pub_path())
            .map_err(|_| Error::KeyStore("no signing key".into()))?;
        minisign::PublicKeyBox::from_string(&s)
            .and_then(|b| b.into_public_key())
            .map_err(|e| Error::KeyStore(e.to_string()))
    }

    pub fn signing_public_string(&self) -> Result<String> {
        Ok(self.signing_public()?.to_base64())
    }

    pub fn trusted(&self) -> Result<Vec<(String, minisign::PublicKey)>> {
        let dir = self.trusted_dir();
        if !dir.exists() {
            return Ok(vec![]);
        }
        let mut out = Vec::new();
        for e in fs::read_dir(dir)? {
            let e = e?;
            let name = e.file_name().to_string_lossy().into_owned();
            if let Some(stem) = name.strip_suffix(".pub") {
                let s = fs::read_to_string(e.path())?;
                let pk = minisign::PublicKey::from_base64(s.trim())
                    .map_err(|e| Error::KeyStore(e.to_string()))?;
                out.push((stem.to_string(), pk));
            }
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(out)
    }

    pub fn add_trusted(&self, name: &str, pk_b64: &str) -> Result<()> {
        if name.is_empty() || name.contains(['/', '\\', '.']) {
            return Err(Error::KeyStore("invalid trusted name".into()));
        }
        minisign::PublicKey::from_base64(pk_b64.trim())
            .map_err(|e| Error::KeyStore(e.to_string()))?;
        fs::create_dir_all(self.trusted_dir())?;
        fs::write(
            self.trusted_dir().join(format!("{name}.pub")),
            pk_b64.trim(),
        )?;
        Ok(())
    }

    pub fn remove_trusted(&self, name: &str) -> Result<()> {
        if name.is_empty() || name.contains(['/', '\\', '.']) {
            return Err(Error::KeyStore("invalid trusted name".into()));
        }
        fs::remove_file(self.trusted_dir().join(format!("{name}.pub")))?;
        Ok(())
    }

    pub fn settings(&self) -> Result<Settings> {
        match fs::read(self.settings_path()) {
            Ok(b) => serde_json::from_slice(&b)
                .map_err(|e| Error::KeyStore(format!("settings.json: {e}"))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Settings::default()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn save_settings(&self, s: &Settings) -> Result<()> {
        fs::create_dir_all(&self.dir)?;
        let b = serde_json::to_string_pretty(s).map_err(|e| Error::KeyStore(e.to_string()))?;
        write_private(&self.settings_path(), &b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_persist_and_reload() {
        let d = tempfile::tempdir().unwrap();
        let ks = KeyStore::open(d.path().join("store"));
        assert!(!ks.exists());
        let info = ks.generate(false).unwrap();
        assert!(info.recipient.starts_with("age1"));
        assert!(ks.exists());
        assert_eq!(ks.recipient_string().unwrap(), info.recipient);
        assert_eq!(ks.signing_public_string().unwrap(), info.signer);
        assert!(ks.generate(false).is_err());
        let info2 = ks.generate(true).unwrap();
        assert_ne!(info2.recipient, info.recipient);
        ks.add_trusted("alice", &info.signer).unwrap();
        assert_eq!(ks.trusted().unwrap().len(), 1);
        assert_eq!(ks.trusted().unwrap()[0].0, "alice");
        ks.remove_trusted("alice").unwrap();
        assert!(ks.trusted().unwrap().is_empty());
        let mut s = ks.settings().unwrap();
        assert_eq!(s.scrypt_log_n, 18);
        s.release_service = Some("https://r.example".into());
        ks.save_settings(&s).unwrap();
        assert_eq!(
            ks.settings().unwrap().release_service.as_deref(),
            Some("https://r.example")
        );
    }

    #[test]
    fn settings_debug_redacts_token() {
        let s = Settings {
            release_token: Some("super-secret-token".into()),
            ..Settings::default()
        };
        let dbg = format!("{s:?}");
        assert!(!dbg.contains("super-secret-token"));
        assert!(dbg.contains("release_token: Some(\"<redacted>\")"));
        assert!(format!("{:?}", Settings::default()).contains("release_token: None"));
    }

    #[cfg(unix)]
    #[test]
    fn secret_files_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let ks = KeyStore::open(d.path().join("store"));
        ks.generate(false).unwrap();
        ks.save_settings(&Settings::default()).unwrap();
        for f in ["identity.txt", "sign.key", "settings.json"] {
            let mode = std::fs::metadata(ks.dir().join(f))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "{f}");
        }
    }

    #[test]
    fn identity_and_signing_key_reload() {
        let d = tempfile::tempdir().unwrap();
        let ks = KeyStore::open(d.path().join("store"));
        let info = ks.generate(false).unwrap();
        assert_eq!(
            ks.identity().unwrap().to_public().to_string(),
            info.recipient
        );
        assert!(ks.plugin_identity_lines().unwrap().is_empty());
        let sk = ks.signing_key().unwrap();
        let pk = ks.signing_public().unwrap();
        let sig = crate::manifest::sign(b"m", &sk, &pk, "id").unwrap();
        crate::manifest::verify(b"m", &sig, &pk).unwrap();
    }
}
