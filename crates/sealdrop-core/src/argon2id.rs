//! Optional Argon2id passphrase stanza (spec 5). Off by default. Files using it do not
//! open in stock age tools; the stanza tag makes them fail cleanly with "no matching keys".

use std::collections::HashSet;

use age::secrecy::{ExposeSecret, SecretString};
use age::{DecryptError, EncryptError};
use age_core::format::{FileKey, Stanza, FILE_KEY_BYTES};
use argon2::{Algorithm, Argon2, Version};
use base64::prelude::{Engine, BASE64_STANDARD_NO_PAD};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;
use zeroize::Zeroizing;

pub const TAG: &str = "sealdrop-argon2id";
const SALT_LEN: usize = 16;
const DOMAIN: &[u8] = b"sealdrop-argon2id";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Params {
    pub t: u32,
    pub m_kib: u32,
    pub p: u32,
}

/// Upper bounds accepted on decrypt (spec 5).
pub const MAX: Params = Params {
    t: 10,
    m_kib: 2 * 1024 * 1024,
    p: 8,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// RFC 9106 first recommendation: t=1, m=2 GiB, p=4.
    Desktop,
    /// RFC 9106 second recommendation: t=3, m=256 MiB, p=4.
    Compat,
}

impl Profile {
    pub fn params(self) -> Params {
        match self {
            Profile::Desktop => Params {
                t: 1,
                m_kib: 2 * 1024 * 1024,
                p: 4,
            },
            Profile::Compat => Params {
                t: 3,
                m_kib: 256 * 1024,
                p: 4,
            },
        }
    }
}

fn derive(pass: &SecretString, salt: &[u8], params: Params) -> Result<Zeroizing<[u8; 32]>, String> {
    let p = argon2::Params::new(params.m_kib, params.t, params.p, Some(32))
        .map_err(|e| e.to_string())?;
    let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut full_salt = Vec::with_capacity(DOMAIN.len() + salt.len());
    full_salt.extend_from_slice(DOMAIN);
    full_salt.extend_from_slice(salt);
    let mut out = Zeroizing::new([0u8; 32]);
    a.hash_password_into(pass.expose_secret().as_bytes(), &full_salt, out.as_mut())
        .map_err(|e| e.to_string())?;
    Ok(out)
}

pub struct Recipient {
    pass: SecretString,
    params: Params,
}

impl Recipient {
    pub fn new(pass: SecretString, profile: Profile) -> Self {
        Self {
            pass,
            params: profile.params(),
        }
    }
    pub fn with_params(pass: SecretString, params: Params) -> Self {
        Self { pass, params }
    }
}

impl age::Recipient for Recipient {
    fn wrap_file_key(
        &self,
        file_key: &FileKey,
    ) -> Result<(Vec<Stanza>, HashSet<String>), EncryptError> {
        let mut salt = [0u8; SALT_LEN];
        rand::rng().fill_bytes(&mut salt);
        let key = derive(&self.pass, &salt, self.params)
            .map_err(|e| EncryptError::Io(std::io::Error::other(e)))?;
        let aead = ChaCha20Poly1305::new(&Key::from(*key));
        let body = aead
            .encrypt(&Nonce::from([0u8; 12]), file_key.expose_secret().as_slice())
            .map_err(|_| EncryptError::Io(std::io::Error::other("aead")))?;
        let stanza = Stanza {
            tag: TAG.into(),
            args: vec![
                BASE64_STANDARD_NO_PAD.encode(salt),
                self.params.t.to_string(),
                self.params.m_kib.to_string(),
                self.params.p.to_string(),
            ],
            body,
        };
        let mut labels = HashSet::new();
        labels.insert(TAG.to_string());
        Ok((vec![stanza], labels))
    }
}

pub struct Identity {
    pass: SecretString,
}

impl Identity {
    pub fn new(pass: SecretString) -> Self {
        Self { pass }
    }
}

fn log2_ceil(v: u32) -> u8 {
    (32 - v.saturating_sub(1).leading_zeros()) as u8
}

impl age::Identity for Identity {
    fn unwrap_stanza(&self, stanza: &Stanza) -> Option<Result<FileKey, DecryptError>> {
        if stanza.tag != TAG {
            return None;
        }
        if stanza.args.len() != 4 || stanza.body.len() != 32 {
            return Some(Err(DecryptError::InvalidHeader));
        }
        let salt = match BASE64_STANDARD_NO_PAD.decode(&stanza.args[0]) {
            Ok(s) if s.len() == SALT_LEN => s,
            _ => return Some(Err(DecryptError::InvalidHeader)),
        };
        let parse = |s: &str| s.parse::<u32>().ok().filter(|v| *v > 0);
        let (t, m_kib, p) = match (
            parse(&stanza.args[1]),
            parse(&stanza.args[2]),
            parse(&stanza.args[3]),
        ) {
            (Some(t), Some(m), Some(p)) => (t, m, p),
            _ => return Some(Err(DecryptError::InvalidHeader)),
        };
        if t > MAX.t || m_kib > MAX.m_kib || p > MAX.p {
            return Some(Err(DecryptError::ExcessiveWork {
                required: log2_ceil(m_kib),
                target: log2_ceil(MAX.m_kib),
            }));
        }
        let key = match derive(&self.pass, &salt, Params { t, m_kib, p }) {
            Ok(k) => k,
            Err(_) => return Some(Err(DecryptError::DecryptionFailed)),
        };
        let aead = ChaCha20Poly1305::new(&Key::from(*key));
        match aead.decrypt(&Nonce::from([0u8; 12]), stanza.body.as_slice()) {
            Ok(pt) if pt.len() == FILE_KEY_BYTES => {
                let mut arr = [0u8; FILE_KEY_BYTES];
                arr.copy_from_slice(&pt);
                Some(Ok(FileKey::new(Box::new(arr))))
            }
            _ => Some(Err(DecryptError::DecryptionFailed)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::secrecy::ExposeSecret;
    use std::io::{Read, Write};

    fn small() -> Params {
        Params {
            t: 1,
            m_kib: 8 * 1024,
            p: 1,
        } // fast for tests
    }

    #[test]
    fn wraps_and_unwraps_file_key() {
        let pass = SecretString::from("six eff words go here now".to_string());
        let r = Recipient::with_params(pass.clone(), small());
        let fk = FileKey::new(Box::new([7u8; FILE_KEY_BYTES]));
        let (stanzas, labels) = age::Recipient::wrap_file_key(&r, &fk).unwrap();
        assert_eq!(stanzas.len(), 1);
        assert_eq!(stanzas[0].tag, TAG);
        assert_eq!(stanzas[0].args.len(), 4);
        assert_eq!(stanzas[0].body.len(), 32);
        assert!(labels.contains(TAG));

        let id = Identity::new(pass);
        let got = age::Identity::unwrap_stanza(&id, &stanzas[0])
            .unwrap()
            .unwrap();
        assert_eq!(got.expose_secret(), fk.expose_secret());

        let wrong = Identity::new(SecretString::from("wrong".to_string()));
        assert!(age::Identity::unwrap_stanza(&wrong, &stanzas[0])
            .unwrap()
            .is_err());
        let other = Stanza {
            tag: "X25519".into(),
            args: vec![],
            body: vec![],
        };
        assert!(age::Identity::unwrap_stanza(&id, &other).is_none());
    }

    #[test]
    fn refuses_excessive_parameters() {
        let id = Identity::new(SecretString::from("x".to_string()));
        let st = Stanza {
            tag: TAG.into(),
            args: vec![
                "AAAAAAAAAAAAAAAAAAAAAA".into(),
                "1".into(),
                (4 * 1024 * 1024).to_string(),
                "4".into(),
            ],
            body: vec![0u8; 32],
        };
        match age::Identity::unwrap_stanza(&id, &st) {
            Some(Err(age::DecryptError::ExcessiveWork { .. })) => {}
            _ => panic!("expected Some(Err(ExcessiveWork))"), // FileKey is not Debug
        }
    }

    #[test]
    fn end_to_end_through_age_and_cannot_mix_with_x25519() {
        let pass = SecretString::from("p".to_string());
        let r: Vec<Box<dyn age::Recipient + Send>> =
            vec![Box::new(Recipient::with_params(pass.clone(), small()))];
        let mut w = crate::crypt::encrypt_writer(Vec::new(), &r, false).unwrap();
        w.write_all(b"argon").unwrap();
        let ct = w.finish().unwrap();
        let ids: Vec<Box<dyn age::Identity>> = vec![Box::new(Identity::new(pass.clone()))];
        let mut out = Vec::new();
        crate::crypt::decrypt_reader(&ct[..], &ids)
            .unwrap()
            .read_to_end(&mut out)
            .unwrap();
        assert_eq!(out, b"argon");

        let x = age::x25519::Identity::generate();
        let mixed: Vec<Box<dyn age::Recipient + Send>> = vec![
            Box::new(Recipient::with_params(pass, small())),
            Box::new(x.to_public()),
        ];
        assert!(crate::crypt::encrypt_writer(Vec::new(), &mixed, false).is_err());
    }
}
