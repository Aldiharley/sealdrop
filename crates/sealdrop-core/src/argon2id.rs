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
use zeroize::{Zeroize, Zeroizing};

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

/// Why a derivation did not produce a key. `BadParams` means the parameters themselves are
/// invalid (a malformed header); `Failed` is any other Argon2 failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeriveError {
    BadParams,
    Failed,
}

fn derive(
    pass: &SecretString,
    salt: &[u8],
    params: Params,
) -> Result<Zeroizing<[u8; 32]>, DeriveError> {
    let p = argon2::Params::new(params.m_kib, params.t, params.p, Some(32))
        .map_err(|_| DeriveError::BadParams)?;
    let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut full_salt = Vec::with_capacity(DOMAIN.len() + salt.len());
    full_salt.extend_from_slice(DOMAIN);
    full_salt.extend_from_slice(salt);
    let mut out = Zeroizing::new([0u8; 32]);
    a.hash_password_into(pass.expose_secret().as_bytes(), &full_salt, out.as_mut())
        .map_err(|_| DeriveError::Failed)?;
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
            .map_err(|e| EncryptError::Io(std::io::Error::other(format!("argon2id: {e:?}"))))?;
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

/// Reject parameters above `MAX` before any derivation is attempted.
fn check_bounds(p: Params) -> Result<(), DecryptError> {
    if p.t > MAX.t || p.m_kib > MAX.m_kib || p.p > MAX.p {
        return Err(DecryptError::ExcessiveWork {
            required: log2_ceil(p.m_kib),
            target: log2_ceil(MAX.m_kib),
        });
    }
    Ok(())
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
        // Argon2 requires m >= 8 * p (and so m >= 8); reject up front, no derivation attempted.
        if m_kib < 8 || m_kib < p.saturating_mul(8) {
            return Some(Err(DecryptError::InvalidHeader));
        }
        let params = Params { t, m_kib, p };
        if let Err(e) = check_bounds(params) {
            return Some(Err(e));
        }
        let key = match derive(&self.pass, &salt, params) {
            Ok(k) => k,
            Err(DeriveError::BadParams) => return Some(Err(DecryptError::InvalidHeader)),
            Err(DeriveError::Failed) => return Some(Err(DecryptError::DecryptionFailed)),
        };
        let aead = ChaCha20Poly1305::new(&Key::from(*key));
        match aead.decrypt(&Nonce::from([0u8; 12]), stanza.body.as_slice()) {
            Ok(pt) => {
                // Wiped on every arm.
                let pt = Zeroizing::new(pt);
                if pt.len() != FILE_KEY_BYTES {
                    return Some(Err(DecryptError::DecryptionFailed));
                }
                let mut arr = [0u8; FILE_KEY_BYTES];
                arr.copy_from_slice(&pt);
                let fk = FileKey::new(Box::new(arr));
                arr.zeroize();
                Some(Ok(fk))
            }
            Err(_) => Some(Err(DecryptError::DecryptionFailed)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;
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
        assert!(matches!(
            age::Identity::unwrap_stanza(&wrong, &stanzas[0]),
            Some(Err(DecryptError::DecryptionFailed))
        ));
        let other = Stanza {
            tag: "X25519".into(),
            args: vec![],
            body: vec![],
        };
        assert!(age::Identity::unwrap_stanza(&id, &other).is_none());
    }

    fn stanza(args: [&str; 4], body_len: usize) -> Stanza {
        Stanza {
            tag: TAG.into(),
            args: args.iter().map(|a| a.to_string()).collect(),
            body: vec![0u8; body_len],
        }
    }

    const SALT_OK: &str = "AAAAAAAAAAAAAAAAAAAAAA"; // 16 zero bytes

    fn unwrap(st: &Stanza) -> Option<Result<FileKey, DecryptError>> {
        age::Identity::unwrap_stanza(&Identity::new(SecretString::from("x".to_string())), st)
    }

    #[test]
    fn refuses_excessive_parameters() {
        let big_m = (4 * 1024 * 1024).to_string();
        for args in [
            [SALT_OK, "1", big_m.as_str(), "4"],
            [SALT_OK, "11", "8192", "1"],
            [SALT_OK, "1", "8192", "9"],
        ] {
            assert!(
                matches!(
                    unwrap(&stanza(args, 32)),
                    Some(Err(DecryptError::ExcessiveWork { .. }))
                ),
                "{args:?}"
            );
        }
    }

    #[test]
    fn bounds_boundaries() {
        // A real 2 GiB derivation is too expensive for a test, so check the bound directly.
        assert!(check_bounds(Params {
            t: 1,
            m_kib: 2 * 1024 * 1024,
            p: 1
        })
        .is_ok());
        assert!(check_bounds(MAX).is_ok());
        for bad in [
            Params {
                t: 1,
                m_kib: 2 * 1024 * 1024 + 1,
                p: 1,
            },
            Params {
                t: MAX.t + 1,
                m_kib: 8192,
                p: 1,
            },
            Params {
                t: 1,
                m_kib: 8192,
                p: MAX.p + 1,
            },
        ] {
            assert!(matches!(
                check_bounds(bad),
                Err(DecryptError::ExcessiveWork { .. })
            ));
        }
    }

    #[test]
    fn rejects_malformed_stanzas() {
        let ok = [SALT_OK, "1", "8192", "1"];
        let mut cases: Vec<(&str, Stanza)> = Vec::new();
        let mut s3 = stanza(ok, 32);
        s3.args.pop();
        cases.push(("3 args", s3));
        let mut s5 = stanza(ok, 32);
        s5.args.push("1".into());
        cases.push(("5 args", s5));
        cases.push(("body 31", stanza(ok, 31)));
        cases.push(("salt not base64", stanza(["!!!!", "1", "8192", "1"], 32)));
        cases.push((
            "salt 8 bytes",
            stanza(["AAAAAAAAAAA", "1", "8192", "1"], 32),
        ));
        cases.push(("t=0", stanza([SALT_OK, "0", "8192", "1"], 32)));
        cases.push(("m=0", stanza([SALT_OK, "1", "0", "1"], 32)));
        cases.push(("p=0", stanza([SALT_OK, "1", "8192", "0"], 32)));
        cases.push(("t=x", stanza([SALT_OK, "x", "8192", "1"], 32)));
        cases.push(("m=5 p=1", stanza([SALT_OK, "1", "5", "1"], 32)));
        cases.push(("m=63 p=8", stanza([SALT_OK, "1", "63", "8"], 32)));
        for (name, st) in cases {
            assert!(
                matches!(unwrap(&st), Some(Err(DecryptError::InvalidHeader))),
                "{name}"
            );
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
        let pass2 = pass.clone();
        let mixed: Vec<Box<dyn age::Recipient + Send>> = vec![
            Box::new(Recipient::with_params(pass, small())),
            Box::new(x.to_public()),
        ];
        assert!(matches!(
            crate::crypt::encrypt_writer(Vec::new(), &mixed, false).err(),
            Some(Error::Encrypt(
                age::EncryptError::IncompatibleRecipients { .. }
            ))
        ));

        // Reversed order is rejected too.
        let reversed: Vec<Box<dyn age::Recipient + Send>> = vec![
            Box::new(x.to_public()),
            Box::new(Recipient::with_params(pass2, small())),
        ];
        assert!(matches!(
            crate::crypt::encrypt_writer(Vec::new(), &reversed, false).err(),
            Some(Error::Encrypt(
                age::EncryptError::IncompatibleRecipients { .. }
            ))
        ));
    }
}
