//! age's native hybrid post-quantum recipient type `mlkem768x25519` (`age1pq1…`,
//! `AGE-SECRET-KEY-PQ-1…`), per C2SP age.md. The `age` crate 0.12 has no identity for it;
//! this module is replaced by the crate's own types when rage 0.13 ships them.

pub(crate) mod kem;

pub const TAG: &str = "mlkem768x25519";
pub const INFO: &[u8] = b"age-encryption.org/mlkem768x25519";
pub const LABEL: &str = "postquantum";
pub const RECIPIENT_HRP: &str = "age1pq";
pub const IDENTITY_HRP: &str = "AGE-SECRET-KEY-PQ-";
pub const ENC_LEN: usize = 1120;
pub const PK_LEN: usize = 1216;
pub const BODY_LEN: usize = 32;

use std::collections::HashSet;
use std::fmt;
use std::str::FromStr;

use age::{DecryptError, EncryptError};
use age_core::format::{FileKey, Stanza, FILE_KEY_BYTES};
use age_core::primitives::{
    bech32_decode, bech32_encode, bech32_encode_to_fmt, hpke_open, hpke_seal,
};
use base64::prelude::{Engine, BASE64_STANDARD_NO_PAD};
use hpke::{Deserializable, Serializable};
use rand_core06::{OsRng, RngCore};
use zeroize::{Zeroize, Zeroizing};

use kem::MlKem768X25519 as Kem;

/// Bech32 (BIP-173 checksum, no length limit: an `age1pq` string is ~1950 characters), via
/// age-core's helpers. The HRP compares case-insensitively; mixed-case strings are rejected.
fn decode_bech32(s: &str, want_hrp: &str) -> Result<Vec<u8>, &'static str> {
    bech32_decode(
        s,
        |_| "invalid Bech32 encoding",
        |hrp| {
            hrp.as_str()
                .eq_ignore_ascii_case(want_hrp)
                .then_some(())
                .ok_or("incorrect HRP")
        },
        |_, bytes| Ok(bytes.collect()),
    )
}

fn hrp(s: &'static str) -> bech32::Hrp {
    bech32::Hrp::parse(s).expect("valid hrp")
}

/// `age1pq1…`: ML-KEM-768 encapsulation key || X25519 public key (1216 bytes).
#[derive(Clone)]
pub struct Recipient(kem::PublicKey);

impl FromStr for Recipient {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = decode_bech32(s.trim(), RECIPIENT_HRP)?;
        kem::PublicKey::from_bytes(&bytes)
            .map(Self)
            .map_err(|_| "invalid recipient")
    }
}

impl fmt::Display for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        bech32_encode_to_fmt(f, hrp(RECIPIENT_HRP), &self.0.to_bytes())
    }
}

impl fmt::Debug for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl PartialEq for Recipient {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_bytes() == other.0.to_bytes()
    }
}

impl age::Recipient for Recipient {
    fn wrap_file_key(
        &self,
        file_key: &FileKey,
    ) -> Result<(Vec<Stanza>, HashSet<String>), EncryptError> {
        use age::secrecy::ExposeSecret;
        let (enc, body) = hpke_seal::<Kem, _>(&self.0, INFO, file_key.expose_secret(), &mut OsRng);
        let stanza = Stanza {
            tag: TAG.into(),
            args: vec![BASE64_STANDARD_NO_PAD.encode(enc.to_bytes())],
            body,
        };
        Ok((vec![stanza], HashSet::from([LABEL.to_string()])))
    }
}

/// `AGE-SECRET-KEY-PQ-1…`: a 32-byte seed (X-Wing decapsulation key).
#[derive(Clone)]
pub struct Identity {
    seed: Zeroizing<[u8; 32]>,
    sk: kem::PrivateKey,
}

impl Identity {
    pub fn generate() -> Self {
        let mut seed = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut *seed);
        let sk = kem::PrivateKey::from_bytes(&*seed).expect("32 bytes");
        Self { seed, sk }
    }

    pub fn to_public(&self) -> Recipient {
        Recipient(<Kem as hpke::Kem>::sk_to_pk(&self.sk))
    }
}

impl FromStr for Identity {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = Zeroizing::new(decode_bech32(s.trim(), IDENTITY_HRP)?);
        let seed: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| "invalid identity")?;
        let seed = Zeroizing::new(seed);
        let sk = kem::PrivateKey::from_bytes(&*seed).map_err(|_| "invalid identity")?;
        Ok(Self { seed, sk })
    }
}

impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = Zeroizing::new(bech32_encode(hrp(IDENTITY_HRP), &*self.seed));
        f.write_str(&Zeroizing::new(s.to_uppercase()))
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("pq::Identity(<redacted>)")
    }
}

/// True for age's two hybrid post-quantum stanza tags.
pub fn is_pq_stanza_tag(tag: &str) -> bool {
    tag == TAG || tag == "mlkem768p256tag"
}

/// Canonical unpadded standard base64 (the age header rule): decodes, and re-encodes to
/// exactly the input.
fn decode_canonical(s: &str) -> Option<Vec<u8>> {
    let bytes = BASE64_STANDARD_NO_PAD.decode(s).ok()?;
    (BASE64_STANDARD_NO_PAD.encode(&bytes) == s).then_some(bytes)
}

impl age::Identity for Identity {
    fn unwrap_stanza(&self, stanza: &Stanza) -> Option<Result<FileKey, DecryptError>> {
        if stanza.tag != TAG {
            return None;
        }
        // Rules in CCTV order: arity, canonical enc of exactly 1120 bytes, body exactly
        // 32 bytes (checked before any decryption), then decapsulate and open.
        if stanza.args.len() != 1 {
            return Some(Err(DecryptError::InvalidHeader));
        }
        let enc = match decode_canonical(&stanza.args[0]) {
            Some(e) if e.len() == ENC_LEN => e,
            _ => return Some(Err(DecryptError::InvalidHeader)),
        };
        if stanza.body.len() != BODY_LEN {
            return Some(Err(DecryptError::InvalidHeader));
        }
        let enc = match kem::EncappedKey::from_bytes(&enc) {
            Ok(e) => e,
            Err(_) => return Some(Err(DecryptError::InvalidHeader)),
        };
        match hpke_open::<Kem>(&enc, &self.sk, INFO, &stanza.body) {
            Ok(mut pt) => {
                if pt.len() != FILE_KEY_BYTES {
                    pt.zeroize();
                    return Some(Err(DecryptError::InvalidHeader));
                }
                let mut fk = Box::new([0u8; FILE_KEY_BYTES]);
                fk.copy_from_slice(&pt);
                pt.zeroize();
                Some(Ok(FileKey::new(fk)))
            }
            // The low-order check lives in `decap` and surfaces as DecapError.
            Err(hpke::HpkeError::DecapError) => Some(Err(DecryptError::InvalidHeader)),
            // Wrong key: ML-KEM's implicit rejection ends here, as an AEAD failure.
            Err(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::secrecy::ExposeSecret;
    use age_core::format::{FileKey, Stanza};
    use base64::prelude::{Engine, BASE64_STANDARD_NO_PAD};
    use std::str::FromStr;

    fn file_key() -> FileKey {
        FileKey::new(Box::new([7u8; 16]))
    }

    #[test]
    fn strings_round_trip_and_have_the_right_prefixes() {
        let id = Identity::generate();
        let s = id.to_string();
        assert!(s.starts_with("AGE-SECRET-KEY-PQ-1"), "{}", &s[..24]);
        assert_eq!(s, s.to_uppercase());
        let back = Identity::from_str(&s).unwrap();
        assert_eq!(back.to_public().to_string(), id.to_public().to_string());
        // Lowercase input is also valid Bech32.
        assert!(Identity::from_str(&s.to_lowercase()).is_ok());
        let r = id.to_public().to_string();
        assert!(r.starts_with("age1pq1"));
        assert!(r.len() > 1900 && r.len() < 2100, "{}", r.len());
        assert_eq!(Recipient::from_str(&r).unwrap().to_string(), r);
        assert!(Recipient::from_str(&r.to_uppercase()).is_ok());
        assert!(Recipient::from_str("age1pq1notvalid").is_err());
        assert!(Identity::from_str("AGE-SECRET-KEY-1QQQ").is_err());
        // Mixed case is invalid Bech32.
        let mixed = format!("{}{}", &s[..30], s[30..].to_lowercase());
        assert!(Identity::from_str(&mixed).is_err());
    }

    #[test]
    fn wrap_and_unwrap() {
        let id = Identity::generate();
        let (stanzas, labels) =
            age::Recipient::wrap_file_key(&id.to_public(), &file_key()).unwrap();
        assert_eq!(labels, std::collections::HashSet::from([LABEL.to_string()]));
        assert_eq!(stanzas.len(), 1);
        let s = &stanzas[0];
        assert_eq!(s.tag, TAG);
        assert_eq!(s.args.len(), 1);
        assert_eq!(
            BASE64_STANDARD_NO_PAD.decode(&s.args[0]).unwrap().len(),
            ENC_LEN
        );
        assert_eq!(s.body.len(), BODY_LEN);
        let got = age::Identity::unwrap_stanza(&id, s).unwrap().unwrap();
        assert_eq!(got.expose_secret(), file_key().expose_secret());
        // A different identity: "no match", not an error.
        assert!(age::Identity::unwrap_stanza(&Identity::generate(), s).is_none());
    }

    fn stanza_for(id: &Identity) -> Stanza {
        age::Recipient::wrap_file_key(&id.to_public(), &file_key())
            .unwrap()
            .0
            .remove(0)
    }

    fn is_header_failure(r: Option<Result<FileKey, age::DecryptError>>) -> bool {
        matches!(r, Some(Err(age::DecryptError::InvalidHeader)))
    }

    #[test]
    fn decode_rules_match_cctv() {
        let id = Identity::generate();
        // Other tags are not ours (uppercase included: CCTV hybrid_uppercase is "no match").
        let mut s = stanza_for(&id);
        s.tag = "MLKEM768X25519".into();
        assert!(age::Identity::unwrap_stanza(&id, &s).is_none());
        let mut s = stanza_for(&id);
        s.tag = "X25519".into();
        assert!(age::Identity::unwrap_stanza(&id, &s).is_none());
        // Extra argument: header failure.
        let mut s = stanza_for(&id);
        s.args.push("extra".into());
        assert!(is_header_failure(age::Identity::unwrap_stanza(&id, &s)));
        // Short / long enc: header failure.
        let mut s = stanza_for(&id);
        let mut enc = BASE64_STANDARD_NO_PAD.decode(&s.args[0]).unwrap();
        enc.pop();
        s.args[0] = BASE64_STANDARD_NO_PAD.encode(&enc);
        assert!(is_header_failure(age::Identity::unwrap_stanza(&id, &s)));
        let mut s = stanza_for(&id);
        let mut enc = BASE64_STANDARD_NO_PAD.decode(&s.args[0]).unwrap();
        enc.push(0);
        s.args[0] = BASE64_STANDARD_NO_PAD.encode(&enc);
        assert!(is_header_failure(age::Identity::unwrap_stanza(&id, &s)));
        // Non-canonical base64 (padding, or trailing bits set): header failure.
        let mut s = stanza_for(&id);
        s.args[0].push('=');
        assert!(is_header_failure(age::Identity::unwrap_stanza(&id, &s)));
        // Body not 32 bytes: header failure, before any decryption.
        let mut s = stanza_for(&id);
        s.body.push(0);
        assert!(is_header_failure(age::Identity::unwrap_stanza(&id, &s)));
        // Wrong AEAD tag: no match.
        let mut s = stanza_for(&id);
        s.body[31] ^= 1;
        assert!(age::Identity::unwrap_stanza(&id, &s).is_none());
        // Low-order X25519 share: header failure.
        let mut s = stanza_for(&id);
        let mut enc = BASE64_STANDARD_NO_PAD.decode(&s.args[0]).unwrap();
        for b in &mut enc[1088..] {
            *b = 0;
        }
        s.args[0] = BASE64_STANDARD_NO_PAD.encode(&enc);
        assert!(is_header_failure(age::Identity::unwrap_stanza(&id, &s)));
    }

    #[test]
    fn debug_of_identity_never_shows_the_seed() {
        let id = Identity::generate();
        let dbg = format!("{id:?}");
        assert!(!dbg.contains("AGE-SECRET-KEY"));
        assert!(!dbg.contains(&id.to_string()[20..40]));
    }
}
