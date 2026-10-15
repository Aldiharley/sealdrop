//! X-Wing (MLKEM768-X25519) as an `hpke::Kem`, for age's `mlkem768x25519` stanza.
//! Mirrors the `age` crate's `native/tagpq/kem.rs`; every constant comes from
//! draft-connolly-cfrg-xwing-kem and C2SP age.md.

use age_core::secrecy::zeroize::Zeroize;
use hpke::{kem::SharedSecret, Deserializable, HpkeError, Serializable};
use ml_kem::{
    kem::{Decapsulate, Encapsulate},
    Ciphertext, EncodedSizeUser, KemCore, MlKem768,
};
use rand_core06::{CryptoRng, RngCore};
use sha2::digest::consts::U32;
use sha2::digest::typenum::{self, Unsigned};
use sha3::{
    digest::{ExtendableOutput, FixedOutput, OutputSizeUser, Update, XofReader},
    Sha3_256, Shake256,
};
use x25519_dalek::{PublicKey as XPublic, StaticSecret};

/// X-Wing label `\.//^\`.
const XWING_LABEL: &[u8] = b"\\.//^\\";
type KemNct = <MlKem768 as KemCore>::CiphertextSize; // 1088
type KemNek = <<MlKem768 as KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize; // 1184

pub(crate) struct Expanded {
    pub dk_pq: <MlKem768 as KemCore>::DecapsulationKey,
    pub sk_x: StaticSecret,
    pub pk_x: XPublic,
}

/// X-Wing `expandDecapsulationKey`: SHAKE256(seed) -> d || z || sk_X.
pub(crate) fn expand_seed(seed: &[u8; 32]) -> Expanded {
    let mut out = [0u8; 96];
    let mut xof = Shake256::default().chain(seed).finalize_xof();
    xof.read(&mut out);
    let mut d = [0u8; 32];
    let mut z = [0u8; 32];
    let mut x = [0u8; 32];
    d.copy_from_slice(&out[..32]);
    z.copy_from_slice(&out[32..64]);
    x.copy_from_slice(&out[64..]);
    let (dk_pq, _) = MlKem768::generate_deterministic(&d.into(), &z.into());
    let sk_x = StaticSecret::from(x);
    let pk_x = XPublic::from(&sk_x);
    out.zeroize();
    d.zeroize();
    z.zeroize();
    x.zeroize();
    Expanded { dk_pq, sk_x, pk_x }
}

#[derive(Clone)]
pub(crate) struct PrivateKey {
    seed: [u8; 32],
    dk_pq: <MlKem768 as KemCore>::DecapsulationKey,
    sk_x: StaticSecret,
    pk_x: XPublic,
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

// `hpke::Kem` requires `PrivateKey: Eq`; the seed determines everything else.
impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.seed == other.seed
    }
}
impl Eq for PrivateKey {}

impl Deserializable for PrivateKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
        let seed: [u8; 32] = encoded
            .try_into()
            .map_err(|_| HpkeError::IncorrectInputLength(32, encoded.len()))?;
        let e = expand_seed(&seed);
        Ok(Self {
            seed,
            dk_pq: e.dk_pq,
            sk_x: e.sk_x,
            pk_x: e.pk_x,
        })
    }
}

impl Serializable for PrivateKey {
    type OutputSize = U32;
    fn write_exact(&self, buf: &mut [u8]) {
        buf.copy_from_slice(&self.seed);
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct PublicKey {
    pub(crate) ek_pq: <MlKem768 as KemCore>::EncapsulationKey,
    pub(crate) pk_x: XPublic,
}

impl Eq for PublicKey {}

impl Deserializable for PublicKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
        if encoded.len() != Self::OutputSize::to_usize() {
            return Err(HpkeError::IncorrectInputLength(
                Self::OutputSize::to_usize(),
                encoded.len(),
            ));
        }
        let (pq, x) = encoded.split_at(KemNek::to_usize());
        let ek_pq = <MlKem768 as KemCore>::EncapsulationKey::from_bytes(
            pq.try_into().expect("correct length"),
        );
        // FIPS 203 §7.2 encapsulation-key check: the key must re-encode to the same bytes
        // (every coefficient < q). `ml-kem` does not perform it in `from_bytes`.
        if ek_pq.as_bytes().as_slice() != pq {
            return Err(HpkeError::ValidationError);
        }
        let pk_x = XPublic::from(<[u8; 32]>::try_from(x).expect("correct length"));
        Ok(Self { ek_pq, pk_x })
    }
}

impl Serializable for PublicKey {
    type OutputSize = typenum::Sum<KemNek, U32>;
    fn write_exact(&self, buf: &mut [u8]) {
        let n = KemNek::to_usize();
        buf[..n].copy_from_slice(&self.ek_pq.as_bytes());
        buf[n..].copy_from_slice(self.pk_x.as_bytes());
    }
}

#[derive(Clone)]
pub(crate) struct EncappedKey {
    ct_pq: Ciphertext<MlKem768>,
    ct_x: [u8; 32],
}

impl Deserializable for EncappedKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
        if encoded.len() != Self::OutputSize::to_usize() {
            return Err(HpkeError::IncorrectInputLength(
                Self::OutputSize::to_usize(),
                encoded.len(),
            ));
        }
        let (pq, x) = encoded.split_at(KemNct::to_usize());
        let ct_pq = <[u8; KemNct::USIZE]>::try_from(pq)
            .expect("correct length")
            .into();
        let ct_x = <[u8; 32]>::try_from(x).expect("correct length");
        Ok(Self { ct_pq, ct_x })
    }
}

impl Serializable for EncappedKey {
    type OutputSize = typenum::Sum<KemNct, U32>;
    fn write_exact(&self, buf: &mut [u8]) {
        let n = KemNct::to_usize();
        buf[..n].copy_from_slice(&self.ct_pq);
        buf[n..].copy_from_slice(&self.ct_x);
    }
}

pub(crate) struct MlKem768X25519;

impl hpke::Kem for MlKem768X25519 {
    type PublicKey = PublicKey;
    type PrivateKey = PrivateKey;
    type EncappedKey = EncappedKey;
    type NSecret = <Sha3_256 as OutputSizeUser>::OutputSize;
    const KEM_ID: u16 = 0x647a;

    fn sk_to_pk(sk: &Self::PrivateKey) -> Self::PublicKey {
        PublicKey {
            ek_pq: sk.dk_pq.encapsulation_key().clone(),
            pk_x: sk.pk_x,
        }
    }

    /// HPKE `DeriveKeyPair` (SHAKE256 LabeledDerive, as in `age::tagpq`). age identities
    /// never go through here: they ARE the 32-byte seed (`PrivateKey::from_bytes`).
    fn derive_keypair(ikm: &[u8]) -> (Self::PrivateKey, Self::PublicKey) {
        let mut seed = [0u8; 32];
        Shake256::default()
            .chain(ikm)
            .chain(b"HPKE-v1")
            .chain(b"KEM")
            .chain(Self::KEM_ID.to_be_bytes())
            .chain((b"DeriveKeyPair".len() as u16).to_be_bytes())
            .chain(b"DeriveKeyPair")
            .chain(32u16.to_be_bytes())
            .finalize_xof_into(&mut seed);
        let sk = PrivateKey::from_bytes(&seed).expect("32 bytes");
        seed.zeroize();
        let pk = Self::sk_to_pk(&sk);
        (sk, pk)
    }

    fn encap<R: CryptoRng + RngCore>(
        pk_recip: &Self::PublicKey,
        sender_id_keypair: Option<(&Self::PrivateKey, &Self::PublicKey)>,
        csprng: &mut R,
    ) -> Result<(SharedSecret<Self>, Self::EncappedKey), HpkeError> {
        // Auth mode is not used by age.
        if sender_id_keypair.is_some() {
            return Err(HpkeError::EncapError);
        }
        let (ct_pq, ss_pq) = pk_recip
            .ek_pq
            .encapsulate(csprng)
            .map_err(|()| HpkeError::EncapError)?;
        let ek_x = StaticSecret::random_from_rng(&mut *csprng);
        let ct_x = XPublic::from(&ek_x);
        let ss_x = ek_x.diffie_hellman(&pk_recip.pk_x);
        if !ss_x.was_contributory() {
            return Err(HpkeError::EncapError);
        }
        let ss = combine(
            &ss_pq,
            ss_x.as_bytes(),
            ct_x.as_bytes(),
            pk_recip.pk_x.as_bytes(),
        );
        Ok((
            SharedSecret(ss),
            EncappedKey {
                ct_pq,
                ct_x: ct_x.to_bytes(),
            },
        ))
    }

    fn decap(
        sk_recip: &Self::PrivateKey,
        pk_sender_id: Option<&Self::PublicKey>,
        encapped_key: &Self::EncappedKey,
    ) -> Result<SharedSecret<Self>, HpkeError> {
        // Auth mode is not used by age.
        if pk_sender_id.is_some() {
            return Err(HpkeError::DecapError);
        }
        // ML-KEM uses implicit rejection: a bad ciphertext yields a random secret, not an error.
        let ss_pq = sk_recip
            .dk_pq
            .decapsulate(&encapped_key.ct_pq)
            .map_err(|()| HpkeError::DecapError)?;
        let ss_x = sk_recip
            .sk_x
            .diffie_hellman(&XPublic::from(encapped_key.ct_x));
        // Low-order point: the all-zero secret is disallowed (CCTV `hybrid_low_order`).
        if !ss_x.was_contributory() {
            return Err(HpkeError::DecapError);
        }
        let ss = combine(
            &ss_pq,
            ss_x.as_bytes(),
            &encapped_key.ct_x,
            sk_recip.pk_x.as_bytes(),
        );
        Ok(SharedSecret(ss))
    }
}

/// X-Wing combiner: SHA3-256(ss_M || ss_X || ct_X || pk_X || label).
fn combine(ss_pq: &[u8], ss_x: &[u8], ct_x: &[u8], pk_x: &[u8]) -> sha3::digest::Output<Sha3_256> {
    let mut h = Sha3_256::default();
    h.update(ss_pq);
    h.update(ss_x);
    h.update(ct_x);
    h.update(pk_x);
    h.update(XWING_LABEL);
    h.finalize_fixed()
}

#[cfg(test)]
mod tests {
    use super::*;
    use age_core::primitives::{hpke_open, hpke_seal};
    use hpke::{Deserializable, Kem as _, Serializable};
    use rand_core06::OsRng;

    #[test]
    fn hpke_round_trip_and_sizes() {
        let (sk, pk) = MlKem768X25519::gen_keypair(&mut OsRng);
        assert_eq!(pk.to_bytes().len(), 1216);
        assert_eq!(sk.to_bytes().len(), 32);
        let (enc, ct) =
            hpke_seal::<MlKem768X25519, _>(&pk, b"info", b"0123456789abcdef", &mut OsRng);
        assert_eq!(enc.to_bytes().len(), 1120);
        assert_eq!(ct.len(), 32);
        let pt = hpke_open::<MlKem768X25519>(&enc, &sk, b"info", &ct).unwrap();
        assert_eq!(pt, b"0123456789abcdef");
        // Seed round trip: a private key re-read from its 32 bytes derives the same public key.
        let sk2 = PrivateKey::from_bytes(&sk.to_bytes()).unwrap();
        assert_eq!(MlKem768X25519::sk_to_pk(&sk2).to_bytes(), pk.to_bytes());
        // Public key round trip through bytes.
        let pk2 = PublicKey::from_bytes(&pk.to_bytes()).unwrap();
        assert_eq!(pk2.to_bytes(), pk.to_bytes());
    }

    #[test]
    fn wrong_lengths_are_rejected() {
        assert!(PublicKey::from_bytes(&[0u8; 1215]).is_err());
        assert!(PublicKey::from_bytes(&[0u8; 1217]).is_err());
        assert!(EncappedKey::from_bytes(&[0u8; 1119]).is_err());
        assert!(EncappedKey::from_bytes(&[0u8; 1121]).is_err());
        assert!(PrivateKey::from_bytes(&[0u8; 31]).is_err());
    }

    #[test]
    fn low_order_x25519_share_fails_decap() {
        let (sk, pk) = MlKem768X25519::gen_keypair(&mut OsRng);
        let (_, enc) = MlKem768X25519::encap(&pk, None, &mut OsRng).unwrap();
        let mut bytes = enc.to_bytes().to_vec();
        // All-zero X25519 point: the shared secret is all zero and must be refused.
        for b in &mut bytes[1088..] {
            *b = 0;
        }
        let bad = EncappedKey::from_bytes(&bytes).unwrap();
        assert!(MlKem768X25519::decap(&sk, None, &bad).is_err());
    }

    #[test]
    fn all_zero_x25519_public_key_fails_encap() {
        let (_, pk) = MlKem768X25519::gen_keypair(&mut OsRng);
        let mut bytes = pk.to_bytes().to_vec();
        // pk_x is the last 32 bytes; the all-zero point gives a non-contributory secret.
        for b in &mut bytes[1184..] {
            *b = 0;
        }
        let bad = PublicKey::from_bytes(&bytes).unwrap();
        assert!(MlKem768X25519::encap(&bad, None, &mut OsRng).is_err());
    }

    #[test]
    fn non_canonical_mlkem_key_is_rejected() {
        let (_, pk) = MlKem768X25519::gen_keypair(&mut OsRng);
        let mut bytes = pk.to_bytes().to_vec();
        // Set a coefficient to a value >= q (3329): 0x0FFF in the first 12-bit slot.
        bytes[0] = 0xFF;
        bytes[1] |= 0x0F;
        assert!(PublicKey::from_bytes(&bytes).is_err());
    }
}
