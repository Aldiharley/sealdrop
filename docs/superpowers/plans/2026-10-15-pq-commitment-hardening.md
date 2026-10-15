# sealdrop 0.3 (PQ recipients, key commitment, hardening) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) or executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship sealdrop 0.3.0: native age `mlkem768x25519` (`age1pq1…`) recipients and identities with a PQ-only policy, a manifest key-commitment field, and the agreed hardening items, with the format spec, vectors, CLI, desktop app and docs updated.

**Architecture:** A new `pq` module in `sealdrop-core` implements the X-Wing KEM as an `hpke::Kem` and the age stanza on top of age-core's HPKE helpers; `crypt::Recipient` gains a `Pq` variant and the key store a PQ identity kind. Key commitment is two thin adapters (a committing recipient at seal, a committed identity at open) plus one optional manifest field. Everything else is plumbing through policy, probe, verify, CLI, Tauri commands and the React screens, then the spec, the vectors and the docs.

**Tech Stack:** Rust 1.85+ (workspace), `age` 0.12.1 / `age-core` 0.12, `ml-kem` 0.2 (`deterministic`), `x25519-dalek` 2 (`static_secrets`), `hpke` 0.12 (`alloc`, no default features), `sha3` 0.10, `rand_core` 0.6 (`getrandom`), `rpassword` 7; Tauri 2 + React 19 + Vite 8 + vitest; Go `age` 1.3.2 for interop.

Spec: `docs/superpowers/specs/2026-10-15-pq-commitment-hardening-design.md` (read it first; section numbers below refer to it). Format spec: `spec/sealdrop-format-v1.md`.

## Global Constraints

- Workspace `rust-version = "1.85"`; `edition = "2021"`. Do not raise either.
- Keep the workspace `rand = "0.9"`; the PQ module uses `rand_core = "0.6"` (feature `getrandom`) for the `hpke`/`ml-kem`/`x25519-dalek` trait bounds, exactly like `age::tagpq`.
- Every task ends with `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings` and `cargo test --workspace` green (interop tests skip when `age` is off PATH; locally `age` 1.3.2 is at `~/go/bin/age`, so add `$HOME/go/bin` to `PATH`).
- Desktop tasks: `cd apps/desktop && npm test && npm run build`. On this machine (Node 20.18) run `npm i --no-save --force @rolldown/binding-win32-x64-msvc` once first; never commit that change.
- Manifest kinds are exactly: `x25519`, `pq`, `hybrid-pq`, `plugin:<name>`, `scrypt`, `argon2id`. Post-quantum kinds are `pq` and `hybrid-pq`.
- Manifest field name: `key_commitment`. Derivation: `HKDF-SHA-256(ikm = file key, salt = empty, info = "sealdrop/commit/v1")`, 32 bytes, lowercase hex.
- Stanza constants: tag `mlkem768x25519`; HPKE info `age-encryption.org/mlkem768x25519`; label set `{"postquantum"}`; recipient HRP `age1pq`; identity HRP `AGE-SECRET-KEY-PQ-`; enc 1120 bytes; body 32 bytes; KEM id `0x647a`; X-Wing label bytes `5c 2e 2f 2f 5e 5c`.
- Never print or log secret material (identity strings, passphrases, file keys). Error messages redact as `crypt::redact` does.
- Commit after every task with a conventional-commit subject and the trailer `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`. Never commit `research_notes/`, `reports/`, or `apps/desktop/package-lock.json` changes from the rolldown workaround.
- Home directory contains a space: quote every path in shell commands.

---

## File map

| Path | Responsibility |
|---|---|
| `crates/sealdrop-core/src/pq/kem.rs` (new) | `MlKem768X25519: hpke::Kem` (X-Wing), key expansion, combiner |
| `crates/sealdrop-core/src/pq.rs` (new) | `pq::Recipient`, `pq::Identity`, stanza encode/decode, constants |
| `crates/sealdrop-core/src/crypt.rs` | `Recipient::Pq`, `Committing` recipient adapter, `CommittedIdentity`, `key_commitment()` |
| `crates/sealdrop-core/src/keys.rs` | `IdentityKind`, `generate(force, kind)`, `identity_kind()`, `native_identities()` |
| `crates/sealdrop-core/src/policy.rs` | `PolicyError::PqMustNotMix`, `is_post_quantum_kind` |
| `crates/sealdrop-core/src/manifest.rs` | `key_commitment: Option<String>` |
| `crates/sealdrop-core/src/seal.rs` | commitment capture, `self_omitted` |
| `crates/sealdrop-core/src/open.rs` | commitment check, `VerifyReport.post_quantum` |
| `crates/sealdrop-core/src/probe.rs` | `Probe.post_quantum` |
| `crates/sealdrop-core/src/pack.rs`, `extract.rs` | case-collision refusal |
| `crates/sealdrop-core/tests/{cctv,interop_age,format_vectors,format_vectors_gen}.rs` | conformance, interop, vectors |
| `crates/sealdrop-cli/src/commands/{keygen,recipient,seal,verify,open}.rs`, `main.rs`, `tests/cli.rs` | CLI surface |
| `apps/desktop/src-tauri/src/commands.rs`; `apps/desktop/src/lib/{types,format,mock,errors,api}.ts`; `screens/{Keys,Seal,Verify,Open}.tsx` | desktop |
| `spec/sealdrop-format-v1.md`, `spec/vectors/**` | format spec and vectors |
| `README.md`, `SECURITY.md`, `docs/VALIDATION.md`, `Cargo.toml` | docs and version |

---

### Task 1: X-Wing KEM as `hpke::Kem` (`pq/kem.rs`)

**Files:**
- Create: `crates/sealdrop-core/src/pq/kem.rs`
- Create: `crates/sealdrop-core/src/pq.rs` (module stub only in this task: `pub(crate) mod kem;` plus the constants)
- Modify: `crates/sealdrop-core/src/lib.rs` (add `pub mod pq;`)
- Modify: `crates/sealdrop-core/Cargo.toml` (add deps)
- Test: unit tests inside `pq/kem.rs`

**Interfaces:**
- Produces: `pub(crate) struct MlKem768X25519;` implementing `hpke::Kem` with `type PrivateKey = kem::PrivateKey` (32-byte seed), `type PublicKey = kem::PublicKey`, `type EncappedKey = kem::EncappedKey`, `KEM_ID = 0x647a`, `NSecret = U32`. `PublicKey`/`EncappedKey`/`PrivateKey` implement `hpke::{Serializable, Deserializable}` with sizes 1216 / 1120 / 32. `pub(crate) fn expand_seed(seed: &[u8; 32]) -> Expanded` where `Expanded { dk_pq, ek_pq, sk_x: x25519_dalek::StaticSecret, pk_x: x25519_dalek::PublicKey }`.
- Constants in `pq.rs`: `pub const TAG: &str = "mlkem768x25519"; pub const INFO: &[u8] = b"age-encryption.org/mlkem768x25519"; pub const LABEL: &str = "postquantum"; pub const RECIPIENT_HRP: &str = "age1pq"; pub const IDENTITY_HRP: &str = "AGE-SECRET-KEY-PQ-"; pub const ENC_LEN: usize = 1120; pub const PK_LEN: usize = 1216; pub const BODY_LEN: usize = 32;`

- [ ] **Step 1: Add dependencies**

In `crates/sealdrop-core/Cargo.toml` `[dependencies]` add (keep alphabetical order of the file):

```toml
hpke = { version = "0.12", default-features = false, features = ["alloc"] }
ml-kem = { version = "0.2", features = ["deterministic"] }
rand_core06 = { package = "rand_core", version = "0.6", features = ["getrandom"] }
sha3 = "0.10"
x25519-dalek = { version = "2", features = ["static_secrets"] }
```

Run `cargo build -p sealdrop-core` to confirm the lockfile resolves to the versions already in the tree (`hpke 0.12.0`, `ml-kem 0.2.3`, `x25519-dalek 2.0.1`, `sha3 0.10.9`, `rand_core 0.6.4`). Run `cargo deny check licenses advisories` and expect `ok`.

- [ ] **Step 2: Write the failing KEM round-trip test**

Create `crates/sealdrop-core/src/pq/kem.rs` with only the test module first:

```rust
//! X-Wing (MLKEM768-X25519) as an `hpke::Kem`, for age's `mlkem768x25519` stanza.
//! Mirrors the `age` crate's `native/tagpq/kem.rs`; every constant comes from
//! draft-connolly-cfrg-xwing-kem and C2SP age.md.

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
        let (enc, ct) = hpke_seal::<MlKem768X25519, _>(&pk, b"info", b"0123456789abcdef", &mut OsRng);
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
    fn non_canonical_mlkem_key_is_rejected() {
        let (_, pk) = MlKem768X25519::gen_keypair(&mut OsRng);
        let mut bytes = pk.to_bytes().to_vec();
        // Set a coefficient to a value >= q (3329): 0x0FFF in the first 12-bit slot.
        bytes[0] = 0xFF;
        bytes[1] |= 0x0F;
        assert!(PublicKey::from_bytes(&bytes).is_err());
    }
}
```

Create `crates/sealdrop-core/src/pq.rs`:

```rust
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
```

Add `pub mod pq;` to `crates/sealdrop-core/src/lib.rs` (alphabetical, after `policy`).

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test -p sealdrop-core pq::kem`
Expected: compile error (`MlKem768X25519` not found).

- [ ] **Step 4: Implement the KEM**

Above the test module in `pq/kem.rs`:

```rust
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
const LABEL: &[u8] = b"\\.//^\\";
type KemNct = <MlKem768 as KemCore>::CiphertextSize; // 1088
type KemNek = <<MlKem768 as KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize; // 1184

pub(crate) struct Expanded {
    pub dk_pq: <MlKem768 as KemCore>::DecapsulationKey,
    pub ek_pq: <MlKem768 as KemCore>::EncapsulationKey,
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
    let (dk_pq, ek_pq) = MlKem768::generate_deterministic(&d.into(), &z.into());
    let sk_x = StaticSecret::from(x);
    let pk_x = XPublic::from(&sk_x);
    out.zeroize();
    d.zeroize();
    z.zeroize();
    x.zeroize();
    Expanded { dk_pq, ek_pq, sk_x, pk_x }
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

impl Deserializable for PrivateKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
        let seed: [u8; 32] = encoded
            .try_into()
            .map_err(|_| HpkeError::IncorrectInputLength(32, encoded.len()))?;
        let e = expand_seed(&seed);
        Ok(Self { seed, dk_pq: e.dk_pq, sk_x: e.sk_x, pk_x: e.pk_x })
    }
}

impl Serializable for PrivateKey {
    type OutputSize = U32;
    fn write_exact(&self, buf: &mut [u8]) {
        buf.copy_from_slice(&self.seed);
    }
}

#[derive(Clone)]
pub(crate) struct PublicKey {
    pub(crate) ek_pq: <MlKem768 as KemCore>::EncapsulationKey,
    pub(crate) pk_x: XPublic,
}

impl Deserializable for PublicKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
        if encoded.len() != Self::OutputSize::to_usize() {
            return Err(HpkeError::IncorrectInputLength(Self::OutputSize::to_usize(), encoded.len()));
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
            return Err(HpkeError::IncorrectInputLength(Self::OutputSize::to_usize(), encoded.len()));
        }
        let (pq, x) = encoded.split_at(KemNct::to_usize());
        let ct_pq = <[u8; KemNct::USIZE]>::try_from(pq).expect("correct length").into();
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
        PublicKey { ek_pq: sk.dk_pq.encapsulation_key().clone(), pk_x: sk.pk_x }
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
        assert!(sender_id_keypair.is_none(), "auth mode is not used by age");
        let (ct_pq, ss_pq) = pk_recip.ek_pq.encapsulate(csprng).map_err(|()| HpkeError::EncapError)?;
        let ek_x = StaticSecret::random_from_rng(&mut *csprng);
        let ct_x = XPublic::from(&ek_x);
        let ss_x = ek_x.diffie_hellman(&pk_recip.pk_x);
        if !ss_x.was_contributory() {
            return Err(HpkeError::EncapError);
        }
        let ss = combine(&ss_pq, ss_x.as_bytes(), ct_x.as_bytes(), pk_recip.pk_x.as_bytes());
        Ok((SharedSecret(ss), EncappedKey { ct_pq, ct_x: ct_x.to_bytes() }))
    }

    fn decap(
        sk_recip: &Self::PrivateKey,
        pk_sender_id: Option<&Self::PublicKey>,
        encapped_key: &Self::EncappedKey,
    ) -> Result<SharedSecret<Self>, HpkeError> {
        assert!(pk_sender_id.is_none(), "auth mode is not used by age");
        // ML-KEM uses implicit rejection: a bad ciphertext yields a random secret, not an error.
        let ss_pq = sk_recip.dk_pq.decapsulate(&encapped_key.ct_pq).map_err(|()| HpkeError::DecapError)?;
        let ss_x = sk_recip.sk_x.diffie_hellman(&XPublic::from(encapped_key.ct_x));
        // Low-order point: the all-zero secret is disallowed (CCTV `hybrid_low_order`).
        if !ss_x.was_contributory() {
            return Err(HpkeError::DecapError);
        }
        let ss = combine(&ss_pq, ss_x.as_bytes(), &encapped_key.ct_x, sk_recip.pk_x.as_bytes());
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
    h.update(LABEL);
    h.finalize_fixed()
}
```

If `Ciphertext<MlKem768>` does not deref to `[u8]` for `copy_from_slice`, use `&self.ct_pq.0` exactly as `age::tagpq::kem` does; if `[u8; KemNct::USIZE]` needs the `Unsigned` import, it is already imported. If `StaticSecret::random_from_rng` is unavailable for `&mut R`, fill `[u8; 32]` with `csprng.fill_bytes` and use `StaticSecret::from(bytes)` (then zeroize the array).

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p sealdrop-core pq::kem`
Expected: 4 passed.

- [ ] **Step 6: Lint and commit**

```bash
cargo fmt --all && cargo clippy -p sealdrop-core --all-targets -- -D warnings
git add crates/sealdrop-core/Cargo.toml Cargo.lock crates/sealdrop-core/src/lib.rs crates/sealdrop-core/src/pq.rs crates/sealdrop-core/src/pq/kem.rs
git commit -m "feat(core): X-Wing (MLKEM768-X25519) KEM for age's mlkem768x25519 type"
```

---

### Task 2: `pq::Recipient` / `pq::Identity` and the stanza; CCTV 147/147

**Files:**
- Modify: `crates/sealdrop-core/src/pq.rs`
- Modify: `crates/sealdrop-core/tests/cctv.rs:74-105`
- Test: unit tests in `pq.rs`; `tests/cctv.rs`

**Interfaces:**
- Consumes: Task 1 `kem::{MlKem768X25519, PrivateKey, PublicKey, EncappedKey, expand_seed}`.
- Produces:
  - `pub struct pq::Recipient(kem::PublicKey)`: `FromStr` (HRP `age1pq`), `Display` (lowercase bech32), `Clone`, `PartialEq`, `Debug` (prints the string), `impl age::Recipient` (labels `{"postquantum"}`).
  - `pub struct pq::Identity { seed: Zeroizing<[u8; 32]>, .. }`: `Identity::generate() -> Self`, `FromStr` (HRP `AGE-SECRET-KEY-PQ-`, case-insensitive bech32), `Display` (UPPERCASE), `to_public() -> Recipient`, `impl age::Identity`, `Clone`.
  - `pub fn pq::is_pq_stanza_tag(tag: &str) -> bool` (`mlkem768x25519` or `mlkem768p256tag`).

- [ ] **Step 1: Write the failing unit tests**

Append to `crates/sealdrop-core/src/pq.rs`:

```rust
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
    }

    #[test]
    fn wrap_and_unwrap() {
        let id = Identity::generate();
        let (stanzas, labels) = age::Recipient::wrap_file_key(&id.to_public(), &file_key()).unwrap();
        assert_eq!(labels, std::collections::HashSet::from([LABEL.to_string()]));
        assert_eq!(stanzas.len(), 1);
        let s = &stanzas[0];
        assert_eq!(s.tag, TAG);
        assert_eq!(s.args.len(), 1);
        assert_eq!(BASE64_STANDARD_NO_PAD.decode(&s.args[0]).unwrap().len(), ENC_LEN);
        assert_eq!(s.body.len(), BODY_LEN);
        let got = age::Identity::unwrap_stanza(&id, s).unwrap().unwrap();
        assert_eq!(got.expose_secret(), file_key().expose_secret());
        // A different identity: "no match", not an error.
        assert!(age::Identity::unwrap_stanza(&Identity::generate(), s).is_none());
    }

    fn stanza_for(id: &Identity) -> Stanza {
        age::Recipient::wrap_file_key(&id.to_public(), &file_key()).unwrap().0.remove(0)
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
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p sealdrop-core pq::tests`
Expected: compile errors (`Identity`, `Recipient` missing).

- [ ] **Step 3: Implement recipient, identity and stanza**

Insert between the constants and the tests in `pq.rs`:

```rust
use std::collections::HashSet;
use std::fmt;
use std::str::FromStr;

use age::{DecryptError, EncryptError};
use age_core::format::{FileKey, Stanza, FILE_KEY_BYTES};
use age_core::primitives::{hpke_open, hpke_seal};
use base64::prelude::{Engine, BASE64_STANDARD_NO_PAD};
use hpke::{Deserializable, Serializable};
use rand_core06::{OsRng, RngCore};
use zeroize::Zeroizing;

use kem::MlKem768X25519 as Kem;

fn bech32_decode(s: &str, want_hrp: &str) -> Result<Vec<u8>, &'static str> {
    let (hrp, data) = bech32::decode(s).map_err(|_| "invalid Bech32 encoding")?;
    if !hrp.as_str().eq_ignore_ascii_case(want_hrp) {
        return Err("incorrect HRP");
    }
    Ok(data)
}

/// `age1pq1…`: ML-KEM-768 encapsulation key || X25519 public key (1216 bytes).
#[derive(Clone)]
pub struct Recipient(kem::PublicKey);

impl FromStr for Recipient {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = bech32_decode(s.trim(), RECIPIENT_HRP)?;
        kem::PublicKey::from_bytes(&bytes).map(Self).map_err(|_| "invalid recipient")
    }
}

impl fmt::Display for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hrp = bech32::Hrp::parse(RECIPIENT_HRP).expect("valid hrp");
        let s = bech32::encode::<bech32::Bech32>(hrp, &self.0.to_bytes()).map_err(|_| fmt::Error)?;
        f.write_str(&s)
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
    fn wrap_file_key(&self, file_key: &FileKey) -> Result<(Vec<Stanza>, HashSet<String>), EncryptError> {
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
        let bytes = bech32_decode(s.trim(), IDENTITY_HRP)?;
        let seed: [u8; 32] = bytes.as_slice().try_into().map_err(|_| "invalid identity")?;
        let sk = kem::PrivateKey::from_bytes(&seed).map_err(|_| "invalid identity")?;
        Ok(Self { seed: Zeroizing::new(seed), sk })
    }
}

impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hrp = bech32::Hrp::parse(IDENTITY_HRP).expect("valid hrp");
        let s = bech32::encode::<bech32::Bech32>(hrp, &*self.seed).map_err(|_| fmt::Error)?;
        f.write_str(&s.to_uppercase())
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
            Ok(pt) => {
                let mut fk = [0u8; FILE_KEY_BYTES];
                if pt.len() != FILE_KEY_BYTES {
                    return Some(Err(DecryptError::InvalidHeader));
                }
                fk.copy_from_slice(&pt);
                Some(Ok(FileKey::new(Box::new(fk))))
            }
            // The low-order check lives in `decap` and surfaces as DecapError.
            Err(hpke::HpkeError::DecapError) => Some(Err(DecryptError::InvalidHeader)),
            // Wrong key: ML-KEM's implicit rejection ends here, as an AEAD failure.
            Err(_) => None,
        }
    }
}
```

Notes for the implementer: `hpke_seal` needs `R: rand::RngCore + rand::CryptoRng` from age-core's `rand 0.8`, which re-exports the `rand_core 0.6` traits, so `rand_core06::OsRng` satisfies it. `FILE_KEY_BYTES` is `pub const` in `age_core::format`. The decrypted `pt` is a `Vec<u8>`; zeroize it after copying (`use zeroize::Zeroize; pt.zeroize()` after the copy; make `pt` mutable).

- [ ] **Step 4: Run the unit tests**

Run: `cargo test -p sealdrop-core pq::`
Expected: all pass (4 from Task 1 plus 4 new).

- [ ] **Step 5: Remove the CCTV skip path**

In `crates/sealdrop-core/tests/cctv.rs` replace lines 74–105 (the `unsupported` logic) so identities parse as x25519 **or** pq and nothing is skipped:

```rust
    let mut failures = Vec::new();
    let mut passed = 0usize;
    for path in &names {
        let v = load(path);
        assert!(!v.expect.is_empty(), "{}: vector without expect", v.name);
        let mut ids: Vec<Box<dyn age::Identity>> = Vec::new();
        for i in &v.identities {
            if let Ok(id) = age::x25519::Identity::from_str(i) {
                ids.push(Box::new(id));
            } else if let Ok(id) = sealdrop_core::pq::Identity::from_str(i) {
                ids.push(Box::new(id));
            } else {
                panic!("{}: identity line of unknown type", v.name);
            }
        }
```

Delete the `skipped` vector and every later reference to it; the summary line becomes
`eprintln!("CCTV: total={} passed={} failed={}", names.len(), passed, failures.len());`
and the final assertions are `assert!(failures.is_empty(), …)` and `assert_eq!(passed, names.len())`.

- [ ] **Step 6: Run CCTV**

Run: `cargo test -p sealdrop-core --test cctv -- --nocapture`
Expected: `CCTV: total=147 passed=147 failed=0`. If a `hybrid_*` vector fails, the failure line prints its comment; fix the rule in `unwrap_stanza` (do not special-case vector names).

- [ ] **Step 7: Lint and commit**

```bash
cargo fmt --all && cargo clippy -p sealdrop-core --all-targets -- -D warnings && cargo test -p sealdrop-core
git add crates/sealdrop-core/src/pq.rs crates/sealdrop-core/tests/cctv.rs
git commit -m "feat(core): native age1pq recipients and identities; CCTV 147/147"
```

---

### Task 3: `Recipient::Pq`, PQ identities in the key store, open uses them; Go-age interop

**Files:**
- Modify: `crates/sealdrop-core/src/crypt.rs:31-75,118-150`
- Modify: `crates/sealdrop-core/src/keys.rs:60-70,156-230`
- Modify: `crates/sealdrop-core/src/open.rs:204-224`
- Modify: `crates/sealdrop-core/src/seal.rs:171` (self recipient parse unchanged; see note)
- Modify: `crates/sealdrop-core/tests/interop_age.rs`
- Modify: `apps/desktop/src-tauri/src/commands.rs:242-261` (compile fix only: `generate(force, IdentityKind::X25519)`; the real desktop work is Task 8)
- Modify: `crates/sealdrop-cli/src/commands/keygen.rs` (compile fix only: `generate(force, IdentityKind::X25519)`; real CLI work is Task 7)
- Test: unit tests in `crypt.rs`, `keys.rs`, `open.rs`; `tests/interop_age.rs`

**Interfaces:**
- Produces:
  - `crypt::Recipient::Pq(crate::pq::Recipient)`; `kind()` → `"pq"`.
  - `keys::IdentityKind { X25519, Pq }` with `as_str()` → `"x25519"` / `"pq"` and `Display`.
  - `KeyStore::generate(&self, force: bool, kind: IdentityKind) -> Result<KeyInfo>`; `KeyInfo { recipient, signer, kind: IdentityKind }`.
  - `KeyStore::identity_kind(&self) -> Result<IdentityKind>`; `KeyStore::recipient_string()` for both kinds; `KeyStore::native_identities(&self) -> Result<Vec<Box<dyn age::Identity>>>` (the x25519 or pq identity line; `Err(InvalidIdentity)` when neither is present); `identity()` unchanged (x25519 only).

- [ ] **Step 1: Failing tests for the recipient variant and key store**

In `crypt.rs` tests add:

```rust
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
    fn round_trips_to_pq_recipient() {
        let id = crate::pq::Identity::generate();
        let specs = vec![Recipient::parse(&id.to_public().to_string()).unwrap()];
        let recips = to_age_recipients(&specs).unwrap();
        let mut w = encrypt_writer(Vec::new(), &recips, false).unwrap();
        w.write_all(b"pq hello").unwrap();
        let ct = w.finish().unwrap();
        let ids: Vec<Box<dyn age::Identity>> = vec![Box::new(id)];
        let mut pt = Vec::new();
        decrypt_reader(&ct[..], &ids).unwrap().read_to_end(&mut pt).unwrap();
        assert_eq!(pt, b"pq hello");
    }
```

In `keys.rs` tests add:

```rust
    #[test]
    fn pq_identity_persists_and_reloads() {
        let d = tempfile::tempdir().unwrap();
        let ks = KeyStore::open(d.path().join("store"));
        let info = ks.generate(false, IdentityKind::Pq).unwrap();
        assert_eq!(info.kind, IdentityKind::Pq);
        assert!(info.recipient.starts_with("age1pq1"));
        assert_eq!(ks.identity_kind().unwrap(), IdentityKind::Pq);
        assert_eq!(ks.recipient_string().unwrap(), info.recipient);
        // No x25519 secret in a PQ store, but one native identity.
        assert!(matches!(ks.identity(), Err(Error::InvalidIdentity)));
        assert_eq!(ks.native_identities().unwrap().len(), 1);
        let text = std::fs::read_to_string(ks.dir().join("identity.txt")).unwrap();
        assert!(text.contains("\nAGE-SECRET-KEY-PQ-1"));
        assert!(text.contains("# public key: age1pq1"));
        // Classic store still reports x25519.
        let ks2 = KeyStore::open(d.path().join("store2"));
        let info2 = ks2.generate(false, IdentityKind::X25519).unwrap();
        assert_eq!(info2.kind, IdentityKind::X25519);
        assert_eq!(ks2.identity_kind().unwrap(), IdentityKind::X25519);
        assert_eq!(ks2.native_identities().unwrap().len(), 1);
    }
```

Update the existing `keys.rs` tests to call `generate(false, IdentityKind::X25519)` / `generate(true, IdentityKind::X25519)`.

In `open.rs` tests add (next to `seal_to_self_verify_and_open`):

```rust
    #[test]
    fn pq_store_seals_to_self_and_opens() {
        let d = tempfile::tempdir().unwrap();
        let ks = KeyStore::open(d.path().join("ks"));
        ks.generate(false, crate::keys::IdentityKind::Pq).unwrap();
        let inp = input(d.path());
        let out = d.path().join("out");
        let r = seal(&ks, req(inp, out.clone(), Mode::Recipients(vec![me(&ks)])), &NoProgress).unwrap();
        assert_eq!(r.manifest_doc.recipients[0].kind, "pq");
        let rep = open(&ks, open_req(r.package, d.path().join("restored")), Box::new(MemoryFetch::expired()), &NoProgress).unwrap();
        assert_eq!(rep.extract.files, 2);
    }
```

(`store()` in the open tests calls `ks.generate(false)`; change it to `generate(false, crate::keys::IdentityKind::X25519)`.)

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p sealdrop-core crypt:: keys:: open::`
Expected: compile errors.

- [ ] **Step 3: Implement**

`crypt.rs`:

```rust
#[derive(Clone)]
#[allow(clippy::large_enum_variant)]
pub enum Recipient {
    X25519(age::x25519::Recipient),
    /// age's native hybrid type (`age1pq1…`, ML-KEM-768 + X25519).
    Pq(crate::pq::Recipient),
    Hybrid(age::tagpq::Recipient),
    Plugin(age::plugin::Recipient),
}
```

In `parse`, insert after the x25519 attempt and before `tagpq`:

```rust
        if let Ok(r) = crate::pq::Recipient::from_str(s) {
            return Ok(Self::Pq(r));
        }
```

`kind()`: `Self::Pq(_) => "pq".into(),`; `Display`: `Self::Pq(r) => write!(f, "{r}"),`; `to_age_recipients`: `Recipient::Pq(r) => out.push(Box::new(r.clone())),`. `plugin_name` returns `None` for it (falls into `_`).

`keys.rs`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IdentityKind {
    X25519,
    Pq,
}

impl IdentityKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::X25519 => "x25519",
            Self::Pq => "pq",
        }
    }
}

impl fmt::Display for IdentityKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone)]
pub struct KeyInfo {
    pub recipient: String,
    pub signer: String,
    pub kind: IdentityKind,
}
```

In `generate(&self, force: bool, kind: IdentityKind)`, replace the x25519 block with:

```rust
        let (recipient, secret_line): (String, Zeroizing<String>) = match kind {
            IdentityKind::X25519 => {
                let id = age::x25519::Identity::generate();
                (id.to_public().to_string(), Zeroizing::new(id.to_string().expose_secret().to_string()))
            }
            IdentityKind::Pq => {
                let id = crate::pq::Identity::generate();
                (id.to_public().to_string(), Zeroizing::new(id.to_string()))
            }
        };
        let created = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
        let body = Zeroizing::new(format!(
            "# created: {created}\n# public key: {recipient}\n{}\n",
            secret_line.as_str()
        ));
```

and return `KeyInfo { recipient, signer: kp.pk.to_base64(), kind }`.

Add:

```rust
    /// The native identity type in the identity file.
    pub fn identity_kind(&self) -> Result<IdentityKind> {
        let lines = self.identity_lines()?;
        if lines.iter().any(|l| l.starts_with("AGE-SECRET-KEY-PQ-1")) {
            Ok(IdentityKind::Pq)
        } else if lines.iter().any(|l| l.starts_with("AGE-SECRET-KEY-1")) {
            Ok(IdentityKind::X25519)
        } else {
            Err(Error::InvalidIdentity)
        }
    }

    fn pq_identity(&self) -> Result<crate::pq::Identity> {
        let lines = self.identity_lines()?;
        let line = lines
            .iter()
            .find(|l| l.starts_with("AGE-SECRET-KEY-PQ-1"))
            .ok_or(Error::InvalidIdentity)?;
        crate::pq::Identity::from_str(line).map_err(|_| Error::InvalidIdentity)
    }

    /// Every native (non-plugin) identity in the file, boxed for age.
    pub fn native_identities(&self) -> Result<Vec<Box<dyn age::Identity>>> {
        match self.identity_kind()? {
            IdentityKind::X25519 => Ok(vec![Box::new(self.identity()?)]),
            IdentityKind::Pq => Ok(vec![Box::new(self.pq_identity()?)]),
        }
    }

    pub fn recipient_string(&self) -> Result<String> {
        match self.identity_kind()? {
            IdentityKind::X25519 => Ok(self.identity()?.to_public().to_string()),
            IdentityKind::Pq => Ok(self.pq_identity()?.to_public().to_string()),
        }
    }
```

Note the x25519 `identity()` must match the prefix `AGE-SECRET-KEY-1` and not `AGE-SECRET-KEY-PQ-1`; `starts_with("AGE-SECRET-KEY-1")` already excludes the PQ form (different 16th character), keep it.

`open.rs` lines 204–224: replace the `match store.identity()` block with

```rust
    if store.has_identity() {
        let mut have_secret = true;
        match store.native_identities() {
            Ok(ids) => inner.extend(ids),
            // Plugin-only identity files have no native secret key line.
            Err(Error::InvalidIdentity) => have_secret = false,
            Err(e) => return Err(e),
        }
```

(rest unchanged). Fix the two compile sites (`keygen.rs`, Tauri `generate_identity`) by passing `IdentityKind::X25519` for now.

- [ ] **Step 4: Run the unit tests**

Run: `cargo test --workspace`
Expected: all green, including the pq open round trip.

- [ ] **Step 5: Interop tests with Go age 1.3.2**

Append to `crates/sealdrop-core/tests/interop_age.rs`:

```rust
/// Go age decrypts a sealdrop package sealed to a sealdrop-generated PQ identity.
#[test]
fn stock_age_decrypts_pq_recipient_package() {
    if !age_available() {
        eprintln!("skipping: age not installed");
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let ks = KeyStore::open(d.path().join("ks"));
    ks.generate(false, sealdrop_core::keys::IdentityKind::Pq).unwrap();
    let me = sealdrop_core::crypt::Recipient::parse(&ks.recipient_string().unwrap()).unwrap();
    assert_eq!(me.kind(), "pq");
    let res = seal(
        &ks,
        SealRequest {
            input: fixture(d.path()),
            out_dir: d.path().join("out"),
            mode: Mode::Recipients(vec![me]),
            include_self: false,
            allow_unrecoverable: false,
            armor: false,
            classification: None,
            expires: None,
            release: None,
        },
        &NoProgress,
    )
    .unwrap();
    let tar = d.path().join("plain.tar");
    let out = Command::new("age")
        .arg("-d")
        .arg("-i")
        .arg(ks.dir().join("identity.txt"))
        .arg("-o")
        .arg(&tar)
        .arg(&res.package)
        .output()
        .unwrap();
    assert!(out.status.success(), "age -d failed: {}", String::from_utf8_lossy(&out.stderr));
    let (sha, _) = sealdrop_core::hashing::sha256_file(&tar).unwrap();
    assert_eq!(sha, res.pack.tar_sha256);
    // age-keygen (when present) derives the same recipient from our identity file.
    if Command::new("age-keygen").arg("--version").output().map(|o| o.status.success()).unwrap_or(false) {
        let y = Command::new("age-keygen").arg("-y").arg(ks.dir().join("identity.txt")).output().unwrap();
        assert!(y.status.success());
        assert_eq!(String::from_utf8_lossy(&y.stdout).trim(), ks.recipient_string().unwrap());
    }
}

/// sealdrop opens a file Go age encrypted to a sealdrop PQ recipient (the raw age layer).
#[test]
fn sealdrop_decrypts_what_stock_age_encrypted_to_pq() {
    if !age_available() {
        eprintln!("skipping: age not installed");
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let id = sealdrop_core::pq::Identity::generate();
    let ct = d.path().join("x.age");
    std::fs::write(d.path().join("x.txt"), b"from go age").unwrap();
    let out = Command::new("age")
        .arg("-r")
        .arg(id.to_public().to_string())
        .arg("-o")
        .arg(&ct)
        .arg(d.path().join("x.txt"))
        .output()
        .unwrap();
    assert!(out.status.success(), "age -e failed: {}", String::from_utf8_lossy(&out.stderr));
    let ids: Vec<Box<dyn age::Identity>> = vec![Box::new(id)];
    let mut pt = Vec::new();
    std::io::Read::read_to_end(
        &mut sealdrop_core::crypt::decrypt_reader(std::fs::File::open(&ct).unwrap(), &ids).unwrap(),
        &mut pt,
    )
    .unwrap();
    assert_eq!(pt, b"from go age");
}
```

Update the existing interop tests' `ks.generate(false)` calls to `generate(false, sealdrop_core::keys::IdentityKind::X25519)`.

- [ ] **Step 6: Run interop with age on PATH**

Run (Git Bash): `PATH="$HOME/go/bin:$PATH" SEALDROP_REQUIRE_AGE=1 cargo test -p sealdrop-core --test interop_age`
Expected: 5 passed. (`age-keygen` is optional; install with `go install filippo.io/age/cmd/age-keygen@latest` to exercise the recipient-equality check.)

- [ ] **Step 7: CI: install age-keygen too**

In `.github/workflows/ci.yml` after the `go install filippo.io/age/cmd/age@latest` line add `go install filippo.io/age/cmd/age-keygen@latest`.

- [ ] **Step 8: Lint and commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
git add -A crates .github/workflows/ci.yml apps/desktop/src-tauri/src/commands.rs
git commit -m "feat(core): pq recipient kind, PQ identities in the key store, Go age interop"
```

---

### Task 4: PQ-only policy, `self_omitted`, `post_quantum` reporting

**Files:**
- Modify: `crates/sealdrop-core/src/policy.rs`
- Modify: `crates/sealdrop-core/src/seal.rs:158-176,330-346`
- Modify: `crates/sealdrop-core/src/probe.rs:22-28,105-125`
- Modify: `crates/sealdrop-core/src/open.rs:20-25,129-135`
- Test: unit tests in each file

**Interfaces:**
- Produces:
  - `policy::is_post_quantum_kind(kind: &str) -> bool` (`pq` | `hybrid-pq`).
  - `PolicyError::PqMustNotMix { classical: Vec<String> }` (fingerprints), message `post-quantum recipients cannot be mixed with classical ones (classical: <fp>, <fp>); seal them separately`.
  - `SealResult.self_omitted: Option<String>` (human sentence, or `None`).
  - `Probe.post_quantum: bool`; `VerifyReport.post_quantum: bool`; `open::post_quantum_kinds(recipients: &[RecipientInfo]) -> bool`.

- [ ] **Step 1: Failing tests**

`policy.rs` tests (add inside `rules()` or a new test):

```rust
    fn pq() -> Recipient {
        Recipient::parse(&crate::pq::Identity::generate().to_public().to_string()).unwrap()
    }

    #[test]
    fn pq_must_not_mix() {
        assert_eq!(check_recipients(&[pq(), pq()], false, false), Ok(()));
        let x = x();
        match check_recipients(&[pq(), x.clone()], false, false) {
            Err(PolicyError::PqMustNotMix { classical }) => assert_eq!(classical, vec![x.fingerprint()]),
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            check_recipients(&[pq(), plugin("yubikey")], false, true),
            Err(PolicyError::PqMustNotMix { .. })
        ));
        assert!(is_post_quantum_kind("pq") && is_post_quantum_kind("hybrid-pq"));
        assert!(!is_post_quantum_kind("x25519") && !is_post_quantum_kind("plugin:pq"));
    }
```

`seal.rs`/`open.rs` test (in `open.rs` tests, which already have helpers):

```rust
    #[test]
    fn classical_self_is_omitted_from_a_pq_package() {
        let (d, ks) = store(); // x25519 store
        let pq = crate::pq::Identity::generate();
        let r = Recipient::parse(&pq.to_public().to_string()).unwrap();
        let res = seal(&ks, req(input(d.path()), d.path().join("out"), Mode::Recipients(vec![r])), &NoProgress).unwrap();
        assert!(res.self_omitted.as_deref().unwrap().contains("post-quantum"));
        assert_eq!(res.manifest_doc.recipients.len(), 1);
        let v = verify(&ks, &res.package, None).unwrap();
        assert!(v.post_quantum);
        let p = crate::probe::probe(&res.package).unwrap();
        assert!(p.post_quantum);
    }

    #[test]
    fn classical_package_reports_not_post_quantum() {
        let (d, ks) = store();
        let res = seal(&ks, req(input(d.path()), d.path().join("out"), Mode::Recipients(vec![me(&ks)])), &NoProgress).unwrap();
        assert!(res.self_omitted.is_none());
        assert!(!verify(&ks, &res.package, None).unwrap().post_quantum);
        assert!(!crate::probe::probe(&res.package).unwrap().post_quantum);
    }
```

(`Recipient` here is `crate::crypt::Recipient`; import it in the test module.)

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p sealdrop-core policy:: open::`
Expected: compile errors.

- [ ] **Step 3: Implement**

`policy.rs`:

```rust
    #[error("post-quantum recipients cannot be mixed with classical ones (classical: {}); seal them separately", .classical.join(", "))]
    PqMustNotMix { classical: Vec<String> },
```

```rust
/// Manifest kinds whose key wrap resists a quantum adversary.
pub fn is_post_quantum_kind(kind: &str) -> bool {
    kind == "pq" || kind == "hybrid-pq"
}
```

In `check_recipients`, after the plugin allow-list loop and before `all_hardware`:

```rust
    if recipients.iter().any(|r| is_post_quantum_kind(&r.kind())) {
        let classical: Vec<String> = recipients
            .iter()
            .filter(|r| !is_post_quantum_kind(&r.kind()))
            .map(|r| r.fingerprint())
            .collect();
        if !classical.is_empty() {
            return Err(PolicyError::PqMustNotMix { classical });
        }
    }
```

`seal.rs`: add `pub self_omitted: Option<String>` to `SealResult`. Replace the include-self block:

```rust
    let mut self_omitted: Option<String> = None;
    if req.include_self && !passphrase_mode && req.release.is_none() {
        let me = Recipient::parse(&store.recipient_string()?)?;
        let given_pq = !specs.is_empty() && specs.iter().all(|r| policy::is_post_quantum_kind(&r.kind()));
        let me_pq = policy::is_post_quantum_kind(&me.kind());
        if !specs.is_empty() && given_pq != me_pq {
            self_omitted = Some(if given_pq {
                "your own identity is classical (x25519), so it was not added to this post-quantum package; create a post-quantum identity with `keygen --pq` to include yourself".into()
            } else {
                "your own identity is post-quantum, so it was not added to this classical package; the recipients would otherwise be mixed".into()
            });
        } else if !specs.iter().any(|r| r.to_string() == me.to_string()) {
            specs.push(me);
        }
    }
```

and set `self_omitted` in the returned `SealResult`. (Timed-release packages never add self today; unchanged.)

`probe.rs`: add `pub post_quantum: bool` to `Probe`; after the loop:

```rust
    // Grease stanzas (`*-grease`) are not real stanzas. A release stanza hides its inner
    // kinds, so a timed package is only known from its manifest (see `open::verify`).
    let real: Vec<&String> = tags.iter().filter(|t| !t.ends_with("-grease")).collect();
    let post_quantum = !real.is_empty()
        && real.iter().all(|t| crate::pq::is_pq_stanza_tag(t));
```

`open.rs`: add `pub post_quantum: bool` to `VerifyReport`, plus

```rust
/// True when every recipient of the signed manifest is a post-quantum kind.
pub fn post_quantum_kinds(recipients: &[crate::manifest::RecipientInfo]) -> bool {
    !recipients.is_empty() && recipients.iter().all(|r| crate::policy::is_post_quantum_kind(&r.kind))
}
```

and in `verify_with` set `post_quantum: post_quantum_kinds(&doc.recipients)` before moving `doc`.

- [ ] **Step 4: Run tests, lint, commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
git add crates/sealdrop-core/src/policy.rs crates/sealdrop-core/src/seal.rs crates/sealdrop-core/src/probe.rs crates/sealdrop-core/src/open.rs
git commit -m "feat(core): PQ-only recipient policy, self_omitted note, post_quantum reporting"
```

---

### Task 5: Manifest key commitment

**Files:**
- Modify: `crates/sealdrop-core/src/manifest.rs:36-50`
- Modify: `crates/sealdrop-core/src/crypt.rs` (new adapters + `key_commitment`)
- Modify: `crates/sealdrop-core/src/seal.rs:240-250,283-300`
- Modify: `crates/sealdrop-core/src/open.rs:236-262`
- Test: unit tests in `crypt.rs` and `open.rs`

**Interfaces:**
- Produces:
  - `manifest::Manifest.key_commitment: Option<String>` (`#[serde(default, skip_serializing_if = "Option::is_none")]`, placed after `plaintext_tar_sha256`).
  - `crypt::key_commitment(file_key: &FileKey) -> [u8; 32]` = `age_core::primitives::hkdf(&[], b"sealdrop/commit/v1", file_key.expose_secret())`; `crypt::COMMIT_INFO: &[u8]`.
  - `crypt::Committing { inner: Vec<Box<dyn age::Recipient + Send>>, captured: Mutex<Option<Zeroizing<[u8;16]>>> }` with `Committing::new(inner)`, `impl age::Recipient` (label consistency check), `fn commitment_hex(&self) -> Option<String>`.
  - `crypt::CommittedIdentity<'a> { inner: &'a dyn age::Identity, expected: Option<[u8; 32]>, mismatch: Cell<bool> }` with `new(inner, expected)`, `impl age::Identity` (delegates `unwrap_stanza` and `unwrap_stanzas`, checks on `Ok`), `fn mismatched(&self) -> bool`.
  - `hex` decoding helper for the manifest value: `crypt::parse_commitment(s: &str) -> Option<[u8; 32]>` (64 lowercase hex chars exactly).

- [ ] **Step 1: Failing tests**

`crypt.rs` tests:

```rust
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
        assert_eq!(c.commitment_hex().unwrap(), hex::encode(key_commitment(&fk)));
        assert_eq!(parse_commitment(&c.commitment_hex().unwrap()).unwrap(), key_commitment(&fk));
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
        assert!(matches!(age::Identity::unwrap_stanza(&good, &stanzas[0]), Some(Ok(_))));
        assert!(!good.mismatched());
        let bad = CommittedIdentity::new(&id, Some([0u8; 32]));
        assert!(matches!(age::Identity::unwrap_stanza(&bad, &stanzas[0]), Some(Err(_))));
        assert!(bad.mismatched());
        let unchecked = CommittedIdentity::new(&id, None);
        assert!(matches!(age::Identity::unwrap_stanza(&unchecked, &stanzas[0]), Some(Ok(_))));
    }
```

`open.rs` tests:

```rust
    #[test]
    fn manifest_carries_a_commitment_and_a_wrong_one_is_refused_before_plaintext() {
        let (d, ks) = store();
        let res = seal(&ks, req(input(d.path()), d.path().join("out"), Mode::Recipients(vec![me(&ks)])), &NoProgress).unwrap();
        let c = res.manifest_doc.key_commitment.clone().unwrap();
        assert_eq!(c.len(), 64);
        // Re-sign the manifest with a wrong commitment (same signer): verify passes, open refuses.
        let (mpath, spath) = bundle_paths(&res.package);
        let text = std::fs::read_to_string(&mpath).unwrap().replace(&c, &"0".repeat(64));
        std::fs::write(&mpath, &text).unwrap();
        let sig = crate::manifest::sign(text.as_bytes(), &ks.signing_key().unwrap(), &ks.signing_public().unwrap(), &res.manifest_doc.package_id).unwrap();
        std::fs::write(&spath, sig.into_string()).unwrap();
        assert!(verify(&ks, &res.package, None).is_ok());
        let out = d.path().join("restored");
        let err = open(&ks, open_req(res.package.clone(), out.clone()), Box::new(MemoryFetch::expired()), &NoProgress).unwrap_err();
        assert!(matches!(err, Error::Verify(ref m) if m.contains("key commitment")), "{err}");
        assert!(!out.join("report").exists());
        // Skipping verification skips the check too.
        let mut r = open_req(res.package.clone(), out.clone());
        r.skip_verify = true;
        assert!(open(&ks, r, Box::new(MemoryFetch::expired()), &NoProgress).is_ok());
    }

    #[test]
    fn manifest_without_commitment_still_opens() {
        let (d, ks) = store();
        let res = seal(&ks, req(input(d.path()), d.path().join("out"), Mode::Recipients(vec![me(&ks)])), &NoProgress).unwrap();
        let (mpath, spath) = bundle_paths(&res.package);
        let mut v: serde_json::Value = serde_json::from_slice(&std::fs::read(&mpath).unwrap()).unwrap();
        v.as_object_mut().unwrap().remove("key_commitment");
        let text = serde_json::to_vec_pretty(&v).unwrap();
        std::fs::write(&mpath, &text).unwrap();
        let sig = crate::manifest::sign(&text, &ks.signing_key().unwrap(), &ks.signing_public().unwrap(), &res.manifest_doc.package_id).unwrap();
        std::fs::write(&spath, sig.into_string()).unwrap();
        assert!(open(&ks, open_req(res.package, d.path().join("restored")), Box::new(MemoryFetch::expired()), &NoProgress).is_ok());
    }
```

Also add the passphrase and timed-release coverage: in the existing timed-release and passphrase open tests, assert `res.manifest_doc.key_commitment.is_some()`.

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p sealdrop-core crypt:: open::` → compile errors.

- [ ] **Step 3: Implement**

`manifest.rs`:

```rust
    pub plaintext_tar_sha256: String,
    /// HKDF-SHA-256(file key, info "sealdrop/commit/v1"), hex. Absent in manifests from
    /// sealdrop < 0.3; decoders check it when present (spec 5.4 step 7).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_commitment: Option<String>,
```

`crypt.rs`:

```rust
use std::cell::Cell;
use std::collections::HashSet;
use std::sync::Mutex;

use age::secrecy::ExposeSecret;
use age_core::format::{FileKey, Stanza, FILE_KEY_BYTES};
use zeroize::Zeroizing;

pub const COMMIT_INFO: &[u8] = b"sealdrop/commit/v1";

/// Spec 5.2 `key_commitment`: HKDF-SHA-256(ikm = file key, salt = empty, info = COMMIT_INFO).
pub fn key_commitment(file_key: &FileKey) -> [u8; 32] {
    age_core::primitives::hkdf(&[], COMMIT_INFO, file_key.expose_secret())
}

/// Exactly 64 lowercase hex characters.
pub fn parse_commitment(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let v = hex::decode(s).ok()?;
    v.try_into().ok()
}

/// Wraps the outer recipient list so `seal` can learn the file key age generated.
/// Replicates age's label rule, because age only sees this one recipient.
pub struct Committing {
    inner: Vec<Box<dyn age::Recipient + Send>>,
    captured: Mutex<Option<Zeroizing<[u8; FILE_KEY_BYTES]>>>,
}

impl Committing {
    pub fn new(inner: Vec<Box<dyn age::Recipient + Send>>) -> Self {
        Self { inner, captured: Mutex::new(None) }
    }

    pub fn commitment_hex(&self) -> Option<String> {
        let g = self.captured.lock().ok()?;
        let fk = g.as_ref()?;
        Some(hex::encode(age_core::primitives::hkdf(&[], COMMIT_INFO, &**fk)))
    }
}

impl age::Recipient for Committing {
    fn wrap_file_key(&self, file_key: &FileKey) -> Result<(Vec<Stanza>, HashSet<String>), age::EncryptError> {
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
        if let Ok(mut g) = self.captured.lock() {
            *g = Some(Zeroizing::new(*file_key.expose_secret()));
        }
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
        Self { inner, expected, mismatch: Cell::new(false) }
    }

    pub fn mismatched(&self) -> bool {
        self.mismatch.get()
    }

    fn check(&self, r: Option<Result<FileKey, age::DecryptError>>) -> Option<Result<FileKey, age::DecryptError>> {
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
    fn unwrap_stanza(&self, stanza: &Stanza) -> Option<Result<FileKey, age::DecryptError>> {
        self.check(self.inner.unwrap_stanza(stanza))
    }
    fn unwrap_stanzas(&self, stanzas: &[Stanza]) -> Option<Result<FileKey, age::DecryptError>> {
        self.check(self.inner.unwrap_stanzas(stanzas))
    }
}
```

Add `subtle = "2"` to `sealdrop-core` dependencies (already in the tree). Check the exact field names of `EncryptError::IncompatibleRecipients` in `age-0.12.1/src/error.rs:181` (`l_labels`, `r_labels`) and adjust if they differ.

`seal.rs`: wrap the final recipient list and record the commitment.

```rust
    let committing = crypt::Committing::new(recipients);
    let outer: Vec<Box<dyn age::Recipient + Send>> = vec![Box::new(OuterRef(&committing))];
    …
    let writer = crypt::encrypt_writer(file, &outer, req.armor)?;
```

`Committing` is used by reference because the manifest needs it after encryption; add in `seal.rs`:

```rust
/// Borrow `Committing` as a boxed recipient without moving it.
struct OuterRef<'a>(&'a crypt::Committing);
impl age::Recipient for OuterRef<'_> {
    fn wrap_file_key(&self, fk: &age_core::format::FileKey)
        -> std::result::Result<(Vec<age_core::format::Stanza>, std::collections::HashSet<String>), age::EncryptError> {
        age::Recipient::wrap_file_key(self.0, fk)
    }
}
```

(`Box<dyn age::Recipient + Send>` requires `Send`; `OuterRef<'a>` is `Send` when `Committing: Sync`, which holds because the captured key sits in a `Mutex` and `Box<dyn age::Recipient + Send>` inside is only accessed through `&self`... if the compiler objects that `dyn age::Recipient + Send` is not `Sync`, store `inner` as `Vec<Box<dyn age::Recipient + Send + Sync>>` and adjust `to_age_recipients` return type accordingly, or build the `Vec<Box<dyn Recipient + Send>>` for `encrypt_writer` as `vec![Box::new(committing)]` and read the commitment through an `Arc<Mutex<..>>` handed out by `Committing::handle()`. Pick whichever compiles cleanly; the test contract is `commitment_hex()` after encryption.)

Then in the `Manifest` literal: `key_commitment: committing.commitment_hex(),` and after `writer.finish()` assert `committing.commitment_hex().is_some()` else `return Err(Error::Other("file key was not captured".into()))`.

`open.rs`: replace `IdentityRef` with the new adapter:

```rust
    let expected = verify_report
        .as_ref()
        .and_then(|v| v.manifest.key_commitment.as_deref())
        .map(|s| crypt::parse_commitment(s).ok_or_else(|| Error::Verify("manifest key_commitment is malformed".into())))
        .transpose()?;
    let wrapper = release::Identity::new(inner, fetch);
    let committed = crypt::CommittedIdentity::new(&wrapper, expected);
    let file = BufReader::new(file);
    let ids: Vec<Box<dyn age::Identity + '_>> = vec![Box::new(IdentityRef(&committed))];
    let reader = match crypt::decrypt_reader(file, &ids) {
        Ok(r) => r,
        Err(e) if committed.mismatched() => {
            let _ = e;
            return Err(Error::Verify("file key does not match the signed manifest's key commitment".into()));
        }
        Err(e) => return Err(e),
    };
```

Keep `IdentityRef` but make it generic over the committed wrapper (`struct IdentityRef<'a>(&'a crypt::CommittedIdentity<'a>)`), delegating both `unwrap_stanza` and `unwrap_stanzas`.

- [ ] **Step 4: Run tests, lint, commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
git add crates/sealdrop-core
git commit -m "feat(core): manifest key_commitment, checked before any plaintext"
```

---

### Task 6: Case-insensitive path collisions (encoder and decoder)

**Files:**
- Modify: `crates/sealdrop-core/src/pack.rs:84-170`
- Modify: `crates/sealdrop-core/src/extract.rs:36-58,300-336`
- Test: unit tests in both files

**Interfaces:**
- Produces: `extract::ExtractError::CaseCollision(String, String)` (`"paths {0} and {1} differ only in letter case"`); `extract::case_collision(paths: impl Iterator<Item = &str>) -> Option<(String, String)>` (pub, shared by pack); `extract::destination_is_case_insensitive(dir: &Path) -> bool` (pub).

- [ ] **Step 1: Failing tests**

`pack.rs` tests:

```rust
    #[test]
    fn refuses_paths_that_collide_in_case() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("r");
        std::fs::create_dir_all(root.join("Sub")).unwrap();
        std::fs::write(root.join("a.txt"), b"1").unwrap();
        // On a case-insensitive FS the second write replaces the first; skip there.
        if std::fs::write(root.join("A.txt"), b"2").is_err() || std::fs::read_dir(&root).unwrap().count() < 3 {
            eprintln!("skipping: case-insensitive file system");
            return;
        }
        let err = pack(&root, Vec::new()).err().unwrap().to_string();
        assert!(err.contains("letter case"), "{err}");
    }
```

`extract.rs` tests:

```rust
    #[test]
    fn case_collision_detector() {
        assert_eq!(case_collision(["r/a.txt", "r/b.txt"].into_iter()), None);
        assert_eq!(
            case_collision(["r/a.txt", "r/Sub/x", "r/A.TXT"].into_iter()),
            Some(("r/a.txt".into(), "r/A.TXT".into()))
        );
        assert_eq!(
            case_collision(["r/sub/x", "r/SUB/y"].into_iter()),
            Some(("r/sub/x".into(), "r/SUB/y".into()))
        );
        // Unicode: Straße vs STRASSE do not collide under simple folding; ä vs Ä do.
        assert!(case_collision(["r/ä", "r/Ä"].into_iter()).is_some());
    }

    #[test]
    fn probe_reports_the_platform() {
        let d = tempfile::tempdir().unwrap();
        let ci = destination_is_case_insensitive(d.path());
        assert_eq!(ci, cfg!(any(windows, target_os = "macos")) || ci);
        // Probe files are cleaned up.
        assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 0);
    }

    #[test]
    fn colliding_package_is_refused_on_case_insensitive_destinations() {
        // A tar with r/a.txt and r/A.txt (built directly, as malicious_tar.rs does).
        let tar = crate::extract::tests::build_tar(&[("r/a.txt", b"1"), ("r/A.txt", b"2")]);
        let d = tempfile::tempdir().unwrap();
        let r = extract(&tar[..], d.path(), &Limits::default(), false);
        if destination_is_case_insensitive(d.path()) {
            assert!(matches!(r, Err(Error::Extract(ExtractError::CaseCollision(_, _)))), "{r:?}");
            assert!(!d.path().join("r").exists());
        } else {
            assert!(r.is_ok());
        }
    }
```

If `extract.rs` has no tar-building helper, add a small `pub(crate) fn build_tar(files: &[(&str, &[u8])]) -> Vec<u8>` in its test module that writes `sealdrop/meta.json` first (format `sealdrop/1`, root `r`, the listed files with sizes and SHA-256) and then each file under `sealdrop/payload/`, using the `tar` crate as `tests/malicious_tar.rs` does.

- [ ] **Step 2: Run to verify they fail** (`cargo test -p sealdrop-core pack:: extract::`).

- [ ] **Step 3: Implement**

`extract.rs`:

```rust
    #[error("paths {0} and {1} differ only in letter case")]
    CaseCollision(String, String),
```

```rust
/// Directory components and full paths that collide under Unicode lowercase folding.
/// Returns the first colliding pair (earlier path, later path). Directories count: `r/sub/x`
/// and `r/SUB/y` collide on the folder.
pub fn case_collision<'a>(paths: impl Iterator<Item = &'a str>) -> Option<(String, String)> {
    let mut seen: HashMap<String, String> = HashMap::new();
    for p in paths {
        let comps: Vec<&str> = p.split('/').collect();
        for i in 1..=comps.len() {
            let prefix = comps[..i].join("/");
            let folded = prefix.to_lowercase();
            match seen.get(&folded) {
                Some(prev) if *prev != prefix => return Some((prev.clone(), prefix)),
                Some(_) => {}
                None => {
                    seen.insert(folded, prefix);
                }
            }
        }
    }
    None
}

/// Creates `sealdrop-case-probe-a` in `dir` and asks for `…-A`. Any error means "unknown",
/// reported as case-sensitive (no refusal); the probe file is always removed.
pub fn destination_is_case_insensitive(dir: &Path) -> bool {
    let lower = dir.join(".sealdrop-case-probe-a");
    let upper = dir.join(".sealdrop-case-probe-A");
    let created = fs::OpenOptions::new().write(true).create_new(true).open(&lower).is_ok();
    if !created {
        return false;
    }
    let insensitive = fs::symlink_metadata(&upper).is_ok();
    let _ = fs::remove_file(&lower);
    insensitive
}
```

In `extract()`, right after the duplicate-path check and before creating the temp dir:

```rust
    fs::create_dir_all(out_dir)?;
    if destination_is_case_insensitive(out_dir) {
        if let Some((a, b)) = case_collision(meta.files.iter().map(|f| f.path.as_str())) {
            return Err(ExtractError::CaseCollision(a, b).into());
        }
    }
```

(Then remove the later duplicate `fs::create_dir_all(out_dir)?;`.) Also enforce it on the stream: because an archive could carry a colliding **entry** that is unlisted in meta, nothing extra is needed: unlisted files are already refused (`UnlistedFile`).

`pack.rs`: in `plan()` before returning, over files and dirs:

```rust
    if let Some((a, b)) = crate::extract::case_collision(
        dirs.iter().map(String::as_str).chain(files.iter().map(|(_, f)| f.path.as_str())),
    ) {
        return Err(Error::Other(format!(
            "cannot seal {}: `{a}` and `{b}` differ only in letter case, so one would replace \
             the other on Windows and macOS; rename one of them",
            root_name
        )));
    }
```

- [ ] **Step 4: Run tests, lint, commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
git add crates/sealdrop-core/src/pack.rs crates/sealdrop-core/src/extract.rs
git commit -m "fix(core): refuse paths that collide in letter case (encoder; decoder on case-insensitive targets)"
```

---

### Task 7: CLI surface

**Files:**
- Modify: `crates/sealdrop-cli/src/main.rs:44-52`
- Modify: `crates/sealdrop-cli/src/commands/keygen.rs`, `recipient.rs`, `seal.rs:33-35,195-226`, `verify.rs`, `open.rs:26-32,80-105,140-150`
- Modify: `crates/sealdrop-cli/Cargo.toml` (add `rpassword = "7"`)
- Test: `crates/sealdrop-cli/tests/cli.rs`

**Interfaces:**
- Consumes: `IdentityKind`, `KeyInfo.kind`, `SealResult.self_omitted`, `VerifyReport.post_quantum`, `PolicyError::PqMustNotMix`.

- [ ] **Step 1: Failing e2e tests** (append to `tests/cli.rs`)

```rust
#[test]
fn pq_keygen_seal_verify_open_and_mixing_is_refused() {
    let d = tempfile::tempdir().unwrap();
    let home = d.path().join("home");
    cmd(&home)
        .args(["keygen", "--pq"])
        .assert()
        .success()
        .stdout(predicate::str::contains("age1pq1"))
        .stderr(predicate::str::contains("post-quantum"));
    let out = cmd(&home).arg("recipient").output().unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    let rec = text.lines().next().unwrap().trim().to_string();
    assert!(rec.starts_with("age1pq1"));
    assert!(text.contains("kind: pq"), "{text}");

    let input = fixture(d.path());
    let outdir = d.path().join("bundle");
    cmd(&home)
        .arg("seal").arg(&input).args(["-r", &rec, "-o"]).arg(&outdir)
        .assert()
        .success()
        .stdout(predicate::str::contains("post-quantum: yes"));
    let pkg = outdir.join("report.sealdrop.age");
    cmd(&home)
        .arg("verify").arg(&pkg)
        .assert()
        .success()
        .stdout(predicate::str::contains("post-quantum: yes"))
        .stdout(predicate::str::contains("recipient: pq"));
    let manifest = std::fs::read_to_string(outdir.join("report.manifest.json")).unwrap();
    assert!(manifest.contains("\"key_commitment\""));
    let restored = d.path().join("restored");
    cmd(&home)
        .arg("open").arg(&pkg).arg("-o").arg(&restored)
        .assert()
        .success()
        .stdout(predicate::str::contains("post-quantum: yes"));
    assert_eq!(std::fs::read(restored.join("report/a.pdf")).unwrap(), b"%PDF");

    // A classical recipient next to the PQ one is refused with exit 1 and names the problem.
    let classic = {
        let h2 = d.path().join("home2");
        cmd(&h2).arg("keygen").assert().success();
        let o = cmd(&h2).arg("recipient").output().unwrap();
        String::from_utf8(o.stdout).unwrap().lines().next().unwrap().trim().to_string()
    };
    cmd(&home)
        .arg("seal").arg(&input).args(["-r", &rec, "-r", &classic, "-o"]).arg(d.path().join("b2"))
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("cannot be mixed"));
}

#[test]
fn classical_self_is_omitted_from_pq_packages_with_a_note() {
    let d = tempfile::tempdir().unwrap();
    let home = d.path().join("home");
    cmd(&home).arg("keygen").assert().success();
    let pq_home = d.path().join("pqhome");
    cmd(&pq_home).args(["keygen", "--pq"]).assert().success();
    let o = cmd(&pq_home).arg("recipient").output().unwrap();
    let rec = String::from_utf8(o.stdout).unwrap().lines().next().unwrap().trim().to_string();
    cmd(&home)
        .arg("seal").arg(fixture(d.path())).args(["-r", &rec, "-o"]).arg(d.path().join("b"))
        .assert()
        .success()
        .stderr(predicate::str::contains("not added"));
}
```

- [ ] **Step 2: Run to verify they fail** (`cargo test -p sealdrop-cli --test cli pq_`): fail on `--pq`.

- [ ] **Step 3: Implement**

`main.rs`:

```rust
    /// Create your identity (age key pair + minisign signing key)
    Keygen {
        /// Replace an existing identity (the old keys are lost)
        #[arg(long)]
        force: bool,
        /// Create a post-quantum identity (age1pq1…, ML-KEM-768 + X25519). Senders need
        /// sealdrop 0.3+ or age 1.3+; the recipient string is about 2 000 characters.
        #[arg(long)]
        pq: bool,
    },
```
and `Cmd::Keygen { force, pq } => commands::keygen::run(force, pq)`.

`keygen.rs`:

```rust
use sealdrop_core::keys::IdentityKind;

pub fn run(force: bool, pq: bool) -> anyhow::Result<()> {
    let ks = crate::store();
    let kind = if pq { IdentityKind::Pq } else { IdentityKind::X25519 };
    let info = ks.generate(force, kind)?;
    out!("{}", info.recipient);
    out!("{}", info.signer);
    eprintln!("identity written to {} (kind: {})", ks.dir().display(), info.kind);
    if pq {
        eprintln!("post-quantum identity: senders need sealdrop 0.3 or age 1.3 or newer");
    }
    eprintln!("share the first line (your recipient) with senders; the second is your signer key");
    Ok(())
}
```

`recipient.rs`: after the two lines, `out!("kind: {}", ks.identity_kind()?);`.

`seal.rs`: flag help `/// Recipient (age1..., age1pq1... post-quantum, age1tagpq1... hybrid post-quantum encrypt-only, or age1<plugin>1...). Repeatable. Post-quantum and classical recipients cannot be mixed in one package.`; after the `package id` line:

```rust
    out!(
        "post-quantum: {}",
        if sealdrop_core::open::post_quantum_kinds(&res.manifest_doc.recipients) { "yes" } else { "no" }
    );
    if let Some(note) = &res.self_omitted {
        eprintln!("note: {note}");
    }
```

`verify.rs`: after `created`: `out!("post-quantum: {}", if v.post_quantum { "yes" } else { "no" });`.

`open.rs`: in the `Some(v)` arm add a line `out!("post-quantum: {}", if v.post_quantum { "yes" } else { "no" });`. Hidden prompt:

```rust
/// Reads a passphrase without echo when stdin is a terminal; otherwise reads one line and
/// says that the input was not hidden.
fn read_secret_prompt(prompt: &str) -> anyhow::Result<SecretString> {
    if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        let s = Zeroizing::new(rpassword::prompt_password(prompt)?);
        anyhow::ensure!(!s.trim().is_empty(), "empty passphrase");
        return Ok(SecretString::from(s.trim().to_string()));
    }
    eprint!("{prompt}(input is not a terminal, so it is read as a line) ");
    read_line_secret()
}
```

Use it for `Prompt::Required` (`read_secret_prompt("passphrase: ")`) and for `Prompt::Optional` (an empty answer means none: catch the `empty passphrase` case and return `None`; simplest is a sibling `read_secret_prompt_optional` that returns `Ok(None)` on empty). Update the `--passphrase-stdin` help: `/// Read the passphrase from the first line of stdin instead of the hidden prompt`.

- [ ] **Step 4: Run, lint, commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings && cargo test -p sealdrop-cli
git add crates/sealdrop-cli
git commit -m "feat(cli): keygen --pq, post-quantum status, mixing refusal note, hidden passphrase prompt"
```

---

### Task 8: Desktop app (Tauri commands + React)

**Files:**
- Modify: `apps/desktop/src-tauri/src/commands.rs:235-262,267-295,355-370,440-475,530-590`
- Modify: `apps/desktop/src/lib/types.ts`, `format.ts:70-75,175-181`, `mock.ts:18-35,120-160`, `errors.ts:26-33`, `api.ts:42`
- Modify: `apps/desktop/src/screens/Keys.tsx:36-60,140-200,300-325`, `Seal.tsx` (result area and recipient chips), `Verify.tsx:300-325`, `Open.tsx:380-445,600-605`
- Test: `apps/desktop/src/lib/*.test.ts` (vitest; add cases to the existing format tests) and `commands.rs` unit tests

**Interfaces:**
- Backend: `IdentityInfo.kind: Option<String>` (`"x25519" | "pq"`), `generate_identity(force: bool, pq: bool)`, `SealOut.self_omitted: Option<String>`, `SealOut.post_quantum: bool`, `VerifyOut.post_quantum: Option<bool>`, `OpenOut.post_quantum: Option<bool>`, `RecipientCheck.kind` may be `"pq"`.
- Frontend: `kindLabel("pq") === "post-quantum"`, `recipientTone("pq") === "blue"`, `api.generateIdentity(force, pq)`.

- [ ] **Step 1: Backend failing test** (`commands.rs` tests)

```rust
    #[test]
    fn recipient_check_maps_pq_kind() {
        let s = sealdrop_core::pq::Identity::generate().to_public().to_string();
        let c = recipient_check(&sealdrop_core::crypt::Recipient::parse(&s).unwrap()).unwrap();
        assert_eq!(c.kind, "pq");
        assert_eq!(c.plugin, None);
        assert!(c.allowed);
    }
```

- [ ] **Step 2: Backend implementation**

`IdentityInfo` gains `pub kind: Option<String>` (`ks.identity_kind().ok().map(|k| k.as_str().to_string())`). `generate_identity(force: bool, pq: bool)` → `ks.generate(force, if pq { IdentityKind::Pq } else { IdentityKind::X25519 })`. `SealOut` gains `self_omitted: Option<String>` and `post_quantum: bool` (`sealdrop_core::open::post_quantum_kinds(&res.manifest_doc.recipients)`). `VerifyOut` gains `post_quantum: Option<bool>` (`Some(v.post_quantum)` on success, `None` in the untrusted case; `Default` gives `None`). `OpenOut` gains `post_quantum: Option<bool>` from `rep.verify.as_ref().map(|v| v.post_quantum)`. Run `cargo test -p sealdrop-desktop`.

- [ ] **Step 3: Frontend failing tests** (in the existing `format.test.ts`, or create `apps/desktop/src/lib/format.pq.test.ts`)

```ts
import { describe, expect, it } from "vitest";
import { kindLabel, recipientTone, recipientsText } from "./format";

describe("post-quantum kinds", () => {
  it("labels and tones pq like hybrid-pq", () => {
    expect(kindLabel("pq")).toBe("post-quantum");
    expect(recipientTone("pq")).toBe("blue");
    expect(recipientsText([{ kind: "pq" }, { kind: "pq" }], false)).toBe("2 (post-quantum)");
  });
});
```

And a mock test (`mock.test.ts` if one exists; else add to the same file):

```ts
import { mock } from "./mock";
it("mock parses age1pq1 as kind pq and refuses mixing", async () => {
  const pq = "age1pq1" + "q".repeat(1990);
  expect(await mock("parse_recipient", { s: pq })).toMatchObject({ kind: "pq", allowed: true });
  await expect(
    mock("seal", { req: { input: "C:/x", out_dir: "C:/o", recipients: [pq, "age1qx7k4m9v2c8l5n3z6p0t7y4h2j8d5s9w3e6r1u4a7g0f2b8x5m3q9c6k4v7w2f3k2"], passphrase: false, words: "eff", argon2id: false, kdf_profile: "default", armor: false, classification: null, expires: null, allow_unrecoverable: false, include_self: false, expire_after_secs: null } }),
  ).rejects.toMatch(/cannot be mixed/);
});
```

- [ ] **Step 4: Frontend implementation**

`types.ts`: `IdentityInfo.kind: "x25519" | "pq" | null`; `RecipientCheck.kind` doc `"x25519", "pq", "hybrid-pq" or "plugin:<name>"`; `SealOut.self_omitted: string | null; post_quantum: boolean`; `VerifyOut.post_quantum: boolean | null`; `OpenOut.post_quantum: boolean | null`.

`format.ts`: `kindLabel`: `if (kind === "pq" || kind === "hybrid-pq") return "post-quantum";` (`recipientTone` already matches `pq`).

`api.ts`: `generateIdentity: (force: boolean, pq = false) => call<T.IdentityInfo>("generate_identity", { force, pq })`.

`mock.ts`: identity state gains `kind: "x25519"`; `generate_identity` honours `args.pq` (recipient `"age1pq1" + "q".repeat(1990)`, kind `"pq"`); `parse_recipient`: before the tagpq line, `if (s.startsWith("age1pq1")) return { kind: "pq", fingerprint, plugin: null, allowed: true };`; `seal`: if recipients contain both a PQ (`startsWith("age1pq1") || startsWith("age1tagpq1")`) and a non-PQ string, `throw "policy refused: post-quantum recipients cannot be mixed with classical ones (classical: 0123456789abcdef); seal them separately"`; `SealOut` gains `self_omitted: null, post_quantum: allPq`; verify/open mocks set `post_quantum` from the chosen package (`?pkg=pq` → true).

`errors.ts` `mapSealError`: before the generic `policy refused` branch:

```ts
  if (/cannot be mixed with classical/i.test(m)) {
    return { text: "Post-quantum and classical recipients can't share one package. Remove one group, or seal twice.", field: undefined };
  }
```

`Keys.tsx`: a `const [pq, setPq] = useState(false)` with a checkbox/switch above "Create identity" labelled **Post-quantum identity** and helper copy: "Protects against a future quantum computer reading packages recorded today. Senders need sealdrop 0.3 or age 1.3 or newer, and your recipient string becomes about 2 000 characters long." `create(force)` calls `api.generateIdentity(force, pq)`. The identity tile shows `<Badge tone="info">{identity.kind === "pq" ? "post-quantum" : "x25519"}</Badge>` next to the Recipient field label (use the existing `Badge` component and a tone it supports). The Replace dialog shows the same switch.

`Seal.tsx`: recipient chips already use `kindLabel`/`recipientTone`; after a successful seal, when `out.self_omitted` is set, render `<Notice tone="info">{out.self_omitted}</Notice>` in the result, and in the summary show `Post-quantum` badge when `out.post_quantum`. Store `selfOmitted` and `postQuantum` in the result state next to the existing fields.

`Verify.tsx` (~line 323) and `Open.tsx` (~line 603): add `<KV k="Post-quantum">{v.post_quantum ? "yes" : "no"}</KV>` when `post_quantum !== null`; `Open.tsx` result header shows a `Badge` "Post-quantum" when `o.post_quantum`.

- [ ] **Step 5: Run and build**

```bash
cd apps/desktop && npm test && npm run build && cd ../.. && cargo test -p sealdrop-desktop
```
Expected: vitest green, build green.

- [ ] **Step 6: Commit**

```bash
git add apps/desktop/src apps/desktop/src-tauri/src/commands.rs
git commit -m "feat(desktop): post-quantum identities and badges, mixing error, self-omitted note"
```

---

### Task 9: Format spec revision and test vectors

**Files:**
- Modify: `spec/sealdrop-format-v1.md` (§1 header line, §4 table and note, §5.2, §5.4, §9, §10, Appendix A/B/C)
- Modify: `crates/sealdrop-core/tests/format_vectors_gen.rs`, `format_vectors.rs`, `spec/vectors/README.md`
- Create: `spec/vectors/keys/pq-identity.txt` (generated once), `spec/vectors/recipient-pq/`, `spec/vectors/commitment-mismatch/`
- Regenerate: all vector directories

- [ ] **Step 1: Spec edits** (exact text)

§4 table: replace the `hybrid-pq` row block with

```
| `x25519` | `age1…` | `X25519` |
| `pq` | `age1pq1…` (age's native hybrid ML-KEM-768 + X25519 type, age ≥ 1.3; C2SP age.md "mlkem768x25519") | `mlkem768x25519` |
| `hybrid-pq` | `age1tagpq1…` (age's hybrid ML-KEM-768 + P-256 *tagged* type) | `mlkem768p256tag` |
| `plugin:<name>` | `age1<name>1…` | defined by the plugin |
| `scrypt` | passphrase | `scrypt` |
```

Replace the "Note: `age1pq1…` is a different type…" paragraph with:

```
`pq` and `hybrid-pq` are the **post-quantum kinds**. An encoder MUST NOT combine a
post-quantum kind with any other public-key kind in one header: a classical stanza next to a
post-quantum one hands the file key to whoever can break the classical stanza later. A decoder
MUST still open such a header (age semantics; CCTV `hybrid_and_x25519`), and MUST report the
package as not post-quantum. A package is *post-quantum* when every real recipient is of a
post-quantum kind (for a timed package, every inner recipient recorded in the manifest).
```

§5.2 table: after `plaintext_tar_sha256` add

```
| `key_commitment` | string | no (MUST be written by encoders from 0.3.0) | Lowercase hex of HKDF-SHA-256(ikm = the 16-byte age file key, salt = empty, info = `sealdrop/commit/v1`, length 32). Derived from the random file key only, never from a passphrase. |
```

and in the `recipients[].kind` row list `x25519`, `pq`, `hybrid-pq`, `plugin:<name>`, `scrypt` or `argon2id`.

§5.4: add step 7:

```
7. After decryption has unwrapped the file key and before any payload is decrypted: if
   `key_commitment` is present, derive it from the unwrapped file key and compare in constant
   time. A mismatch is a verification failure; no plaintext may be written. When the field is
   absent, or verification was skipped (§5.5), there is nothing to check.
```

§9 bullets: extend the first bullet: "From 0.3.0 the manifest also commits to the file key (`key_commitment`), so a verified package has exactly one file key that opens it, closing the stanza-level non-commitment." Add:

```
- **Security level.** age's file key is 16 bytes, so every sealdrop package is 128-bit secure
  against key search whichever 256-bit AEAD encrypts the bytes. This is the level of TLS 1.3,
  Signal and WireGuard. Say "128-bit security level, 256-bit keys", not "256-bit encryption".
- **Harvest now, decrypt later.** `x25519` and plugin stanzas can be opened retroactively by a
  future quantum computer; `pq` and `hybrid-pq` stanzas cannot (unless the hybrid's both parts
  fail). Packages that must stay confidential beyond about 2035 SHOULD be sealed to
  post-quantum kinds only. Symmetric parts (ChaCha20-Poly1305, HKDF, SHA-256) need no change.
```

§10: append

```
### 10.1 Reserved identifiers (roadmap)

| Identifier | Reserved for | Status |
|---|---|---|
| `sealdrop-manifest/2` | A manifest signed by Ed25519 (minisign) **and** ML-DSA-65 together, both required to verify | Planned 2029–2031, gated on an independently audited Rust ML-DSA implementation |
| `sealdrop-encryption.org/v2` (age-style first line) | A sealdrop payload format on Cobblestone-128 (key-committing chunked AES-128-GCM), one suite per version, dual-read forever | Not scheduled; only if a FIPS/AES or committing-payload requirement materialises |

Readers of this version MUST reject these identifiers as unknown formats.
```

Appendix A: add rows for §4 `pq` (`core pq.rs`: `Recipient`, `Identity`, `is_pq_stanza_tag`), the mixing rule (`core policy.rs`: `check_recipients`, `is_post_quantum_kind`), `key_commitment` (`core crypt.rs`: `key_commitment`, `Committing`, `CommittedIdentity`; `core open.rs`: `open`), case collisions (`core extract.rs`: `case_collision`, `destination_is_case_insensitive`; `core pack.rs`: `plan`). Appendix B: new row `pq` recipients: `age -d -i key.txt` works with age ≥ 1.3.0. Appendix C header → `(0.3.0)`; keep rows a–d, add `e | §9 case-insensitive file systems | Detection probes the destination folder; a destination on a different, case-insensitive volume than the probe cannot occur because the temp dir is created inside it, but network file systems may answer the probe inconsistently.` Update the first-page status line to 0.3.0 and the §1 non-goals ("No new ciphers" stays; add "… ML-KEM-768 and X25519 through age's own hybrid recipient type.").

- [ ] **Step 2: Vector generator**

In `format_vectors_gen.rs`:
- `keys()`: also ensure `spec/vectors/keys/pq-identity.txt` exists: if missing, write `sealdrop_core::pq::Identity::generate().to_string()` plus a `# public key:` comment line (same layout as `identity.txt`), mode 0600. Load it as `pq_identity: sealdrop_core::pq::Identity`.
- New vector `recipient-pq`: `seal_into(&ks, &d, Mode::Recipients(vec![Recipient::parse(&pq_identity.to_public().to_string())]), false, None)`; `vector.json` with `"expect": "success", "stock_age": "opens", "inputs": {"identity": <the AGE-SECRET-KEY-PQ-1 line>, "signer_key": signer}, "comment": "§4 pq recipient (mlkem768x25519); stock age ≥ 1.3 opens it", "min_age": "1.3.0"`.
- New vector `commitment-mismatch`: seal a recipient package, replace the `key_commitment` hex in the manifest with 64 `0`s, re-sign with the right key and the right trusted comment (same code shape as `manifest-wrong-comment`), `"expect": "verify failure", "stock_age": "opens", "comment": "§5.4 step 7: signature valid, ciphertext hash valid, key_commitment does not match the file key"`.
- Regenerate everything: `SEALDROP_VECTORS_FORCE=1 cargo test -p sealdrop-core --features test-support --test format_vectors_gen -- --ignored regenerate_format_vectors` (Git Bash: `SEALDROP_VECTORS_FORCE=1 cargo test …`). Confirm every success vector's manifest now contains `key_commitment`.

- [ ] **Step 3: Conformance test**

`format_vectors.rs`:
- `store_for`: when `inputs.identity` starts with `AGE-SECRET-KEY-PQ-1`, write it as the identity line (the store already parses it); nothing else changes.
- `run_open`: `verify failure` for `commitment-mismatch` must be produced by `open` (verify alone passes): assert that `open` fails with `Error::Verify` containing `key commitment` **and** that `verify` succeeds for that vector name; add a generic rule: for `expect == "verify failure"`, `open` must fail with `Error::Verify`.
- `stock_age_claims`: read `min_age` when present; parse `age --version` (`v1.3.2`) and skip the claim with a message when the binary is older.
- `all_format_vectors` directory-count assertion → 20.

Run: `PATH="$HOME/go/bin:$PATH" SEALDROP_REQUIRE_AGE=1 cargo test -p sealdrop-core --test format_vectors` → pass.

- [ ] **Step 4: README of the vectors**

`spec/vectors/README.md`: "There are 20 vectors…" and list `recipient-pq` and `commitment-mismatch`; mention `keys/pq-identity.txt`.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
git add spec crates/sealdrop-core/tests
git commit -m "spec: pq kind, PQ-only rule, key_commitment, roadmap identifiers; 20 vectors"
```

---

### Task 10: Version bump, docs, validation evidence

**Files:**
- Modify: `Cargo.toml` (`version = "0.3.0"`), `apps/desktop/package.json`, `apps/desktop/src-tauri/tauri.conf.json`, `apps/desktop/src-tauri/Cargo.toml` if it pins its own version (grep `0.2.2`).
- Modify: `README.md:355-392` and the intro/security paragraphs; `SECURITY.md` (Scope / Known limitations); `docs/VALIDATION.md` (new file content for 0.3.0, keep the old one as `docs/VALIDATION-0.2.md`? No: VALIDATION.md is rewritten for 0.3.0 and the 0.2 one is kept by git history; add a link line at the top pointing to the 0.2.2 tag's copy).

- [ ] **Step 1: Bump**

`grep -rn "0\.2\.2" --include=*.toml --include=*.json --include=*.md . | grep -v target | grep -v node_modules` and update every version occurrence that names the current release (Cargo workspace, Tauri config, package.json, README install links stay pointing at v0.2.2 assets until a release is cut, so leave the Install section's download URLs untouched and add one sentence: "0.3.0 is on `main`; installers follow with the next release.").

- [ ] **Step 2: README**

- Known limitations: delete the "19 post-quantum conformance vectors are skipped" bullet; replace with "**Post-quantum.** `keygen --pq` creates an `age1pq1…` identity (ML-KEM-768 + X25519, age 1.3's native type); packages sealed only to post-quantum recipients are marked `post-quantum: yes`. Post-quantum and classical recipients cannot be mixed in one package. `age1tagpq1…` (the tagged hybrid type) remains encrypt-only." Delete the case-insensitive bullet (now refused at seal time and at open time on such systems) and the "interactive passphrase prompt shows what you type" bullet (now hidden).
- Command table: `keygen [--pq] [--force]`; `-r` row: `age1...`, `age1pq1...` (post-quantum), `age1tagpq1...` (hybrid, encrypt-only) or `age1<plugin>1...`.
- Add a short "Security level" paragraph under the security/How-it-works section: "A sealdrop package is 128-bit secure against key search (age's file key is 16 bytes), the same level as TLS 1.3, Signal and WireGuard, with 256-bit ChaCha20-Poly1305 keys underneath. Post-quantum recipients protect the key wrap against a future quantum computer; the symmetric layer already resists one."
- Mention `key_commitment` in the manifest description.

- [ ] **Step 3: SECURITY.md**

Under Scope/Known limitations: the 128-bit statement, the PQ recommendation for data that must stay confidential beyond ~2035, that the manifest commits to the file key from 0.3.0, and the roadmap (hybrid ML-DSA signature, payload v2) with a pointer to `docs/research/2026-10-15-beyond-chacha20-poly1305.md`.

- [ ] **Step 4: VALIDATION.md for 0.3.0**

Re-run and record, in the same table layout as the 0.2 file: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` with `SEALDROP_REQUIRE_AGE=1` and `~/go/bin` on PATH (counts per crate), CCTV line (`total=147 passed=147 failed=0`), interop (5 tests), format vectors (20), `cargo deny check licenses advisories`, `npm test`, `npm run build`. Add the **RNG audit** section: list `age` (OsRng via getrandom, panics on failure), `pq::Identity::generate` (`rand_core::OsRng::fill_bytes`, panics on failure), `release::Deposit::new` / `Recipient::wrap_file_key` (`rand::rng().fill_bytes`, panics on failure), `passphrase::generate` (`rand::rng()`), `uuid::new_v4` (getrandom), `minisign::KeyPair::generate_unencrypted_keypair` (getrandom); state that no call site catches or defaults a randomness error. Add a "Manual PQ session" section: `keygen --pq` → `seal` to it from a second store → `verify` (`post-quantum: yes`) → `open`, and Go `age -d -i identity.txt` on the same package, with the commands and outputs.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
git add -A Cargo.toml Cargo.lock apps/desktop/package.json apps/desktop/src-tauri README.md SECURITY.md docs/VALIDATION.md
git commit -m "chore: 0.3.0; docs for post-quantum identities, key commitment and the security level"
```

---

## Self-review against the spec

- §3 KEM, keys, stanza, decode rules, acceptance (CCTV, interop, reviewer): Tasks 1–3 (reviewer gate is part of the SDD review package for Tasks 1–2).
- §4.1 `Recipient::Pq`, kinds: Task 3. §4.2 key store: Task 3. §4.3 policy and self-omitted: Task 4. §4.4 mixed headers open, `post_quantum`: Tasks 2 (CCTV `hybrid_and_x25519`) and 4.
- §5 commitment: Task 5. §6 hardening: Tasks 6 (case), 7 (prompt), 10 (wording, RNG audit), 4/7/8 (PQ visibility).
- §7 spec and vectors: Task 9. §8 CLI/desktop: Tasks 7–8. §9 errors: typed in Tasks 4–6. §10 testing: each task; CI: Task 3 (age-keygen).
- Type consistency: `IdentityKind` (Task 3) is used by Tasks 7–8; `SealResult.self_omitted`, `VerifyReport.post_quantum`, `Probe.post_quantum`, `post_quantum_kinds` (Task 4) by Tasks 7–8; `Manifest.key_commitment` (Task 5) by Task 9; `case_collision` (Task 6) by pack in the same task.
