# Design: sealdrop 0.3 — post-quantum recipients, key commitment, hardening

Date: 15 October 2026. Status: approved.

Source: the deep-research report
[`docs/research/2026-10-15-beyond-chacha20-poly1305.md`](../../research/2026-10-15-beyond-chacha20-poly1305.md),
whose recommendations the owner accepted in full on 15 October 2026. This cycle delivers its
items 1 to 3. Items 4 and 5 become a roadmap section in the format spec with identifiers
reserved.

## 1. Why

ChaCha20-Poly1305 as age uses it is not a weak link, and a cipher change is not warranted.
The real ceilings on a sealdrop package are elsewhere:

1. The X25519 recipient stanza is the only part a future quantum computer opens
   retroactively ("harvest now, decrypt later"). Packages that must stay confidential past
   2035 need post-quantum key wrapping, and every relevant mandate converges on 2030.
2. age's stanza wrap is not key-committing. sealdrop's signed ciphertext hash commits the
   bytes to a signer, not to a key; a cheap manifest field closes that.
3. The classes auditors actually flag in tools like this (passphrase handling, path
   handling, honest security claims) have a few concrete gaps left.

## 2. Decisions (owner, 15 Oct 2026)

| # | Decision | Choice |
|---|---|---|
| 1 | Scope | Items 1–3 now; items 4 (hybrid Ed25519 + ML-DSA-65 manifest signature) and 5 (payload format v2 on Cobblestone-128) are roadmap text only, with their identifiers reserved. |
| 2 | PQ engine | Implement age's native `mlkem768x25519` recipient and identity in `sealdrop-core` (C2SP age spec; X-Wing KEM), validated against the 19 CCTV vectors that are skipped today and against Go age 1.3.2. Replace with the `age` crate's own types when rage 0.13 ships them. |
| 3 | PQ default | Opt-in now: `keygen --pq`. x25519 stays the default identity type until peers can encrypt to `age1pq1…` strings. |
| 4 | Payload | Unchanged. age v1, ChaCha20-Poly1305 STREAM. No cascades, no "paranoid mode", no runtime cipher field. |

## 3. Native `mlkem768x25519` (crate `sealdrop-core`, module `pq`)

Layout mirrors the `age` crate's `native/tagpq.rs` + `native/tagpq/kem.rs`:
`crates/sealdrop-core/src/pq.rs` (Recipient, Identity, stanza encode/decode) and
`crates/sealdrop-core/src/pq/kem.rs` (the `hpke::Kem` implementation).

### 3.1 Keys

- **Identity**: 32 bytes from the OS CSPRNG. Bech32 with HRP `AGE-SECRET-KEY-PQ-`, rendered
  uppercase (`AGE-SECRET-KEY-PQ-1…`). Parsing accepts the uppercase form (Bech32 is
  case-insensitive, mixed case is invalid).
- **Expansion** (X-Wing `expandDecapsulationKey`): `expanded = SHAKE256(seed, 96)`;
  ML-KEM-768 `KeyGen_internal(d = expanded[0:32], z = expanded[32:64])`
  (`MlKem768::generate_deterministic`); `sk_X = expanded[64:96]`;
  `pk_X = X25519(sk_X, basepoint)`.
- **Recipient**: `pk = pk_M || pk_X` (1184 + 32 = 1216 bytes), Bech32 HRP `age1pq`
  (`age1pq1…`, about 2 000 characters). Parsing rejects any other length, and an ML-KEM
  encapsulation key that fails the FIPS 203 §7.2 modulus check (the `ml-kem` crate's
  `from_bytes` performs it).

### 3.2 KEM (`pq/kem.rs`, `impl hpke::Kem for MlKem768X25519`)

- `KEM_ID = 0x647a`, `NSecret = 32`.
- `PrivateKey` = the 32-byte seed (`Serializable`/`Deserializable` over exactly 32 bytes,
  expanding on deserialise). `PublicKey` = `(ek_pq, pk_x)`. `EncappedKey` =
  `ct_M || ct_X` (1088 + 32 = 1120 bytes; any other length is an error).
- `encap`: `(ct_M, ss_M) = ML-KEM-768.Encaps(ek_pq)`; `ek_X` random 32 bytes;
  `ct_X = X25519(ek_X, basepoint)`; `ss_X = X25519(ek_X, pk_X)`; shared secret =
  `SHA3-256(ss_M || ss_X || ct_X || pk_X || label)` with the six-byte X-Wing label
  `\.//^\` (hex `5c2e2f2f5e5c`; in Rust source `b"\\.//^\\"`).
- `decap`: `ss_M = ML-KEM-768.Decaps(dk_pq, ct_M)` (implicit rejection, never an error);
  `ss_X = X25519(sk_X, ct_X)`; **reject an all-zero `ss_X`** (x25519-dalek
  `SharedSecret::was_contributory()`), returning `HpkeError::DecapError` (CCTV
  `hybrid_low_order` expects a header failure); combine as above with the identity's own
  `pk_X`.
- `derive_keypair(ikm)`: HPKE `DeriveKeyPair` via `SHAKE256.LabeledDerive(ikm, "DeriveKeyPair", "", 32)`
  as in the crate's `tagpq` code, then expand. Only used by the `hpke` trait, never by age keys.
- Randomness: the `hpke`, `ml-kem` and `x25519-dalek` crates in the tree take `rand_core 0.6`
  RNGs; use `rand_core 0.6`'s `OsRng` (via the `rand 0.8` already in the tree as a dependency
  of `age`), exactly as `age::tagpq` does. Add `rand_core = "0.6"` / `rand = "0.8"` explicitly
  only if cargo needs it for the trait bounds; do not change the workspace `rand 0.9` elsewhere.

### 3.3 Stanza

- Encode: `(enc, ct) = age_core::primitives::hpke_seal::<Kem>(pk, info, file_key)` with
  `info = b"age-encryption.org/mlkem768x25519"`; stanza tag `mlkem768x25519`, one argument
  `base64(enc)` (standard alphabet, unpadded), body `ct` (32 bytes). `wrap_file_key` returns
  the label set `{"postquantum"}` so the age crate refuses to combine it with unlabeled
  (classical) recipients at the library level too.
- Decode (`unwrap_stanza`), in this order, matching CCTV: tag must be exactly
  `mlkem768x25519` (any other tag, including a different case → `None`, i.e. not ours);
  exactly one argument, else **header failure**; argument must be canonical unpadded base64
  of exactly 1120 bytes, else header failure; body must be exactly 32 bytes, else header
  failure (checked **before** any decryption; mitigates partitioning oracles); decapsulation
  low-order failure → header failure; AEAD failure → "no match" (`None` after trying), so a
  wrong identity is indistinguishable from an unrelated stanza, as age requires.
- Header-failure results are reported as `Some(Err(DecryptError::InvalidHeader))`, no-match
  as `None`; the CCTV harness distinguishes the two exactly as it does for the x25519 vectors.

### 3.4 Acceptance for the module

- Every CCTV vector whose name starts with `hybrid` or `armor_hybrid` passes; the skip
  branch in `tests/cctv.rs` is deleted and the test asserts `skipped == 0` (147/147).
- `tests/interop_age.rs`: Go `age` 1.3.2 decrypts a sealdrop PQ package with a sealdrop
  identity file; sealdrop opens a file Go `age -r age1pq1…` encrypted (test identity
  generated by sealdrop, recipient derived by sealdrop and checked equal to Go
  `age-keygen -y` output when `age-keygen` is on PATH).
- Unit tests: round trip; recipient string round trip; identity string round trip and
  uppercase rendering; every reject rule in §3.3 with a hand-built stanza; the label set.
- An independent reviewer compares the module line by line with the C2SP text and the
  X-Wing pseudocode before the task is accepted (part of the SDD review package).

## 4. Recipient and identity model

### 4.1 `crypt::Recipient`

New variant `Pq(pq::Recipient)`. `parse` order: x25519, pq, tagpq (`Hybrid`), plugin. (The
pq HRP `age1pq` would otherwise parse as a plugin named `pq`.) `kind()` returns `pq`.
Fingerprint rule unchanged (first 16 hex of SHA-256 of the canonical string).
`to_age_recipients` boxes it like the others.

Manifest kinds after this change: `x25519`, `pq`, `hybrid-pq`, `plugin:<name>`, `scrypt`,
`argon2id`. `pq` and `hybrid-pq` are the **post-quantum kinds**.

### 4.2 Key store

- `KeyStore::generate(force, kind: IdentityKind)` with `IdentityKind::{X25519, Pq}`. The
  identity file holds exactly one native secret line (`AGE-SECRET-KEY-1…` or
  `AGE-SECRET-KEY-PQ-1…`) plus the usual comment lines and any hand-added `AGE-PLUGIN-…`
  lines. `# public key:` comment carries the recipient string as today.
- New `KeyStore::identity_kind() -> Result<IdentityKind>`, `recipient_string()` works for
  both kinds, and `native_identities() -> Result<Vec<Box<dyn age::Identity>>>` replaces the
  x25519-only `identity()` at the call sites in `open.rs`, the CLI and the Tauri commands
  (`identity()` stays for tests that need the concrete type).
- `KeyInfo`/`IdentityInfo` gain `kind: "x25519" | "pq"`.

### 4.3 Policy (`policy.rs`)

New rule, checked in `check_recipients` after the existing ones:

> If any real recipient is of a post-quantum kind, every real recipient MUST be of a
> post-quantum kind. Otherwise `PolicyError::PqMustNotMix { classical: Vec<String> }`
> (fingerprints of the offending recipients).

Plugin recipients count as classical (their algorithm is unknown). The rule applies to the
inner set of a timed-release package (it is the same `specs` list). There is no override
flag: a mixed set defeats the purpose, and the user can seal twice.

`include_self`: in `seal`, when the given recipients are all post-quantum and the sender's
own identity is classical (or vice versa), self is **not** added and `SealResult` gains
`self_omitted: Option<String>` with the reason, which the CLI prints as a note and the app
shows in the result. When the kinds agree, self is added as before.

### 4.4 Opening mixed headers

A header that contains both `mlkem768x25519` and classical stanzas is **opened** (CCTV
`hybrid_and_x25519` expects success). `probe::Probe` gains `post_quantum: bool` = every real
stanza tag (grease excluded) is `mlkem768x25519` or `mlkem768p256tag`, or the header is a
`sealdrop-release` stanza whose manifest-recorded inner kinds are all post-quantum (the
header cannot show inner stanzas; the verified manifest is the source, else `false`).
`VerifyReport` gains `post_quantum: bool` computed from the verified manifest's recipient
kinds. CLI `verify`/`open` print `post-quantum: yes|no`; the app shows a badge.

## 5. Manifest key commitment

- Field: `key_commitment` (optional string) = lowercase hex of
  `HKDF-SHA-256(ikm = file key (16 bytes), salt = empty, info = "sealdrop/commit/v1", L = 32)`.
  Derived from the random file key, never from a passphrase, so it adds no offline
  guessing surface.
- **Seal**: `crypt::Committing` is a `age::Recipient` adapter around the outer recipient
  list. Its `wrap_file_key` records the file key (Zeroizing, `RefCell`/`Mutex`) and
  delegates to each inner recipient, concatenating their stanzas. Because the adapter hides
  the individual recipients from `Encryptor::with_recipients`, it must replicate age's own
  label check: every inner recipient must return the same label set, otherwise it returns
  `EncryptError::IncompatibleRecipients`, and it returns that common set. `seal` writes
  `key_commitment` for every package (plain, passphrase, timed).
- **Open**: the existing `IdentityRef` wrapper becomes `crypt::CommittedIdentity { inner,
  expected: Option<[u8; 32]> }`. On a successful unwrap with `expected = Some`, it derives
  the commitment and, on mismatch, returns `Some(Err(DecryptError::InvalidHeader))` and sets a
  flag; `open` maps that flag to `Error::Verify("file key does not match the signed manifest's
  key commitment")`. No plaintext is produced because the age `Decryptor` never receives a
  file key. `expected` is `Some` only when verification ran and the manifest carries the
  field; `--skip-verify`, a missing manifest or an older manifest means no check.
- Compatibility: `sealdrop-manifest/1` is unchanged (optional field; readers already MUST
  ignore unknown fields). Encoders MUST write the field from 0.3.0; decoders MUST check it
  when present and verification ran.

## 6. Hardening

| Item | Change | Where |
|---|---|---|
| Passphrase prompt | `sealdrop open` reads the passphrase without echo (the `rpassword` crate, already in the dependency tree via age's CLI deps; add it to `sealdrop-cli`), falls back to the echoing prompt only when stdin is not a terminal and `--passphrase-stdin` was not given, and says so. | `sealdrop-cli` `commands/open.rs` |
| Case collisions, encoder | `pack` refuses an input whose entry paths collide under Unicode simple case folding (`to_lowercase` per component is sufficient and matches what Windows/macOS do for ASCII; document that it is a lower bound). Error names both paths. | `pack.rs` |
| Case collisions, decoder | `extract` detects a case-insensitive destination (create `sealdrop-case-probe-a` in the temp root, test `…-A` exists) and then refuses a package whose paths collide under the same folding, before writing anything. | `extract.rs` |
| Honest wording | README, SECURITY.md and the app's Keys/Settings copy say "128-bit security level, 256-bit keys" where they currently imply more; the README's post-quantum paragraph is rewritten for `age1pq1…` support. | docs, `apps/desktop` |
| PQ visibility | `post-quantum: yes/no` in verify and open output; app badge. | CLI, desktop |
| RNG audit | A short VALIDATION.md section lists every random source (`rand::rng()`, `OsRng`, age's own) and confirms each aborts on failure rather than returning zeros. | docs |

## 7. Spec and vectors (`spec/sealdrop-format-v1.md`, `spec/vectors/`)

- §4 table: row `pq` / `age1pq1…` / `mlkem768x25519`, the note about `age1pq` being
  parsed as a plugin is replaced by the real definition and a pointer to C2SP; the
  **mixing rule**: an encoder MUST NOT combine post-quantum kinds with other public-key kinds
  in one header; a decoder MUST still open such a header but MUST report it as not
  post-quantum.
- §5.2: `key_commitment` row and derivation; §5.4: new step after the ciphertext hash
  check ("after unwrapping the file key, if `key_commitment` is present, derive and compare;
  mismatch is a verify failure and no plaintext may be written"); §5.2 `recipients[].kind`
  list gains `pq`.
- §9: new bullets on what the commitment proves, on the 128-bit security level of the
  file key, and on harvest-now-decrypt-later for classical kinds.
- §10: roadmap subsection "Reserved identifiers": `sealdrop-manifest/2` (manifest signed by
  Ed25519 and ML-DSA-65 together, both required; target 2029–2031, gated on an audited Rust
  ML-DSA implementation) and `sealdrop-encryption.org/v2` (payload on Cobblestone-128,
  only if a FIPS/AES or committing-payload requirement materialises; not scheduled).
  Readers MUST reject these identifiers today (unknown format).
- Appendix A rows for the new rules; Appendix B (stock age can open `pq` packages with
  age ≥ 1.3.0); Appendix C refreshed for 0.3.0 (the `hybrid-pq` identity gap remains).
- Vectors: regenerate the whole set with the existing generator so every success vector
  carries `key_commitment` (secrets unchanged; packages change because file keys are random
  per seal; `plaintext_tar_sha256` values stay). Add `recipient-pq` (success, `stock_age:
  opens` with age ≥ 1.3) and `commitment-mismatch` (verify failure: manifest re-signed with
  a wrong `key_commitment`). The committed vector secrets gain one PQ identity.
- `README.md` in `spec/vectors/` and the conformance test's `stock_age` check learn that
  `opens` for a PQ vector needs age ≥ 1.3 (skip with a message on older binaries).

## 8. Surfaces

**CLI** (`sealdrop-cli`): `keygen [--pq] [--force]` (prints kind); `recipient` prints the
recipient and kind; `seal` surfaces `PqMustNotMix` with the offending fingerprints and the
self-omitted note; `verify`/`open` print `post-quantum: yes|no`; `open` hidden passphrase
prompt. `--help` texts updated (`age1pq1…` is supported; `age1tagpq1…` remains encrypt-only).

**Desktop** (`apps/desktop`): Keys → "Create identity" gains a "Post-quantum identity"
switch (off by default) with two lines of copy (what it protects against, that senders
need sealdrop 0.3 or age 1.3+, and that the recipient string is long); the identity tile
shows a kind badge; "Replace identity…" offers the same switch. Seal → recipient chip kind
label "post-quantum" for `pq`, the mixing error mapped to the recipients field, the
self-omitted note shown under the result. Verify/Open → post-quantum badge in the summary.
`format.ts` (`looksLike…`, `kindLabel`, colours), `types.ts`, `mock.ts` (`age1pq1…` parses to
kind `pq`; mixed sets produce the policy error) and the vitest suite follow.

## 9. Error handling

- All new failure paths are typed: `PolicyError::PqMustNotMix`, `Error::Verify` for the
  commitment, `ExtractError::CaseCollision(a, b)` and a matching pack error, the pq decode
  rules through `DecryptError::InvalidHeader`. Messages never echo secret material
  (identity strings are redacted as today).
- A failure after the package file exists still removes the bundle (existing `Cleanup`).

## 10. Testing and validation

- Unit: §3.4; policy matrix (pq+pq ok, pq+x25519 refused, pq+plugin refused, tagpq+pq ok,
  passphrase unaffected); key store both kinds; commitment match/mismatch/absent/skip-verify;
  pack and extract collision cases (including the probe on a case-sensitive FS);
  probe/verify `post_quantum` for plain, mixed, timed.
- Integration: CCTV 147/147 (skip path removed); interop both directions; format vectors
  (new set); CLI e2e `keygen --pq` → `seal` → `verify` → `open`, mixing refusal exit code,
  hidden prompt path via `--passphrase-stdin` only (TTY behaviour is covered by a unit test
  on the decision function); desktop vitest.
- Static: `cargo clippy -D warnings`, `cargo fmt --check`, `cargo deny`, `npm test`, CI
  green on the branch.
- Process: implementation plan → subagent-driven development with task briefs and review
  packages → final whole-branch review → fix wave → `docs/VALIDATION.md` for 0.3.0 →
  commit and push to `main`. No release is cut unless the owner asks.

## 11. Out of scope

Hybrid ML-DSA manifest signatures, payload format v2, PQ *default* identities, bundling
`age-plugin-pq`, a `hybrid-pq` (`age1tagpq1…`) identity, SLIP-39 escrow, hosted viewer,
and the other deferred items in `docs/superpowers/reviews/`.
