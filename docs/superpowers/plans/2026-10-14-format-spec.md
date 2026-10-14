# sealdrop Package Format v1 Spec Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) or executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish a normative specification of everything sealdrop adds on top of age (container, two stanzas, manifest, extraction rules, release-service protocol, receipts) with known-answer test vectors and a conformance test that runs in CI.

**Architecture:** One CC0 Markdown document under `spec/`, derived rule-by-rule from the reference implementation in `crates/sealdrop-core` and `crates/sealdrop-release`. Vectors are generated once by an `#[ignore]`d test (deterministic committed secrets, age randomness accepted as in C2SP's CCTV) and consumed by a normal integration test.

**Tech Stack:** Markdown; Rust test code in `sealdrop-core` (features `test-support` for the generator); existing crates only (no new dependencies except `serde_json` already present).

Design: `docs/superpowers/specs/2026-10-14-format-spec-design.md`.

## Global Constraints

- Every normative value in the spec MUST equal the implementation. Sources of truth (read before writing a section): `crates/sealdrop-core/src/{pack.rs,extract.rs,argon2id.rs,release.rs,manifest.rs,seal.rs,open.rs,probe.rs}`, `crates/sealdrop-release/src/{routes.rs,db.rs,app.rs,ratelimit.rs}`, `crates/sealdrop-release/README.md`.
- Identifiers (verbatim): container `sealdrop/1`, manifest `sealdrop-manifest/1`, stanza tags `sealdrop-argon2id` and `sealdrop-release`, API prefix `/v1/`, file names `<name>.sealdrop.age`, `<name>.manifest.json`, `<name>.manifest.json.minisig`, tar paths `sealdrop/meta.json` and `sealdrop/payload/`.
- Encodings: base64 standard alphabet without padding everywhere (as age); SHA-256 lowercase hex (64 chars); RFC 3339 UTC `YYYY-MM-DDTHH:MM:SSZ`; UUIDs lowercase hyphenated.
- Limits (verbatim from `extract.rs`/`release.rs`/`argon2id.rs`/`routes.rs`): `meta.json` ≤ 1 048 576 bytes; max entries 100 000; max bytes 68 719 476 736 (64 GiB); max per-file 64 GiB; max tar extension header 1 048 576 bytes; max input 65 GiB; age header probe limit 65 536 bytes; inner stanzas ≤ 64; inner JSON ≤ 65 536 bytes; Argon2id bounds t ≤ 10, m_kib ≤ 2 097 152, p ≤ 8, m_kib ≥ 8, m_kib ≥ 8·p; service `window_secs` 1..=31 622 400 (366 days); request body ≤ 16 KiB; release id 1–64 chars of `A-Za-z0-9-` on the service side and a canonical UUID on the client side.
- Spec text and vectors are CC0-1.0 (`spec/LICENSE`); code stays Apache-2.0.
- RFC 2119 keywords in capitals; no marketing language; short sentences.
- Commit messages conventional; end with the harness's Co-Authored-By line; push to `origin main` after each task.
- Node is not needed for this plan. Quote all paths in Bash (home directory contains a space).

## File map

```
spec/
  LICENSE                         CC0-1.0 text
  sealdrop-format-v1.md           the normative spec
  vectors/
    README.md                     how to run / regenerate
    keys/                         committed test-only secrets (generated once)
      identity.txt  signer.key  signer.pub  service.key  service.pub
    <vector-name>/vector.json + files
crates/sealdrop-core/
  tests/format_vectors.rs         conformance test (CI)
  tests/format_vectors_gen.rs     #[ignore] generator (feature test-support)
README.md                         "Format specification" section + link
CONTRIBUTING.md                   how to regenerate vectors
```

---

### Task 1: The normative specification text

**Files:**
- Create: `spec/LICENSE`, `spec/sealdrop-format-v1.md`

**Interfaces:**
- Produces: section numbers referenced by vectors' `comment` fields and by Appendix A; the `vector.json` schema in §11 that Task 2 implements exactly.

- [ ] **Step 1: `spec/LICENSE`** — the CC0 1.0 Universal legal text (fetch `https://creativecommons.org/publicdomain/zero/1.0/legalcode.txt`, save verbatim).

- [ ] **Step 2: Write `spec/sealdrop-format-v1.md` with exactly these sections and facts** (read the named source files first; where this list and the code differ, the code wins and the list is wrong — report it):

**Front matter.** Title "sealdrop package format v1"; status "Stable — matches sealdrop 0.2.1"; licence CC0; one-paragraph abstract; "Reference implementation: https://github.com/Aldiharley/sealdrop".

**1. Scope and goals.** Goals: any file/folder restored exactly; interop (a package whose header contains only standard age stanzas MUST be decryptable by any age v1 implementation and extractable by any ustar tar reader); proof of what was delivered; optional timed release. Non-goals (verbatim): "No DRM, screenshot or forwarding prevention. Timed release limits when the *encrypted package* can be opened; it cannot recall decrypted content." No new ciphers; nothing below the age layer.

**2. Conventions.** RFC 2119; base64 = RFC 4648 standard alphabet, no padding; `sha256` fields are lowercase hex; timestamps RFC 3339 UTC with `Z`; UUIDs per RFC 9562, lowercase hyphenated; "age" = C2SP age v1 (link https://github.com/C2SP/C2SP/blob/main/age.md); "minisign" = https://jedisct1.github.io/minisign/ (public key = 42 bytes base64, 56 chars, starts `RW`).

**3. Plaintext container.** Tar, ustar headers (`tar::Header::new_ustar`), GNU `L` long-name entries permitted for names > 100 bytes; mode 0644 files / 0755 directories; entry order: `sealdrop/meta.json` (regular file) FIRST, then (folder packages only) a directory entry for `sealdrop/payload/<root>` and every subdirectory, then regular files, directories and files each in byte-wise sorted path order. `meta.json` schema with example:
```json
{ "format": "sealdrop/1", "tool": "sealdrop 0.2.1", "created": "2026-10-14T11:21:18Z",
  "root": "report", "files": [ { "path": "report/a.pdf", "size": 123, "sha256": "<hex>" } ] }
```
`root` = file name for a single file, folder name for a folder; `files[].path` is relative to `sealdrop/payload/`, `/`-separated, MUST begin with `root` as its first component, directories are not listed. Path rules (encoder MUST NOT produce, decoder MUST reject): absolute; any `\` `:` NUL; empty, `.` or `..` components; component ending in space or dot; any byte < 0x20 or `< > " | ? *`; first component (before the first dot) case-insensitively equal to CON PRN AUX NUL COM1–COM9 LPT1–LPT9; non-UTF-8. Symlinks and hardlinks are never packed (skipped) and MUST be rejected on extraction. Every listed file MUST appear exactly once; unlisted files MUST be rejected; `meta.json` MUST be ≤ 1 MiB. Encoder MUST verify each file's size did not change between hashing and writing.

**4. Encryption.** The container is encrypted as one age v1 file (binary, or ASCII armor per age). Standard recipients permitted: X25519 (`age1…`), hybrid ML-KEM-768+X25519 (`age1pq…`), scrypt passphrase, age plugins. Note: age appends random `*-grease` stanzas; "stand alone" below counts real stanzas only. Decoders MUST tolerate leading ASCII whitespace before an armored file. scrypt decoders SHOULD refuse logN > 22 (sealdrop does).

4.1 `sealdrop-argon2id` (OPTIONAL, non-standard): `-> sealdrop-argon2id <salt-b64> <t> <m_kib> <p>`; salt 16 random bytes; key = Argon2id, version 0x13, output 32 bytes, password = passphrase UTF-8, salt′ = ASCII `sealdrop-argon2id` ‖ salt (33 bytes… state exact length 17+16=33); body = ChaCha20-Poly1305(key, nonce = 12 zero bytes, plaintext = 16-byte age file key) → 32 bytes. Encoder profiles: desktop t=1 m_kib=2097152 p=4; compat t=3 m_kib=262144 p=4. Decoder MUST reject (as a header error, before deriving): arg count ≠ 4, body ≠ 32 bytes, salt ≠ 16 bytes, non-numeric or zero t/m/p, m_kib < 8, m_kib < 8·p; MUST reject as excessive work t > 10, m_kib > 2097152, p > 8. Wrong passphrase → decryption failure. The stanza MUST be the only real stanza (age label set `{"sealdrop-argon2id"}`). Stock age rejects these files ("no identity matched").

4.2 `sealdrop-release` (timed release): `-> sealdrop-release <release_id> <service-b64> <nonce-b64> <unlock-token-b64>`; `release_id` UUID; service = UTF-8 URL; nonce 12 random bytes; unlock token 32 random bytes; body = ChaCha20-Poly1305(K_release, nonce, JSON) where K_release is 32 random bytes held by the service and JSON is `{"stanzas":[{"tag":"X25519","args":["…"],"body":"<base64>"}, …]}` — the inner stanzas produced by the real recipients (any of §4's standard kinds or §4.1) wrapping the SAME file key. Limits: ≤ 64 inner stanzas, JSON ≤ 65 536 bytes (both sides). MUST stand alone (label `{"sealdrop-release"}`); the sender's own key is NOT added. Decoder algorithm: validate `release_id` (canonical UUID) and service URL (§7.1) BEFORE any request; POST unlock (§7.3); decrypt body; unwrap inner stanzas with local identities; a timed+passphrase package → the passphrase is required before any request (decoders MUST NOT start the window by fetching first). Security: anyone holding the file can trigger first unlock (denial of the window) but cannot read it.

**5. Delivery bundle.** Names. Manifest schema (every field, types, optional ones), example from a real package; `recipients[].kind` ∈ `x25519 | hybrid-pq | plugin:<name> | scrypt | argon2id`; `fingerprint` = first 16 hex chars of SHA-256 of the recipient string, empty string for passphrase kinds; `release` object `{service, release_id, window_secs, service_key}` present only for timed packages; `notes` fixed text (verbatim from `manifest.rs` `NOTES`); `expires` advisory, never enforced. Signature: minisign, prehashed (default), over the EXACT bytes of `manifest.json`, trusted comment `sealdrop manifest <package_id>`, file `<name>.manifest.json.minisig`. **Verification algorithm (MUST precede decryption, in order):** 1 read manifest ≤ 1 MiB and parse, `format` must equal `sealdrop-manifest/1`; 2 resolve signer key (explicit, own, or trust store — the manifest's `signer` field is NOT trusted by itself); 3 minisign verify; 4 signed trusted comment MUST equal `sealdrop manifest ` + `package_id`; 5 `ciphertext.file` MUST contain no `/` or `\` and MUST equal the package's bare file name; 6 SHA-256 and byte size of the package file MUST equal `ciphertext.sha256`/`ciphertext.size`; hash and decrypt the same open file handle. If the manifest is absent a decoder MUST refuse unless the user explicitly skips verification, and MUST then label the result unverified.

**6. Extraction requirements.** Rules 1–6 from the design + stream guard: before the tar parser sees a header, refuse extension entries (`L`,`K`,`x`,`g`) with declared size > 1 MiB, refuse PAX `x` payloads containing `size=`, refuse GNU sparse (`S`) and global (`g`) headers, cap total input at 65 GiB; `meta.json` first; counting limits (100 000 entries, 64 GiB total, per-file cap); hash while writing into a temp dir inside the destination; compare to `meta.json`; on success rename into place; existing target: refuse unless overwrite, and overwrite MUST park the old tree (`<target>.sealdrop-old-<random>`), rename the new one in, then delete the parked copy (restore on failure); header `size` MUST equal the effective entry size.

**7. Release service protocol v1.** 7.1 URL rules (client): `https://host[:port][/path]`, or `http://` only for `localhost`, `127.0.0.1`, `[::1]`; no `? # @ \`, whitespace or control chars; port ≤ 5 digits; clients MUST NOT follow redirects; SHOULD time out (sealdrop: 30 s). 7.2 Deposit: `PUT /v1/releases/{id}`, `Authorization: Bearer <deposit token>` (scheme case-insensitive), body `{"k_release":"<b64 of 32 bytes>","window_secs":N,"unlock_token_hash":"<sha256 hex of the raw 32-byte token>","package_sha256":"<hex>"}` → `201 {"service_key":"<minisign pubkey base64>"}`; 400 validation (list), 401, 409 duplicate id, 413 > 16 KiB, 429. 7.3 Unlock: `POST /v1/releases/{id}/unlock` body `{"unlock_token":"<b64>"}` → `200 {"k_release","first_unlock","expires_at","now"}`; first successful call sets `first_unlock` = service clock and `expires_at = first_unlock + window_secs` atomically (later concurrent calls see the stored values); allowed repeatedly while `now < expires_at`; `410` once `now ≥ expires_at` and the key MUST be deleted; 403 wrong token; 404 unknown. 7.4 Receipt: `GET /v1/releases/{id}/receipt` Bearer → 200 `{"receipt_json":"<string>","signature":"<minisign box>"}`; served after key deletion. 7.5 Service duties: clock is authoritative (host MUST run NTP); tokens stored hashed; keys deleted on expiry and swept at least every 60 s; releases never opened are purged after a retention period (operator default 90 days) — senders MUST disclose this; rate limiting per client address, `X-Forwarded-For` honoured only when the operator opts in. 7.6 `GET /healthz` → 200.

**8. Receipts.** `receipt_json` = pretty JSON `{release_id, package_sha256, first_unlock|null, expires_at|null, unlock_count, service_key, now}`; `signature` = minisign over the exact `receipt_json` bytes, trusted comment `sealdrop receipt <release_id>`. Verification (MUST): signature under the `service_key` recorded in the SIGNED manifest (never the key inside the receipt alone — trust-on-first-use is NOT conforming for sender tools), `release_id` and `package_sha256` equal the manifest's, trusted comment equals `sealdrop receipt <release_id>`.

**9. Security considerations.** Manifest hash binding = proof of which ciphertext was sent (closes age's key-commitment ambiguity, cite Len et al.); unlock token visible; service learns only id/times/hash; timed release limits (cannot recall plaintext; recipient clock irrelevant; service availability required); Argon2id adds little over scrypt logN 18 and costs interop; case-insensitive filesystems (names differing only by case); recipients SHOULD confirm signer keys out of band.

**10. Versioning.** Identifiers listed; incompatible changes require new identifiers; unknown JSON fields MUST be ignored by readers; unknown stanza tags are ignored by age semantics.

**11. Test vectors.** Directory layout; `vector.json` schema EXACTLY:
```json
{ "name": "recipient-x25519", "expect": "success",
  "stock_age": "opens" | "opens-interactive" | "rejects" | "n/a",
  "inputs": { "identity": "AGE-SECRET-KEY-1…", "passphrase": "…", "k_release": "<b64>", "signer_key": "RW…", "service_key": "RW…" },
  "expected": { "package_id": "…", "plaintext_tar_sha256": "<hex>", "files": [ { "path": "…", "size": 0, "sha256": "<hex>" } ] },
  "files": { "package": "package.sealdrop.age", "manifest": "manifest.json", "signature": "manifest.json.minisig", "tar": "input.tar", "receipt": "receipt.json" },
  "comment": "…" }
```
`expect` ∈ `success | header failure | verify failure | extract failure | receipt ok | receipt failure`; every key in `inputs`/`files` optional. How to run: `cargo test -p sealdrop-core --test format_vectors`.

**Appendix A.** Table: rule → file/function (e.g. §3 path rules → `extract::check_path`; §4.1 → `argon2id.rs`; §4.2 → `release.rs::{Recipient,Identity,validate_service_url,validate_release_id}`; §5 verify → `open::verify_with`; §6 guard → `extract::GuardedReader`; §7 → `sealdrop-release/src/routes.rs`; §8 → `release::verify_receipt_for`).
**Appendix B.** Stock-age matrix: X25519/hybrid/scrypt packages → `age -d … | tar -x` works; Argon2id and timed-release → "no identity matched"; manifest verification needs `minisign -V -p <key> -m manifest.json`.

- [ ] **Step 3: Self-check against the code** — for every number and string in the Global Constraints, `grep` it in the named source file and in the spec; paste the grep summary into your report. Fix any mismatch in the spec (never the code).

- [ ] **Step 4: Commit**
```bash
git add spec && git commit -m "spec: sealdrop package format v1 (CC0)" && git push origin main
```

---

### Task 2: Deterministic test-vector generator and the committed vectors

**Files:**
- Create: `crates/sealdrop-core/tests/format_vectors_gen.rs`, `spec/vectors/README.md`, `spec/vectors/keys/*`, 18 vector directories.
- Modify: `crates/sealdrop-core/Cargo.toml` (nothing new unless `flate2`/`tar` dev-deps are missing — both exist).

**Interfaces:**
- Consumes: `sealdrop_core::{seal::{seal, SealRequest, Mode, Kdf, ReleaseConfig, test_support::last_memory_deposit}, keys::KeyStore, passphrase::WordList, argon2id::{Recipient as ArgonRecipient, Params}, crypt::{encrypt_writer, Recipient}, manifest::{Manifest, sign}, release::{sign_receipt, Receipt}, hashing::sha256_hex, progress::NoProgress}`.
- Produces: `spec/vectors/<name>/vector.json` per §11 and the files it names. Vector names (exact): `recipient-x25519`, `armored-x25519`, `passphrase-scrypt`, `passphrase-argon2id-compat`, `timed-release-x25519`, `timed-release-passphrase`, `argon2id-reject-t-too-large`, `argon2id-reject-p-too-large`, `manifest-tampered`, `manifest-wrong-comment`, `ciphertext-tampered`, `tar-reject-traversal`, `tar-reject-symlink`, `tar-reject-pax-size`, `tar-reject-long-name-bomb`, `tar-reject-unlisted-file`, `receipt-valid`, `receipt-wrong-key`.

Design notes the generator follows: the `KeyStore` for vectors lives at `spec/vectors/keys/store/` (its `identity.txt`, `sign.key`, `sign.pub` are the committed secrets; created on first run, reused afterwards so vectors stay stable across regeneration); the service key pair is `spec/vectors/keys/service.key|pub` (minisign boxes). Timed vectors seal against `memory://spec.vectors` under the `test-support` feature and record the `K_release` that `test_support::last_memory_deposit()` returns. Passphrase vectors use a fixed passphrase by sealing with `Mode::Passphrase` and then RE-sealing? No — `seal` always generates the passphrase; instead the generator seals and records the generated words in `inputs.passphrase` (vectors stay stable because the keys dir is reused and the generator only runs when the vector directory is absent or `--force`). Argon2id compat vector uses `Params { t: 3, m_kib: 8192, p: 1 }` via a direct `encrypt_writer` of a packed tar (no manifest) so it is cheap; `expect` for it is `success` with `files.manifest` absent.

- [ ] **Step 1: Write `format_vectors_gen.rs`**
```rust
//! Regenerates `spec/vectors/`. Run with:
//!   cargo test -p sealdrop-core --features test-support --test format_vectors_gen -- --ignored regenerate_format_vectors
//! Existing vector directories are kept unless SEALDROP_VECTORS_FORCE=1.
#![cfg(feature = "test-support")]

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use age::secrecy::SecretString;
use sealdrop_core::keys::KeyStore;
use sealdrop_core::passphrase::WordList;
use sealdrop_core::progress::NoProgress;
use sealdrop_core::seal::{seal, Kdf, Mode, ReleaseConfig, SealRequest};
use serde_json::{json, Value};

fn root() -> PathBuf { PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors") }

fn fixture(dir: &Path) -> PathBuf {
    let p = dir.join("report");
    fs::create_dir_all(p.join("sub")).unwrap();
    fs::write(p.join("a.txt"), b"alpha\n").unwrap();
    fs::write(p.join("sub/b.bin"), (0u8..=255).collect::<Vec<u8>>()).unwrap();
    p
}

fn keys() -> (KeyStore, minisign::KeyPair) {
    let k = root().join("keys");
    fs::create_dir_all(&k).unwrap();
    let ks = KeyStore::open(k.join("store"));
    if !ks.exists() { ks.generate(false).unwrap(); }
    let sk_path = k.join("service.key");
    if !sk_path.exists() {
        let kp = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
        fs::write(&sk_path, kp.sk.to_box(Some("spec vectors service key")).unwrap().into_string()).unwrap();
        fs::write(k.join("service.pub"), kp.pk.to_box().unwrap().into_string()).unwrap();
    }
    let sk = minisign::SecretKeyBox::from_string(&fs::read_to_string(&sk_path).unwrap()).unwrap().into_unencrypted_secret_key().unwrap();
    let pk = minisign::PublicKeyBox::from_string(&fs::read_to_string(k.join("service.pub")).unwrap()).unwrap().into_public_key().unwrap();
    (ks, minisign::KeyPair { pk, sk })
}

fn want(name: &str) -> Option<PathBuf> {
    let d = root().join(name);
    if d.exists() && std::env::var("SEALDROP_VECTORS_FORCE").is_err() { return None; }
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    Some(d)
}

fn write_json(d: &Path, v: Value) { fs::write(d.join("vector.json"), serde_json::to_vec_pretty(&v).unwrap()).unwrap(); }

fn files_json(m: &sealdrop_core::pack::Meta) -> Value {
    json!(m.files.iter().map(|f| json!({"path": f.path, "size": f.size, "sha256": f.sha256})).collect::<Vec<_>>())
}

/// Seals the fixture with `mode` into `d`, copying the three bundle files in and returning the manifest doc + pack report.
fn seal_into(ks: &KeyStore, d: &Path, mode: Mode, armor: bool, release: Option<ReleaseConfig>, include_self: bool)
    -> (sealdrop_core::seal::SealResult, Value) {
    let tmp = tempfile::tempdir().unwrap();
    let input = fixture(tmp.path());
    let res = seal(ks, SealRequest { input, out_dir: tmp.path().join("out"), mode, include_self, allow_unrecoverable: false,
        armor, classification: Some("spec-vector".into()), expires: None, release }, &NoProgress).unwrap();
    fs::copy(&res.package, d.join("package.sealdrop.age")).unwrap();
    fs::copy(&res.manifest, d.join("manifest.json")).unwrap();
    fs::copy(&res.signature, d.join("manifest.json.minisig")).unwrap();
    let expected = json!({ "package_id": res.manifest_doc.package_id, "plaintext_tar_sha256": res.pack.tar_sha256, "files": files_json(&res.pack.meta) });
    (res, expected)
}

fn identity_line(ks: &KeyStore) -> String {
    let t = fs::read_to_string(ks.dir().join("identity.txt")).unwrap();
    t.lines().find(|l| l.starts_with("AGE-SECRET-KEY-1")).unwrap().to_string()
}

#[test]
#[ignore]
fn regenerate_format_vectors() {
    let (ks, service) = keys();
    let me = sealdrop_core::crypt::Recipient::parse(&ks.recipient_string().unwrap()).unwrap();
    let signer = ks.signing_public_string().unwrap();
    let bundle_files = json!({"package": "package.sealdrop.age", "manifest": "manifest.json", "signature": "manifest.json.minisig"});

    for (name, armor) in [("recipient-x25519", false), ("armored-x25519", true)] {
        if let Some(d) = want(name) {
            let (_, expected) = seal_into(&ks, &d, Mode::Recipients(vec![me.clone()]), armor, None, false);
            write_json(&d, json!({"name": name, "expect": "success", "stock_age": "opens",
                "inputs": {"identity": identity_line(&ks), "signer_key": signer}, "expected": expected, "files": bundle_files,
                "comment": "X25519 recipient; decryptable by stock age with -i keys/store/identity.txt"}));
        }
    }
    if let Some(d) = want("passphrase-scrypt") {
        let (res, expected) = seal_into(&ks, &d, Mode::Passphrase { list: WordList::Eff, words: 6, kdf: Kdf::Scrypt { log_n: 12 } }, false, None, false);
        write_json(&d, json!({"name": "passphrase-scrypt", "expect": "success", "stock_age": "opens-interactive",
            "inputs": {"passphrase": res.passphrase.as_ref().unwrap().joined().to_string(), "signer_key": signer}, "expected": expected, "files": bundle_files,
            "comment": "scrypt logN 12 (test cost); stock age opens it when the passphrase is typed"}));
    }
    if let Some(d) = want("passphrase-argon2id-compat") {
        let (res, expected) = seal_into(&ks, &d, Mode::Passphrase { list: WordList::Eff, words: 6, kdf: Kdf::Argon2id(sealdrop_core::argon2id::Profile::Compat) }, false, None, false);
        write_json(&d, json!({"name": "passphrase-argon2id-compat", "expect": "success", "stock_age": "rejects",
            "inputs": {"passphrase": res.passphrase.as_ref().unwrap().joined().to_string(), "signer_key": signer}, "expected": expected, "files": bundle_files,
            "comment": "sealdrop-argon2id stanza, compat profile (t=3, m=256 MiB, p=4); stock age reports no identity matched"}));
    }
    for (name, mode) in [("timed-release-x25519", Mode::Recipients(vec![me.clone()])),
                         ("timed-release-passphrase", Mode::Passphrase { list: WordList::Eff, words: 6, kdf: Kdf::Scrypt { log_n: 12 } })] {
        if let Some(d) = want(name) {
            let rc = ReleaseConfig { service: "memory://spec.vectors".into(), token: "unused".into(), window_secs: 600 };
            let (res, expected) = seal_into(&ks, &d, mode, false, Some(rc), false);
            let k = sealdrop_core::seal::test_support::last_memory_deposit().unwrap();
            let mut inputs = json!({"k_release": base64::Engine::encode(&base64::prelude::BASE64_STANDARD_NO_PAD, *k), "signer_key": signer});
            if let Some(p) = &res.passphrase { inputs["passphrase"] = json!(p.joined().to_string()); } else { inputs["identity"] = json!(identity_line(&ks)); }
            write_json(&d, json!({"name": name, "expect": "success", "stock_age": "rejects", "inputs": inputs, "expected": expected, "files": bundle_files,
                "comment": "sealdrop-release stanza; the unlock token is in the header, K_release is what the service would return"}));
        }
    }
    // Argon2id decoder bounds: encode with out-of-range t / p (cheap at tiny memory), expect header failure.
    for (name, params, why) in [
        ("argon2id-reject-t-too-large", sealdrop_core::argon2id::Params { t: 11, m_kib: 8192, p: 1 }, "t=11 exceeds the decoder bound of 10"),
        ("argon2id-reject-p-too-large", sealdrop_core::argon2id::Params { t: 1, m_kib: 8192, p: 9 }, "p=9 exceeds the decoder bound of 8"),
    ] {
        if let Some(d) = want(name) {
            let tmp = tempfile::tempdir().unwrap(); let input = fixture(tmp.path());
            let mut tar = Vec::new(); let (report, _) = sealdrop_core::pack::pack(&input, &mut tar).unwrap();
            let pass = SecretString::from("spec vector passphrase".to_string());
            let r: Vec<Box<dyn age::Recipient + Send>> = vec![Box::new(sealdrop_core::argon2id::Recipient::with_params(pass, params))];
            let mut w = sealdrop_core::crypt::encrypt_writer(fs::File::create(d.join("package.sealdrop.age")).unwrap(), &r, false).unwrap();
            w.write_all(&tar).unwrap(); w.finish().unwrap();
            write_json(&d, json!({"name": name, "expect": "header failure", "stock_age": "rejects",
                "inputs": {"passphrase": "spec vector passphrase"}, "expected": {"plaintext_tar_sha256": report.tar_sha256},
                "files": {"package": "package.sealdrop.age"}, "comment": why}));
        }
    }
    // Manifest/ciphertext tamper vectors derived from a fresh recipient package.
    for (name, mutate, why) in [
        ("manifest-tampered", 0u8, "one signed byte of manifest.json changed (classification case)"),
        ("manifest-wrong-comment", 1u8, "manifest re-signed by the right key but with trusted comment 'sealdrop manifest wrong'"),
        ("ciphertext-tampered", 2u8, "one byte of the package flipped; signature still valid, hash mismatch"),
    ] {
        if let Some(d) = want(name) {
            let (res, expected) = seal_into(&ks, &d, Mode::Recipients(vec![me.clone()]), false, None, false);
            match mutate {
                0 => { let m = fs::read_to_string(d.join("manifest.json")).unwrap().replace("\"spec-vector\"", "\"Spec-vector\""); fs::write(d.join("manifest.json"), m).unwrap(); }
                1 => { let bytes = fs::read(d.join("manifest.json")).unwrap();
                       let sig = minisign::sign(Some(&ks.signing_public().unwrap()), &ks.signing_key().unwrap(), std::io::Cursor::new(&bytes), Some("sealdrop manifest wrong"), None).unwrap();
                       fs::write(d.join("manifest.json.minisig"), sig.into_string()).unwrap(); }
                _ => { let mut b = fs::read(d.join("package.sealdrop.age")).unwrap(); let i = b.len() - 10; b[i] ^= 1; fs::write(d.join("package.sealdrop.age"), b).unwrap(); }
            }
            let _ = res;
            write_json(&d, json!({"name": name, "expect": "verify failure", "stock_age": "n/a", "inputs": {"identity": identity_line(&ks), "signer_key": signer},
                "expected": expected, "files": bundle_files, "comment": why}));
        }
    }
    // Raw tar rejects (the extractor must refuse before writing any file).
    tar_reject_vectors();
    // Receipts.
    if let Some(d) = want("receipt-valid") {
        let r = sealdrop_core::release::Receipt { release_id: "3b1f8c6e-5d2a-4e9b-9c7f-1a2b3c4d5e6f".into(), package_sha256: "ab".repeat(32), first_unlock: Some("2026-10-14T09:00:00Z".into()),
            expires_at: Some("2026-10-14T09:10:00Z".into()), unlock_count: 1, service_key: service.pk.to_base64(), now: "2026-10-14T09:01:00Z".into() };
        let s = sealdrop_core::release::sign_receipt(&r, &service.sk, &service.pk).unwrap();
        fs::write(d.join("receipt.json"), serde_json::to_vec_pretty(&s).unwrap()).unwrap();
        write_json(&d, json!({"name": "receipt-valid", "expect": "receipt ok", "stock_age": "n/a", "inputs": {"service_key": service.pk.to_base64()},
            "expected": {"release_id": r.release_id, "package_sha256": r.package_sha256}, "files": {"receipt": "receipt.json"}, "comment": "signed by keys/service.key"}));
    }
    if let Some(d) = want("receipt-wrong-key") {
        let r = sealdrop_core::release::Receipt { release_id: "3b1f8c6e-5d2a-4e9b-9c7f-1a2b3c4d5e6f".into(), package_sha256: "ab".repeat(32), first_unlock: None, expires_at: None,
            unlock_count: 0, service_key: ks.signing_public_string().unwrap(), now: "2026-10-14T09:01:00Z".into() };
        let s = sealdrop_core::release::sign_receipt(&r, &ks.signing_key().unwrap(), &ks.signing_public().unwrap()).unwrap();
        fs::write(d.join("receipt.json"), serde_json::to_vec_pretty(&s).unwrap()).unwrap();
        write_json(&d, json!({"name": "receipt-wrong-key", "expect": "receipt failure", "stock_age": "n/a", "inputs": {"service_key": service.pk.to_base64()},
            "expected": {"release_id": r.release_id, "package_sha256": r.package_sha256}, "files": {"receipt": "receipt.json"},
            "comment": "internally consistent receipt signed by a key that is not the manifest's service_key"}));
    }
}

fn tar_reject_vectors() {
    use tar::{Builder, EntryType, Header};
    fn meta(root: &str, files: &[(&str, &[u8])]) -> Vec<u8> {
        let files: Vec<Value> = files.iter().map(|(p, d)| json!({"path": p, "size": d.len(), "sha256": sealdrop_core::hashing::sha256_hex(d)})).collect();
        serde_json::to_vec(&json!({"format": "sealdrop/1", "tool": "spec", "created": "2026-01-01T00:00:00Z", "root": root, "files": files})).unwrap()
    }
    fn add(b: &mut Builder<&mut Vec<u8>>, path: &str, data: &[u8]) {
        let mut h = Header::new_gnu(); h.set_size(data.len() as u64); h.set_mode(0o644); h.set_entry_type(EntryType::Regular);
        b.append_data(&mut h, path, data).unwrap();
    }
    /// Writes a raw 512-byte header with an arbitrary (possibly invalid) name/type/size, then `body`.
    fn raw(out: &mut Vec<u8>, name: &str, typeflag: u8, size: u64, body: &[u8]) {
        let mut h = Header::new_gnu(); h.set_size(size); h.set_mode(0o644); h.set_entry_type(EntryType::new(typeflag));
        let bytes = h.as_mut_bytes(); let n = name.as_bytes(); bytes[..n.len().min(100)].copy_from_slice(&n[..n.len().min(100)]);
        h.set_cksum(); out.extend_from_slice(h.as_bytes()); out.extend_from_slice(body); let pad = (512 - body.len() % 512) % 512; out.extend(std::iter::repeat_n(0u8, pad));
    }
    let cases: Vec<(&str, Box<dyn Fn() -> Vec<u8>>, &str)> = vec![
        ("tar-reject-traversal", Box::new(|| { let mut o = Vec::new(); { let mut b = Builder::new(&mut o); add(&mut b, "sealdrop/meta.json", &meta("r", &[("r/../../evil", b"x")])); b.finish().unwrap(); } raw(&mut o, "sealdrop/payload/r/../../evil", b'0', 1, b"x"); o.extend(std::iter::repeat_n(0u8, 1024)); o }), "path with .. must be rejected"),
        ("tar-reject-symlink", Box::new(|| { let mut o = Vec::new(); { let mut b = Builder::new(&mut o); add(&mut b, "sealdrop/meta.json", &meta("r", &[("r/a", b"x")])); let mut h = Header::new_gnu(); h.set_entry_type(EntryType::Symlink); h.set_size(0); b.append_link(&mut h, "sealdrop/payload/r/link", "/etc/passwd").unwrap(); b.finish().unwrap(); } o }), "symlink entries must be rejected"),
        ("tar-reject-pax-size", Box::new(|| { let mut o = Vec::new(); { let mut b = Builder::new(&mut o); add(&mut b, "sealdrop/meta.json", &meta("r", &[("r/a", b"x")])); b.finish().unwrap(); } o.truncate(o.len() - 1024); raw(&mut o, "sealdrop/payload/r/a", b'x', 12, b"11 size=1\n"); raw(&mut o, "sealdrop/payload/r/a", b'0', 1, b"x"); o.extend(std::iter::repeat_n(0u8, 1024)); o }), "PAX size= override must be refused"),
        ("tar-reject-long-name-bomb", Box::new(|| { let mut o = Vec::new(); raw(&mut o, "././@LongLink", b'L', 2 * 1024 * 1024, b""); o }), "GNU long-name header declaring 2 MiB must be refused before buffering"),
        ("tar-reject-unlisted-file", Box::new(|| { let mut o = Vec::new(); { let mut b = Builder::new(&mut o); add(&mut b, "sealdrop/meta.json", &meta("r", &[("r/a", b"x")])); add(&mut b, "sealdrop/payload/r/b", b"x"); b.finish().unwrap(); } o }), "a file not listed in meta.json must be rejected"),
    ];
    for (name, build, why) in cases {
        if let Some(d) = want(name) {
            fs::write(d.join("input.tar"), build()).unwrap();
            write_json(&d, json!({"name": name, "expect": "extract failure", "stock_age": "n/a", "files": {"tar": "input.tar"}, "comment": why}));
        }
    }
}
```
If `Header::as_mut_bytes`/`EntryType::new` differ in tar 0.4.46, read `~/.cargo/registry/src/*/tar-0.4.46/src/header.rs` and adapt; the pax-size vector may instead be assembled from the `tests/malicious_tar.rs` raw-header helper (copy it; do not import test code across files). Add `base64` and `tempfile` to `[dev-dependencies]` if missing.

- [ ] **Step 2: Generate** — `cargo test -p sealdrop-core --features test-support --test format_vectors_gen -- --ignored regenerate_format_vectors`; then `ls spec/vectors` shows 18 directories + `keys/`.

- [ ] **Step 3: `spec/vectors/README.md`** — what the keys are (test-only, CC0), how to run the conformance test, how to regenerate (`SEALDROP_VECTORS_FORCE=1` + the command), a note that ciphertexts are not reproducible byte-for-byte (age randomness) so regeneration changes files but not semantics.

- [ ] **Step 4: Make sure `.gitignore` does not swallow the vectors** — `git check-ignore -v spec/vectors/recipient-x25519/package.sealdrop.age spec/vectors/keys/store/identity.txt spec/vectors/keys/service.key` must print nothing; if it does, add `!spec/vectors/**` after the existing negations in `.gitignore` (the keys dir is test material; the comment must say so).

- [ ] **Step 5: Commit** — `git add spec crates/sealdrop-core && git commit -m "spec: test vectors and generator" && git push origin main`.

---

### Task 3: Conformance test, CI, docs links

**Files:**
- Create: `crates/sealdrop-core/tests/format_vectors.rs`
- Modify: `README.md` (new "Format specification" section after "Interop with stock age"), `CONTRIBUTING.md` (regeneration command), `.github/workflows/ci.yml` (nothing new: `cargo test --workspace` already runs it — verify).

**Interfaces:**
- Consumes: `spec/vectors/*/vector.json` per §11; core APIs `open::{open, verify, OpenRequest}`, `extract::{extract, Limits}`, `release::{verify_receipt_for, MemoryFetch, Deposit}`, `crypt::decrypt_reader`, `argon2id::Identity`, `KeyStore`.

- [ ] **Step 1: Write the consumer**
```rust
//! Runs every vector in spec/vectors against the reference implementation.
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use age::secrecy::SecretString;
use sealdrop_core::extract::{extract, Limits};
use sealdrop_core::keys::KeyStore;
use sealdrop_core::open::{open, verify, OpenRequest};
use sealdrop_core::progress::NoProgress;
use sealdrop_core::release::{verify_receipt_for, MemoryFetch, ReleaseFetch, Unlock};
use sealdrop_core::Error;
use serde_json::Value;
use zeroize::Zeroizing;

fn vectors() -> PathBuf { PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors") }

/// A fetch that serves the vector's K_release for any id (token is validated by the real stanza/header rules elsewhere).
struct VectorFetch([u8; 32]);
impl ReleaseFetch for VectorFetch {
    fn unlock(&self, _s: &str, _id: &str, _t: &str) -> sealdrop_core::Result<Unlock> {
        Ok(Unlock { k_release: Zeroizing::new(self.0), first_unlock: "2026-10-14T09:00:00Z".into(), expires_at: "2026-10-14T09:10:00Z".into(), now: "2026-10-14T09:00:01Z".into() })
    }
}

fn store_for(v: &Value, tmp: &Path) -> KeyStore {
    // The vector store holds the test identity and signer key; copy it so tests never write into spec/.
    let src = vectors().join("keys/store"); let dst = tmp.join("store"); fs::create_dir_all(&dst).unwrap();
    for f in ["identity.txt", "sign.key", "sign.pub"] { fs::copy(src.join(f), dst.join(f)).unwrap(); }
    let ks = KeyStore::open(&dst);
    if let Some(k) = v["inputs"]["signer_key"].as_str() { ks.add_trusted("vector", k).unwrap(); }
    ks
}

fn run(dir: &Path) -> Result<(), String> {
    let v: Value = serde_json::from_slice(&fs::read(dir.join("vector.json")).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    let expect = v["expect"].as_str().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let pass = v["inputs"]["passphrase"].as_str().map(|p| SecretString::from(p.to_string()));
    let fetch: Box<dyn ReleaseFetch> = match v["inputs"]["k_release"].as_str() {
        Some(b) => { let raw = base64::Engine::decode(&base64::prelude::BASE64_STANDARD_NO_PAD, b).unwrap(); let mut k = [0u8; 32]; k.copy_from_slice(&raw); Box::new(VectorFetch(k)) }
        None => Box::new(MemoryFetch::expired()),
    };
    match expect {
        "success" | "verify failure" | "header failure" => {
            let pkg = dir.join(v["files"]["package"].as_str().unwrap());
            // Vectors without a manifest (argon2id bounds) are opened with skip_verify.
            let has_manifest = v["files"]["manifest"].is_string();
            let work = tmp.path().join("pkg"); fs::create_dir_all(&work).unwrap();
            let p2 = work.join("package.sealdrop.age"); fs::copy(&pkg, &p2).unwrap();
            if has_manifest { fs::copy(dir.join("manifest.json"), work.join("package.manifest.json")).unwrap(); fs::copy(dir.join("manifest.json.minisig"), work.join("package.manifest.json.minisig")).unwrap(); }
            let ks = store_for(&v, tmp.path());
            let r = open(&ks, OpenRequest { package: p2, out_dir: tmp.path().join("out"), signer: None, skip_verify: !has_manifest, overwrite: false, passphrase: pass, limits: Limits::default() }, fetch, &NoProgress);
            match (expect, r) {
                ("success", Ok(rep)) => {
                    let want = v["expected"]["files"].as_array().unwrap();
                    if rep.extract.files != want.len() { return Err(format!("{} files, expected {}", rep.extract.files, want.len())); }
                    for f in want { let p = tmp.path().join("out").join(f["path"].as_str().unwrap()); let got = fs::read(&p).map_err(|e| format!("{}: {e}", p.display()))?; if sealdrop_core::hashing::sha256_hex(&got) != f["sha256"].as_str().unwrap() { return Err(format!("hash mismatch {}", p.display())); } }
                    Ok(())
                }
                ("success", Err(e)) => Err(format!("expected success, got {e}")),
                ("verify failure", Err(Error::Verify(_))) => Ok(()),
                ("verify failure", other) => Err(format!("expected Error::Verify, got {}", other.err().map(|e| e.to_string()).unwrap_or("Ok".into()))),
                ("header failure", Err(Error::Decrypt(_))) => Ok(()),
                ("header failure", other) => Err(format!("expected a decrypt/header error, got {}", other.err().map(|e| e.to_string()).unwrap_or("Ok".into()))),
                _ => unreachable!(),
            }
        }
        "extract failure" => {
            let tar = fs::read(dir.join(v["files"]["tar"].as_str().unwrap())).unwrap();
            match extract(&tar[..], &tmp.path().join("out"), &Limits::default(), false) {
                Err(Error::Extract(_)) => Ok(()),
                Err(Error::Io(e)) if e.get_ref().and_then(|r| r.downcast_ref::<sealdrop_core::extract::ExtractError>()).is_some() => Ok(()),
                other => Err(format!("expected ExtractError, got {}", other.err().map(|e| e.to_string()).unwrap_or("Ok".into()))),
            }
        }
        "receipt ok" | "receipt failure" => {
            let s: sealdrop_core::release::SignedReceipt = serde_json::from_slice(&fs::read(dir.join(v["files"]["receipt"].as_str().unwrap())).unwrap()).unwrap();
            let r = verify_receipt_for(&s, v["inputs"]["service_key"].as_str().unwrap(), v["expected"]["release_id"].as_str().unwrap(), v["expected"]["package_sha256"].as_str().unwrap());
            match (expect, r.is_ok()) { ("receipt ok", true) | ("receipt failure", false) => Ok(()), _ => Err(format!("unexpected receipt outcome: {:?}", r.map(|_| ()).map_err(|e| e.to_string()))) }
        }
        other => Err(format!("unknown expect {other}")),
    }
}

#[test]
fn all_format_vectors() {
    let mut names: Vec<PathBuf> = fs::read_dir(vectors()).unwrap().map(|e| e.unwrap().path()).filter(|p| p.is_dir() && p.file_name().unwrap() != "keys").collect();
    names.sort();
    assert_eq!(names.len(), 18, "expected 18 vectors, found {}", names.len());
    let failures: Vec<String> = names.iter().filter_map(|d| run(d).err().map(|e| format!("{}: {e}", d.file_name().unwrap().to_string_lossy()))).collect();
    assert!(failures.is_empty(), "format vector failures:\n{}", failures.join("\n"));
}

/// When the Go `age` binary is present, prove the `stock_age` claims for key-based vectors.
#[test]
fn stock_age_claims() {
    if Command::new("age").arg("--version").output().map(|o| !o.status.success()).unwrap_or(true) {
        if std::env::var("SEALDROP_REQUIRE_AGE").is_ok() { panic!("age binary required"); }
        eprintln!("skipping: age not installed"); return;
    }
    let ident = vectors().join("keys/store/identity.txt");
    for d in fs::read_dir(vectors()).unwrap().map(|e| e.unwrap().path()).filter(|p| p.is_dir() && p.file_name().unwrap() != "keys") {
        let v: Value = serde_json::from_slice(&fs::read(d.join("vector.json")).unwrap()).unwrap();
        let Some(pkg) = v["files"]["package"].as_str() else { continue };
        let claim = v["stock_age"].as_str().unwrap();
        if claim == "n/a" || claim == "opens-interactive" { continue; }
        let out = Command::new("age").args(["-d", "-i"]).arg(&ident).arg(d.join(pkg)).output().unwrap();
        match claim {
            "opens" => { assert!(out.status.success(), "{}: stock age failed: {}", v["name"], String::from_utf8_lossy(&out.stderr));
                         let mut ar = tar::Archive::new(&out.stdout[..]); let first = ar.entries().unwrap().next().unwrap().unwrap(); assert_eq!(first.path().unwrap().to_string_lossy(), "sealdrop/meta.json"); }
            "rejects" => assert!(!out.status.success(), "{}: stock age unexpectedly opened it", v["name"]),
            other => panic!("bad stock_age {other}"),
        }
    }
}
```
Note for the timed vectors: `open` validates the service URL from the header; `memory://spec.vectors` is accepted only under `cfg(test)`/`test-support`. Integration tests are NOT `cfg(test)` for the library crate, so run this test file with `--features test-support` — add to the CI test step `cargo test -p sealdrop-core --features test-support --test format_vectors` (and keep the feature-off workspace run so `no_memory_seam` still runs). Alternatively make the timed vectors' header service `https://spec.vectors.invalid` (production-valid URL) and let `VectorFetch` ignore it — do this instead: in the generator use `service: "https://spec.vectors.invalid"` for the manifest/header while still depositing via `memory://`? Not possible (one `ReleaseConfig`). Decision: use the `--features test-support` invocation in CI for this test file and document it in `spec/vectors/README.md`.

- [ ] **Step 2: Run** — `export PATH="$PATH:$HOME/go/bin"; SEALDROP_REQUIRE_AGE=1 cargo test -p sealdrop-core --features test-support --test format_vectors -- --nocapture`. Expected: `all_format_vectors` passes (18/18) and `stock_age_claims` passes with no "skipping". Fix generator/vector mismatches by regenerating (never by loosening the test).

- [ ] **Step 3: CI** — in `.github/workflows/ci.yml` rust job add after the workspace test: `- run: cargo test -p sealdrop-core --features test-support --test format_vectors` (with `SEALDROP_REQUIRE_AGE: "1"` env as the other test step).

- [ ] **Step 4: Docs** — README: new section "## Format specification" (3 sentences: the format is public, CC0, link `spec/sealdrop-format-v1.md`; vectors in `spec/vectors/`; "other tools are welcome to implement it"); add it to the README Contents list and the Roadmap line "publish the format spec" if present. CONTRIBUTING: a "Regenerating the format test vectors" paragraph with the exact command and the `SEALDROP_VECTORS_FORCE=1` note.

- [ ] **Step 5: Full verification and commit** — `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test --workspace`, the Step 2 command; then `git add -A && git commit -m "test: format-spec conformance vectors in CI; link the spec from the README" && git push origin main`.

---

## Self-review

- Design §3 outline → Task 1 (all eleven sections + appendices listed with facts). §4 vectors → Task 2 (18 names match; `vector.json` schema identical to Task 1 §11; `stock_age` values `opens|opens-interactive|rejects|n/a`). Conformance in CI → Task 3. Licence → Task 1 Step 1. README/CONTRIBUTING → Task 3 Step 4.
- Placeholders: none ("TBD"/"TODO" absent); every code step has code; the one open implementation question (tar raw-header API) names the fallback.
- Type consistency: `VectorFetch` implements `ReleaseFetch::unlock(&self, &str, &str, &str) -> Result<Unlock>` matching `release.rs`; `Unlock { k_release, first_unlock, expires_at, now }`; `verify_receipt_for(&SignedReceipt, &str, &str, &str)`; `OpenRequest` fields as in `open.rs`; `Deposit`/`last_memory_deposit` as in `seal.rs`; `argon2id::Recipient::with_params(SecretString, Params)` exists.
- Known deviation from the design: the argon2id reject vectors are `t-too-large` and `p-too-large` (encoder-producible) instead of `m-too-large`/`m-lt-8p`/`bad-salt`, which cannot be produced through the encoder without a valid header MAC; the design doc is updated to match.
