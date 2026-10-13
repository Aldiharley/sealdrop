# sealdrop 0.2 design: core library, CLI and desktop app

Date: 13 October 2026. Status: approved for implementation.
Source documents: `TECH_SPEC.md` (product spec) and `RESEARCH.md` (research).

This document records the decisions made for the first implementation pass. Where it
and `TECH_SPEC.md` differ, this document wins for this pass; the deferred items in
section 10 go back to the spec's later milestones.

## 1. Scope of this pass

In scope (spec milestones 0.1 and the desktop shell from 0.2):

- Rust core library `sealdrop-core`: tar packaging, age encryption to recipients,
  generated-passphrase mode (scrypt), optional Argon2id passphrase mode (off by default),
  signed delivery manifest, verify, hardened extraction, identity store, policy rules.
- CLI `sealdrop`: `keygen`, `seal`, `open`, `verify`, `recipient`, `trust`.
- Desktop app: Tauri 2 + React 19 + TypeScript, five screens, pastel neumorphic design.
- Hardware keys: pass-through to installed `age-plugin-*` binaries from an allow-list.
- **Timed release** (added 13 Oct 2026 after `docs/research/2026-10-13-post-unlock-expiry.md`):
  a package can be sealed so it is openable only within a sender-chosen window
  (seconds to days) after the recipient first opens it, enforced by a self-hostable
  key-release service `sealdrop-release` shipped in this repo, with signed unlock
  receipts returned to the sender.
- Conformance: C2SP CCTV age test vectors (147) run in CI.
- Interop check against the reference Go `age` binary.
- Repository hygiene: hardened `.gitignore`, GitHub Actions CI, Apache-2.0.
- README with screenshots and a banner in the same visual style as the app.

Out of scope: see section 10.

## 2. Decisions

| # | Decision | Choice | Why |
|---|---|---|---|
| 1 | Language and crypto library | Rust, `age` crate 0.12.1 (rage) | Spec §9; audited format; exposes `Recipient`/`Identity` traits for extension |
| 2 | Desktop shell | Tauri 2.12 (stable), system WebView | Spec §9; small binary; Rust core linked in-process |
| 3 | Frontend stack | React 19, Vite, TypeScript, hand-written CSS (no UI framework) | Neumorphic look needs custom CSS; smallest dependency surface |
| 4 | Argon2id passphrase mode | Shipped, off by default, as an in-process custom stanza `sealdrop-argon2id` | User decision 13 Oct 2026; stock age rejects the file ("no matching keys") instead of mis-decrypting |
| 5 | Signatures | minisign format via the `minisign` crate 0.10 | Spec §4.3; `.minisig` verifiable with the standalone `minisign` tool |
| 6 | Passphrase word lists | EFF long list, 6 words default (77.5 bits); BIP-39, 10 words (110 bits) on request | Spec §5.2 |
| 7 | scrypt work factor | logN 18 default, logN 20 "high" profile; decrypt refuses logN > 22 | Spec §5.2 |
| 8 | Identity storage | OS config dir, plain files, 0600 on Unix | Simple, inspectable, interoperable with `age -i identity.txt` |
| 9 | Escrow, hosted viewer, wormhole | Deferred | Scope decision 13 Oct 2026 |
| 10 | Post-unlock expiry ("shred after N") | Implemented as **timed release**: key custody on a service, not a local timer; no blockchain | Research 13 Oct 2026: local timers and shredding are defeatable; a chain cannot hold a secret; a signed receipt proves first unlock |
| 11 | Release service stack | Rust, `axum` + `rusqlite` (bundled SQLite), single binary, Apache-2.0 | Same language as the core; one static binary to self-host |
| 12 | Service time source | The service's own UTC clock; host must run NTP/NTS. Roughtime cross-check deferred | The recipient's clock is irrelevant by construction; the sender's organisation controls the service host |

## 3. Repository layout

```
sealdrop/
  Cargo.toml                       # workspace: crates/*, apps/desktop/src-tauri
  crates/sealdrop-core/            # library, no interactive I/O
  crates/sealdrop-cli/             # `sealdrop` binary
  crates/sealdrop-release/         # `sealdrop-release` key-release service (axum + SQLite)
  apps/desktop/                    # Tauri app
    src-tauri/                     # Rust side: thin commands over sealdrop-core
    src/                           # React UI
  testkit/                         # C2SP CCTV age vectors (git subtree of CCTV/age/testdata)
  docs/superpowers/specs/          # this file
  docs/superpowers/plans/          # implementation plan
  docs/design/                     # UI design brief and generated assets
  .github/workflows/ci.yml
  RESEARCH.md  TECH_SPEC.md  README.md  LICENSE  .gitignore
```

## 4. Package format (as built)

### 4.1 Plaintext tar

POSIX ustar/pax stream, entries in this order:

```
sealdrop/meta.json
sealdrop/payload/<original name>            # a file, or
sealdrop/payload/<folder name>/...          # a folder, recursively
```

`meta.json`:

```json
{
  "format": "sealdrop/1",
  "tool": "sealdrop 0.2.0",
  "created": "2026-10-13T09:00:00Z",
  "root": "report.pdf",
  "files": [
    { "path": "report.pdf", "size": 123456, "sha256": "<hex>" }
  ]
}
```

`path` is relative to `sealdrop/payload/`, uses `/` separators, and must pass the
same checks as extraction (section 7). Directories are not listed; they are implied.
Symlinks in the input are skipped with a warning (they are never packed).

### 4.2 Encryption

age v1 exactly, via the `age` crate. Binary by default, ASCII armor with `--armor`.
Recipients:

- `age1…` X25519 and `age1pq…` hybrid post-quantum recipients, parsed by the crate.
- `age1<plugin>1…` plugin recipients, only if `<plugin>` is in the allow-list
  `{yubikey, fido2prf, se, tpm}` and the `age-plugin-<plugin>` binary is on PATH.
- scrypt passphrase: `age::scrypt::Recipient` with the chosen work factor.
- `sealdrop-argon2id` stanza (section 5).

Passphrase modes (scrypt or Argon2id) cannot be combined with any other recipient.
The core returns `PolicyError::PassphraseMustBeAlone`; the CLI and app state this
before encrypting.

### 4.3 Delivery bundle

```
<name>.sealdrop.age
<name>.manifest.json
<name>.manifest.json.minisig
```

`manifest.json`:

```json
{
  "format": "sealdrop-manifest/1",
  "package_id": "<uuid v4>",
  "tool": "sealdrop 0.2.0",
  "created": "2026-10-13T09:00:00Z",
  "ciphertext": { "file": "<name>.sealdrop.age", "size": 1234, "sha256": "<hex>" },
  "plaintext_tar_sha256": "<hex>",
  "recipients": [ { "kind": "x25519", "fingerprint": "<hex, first 16 of sha256 of recipient string>" } ],
  "signer": "<minisign public key, base64>",
  "classification": "confidential",
  "expires": "2026-12-31",
  "release": { "service": "https://release.example.org", "release_id": "<uuid v4>", "window_secs": 600 },
  "notes": "expires is advisory and is not enforced by any software; release.window_secs is enforced by the named service for the encrypted package only"
}
```

`release` is present only for timed-release packages (section 5.5).

The `.minisig` is a standard minisign signature over the exact bytes of
`manifest.json`, with the trusted comment `sealdrop manifest <package_id>`.
Passphrase-mode manifests list `{ "kind": "scrypt" }` or `{ "kind": "argon2id" }`
and never include the passphrase or its hash.

## 5. Argon2id stanza

Stanza: `-> sealdrop-argon2id <salt-b64> <t> <m_kib> <p>` with a 32-byte wrapped file
key body (ChaCha20-Poly1305 of the 16-byte file key, zero nonce, key derived from
the passphrase). Salt is 16 random bytes. The derived key is `Argon2id(passphrase,
"sealdrop-argon2id" || salt, t, m, p, 32 bytes)`.

Profiles: `desktop` t=1, m=2 GiB, p=4 (RFC 9106 first recommendation);
`compat` t=3, m=256 MiB, p=4 (RFC 9106 second recommendation, browser-friendly).
Decrypt bounds: t ≤ 10, m ≤ 2 GiB, p ≤ 8, otherwise `DecryptError::ExcessiveWork`.

Encrypt labels: the recipient returns the label set `{"sealdrop-argon2id"}` so the
`age` crate refuses to combine it with any other recipient, mirroring scrypt.

The docs state plainly that this mode adds little over scrypt logN 18 and that files
made with it do not open in stock age tools.

### 5.5 Timed release

Goal: the package can be opened only within `window` after the recipient first opens
it; the recipient's clock and timezone cannot affect this; the sender gets proof of
the first unlock. Research: `docs/research/2026-10-13-post-unlock-expiry.md`.

**Mechanism: nested wrap.** At seal, the core generates a random 32-byte `K_release`.
The inner recipients (the recipient's X25519/plugin key, or a generated passphrase
via scrypt/Argon2id) wrap the file key as usual, producing inner stanzas. The inner
stanzas are serialised in age wire format and encrypted with
ChaCha20-Poly1305 under `K_release` (random 12-byte nonce). The age header then
contains exactly one stanza:

```
-> sealdrop-release <release_id> <service-url-b64> <nonce-b64>
<ciphertext of inner stanzas>
```

Opening therefore requires **both** `K_release` from the service **and** the
recipient's own key or passphrase. Timed release must be the only recipient
(label set `{"sealdrop-release"}`); in particular the sender's self-recipient is not
added, because it would bypass the service. Stock age fails on the file with "no
matching keys", as intended.

**Deposit (sender, at seal).** `PUT /v1/releases/{release_id}` with
`{ k_release, window_secs, unlock_token_hash, package_sha256 }`, authenticated by a
deposit token the service operator issues to senders. `unlock_token` is 32 random
bytes placed in the manifest; the service stores only its SHA-256.

**Unlock (recipient, at open).** `POST /v1/releases/{release_id}/unlock` with
`{ unlock_token }`. On the first successful call the service records `first_unlock`
from its own clock and computes `expires_at = first_unlock + window`. While
`now < expires_at` it returns `{ k_release, first_unlock, expires_at }` (re-opening
inside the window is allowed). After `expires_at` it returns `410 Gone`, deletes
`k_release`, and keeps only the receipt metadata. A sweeper also deletes expired keys
every minute. The service never sees the file key or plaintext.

**Receipt (sender).** `GET /v1/releases/{release_id}/receipt` (deposit token) returns
`{ release_id, package_sha256, first_unlock, expires_at, unlock_count, service_key }`
signed with the service's Ed25519 key (minisign format), verifiable offline with
`sealdrop receipt verify`. This replaces any blockchain: the service, not a public
ledger, attests to the unlock time, and the receipt is private to the sender.

**Known limits, stated in the UI and docs.**
- Expiry applies to the encrypted package only; nothing can recall decrypted content.
- Anyone holding the bundle can trigger first unlock (denial of the window), but
  cannot read the file without the recipient's key.
- The service operator can refuse service; they cannot read the file.
- Service availability is required at open time; offline open is impossible.

**Service (`sealdrop-release`).** Single binary. `sealdrop-release keygen` (service
signing key), `sealdrop-release token new <name>` (deposit tokens, stored hashed),
`sealdrop-release serve --listen <addr> --db <path>`. TLS is terminated by a
reverse proxy; the README gives a Caddy example and a Docker image. Per-IP rate
limiting; request and body size caps; no logging of tokens. Retention of receipt rows:
90 days, configurable.

## 6. Core library modules

| Module | Public surface | Notes |
|---|---|---|
| `pack` | `pack(input: &Path, w: impl Write) -> Result<PackReport>` | Streams; `PackReport` has `files`, `total_bytes`, `tar_sha256`, `meta` |
| `extract` | `extract(r: impl Read, out_dir: &Path, limits: Limits) -> Result<ExtractReport>` | Section 7 |
| `crypt` | `encrypt(w, recipients: RecipientSet, armor) -> StreamWriter`, `decrypt(r, identities, max_work_factor) -> StreamReader`, `parse_recipient(&str)`, `parse_identity(&str)` | Wraps `age` |
| `argon2id` | `Recipient`, `Identity`, `Params`, `Profile` | Section 5 |
| `release` | `Recipient { inner, k_release, release_id, service }`, `Identity { inner, fetch: Box<dyn ReleaseFetch> }`, `ReleaseClient` (HTTP, `ureq`), `Receipt` + verify | Section 5.5; `ReleaseFetch` is a trait so tests inject an in-memory service |
| `passphrase` | `generate(WordList, count) -> Passphrase { words, entropy_bits }` | Word lists embedded; sha256 of each list asserted in tests |
| `manifest` | `Manifest`, `build(...)`, `sign(&Manifest, &SecretKey) -> SignatureBox`, `verify(bytes, sig, &PublicKey)` | minisign |
| `policy` | `check_recipients(&RecipientSet, allow_unrecoverable) -> Result<(), PolicyError>`, `plugin_allowed(name) -> bool` | Rules from spec §5.4 and §10, plus: passphrase and timed-release stanzas stand alone in the age header (inner recipients live inside the timed-release wrap) |
| `keys` | `KeyStore::open(dir) `, `generate()`, `identity()`, `recipient_string()`, `signing_key()`, `trusted_signers()` | Files: `identity.txt`, `sign.key`, `sign.pub`, `trusted/<name>.pub` |
| `seal` | `seal(SealRequest) -> SealResult` | Pack → encrypt (tee hash) → manifest → sign |
| `open` | `verify(bundle, signer) -> VerifyReport`, `open(OpenRequest) -> OpenReport` | Verify before decrypt unless `skip_verify` |
| `progress` | `trait Progress { fn on(&self, event: ProgressEvent) }` | CLI prints, app emits Tauri events |

Secrets are `secrecy::SecretString` or zeroizing byte types. No secret implements
`Debug` in a way that prints its contents.

## 7. Hardened extraction

For every tar entry:

1. Entry type must be regular file or directory. Symlinks, hardlinks, character and
   block devices, FIFOs and unknown types are rejected with `ExtractError::ForbiddenEntry`.
2. Path must be relative, must start with `sealdrop/`, must not contain `..`, `.`,
   empty components, NUL, or (on Windows) `\`, `:` or reserved device names.
3. `sealdrop/meta.json` must be the first entry and is parsed with a 1 MiB cap.
4. Running totals: entries ≤ `limits.max_entries` (default 100,000), bytes ≤
   `limits.max_bytes` (default 64 GiB), single file ≤ `limits.max_file_bytes`.
5. Files are written under a temp dir inside `out_dir`, hashed while writing, and
   compared with `meta.json`. Any mismatch aborts and the temp dir is removed.
6. On success the temp dir is renamed to the final name. Existing targets are never
   overwritten unless `overwrite: true`.

## 8. CLI

```
sealdrop keygen [--force]
sealdrop recipient
sealdrop seal <path> [-r <recipient>]... [--passphrase] [--words eff|bip39]
                     [--argon2id] [--kdf-profile default|high]
                     [--armor] [--classification <label>] [--expires <date>]
                     [--allow-unrecoverable] [--no-self] [-o <dir>] [--qr]
                     [--expire-after <N>{s|m|h|d} --release-service <url>]
sealdrop verify <file.sealdrop.age> [--signer <RWQ...>]
sealdrop open   <file.sealdrop.age> [-o <dir>] [--signer <RWQ...>] [--skip-verify] [--overwrite]
sealdrop receipt fetch <file.manifest.json>        # sender: fetch + verify + save <name>.receipt.json
sealdrop receipt verify <file.receipt.json> [--service-key <RWQ...>]
sealdrop trust add <name> <RWQ...> | list | remove <name>

sealdrop-release keygen | token new <name> | serve --listen <addr> --db <path>
```

Timed release:

- `--expire-after` requires `--release-service` (or the configured default) and the
  deposit token from `SEALDROP_RELEASE_TOKEN` or the key store.
- `open` on a timed package prints the service URL and the window before making
  the single network call; it never caches `k_release` on disk.
- `open` prints: "This package expires <window> after first open (service clock).
  Expiry applies to the encrypted package only."

Behaviour:

- `seal` with no `-r` and no `--passphrase` fails with a usage error.
- `seal` always adds the sender's own recipient unless `--no-self` (so the sender can
  reopen), except in passphrase modes and timed release, where it would bypass the
  rule that the stanza stands alone.
- `verify` without `--signer` uses the trusted store; if the signer is unknown it
  exits 2 and prints the signer key for the user to add.
- Passphrases print once to the terminal (or as a QR code with `--qr`) and are never
  written to any file or log.
- Exit codes: 0 success, 1 error, 2 verification failed, 3 policy refused.

## 9. Desktop app

Tauri 2.12 with the `dialog` plugin only; no `shell`, `http`, or `fs` plugin exposed
to the WebView. Strict CSP (`default-src 'self'`). All file access happens in Rust
commands that take paths chosen through native dialogs or drag-and-drop.

Commands (one per core function): `get_identity`, `generate_identity`, `seal`,
`verify`, `open_package`, `list_trusted`, `add_trusted`, `remove_trusted`,
`get_settings`, `set_settings`. Long operations emit `progress` events.

Screens: **Seal**, **Open**, **Verify**, **Keys**, **Settings**. Visual direction:
pastel neumorphic tiles and pills on a warm off-white base, dusty pink / periwinkle
blue / sage accents, rounded sans-serif type, soft dual shadows. A written design
brief in `docs/design/brief.md` governs the UI subagents; it is derived from the two
reference images supplied on 13 Oct 2026 but adapted to sealdrop's content.

Timed release in the app: the **Seal** screen has a "Timed release" toggle with a
number field and unit picker (seconds / minutes / hours / days) and shows the
sentence "The recipient can open this only within [window] after they first open it.
This does not protect the contents once decrypted." **Open** shows a countdown pill
("expires in 9 m 41 s", computed from the service's `expires_at`, never from a
local timer) and, for timed packages, extracts by default to a per-session temporary
folder that is deleted when the app closes, with a "Save to…" alternative. **Keys**
shows receipts for packages the user sent ("opened 13 Oct 09:12 UTC, expired").
**Settings** holds the release service URL and deposit token. The Tauri `http`
capability is scoped to that single URL and nothing else.

The Argon2id option in Settings carries the honesty note from spec §5.3. A
hardware-only recipient set shows the recovery rule and requires a second recipient
or an explicit "I accept this package may become unrecoverable" tick.

## 10. Deferred

SLIP-39 escrow (spec §6), hosted viewer (§8), magic-wormhole and one-time-link
helpers (§7), mail-gateway test matrix, cargo-fuzz in CI, reproducible builds,
external review, domain and trademark check, .NET shell, Roughtime cross-check and
RFC 3161 countersignature of receipts, `age-plugin-sealdrop` binary for stock-age
interop with timed-release files.

Amendment to TECH_SPEC §3 non-goal 1 (to be applied in the README): "No DRM,
screenshot or forwarding prevention. Timed release limits when the *encrypted
package* can be opened; it cannot recall decrypted content."

## 11. Testing

- Unit tests per module, written first (TDD).
- CCTV: every vector in `testkit/` is executed; `expect` values map to core error
  types; the payload hash is checked for all bytes released, including on failure.
- Interop: `tests/interop_age.rs` runs only when `age` is on PATH; CI installs it with
  `go install filippo.io/age/cmd/age@latest`. Asserts: stock age decrypts a
  recipient-mode and a scrypt-mode package; stock age fails on an Argon2id package.
- Extraction: hand-built malicious tars for every rule in section 7.
- Property tests: random directory trees round-trip through pack → extract.
- CLI: `assert_cmd` end-to-end for each command, including tamper detection
  (flip one ciphertext byte → `verify` exits 2) and policy refusal (exit 3).
- Desktop: `cargo tauri build` succeeds; screens exercised in the in-app browser.
- Timed release: core round trip with an in-memory `ReleaseFetch`; service
  integration tests (axum `TestServer`): first unlock sets `first_unlock`; repeat
  unlock inside the window succeeds; unlock after the window returns 410 and the key
  row is gone; wrong token 403; receipt signature verifies and fails on tampering;
  sweeper deletes expired keys; a file sealed with timed release has exactly one
  stanza and stock `age -d` fails on it.

## 12. CI and hygiene

GitHub Actions on push and PR: `cargo fmt --check`, `cargo clippy --all-targets
-D warnings`, `cargo test --workspace`, `cargo deny check licenses`, and a desktop
build on Windows. `.gitignore` excludes build output, dependencies, every key or
identity file pattern, every `.age`/`.minisig` outside `testkit/`, env files and
OS/IDE noise.
