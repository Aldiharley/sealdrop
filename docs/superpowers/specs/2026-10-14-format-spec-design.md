# Design: publishing "sealdrop package format v1" with test vectors

Date: 14 October 2026. Status: approved.

## 1. Why

sealdrop deliberately builds on the age format so recipients are never locked in. Its own
additions (packaging layout, custom stanzas, signed manifest, timed release, receipts) are
today defined only by the reference implementation. Publishing them as a normative
specification with test vectors makes sealdrop the authority on its format, lets other
tools interoperate on sealdrop's terms, and keeps the reference implementation honest
(the vectors run in CI). It never requires defending a new cipher: every cryptographic
primitive stays age's.

## 2. Decisions

| # | Decision | Choice |
|---|---|---|
| 1 | Placement | In this repository: `spec/sealdrop-format-v1.md`, `spec/vectors/`. Can move to its own repo later without text changes. |
| 2 | Scope | Package format AND release-service protocol AND receipts, in one document. |
| 3 | Licence | Spec text and vectors CC0-1.0 (`spec/LICENSE`), like C2SP. Code remains Apache-2.0. |
| 4 | Normative style | RFC 2119 keywords; every rule traceable to the implementation (file and function named in an appendix). |
| 5 | Vectors | Known-answer files generated once by a test-gated generator in `sealdrop-core` with committed deterministic secrets; a conformance test consumes them in CI. |
| 6 | Versioning | Existing identifiers are the version anchors: `sealdrop/1` (container), `sealdrop-manifest/1`, stanza tags `sealdrop-argon2id` / `sealdrop-release`, HTTP `/v1/`. Incompatible change = new identifier; additive JSON fields allowed. |

## 3. Document outline (`spec/sealdrop-format-v1.md`)

1. Scope and goals; interop statement (packages whose header holds only standard age
   stanzas MUST be decryptable by any conforming age v1 implementation).
2. Conventions: base64 standard alphabet without padding; SHA-256 lowercase hex; RFC 3339
   UTC `YYYY-MM-DDTHH:MM:SSZ`; lowercase hyphenated UUID; RFC 2119.
3. Plaintext container: ustar tar (GNU long-name entries permitted); entry order
   (`sealdrop/meta.json` first, directories, then files sorted by name); `meta.json`
   schema; path rules (relative, `/`-separated, prefix `sealdrop/payload/`, first
   component equals `root`, no `.`/`..`/empty components, no NUL `\` `:`, no bytes
   < 0x20 or `< > " | ? *`, no trailing space or dot, no Windows reserved stems
   CON PRN AUX NUL COM1-9 LPT1-9, UTF-8 only); symlinks never packed; every listed
   file present exactly once; `meta.json` ≤ 1 MiB.
4. Encryption: age v1 binary or armored; permitted stanzas; grease note; the two
   sealdrop stanzas defined bit-exactly with encoder profiles and decoder rejection rules
   (Argon2id: salt 16 bytes, domain-separated salt, zero nonce, body 32 bytes, bounds
   t ≤ 10, m ≤ 2 GiB, p ≤ 8, m ≥ 8 and m ≥ 8p; release: four args, random 12-byte nonce,
   inner-stanza JSON, ≤ 64 stanzas, ≤ 64 KiB, service URL and release-id validation
   before any request, no redirects); stand-alone rule for both.
5. Delivery bundle: file names; manifest schema and field semantics; recipient kinds and
   fingerprints; minisign signature with trusted comment `sealdrop manifest <package_id>`;
   the ordered verification algorithm that MUST run before decryption.
6. Extraction requirements for decoders: entry types, meta-first, limits (100 000
   entries, 64 GiB, 1 MiB extension headers, input cap), stream guard (refuse PAX
   `size=`, GNU sparse, global headers), temp directory and rename, per-file hash
   check, duplicate and missing files, overwrite semantics.
7. Release service protocol v1: `PUT /v1/releases/{id}`, `POST .../unlock`,
   `GET .../receipt`, `GET /healthz`; request/response JSON; status codes; validation
   table; window semantics on the service clock (`first_unlock`, `expires_at`, `now`);
   key deletion on expiry; retention of never-opened releases; tokens hashed at rest;
   bearer scheme case-insensitive; rate limiting and proxy header.
8. Receipts: JSON fields including `now`; minisign signature with trusted comment
   `sealdrop receipt <release_id>`; pinned verification algorithm.
9. Security considerations: hash binding closes key-commitment ambiguity; unlock token is
   visible by design (window denial, not confidentiality); limits of timed release;
   Argon2id interop cost; case-insensitive filesystems; what a decoder MUST print or
   refuse when the manifest is absent.
10. Versioning and extension rules.
11. Test vectors: layout, `vector.json` schema, how to run.
Appendix A: mapping of each normative rule to the reference implementation.
Appendix B: differences from plain age (what stock age can and cannot open).

## 4. Test vectors (`spec/vectors/`)

Layout: one directory per vector, containing `vector.json` and the files it names.

`vector.json` fields: `name`, `expect` (`success` | `header failure` | `verify failure`
| `extract failure` | `receipt ok` | `receipt failure`), `stock_age` (`opens` |
`rejects` | `n/a`), `inputs` (`identity`, `passphrase`, `k_release`, `signer_key`,
`service_key` as applicable), `expected` (`plaintext_tar_sha256`, `files[] {path,size,
sha256}`, `package_id`), `files` (`package`, `manifest`, `signature`, `tar`, `receipt`),
`comment`.

Deterministic secrets committed for vectors only: one X25519 identity, the passphrase
`spec vector passphrase`, one 32-byte `K_release` and unlock token, one minisign signer
key pair, one service key pair. They are test material, never used elsewhere.

Vector set: `recipient-x25519`, `armored-x25519`, `passphrase-scrypt`,
`passphrase-argon2id-compat`, `timed-release-x25519`, `timed-release-passphrase`,
`argon2id-reject-t-too-large`, `argon2id-reject-p-too-large` (the decoder bounds that an
encoder can produce cheaply; malformed salts or a bad header MAC cannot be generated
through the encoder), `manifest-tampered`, `manifest-wrong-comment`,
`ciphertext-tampered`, `tar-reject-traversal`, `tar-reject-symlink`,
`tar-reject-pax-size`, `tar-reject-long-name-bomb`, `tar-reject-unlisted-file`,
`receipt-valid`, `receipt-wrong-key`.

Generator: `#[ignore]`d test `regenerate_format_vectors` in `sealdrop-core`
(`cargo test -p sealdrop-core --features test-support -- --ignored regenerate_format_vectors`),
writing into `spec/vectors/`. Consumer: `crates/sealdrop-core/tests/format_vectors.rs`,
run in CI, which also asserts that every vector directory is listed and that `stock_age`
claims hold when the `age` binary is present.

## 5. Out of scope

CLI flags, desktop UI, local key-store layout, deferred features (escrow, hosted viewer).
