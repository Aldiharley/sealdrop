# sealdrop: Technical Specification

*Open-source tool for sending any sensitive file or folder with strong, standard encryption, a signed delivery record, hardware-key unlock and recovery. Apache-2.0. Author: Dennis Liu. Draft: 13 October 2026.*

Research behind this spec: `RESEARCH.md` in this folder.

This is a design specification for review, not an instruction to build.

---

## 1. Summary

sealdrop wraps the audited, widely used **age** encryption format in a friendly desktop app and CLI built for people who send sensitive files: security consultants, legal and finance teams, anyone delivering reports to clients.

It does **not** invent cryptography. The "wallet-grade" goal is met by:

- using random keys (public-key recipients) by default;
- using only generated high-entropy passphrases when a password is unavoidable;
- using the same memory-hard key derivation as an Ethereum wallet keystore.

What sealdrop adds is the missing workflow on top:

- packaging any file or folder;
- a signed delivery manifest;
- hardware-key unlock with enforced recovery;
- k-of-n escrow;
- recipient onboarding;
- safe secret delivery.

## 2. Goals

1. Encrypt **any file type and any size**, plus whole folders, and restore them exactly.
2. Interoperate with standard age tools, so a recipient can always decrypt with `age -d` and extract with any tar tool, even if sealdrop disappears.
3. Default to public-key recipients, so no secret ever has to be sent.
4. Make passphrase mode safe by generating passphrases (no user-chosen passwords).
5. Prove what was delivered: a signed manifest with hashes, so sender and recipient can confirm it is the exact file.
6. Support hardware unlock (YubiKey, FIDO2 security keys, passkeys) without risking permanent loss.
7. Offer optional recovery through a k-of-n split escrow key.

## 3. Non-goals

- No revocation, DRM, screenshot or forwarding prevention, or "self-destruct". File encryption cannot do these. The README says so plainly and points to rights-management systems when those are needed.
- No new ciphers, cascades, custom formats or deniability.
- No crypto wallet code, blockchain or wallet-core.
- No protection against a compromised sender or recipient device.
- No self-decrypting HTML attachments (they match HTML smuggling and cannot use hardware keys).

## 4. Package format

### 4.1 Plaintext packaging (inside the encryption)

age encrypts a byte stream but stores no filename or type. So the plaintext is a **tar (POSIX ustar/pax) stream** containing:

```
sealdrop/
  meta.json          # inner metadata: original names, sizes, SHA-256 per file, created, tool version
  payload/           # the file(s) or folder, unchanged
```

- One file or a whole folder; any type (PDF, HTML, Office, images, archives, databases, source code).
- Streamed: files are never fully loaded into memory, so size is limited only by disk.
- Fallback without sealdrop: `age -d file.sealdrop.age | tar -x`.

### 4.2 Encryption

- **Format:** age v1 exactly ([C2SP spec](https://github.com/C2SP/C2SP/blob/main/age.md)), binary or ASCII-armored.
- **Cipher:** whatever age specifies: ChaCha20-Poly1305 in 64 KiB STREAM chunks with HKDF-SHA-256. Truncation, reordering and tampering of any chunk are detected.
- **Conformance:** must pass the [C2SP CCTV age test vectors](https://github.com/C2SP/CCTV/tree/main/age).

### 4.3 Delivery bundle (outside the encryption)

```
report-2026-10-13.sealdrop.age            # the encrypted package
report-2026-10-13.manifest.json           # signed delivery record (no secrets)
report-2026-10-13.manifest.json.minisig   # minisign signature
```

`manifest.json` holds:

- SHA-256 of the `.age` file and of the plaintext tar;
- package ID, version and created date;
- fingerprints of all recipients, including escrow;
- sender's signing key fingerprint;
- classification label and an **advisory** expiry date, which the README explains is not enforced.

The signature over the ciphertext hash also closes age's key-commitment ambiguity, because there's proof of exactly which encrypted file was sent.

## 5. Key modes

### 5.1 Recipients (default)

- The recipient creates an age key pair, or a hardware-backed identity, and sends only the **public** recipient string.
- Encryption targets the recipient, plus the sender's own key so they can reopen it, plus the optional escrow key (section 6).
- Supports X25519 and the hybrid post-quantum `age1pq` recipients ([age v1.3.0](https://github.com/FiloSottile/age/releases/tag/v1.3.0)).
- The file key is 128 random bits, so offline cracking is infeasible regardless of any KDF.

### 5.2 Passphrase (fallback)

- Uses age's scrypt recipient: logN=18 (256 MiB) by default, with logN=20 as a "high" profile. Decryption refuses anything above logN=22, to block denial-of-service files.
- **Generated passphrases only:**
  - 10 words from the BIP-39 list (about 110 bits), or
  - at least 6 EFF long-list words (about 77.5 bits).
- The entropy is shown on screen.
- age forbids combining a passphrase with other recipients, so passphrase files cannot include an escrow key. The UI must say this before encrypting.

### 5.3 Argon2id (optional, labelled non-standard)

- Shipped as an age **plugin** stanza, so plain age tools reject the file rather than mis-decrypt it.
- Parameters stored in the stanza and bounded on decrypt:
  - desktop: t=1, p=4, m=2 GiB ([RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html));
  - browser-compatible: t=3, p=4, m=256 MiB to 1 GiB.
- Honest note in the docs: this adds little over scrypt logN=18 and costs interoperability. Off by default.

### 5.4 Hardware keys

- **YubiKey PIV** via [age-plugin-yubikey](https://github.com/str4d/age-plugin-yubikey).
- **FIDO2 security keys** via `age-plugin-fido2prf` (interoperates with [typage](https://github.com/FiloSottile/typage) in the browser).
- **Apple Secure Enclave and TPM** via [age-plugin-se](https://github.com/remko/age-plugin-se) and [age-plugin-tpm](https://github.com/Foxboron/age-plugin-tpm).
- **Passkeys** only in the hosted viewer (section 8), on a fixed origin the publisher controls.
- **Rule:** a hardware-only or passkey-only recipient always requires a second recovery recipient, unless the user explicitly ticks "unrecoverable". Users delete passkeys without realising data depends on them ([summary](https://simonwillison.net/2026/Feb/27/passkeys/)).

## 6. Recovery and escrow

- Optional organisation escrow identity: an X25519 key generated on an offline machine, then split into k-of-n shares (for example 2-of-3 or 3-of-5) with [SLIP-39](https://github.com/satoshilabs/slips/blob/master/slip-0039.md).
- Shares are held by different people. Recombination happens only on an air-gapped machine, and each use is logged.
- Escrow is an explicit, visible choice per package. "No recovery" is allowed but must be confirmed.

## 7. Secret delivery

- **Recipient mode:** nothing secret travels. Onboarding is a "send me your public key" flow: the recipient runs `sealdrop keygen`, or uses the hosted page (section 8), and returns only the public recipient string.
- **Passphrase mode:** the passphrase must travel on a different channel from the file. Helpers:
  - a phone-friendly word display and QR code;
  - links to one-time expiring secret services ([Yopass](https://github.com/jhaals/yopass), [Bitwarden Send](https://bitwarden.com/help/about-send/));
  - a live handoff via [magic-wormhole](https://github.com/magic-wormhole/magic-wormhole).
- **Ciphertext delivery:** recommended default is a share link or portal, not an email attachment. The docs include a test matrix for mail gateways (Defender's opt-in quarantine of unscannable password-protected attachments, HTML filters) and file-sharing services.

## 8. Hosted viewer (later phase)

A static web viewer that replaces self-decrypting attachments:

- served from a fixed origin, with a strict Content Security Policy and Subresource Integrity pinning;
- makes no network calls after load, and stores no keys in localStorage or URLs;
- decrypts with typage (scrypt, X25519, passkeys via WebAuthn PRF), or libsodium.js only for the Argon2id plugin;
- renders HTML reports in a sandboxed iframe and PDFs in the browser's viewer;
- passkeys work because the page has a real origin.

## 9. Architecture

| Layer | Choice | Notes |
|---|---|---|
| Core library | Rust, [`age` crate](https://github.com/str4d/rage) 0.12.x + `age-plugin` | Packaging (tar streaming), manifest, signing, policy |
| Supporting crates | `argon2` (RustCrypto) for the plugin; `zeroize`, `secrecy` for secrets in memory; `minisign` or `ed25519-dalek` for signatures; a SLIP-39 implementation for escrow that passes the Trezor reference test vectors | |
| CLI | Rust, `sealdrop` binary | `keygen`, `seal`, `open`, `verify`, `escrow split/combine` |
| Desktop app | Tauri (Rust + web UI) | Windows, macOS, Linux; drag-and-drop; no network by default |
| .NET integration (optional) | Rust core exposed through a C ABI (cbindgen or uniffi) to a WPF/WinUI shell | No mature .NET age implementation exists; do not reimplement age in C# |
| Browser | typage (`age-encryption` on npm) | Hosted viewer only |

## 10. Security requirements

1. Never implement anything below the age format layer.
2. **Tar extraction must be hardened:**
   - reject absolute paths, `..` components, symlinks and hardlinks pointing outside the output folder, and device files;
   - enforce size and file-count limits;
   - verify each file against the SHA-256 in `meta.json` before reporting success.
3. Bound every parser: header size, recipient count, KDF parameters, tar entry counts.
4. Verify the manifest signature, and the `.age` hash against the manifest, **before** decrypting.
5. Keep secrets in zeroizing types. No passphrases or keys in logs, crash reports or the clipboard beyond a short, user-initiated copy.
6. Plugins only from an allow-list of known plugin names (age v1.2.1 fixed a plugin-name execution bug).
7. Fuzz all parsers with cargo-fuzz.
8. Use reproducible builds, with releases signed with minisign.
9. Budget an external review of the glue code (packaging, manifest, plugins, viewer) before 1.0.

## 11. CLI sketch

```
sealdrop keygen                         # create identity, print public recipient
sealdrop seal ./report.pdf -r age1...   # encrypt any file or folder to recipients
sealdrop seal ./findings/ --passphrase  # generate a passphrase, show entropy
sealdrop verify report.sealdrop.age     # check signature and hashes, no decryption
sealdrop open report.sealdrop.age       # verify, decrypt, safely extract
sealdrop escrow split --k 2 --n 3       # create and split an escrow identity
```

## 12. Milestones

1. **0.1:** Rust core and CLI: tar packaging, age encryption to recipients, generated-passphrase mode, signed manifest, verify, hardened extraction, CCTV vectors passing.
2. **0.2:** Tauri desktop app, YubiKey and FIDO2 plugins, enforced recovery recipient.
3. **0.3:** SLIP-39 escrow, recipient onboarding page, delivery helpers, mail-gateway test matrix.
4. **0.4:** hosted viewer with passkeys.
5. **1.0:** external review of glue code, fuzzing in CI, reproducible signed releases.

## 13. Licensing

- Code: Apache-2.0.
- Dependencies: age (BSD-3), rage and the `age` crate (Apache-2.0/MIT), typage (BSD-3), libsodium (ISC), minisign (ISC). All compatible.
- Do not copy code from Picocrypt or Kryptor (GPL-3.0).

## 14. Open decisions

1. **Name: decided, "sealdrop" (13 Oct 2026).** Free on crates.io and npm at the time of checking; still to do: domain and trademark check before publishing.
2. **Whether to ship the Argon2id plugin at all,** given that it adds little and costs interoperability.
3. **Desktop shell:** Tauri (consistent with Belay) or a native .NET shell for Windows-first users.
4. **Which SLIP-39 implementation,** or port the Trezor reference with its test vectors.
5. **Whether the hosted viewer is in scope for 1.0.**
