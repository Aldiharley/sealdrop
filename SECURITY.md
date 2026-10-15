# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem. Use one of these:

- GitHub: open a private report at <https://github.com/Aldiharley/sealdrop/security/advisories/new> (the repository's security advisories).
- Email: dennisdlvison@gmail.com

Include the version (`sealdrop --version`), your operating system, what you did, what you expected and what happened. A short proof of concept helps. If the problem involves a crafted package, attach it.

You will get an acknowledgement within a few days. This is a small open-source project run by one maintainer, so there is no bug bounty and no guaranteed fix time. Fixes for confirmed issues are released as a new 0.3.x version, and the advisory credits you unless you ask not to be named.

## Supported versions

| Version | Supported |
|---|---|
| 0.3.x | Yes |
| 0.2.x | 0.2.2 supported until the 0.3.0 release ships |
| Earlier | No |

## Scope

In scope:

- `sealdrop-core` (packing, encryption, manifest and signature handling, hardened extraction, key store, policy rules)
- the `sealdrop` CLI
- the `sealdrop-release` key-release service
- the Tauri desktop app

Examples: an archive that escapes the output folder or overwrites a file; a package that passes `verify` but was altered; a way to read a timed-release package after its window without the service's key; a secret (passphrase, key, token) written to disk or a log; the service handing out a key outside the window.

Out of scope:

- Bugs in age itself (report those to [age](https://github.com/FiloSottile/age) or [rage](https://github.com/str4d/rage)), unless sealdrop uses it in a way that creates the problem.
- Anything a recipient can do with the contents after decrypting them: copying, screenshots, forwarding, photographs. sealdrop does not claim to prevent these. See "What it does not do" in the [README](README.md#what-it-does-not-do).
- A compromised sender or recipient device.
- A malicious or misconfigured release service operator refusing service. (An operator reading the file is in scope, since the service is designed never to see the file key.)
- Third-party age plugins (`age-plugin-yubikey` and others) and hardware.
- Self-hosting mistakes, such as exposing the service without TLS or without NTP.

## Known limitations

These are documented and are not vulnerabilities: see [Security in the README](README.md#security) and [docs/VALIDATION.md](docs/VALIDATION.md).

- **Security level.** The security level is at most 128 bits against key search, because age's file key is 16 bytes. A package sealed to recipients reaches it (128-bit security level, 256-bit keys), the same level as TLS 1.3, Signal and WireGuard. A passphrase package is bounded by the passphrase's entropy plus the key-derivation cost instead (see [Passphrase mode](README.md#passphrase-mode) and the spec's §9 Argon2id bullet): six EFF words give about 77.5 bits, plus about 2^18 scrypt work per guess. The symmetric layer is not what a quantum computer would break: Grover's quadratic speed-up leaves a 128-bit level at roughly 2^64 quantum operations, performed serially under depth limits that NIST and ANSSI consider out of reach, so no symmetric change is needed. The quantum exposure is the classical key wrap (X25519 and the plugin recipients).
- **Post-quantum recipients.** For data that must stay confidential beyond about 2035, seal to post-quantum recipients (`keygen --pq`, `age1pq1…`, ML-KEM-768 + X25519). A package sealed to a classical recipient can be recorded now and opened later if X25519 is broken. Post-quantum and classical recipients cannot be mixed in one package, so a classical recipient never weakens a post-quantum package. `age1tagpq1…` remains encrypt-only.
- **Key commitment.** From 0.3.0 the signed manifest commits to the package's file key (`key_commitment`), and, when the manifest is verified, `open` checks it before any plaintext is written. Packages made by 0.2.x and earlier have no commitment and still open; for them the manifest is not bound to the file key.
- **No external audit.** sealdrop has not been audited. Its ML-KEM-768 + X25519 code is checked against the C2SP CCTV age vectors (147 of 147) and against Go age 1.3.2 in both directions, which is conformance evidence, not a review.
- **Roadmap.** A hybrid Ed25519 + ML-DSA-65 manifest signature (`sealdrop-manifest/2`) and a payload v2 format are reserved in the format spec and not implemented; today's manifest signature is Ed25519 only, so a future quantum computer could forge a signature on a new manifest. A signature forgery alone would not decrypt a package; decryption exposure is the classical key wrap described above. The reasoning and sources are in [docs/research/2026-10-15-beyond-chacha20-poly1305.md](docs/research/2026-10-15-beyond-chacha20-poly1305.md).
- Timed release needs the service to be up at open time, and trusts the service host's clock.
