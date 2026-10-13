# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem. Use one of these:

- GitHub: open a private report at <https://github.com/Aldiharley/sealdrop/security/advisories/new> (the repository's security advisories).
- Email: dennisdlvison@gmail.com

Include the version (`sealdrop --version`), your operating system, what you did, what you expected and what happened. A short proof of concept helps. If the problem involves a crafted package, attach it.

You will get an acknowledgement within a few days. This is a small open-source project run by one maintainer, so there is no bug bounty and no guaranteed fix time. Fixes for confirmed issues are released as a new 0.2.x version, and the advisory credits you unless you ask not to be named.

## Supported versions

| Version | Supported |
|---|---|
| 0.2.x | Yes |
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

These are documented and are not vulnerabilities: see [Security in the README](README.md#security) and [docs/VALIDATION.md](docs/VALIDATION.md). They include the 19 skipped post-quantum conformance vectors, the case-insensitive file-system limitation, and the echoing interactive passphrase prompt in 0.2.
