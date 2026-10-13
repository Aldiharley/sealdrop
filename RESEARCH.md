# Research: "wallet-grade" encryption for sensitive files

Research date: 13 October 2026. GitHub data pulled with `gh` on that date. Numbers marked as estimates are arithmetic on public benchmarks, not measurements.

## Bottom line

1. **A wallet keystore is not stronger than a well-built password-encrypted file.** The Ethereum keystore v3 test vector uses scrypt N=2^18, r=8, p=1 ([ethereum.org](https://ethereum.org/en/developers/docs/data-structures-and-encoding/web3-secret-storage/)). `age -p` uses the same scrypt cost by default ([age scrypt.go](https://github.com/FiloSottile/age/blob/main/scrypt.go)). Trust Wallet wallet-core defaults to a weaker setting (N=2^14, about 16 MiB) ([ScryptParameters.h](https://github.com/trustwallet/wallet-core/blob/master/src/Keystore/ScryptParameters.h), [StoredKey.cpp](https://github.com/trustwallet/wallet-core/blob/master/src/Keystore/StoredKey.cpp)).
2. **Wallet security comes from key entropy, not the KDF.** A BIP-39 seed is 128 to 256 random bits and goes through only 2,048 PBKDF2 iterations ([BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)).
3. **Do not fork wallet-core and do not invent a format.** Build on the age v1 format ([C2SP spec](https://github.com/C2SP/C2SP/blob/main/age.md)) with existing implementations.
4. **Self-decrypting HTML is a poor fit for emailed sensitive files.** It matches HTML smuggling (MITRE [T1027.006](https://attack.mitre.org/techniques/T1027/006/)), and passkeys cannot work from a file opened from disk ([WebAuthn L3](https://www.w3.org/TR/webauthn-3/)).

## Entropy versus KDF cost (estimates)

Scaled linearly from public hashcat benchmarks on an RTX 4090 ([gist](https://gist.github.com/Chick3nman/32e662a5bb63bc4f51b847bb422222fd)). Rough estimates only.

| KDF setting | Est. guesses/s per RTX 4090 | 8 random lowercase letters (~2^37.6) | 6 EFF Diceware words (~2^77.5) |
|---|---|---|---|
| wallet-core default (N=2^14, p=4) | ~1,800 | ~3.7 years | effectively infinite |
| age default / ETH standard (N=2^18) | ~445 | ~15 years (about 54 days on 100 GPUs) | ~16 million years on one million GPUs |
| StatiCrypt (600k PBKDF2-SHA256) | ~14,800 | ~164 days | ~470,000 years on one million GPUs |
| 7-Zip default (2^19 SHA-256 rounds) | ~84,000 | ~29 days | far out of reach |

Weakest to strongest KDF changes cost by roughly 100 to 200 times. Human password to six random words changes it by about 2^40. **Entropy is the lever.**

## Best-practice references

- Argon2id: [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html) (t=1, p=4, m=2 GiB; or t=3, p=4, m=64 MiB when memory-constrained).
- OWASP minimums (server login hashing, not files): [Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).
- libsodium presets: [docs](https://doc.libsodium.org/password_hashing/default_phf).
- Streaming AEAD (STREAM): [ePrint 2015/189](https://eprint.iacr.org/2015/189); libsodium secretstream: [docs](https://doc.libsodium.org/secret-key_cryptography/secretstream).
- Key commitment / partitioning oracles: [Len et al., USENIX Sec 2021](https://usenix.org/conference/usenixsecurity21/presentation/len); invisible salamanders: [Dodis et al.](https://eprint.iacr.org/2019/016); age-specific note: [Stäuble 2022](https://ethz.ch/content/dam/ethz/special-interest/infk/inst-infsec/appliedcrypto/education/theses/semester-project_mirco-stauble.pdf).
- age authentication properties: [Filippo Valsorda](https://words.filippo.io/dispatches/age-authentication/).
- Passphrase entropy: [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b/passwords/), [EFF dice](https://www.eff.org/dice).
- Crypto "right answers": [Latacora](https://www.latacora.com/blog/cryptographic-right-answers/); on PGP: [Latacora](https://www.latacora.com/blog/2019/07/16/the-pgp-problem/).

## Existing tools

| Tool | Stars / licence / last push | KDF | Cipher / format | Key options | Audit found |
|---|---|---|---|---|---|
| [age](https://github.com/FiloSottile/age) (Go) | 23,897 / BSD-3 / 2026-08-29 | scrypt logN 18, max 22 on decrypt | ChaCha20-Poly1305 STREAM | X25519, ML-KEM-768+X25519 hybrid, SSH, plugins | None found |
| [rage](https://github.com/str4d/rage) (Rust) | 3,682 / Apache-2.0 / 2026-08-20 | same as age | age format | same + plugins | None found |
| [typage](https://github.com/FiloSottile/typage) (TS) | 488 / BSD-3 / 2026-08-28 | scrypt | age format | passkeys/FIDO2 via WebAuthn PRF | None found |
| [age-plugin-yubikey](https://github.com/str4d/age-plugin-yubikey) | 990 / Apache-2.0 | n/a | plugin | YubiKey PIV | None found |
| [age-plugin-fido2-hmac](https://github.com/olastor/age-plugin-fido2-hmac) | 111 / MIT | n/a | plugin | FIDO2 hmac-secret | experimental |
| [age-plugin-sss](https://github.com/olastor/age-plugin-sss) | 60 / MIT | n/a | plugin | Shamir split | experimental |
| GnuPG `-c` | GPL-3.0 | iterated S2K, not memory-hard | AES-256 | passphrase, PGP keys | not checked |
| 7-Zip | no licence detected (mirror) | iterated SHA-256, 2^19 | AES-256-CBC, CRC only (no MAC) | passphrase | None found |
| [Picocrypt](https://github.com/Picocrypt/Picocrypt) | 1,550 / GPL-3.0 / archived 2025 | Argon2id 1 GiB | XChaCha20 + BLAKE2b | passphrase, keyfiles | Radically Open Security 2024 ([report](https://github.com/Picocrypt/storage/blob/main/Picocrypt.Audit.Report.pdf)) |
| [hat.sh](https://github.com/sh-dv/hat.sh) | 2,288 / MIT / 2024-07-17 | Argon2id 64 MiB | libsodium secretstream | passphrase, X25519 | None found |
| [Cryptomator](https://github.com/cryptomator/cryptomator) | 16,299 / GPL-3.0 | scrypt | vault format | passphrase | Cure53 2017 (libraries) |
| [StatiCrypt](https://github.com/robinmoisson/staticrypt) | 8,052 / MIT | PBKDF2 chain (~600k) | AES-256-CBC + HMAC, same key | passphrase | None; author not a cryptographer |
| [Kryptor](https://github.com/samuel-lucas6/Kryptor) (C#) | 505 / GPL-3.0 / 2025-01-12 | not verified | own format | passphrase, keys | None found |
| [minisign](https://github.com/jedisct1/minisign) | 2,853 / ISC | n/a | Ed25519 signatures | | |
| [libsodium](https://github.com/jedisct1/libsodium) | 13,988 / ISC | Argon2id, scrypt | XChaCha20-Poly1305, secretstream | X25519 | Matthew Green 2017 |
| [wallet-core](https://github.com/trustwallet/wallet-core) | 3,569 / Apache-2.0 | scrypt, default 16 MiB | AES-CTR + Keccak MAC | password | not checked; not a file tool |

RustCrypto `chacha20poly1305` had an NCC Group review with no significant findings ([README](https://github.com/RustCrypto/AEADs/tree/master/chacha20poly1305)). Existing age GUIs: [awesome-age](https://github.com/FiloSottile/awesome-age) (web demos, a Windows context-menu tool); none combines hardware unlock, recovery, signing and a delivery workflow.

## Self-decrypting HTML

- StatiCrypt design and weaknesses: [cryptoEngine.js](https://github.com/robinmoisson/staticrypt/blob/main/lib/cryptoEngine.js), [codec.js](https://github.com/robinmoisson/staticrypt/blob/main/lib/codec.js): PBKDF2 (not memory-hard), same key for AES and HMAC, "remember me" stores the key in localStorage, share links put the key in the URL fragment.
- WebCrypto has no Argon2 or scrypt ([MDN](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/deriveKey)); a WICG proposal is unofficial ([WICG](https://wicg.github.io/webcrypto-modern-algos/)).
- HTML smuggling: [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2021/11/11/html-smuggling-surges-highly-evasive-loader-technique-increasingly-used-in-banking-malware-targeted-attacks/), [Defender anti-malware](https://learn.microsoft.com/en-us/defender-office-365/anti-malware-protection-about), [Safe Attachments](https://learn.microsoft.com/en-us/defender-office-365/safe-attachments-about) (opt-in quarantine of password-protected attachments it cannot scan).

## Secret delivery, hardware keys, recovery, time-lock

- Public-key recipients avoid sending any secret; hybrid post-quantum since [age v1.3.0](https://github.com/FiloSottile/age/releases/tag/v1.3.0).
- One-time secret links: [Yopass](https://github.com/jhaals/yopass), [PrivateBin](https://github.com/PrivateBin/PrivateBin), [Bitwarden Send](https://bitwarden.com/help/about-send/); live handoff: [magic-wormhole](https://github.com/magic-wormhole/magic-wormhole).
- Hardware: [age-plugin-yubikey](https://github.com/str4d/age-plugin-yubikey), [age-plugin-se](https://github.com/remko/age-plugin-se), [age-plugin-tpm](https://github.com/Foxboron/age-plugin-tpm), typage fido2prf.
- Warning against passkey-only encryption: [Simon Willison summary](https://simonwillison.net/2026/Feb/27/passkeys/).
- Split secrets: [SLIP-39](https://github.com/satoshilabs/slips/blob/master/slip-0039.md), [python-shamir-mnemonic](https://github.com/trezor/python-shamir-mnemonic).
- Time-lock: [tlock](https://github.com/drand/tlock) gives "not before" only; true expiry is impossible once someone holds key and ciphertext.

## Threat-model limits

File encryption cannot revoke access after decryption, stop forwarding of plaintext, or prevent screenshots. Even rights management depends on apps honouring rights ([Purview usage rights](https://learn.microsoft.com/en-us/purview/rights-management-usage-rights)).

## Unverified

- Whether Defender's quarantine setting treats `.age` files as password-protected.
- WebAuthn PRF support on Firefox and Windows Hello (sources conflict).
- Absence of public audits for age, rage, typage (none found, which does not prove none exist).
- GPU guess rates are linear scaling, not measurements.
