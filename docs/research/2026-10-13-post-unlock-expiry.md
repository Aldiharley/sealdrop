# Research: post-unlock expiry ("countdown after first unlock")

Research date: 13 October 2026. Author: Security Engineer (research draft for Dennis Liu). Status: for review, not an instruction to build. Companion to `TECH_SPEC.md` and `RESEARCH.md`.

**Requested feature:** the sender sets a window (seconds to days); the countdown starts at the recipient's first unlock; after it expires the file is "shredded"; the countdown must survive clock and timezone tampering on the recipient's machine; and the owner asks whether blockchain is needed to prove first use, and how to stop a recipient copying the file before logging in.

## 1. Bottom line

- **"Not after" is enforceable only for the encrypted package, never for the plaintext.** Once a recipient has decrypted, nothing stops copying, screenshots, photos or forwarding. Even Microsoft's rights-management stack says its usage rights are "interpreted by applications" and that "applications may vary in how they implement usage rights" ([Purview usage rights](https://learn.microsoft.com/en-us/purview/rights-management-usage-rights)); the "Copy" right there explicitly governs screen captures, so it is an app-level courtesy, not a cryptographic property. The spec's non-goal (section 3: no DRM, no self-destruct) is correct and should stay.
- **Local "shredding" is best-effort.** NIST SP 800-88r1 states that flash devices "may contain spare cells and perform wear levelling, making it infeasible for a user to sanitize all previous data" by overwriting ([NIST SP 800-88r1](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-88r1.pdf), section 2.4). Wei et al. found that "none of the existing hard drive-oriented techniques for individual file sanitization are effective on SSDs" ([FAST '11](https://www.usenix.org/legacy/events/fast11/tech/full_papers/Wei.pdf)). Add OS snapshots, cloud sync and backups, and "shred" means "delete and hope".
- **A purely local timer is always defeatable.** If the recipient's machine ever holds both ciphertext and file key, they can copy both before the deadline, run the app in a VM and restore a snapshot, or patch the open-source binary. No clock trick fixes this; it is a key-custody problem.
- **The only robust "not after" is: the key never lives on the recipient's machine.** Hold the file key (or an unwrap capability) on a service that releases it once, records first-unlock time on *its* clock, and refuses after the window. This is how Yopass, Bitwarden Send, PrivateBin and Proton Drive expiring links work. The recipient's system clock becomes irrelevant.
- **Blockchain is not needed and does not help with the secret.** A public chain cannot hold a key. For "proof of first unlock", a signed receipt from the release service (optionally anchored in a transparency log) is cheaper, private and sufficient.

## 2. Mechanisms that work, ranked

### 2a. Online one-time / time-windowed key release (recommended)

**How it works.** The age file key is wrapped to a key held by a *release service*. At first unlock the recipient's app authenticates, the service unwraps once, stamps `first_unlock = now()` on its own clock, and from then on answers only until `first_unlock + window`, then deletes the wrapped key. The app keeps the file key in zeroizing memory only.

**Prior art (all do one-time or absolute expiry; none does "window after first open"):**

| Tool | Model | Expiry controls | Licence |
|---|---|---|---|
| [Yopass](https://github.com/jhaals/yopass) | browser encrypts; key in URL fragment ("URL fragments are not sent to the server"); server stores ciphertext in Redis/Memcached | "A one-time secret is removed after its first retrieval"; automatic expiration with custom durations | Apache-2.0 (some features need a business licence) |
| [PrivateBin](https://github.com/PrivateBin/PrivateBin) | zero-knowledge; "the key used to encrypt the paste is part of the URL" | expiration times incl. "burn after reading"; README warns "who accessed a paste (first) might still be disclosed via access logs" | see repo LICENSE.md |
| [Bitwarden Send](https://bitwarden.com/help/send-lifespan/) | end-to-end encrypted; link "doesn't contain any data related to its contents" | deletion date up to 31 days ("purged from Bitwarden systems"), optional expiration date, maximum access count | proprietary service, open-source clients |
| [Proton Drive links](https://proton.me/support/password-protect-files-proton-drive) | "links are generated locally in your browser, so Proton never has access to your files" | password; "enable Set expiration date and choose a desired date" | proprietary |
| [OnionShare](https://docs.onionshare.org/2.6/en/advanced.html) | sender's own machine serves over a Tor onion service | stops after download; scheduled auto-start ("dead man's switch") and auto-stop | GPL-3.0 |

**Why ciphertext copied before unlock is harmless.** The `.age` file contains only a wrapped key the recipient cannot unwrap; copies of it are inert. A copied ciphertext plus a copied passphrase still needs the service to say yes, once, inside the window.

**Why the recipient's clock does not matter.** The window is enforced where the key lives. The recipient can set their clock to 1970; the service never asks it.

**Protects against:** reading after the window; reading twice from different machines; recipient clock tampering; the sender not knowing whether the file was opened.
**Does not protect against:** copying or screenshotting plaintext inside the window; dumping the file key from the open-source app's memory (pointless, since they can just save the plaintext); a compromised or dishonest release service.
**Trust assumptions:** the service operator (sees first-unlock time and recipient fingerprint, never plaintext, see section 5); availability (no service, no unlock).
**Cost:** one small HTTP service plus a database row per package. Small self-hosted; medium if sealdrop runs a public instance (abuse, uptime, GDPR).

### 2b. Threshold / conditional decryption networks

- **TACo (Threshold Network / NuCypher).** Nodes "individually verify the requestor's fulfillment of pre-specified conditions" and each provides a decryption fragment; the docs give "if I do not check-in over the next 7 days" as a time example ([docs.taco.build](https://docs.taco.build/)). Older docs described a `TimeCondition` on a target chain's latest block timestamp (page now 404, unverified). Reality check: the client SDK `@nucypher/taco` is **GPL-3.0** and its repo states "The NuCypher organization is no longer active and will not continue development or maintenance of this code base" ([taco-web](https://github.com/nucypher/taco-web)); the service is in hand-over to the World Ethical Data Foundation with "a stable service planned for relaunch in Q3 2026". For an Apache-2.0 desktop tool, both are blockers.
- **Lit Protocol.** A TEE-based "programmable runtime": "Keys never leave the enclave, and the code that's allowed to use them is governed on-chain"; billing is "credit-based, with requests metered" in LITKEY tokens ([developer docs](https://developer.litprotocol.com/)). No built-in "expire after" condition was found; you would write one in a JavaScript Lit Action. Per-request prices: unverified (pricing page 404). Recipients of a consulting report should not need a crypto token to open it.
- **Shutter Network.** "A threshold encryption based frontrunning protection system for Ethereum smart contracts"; keypers release keys per batch of blocks ([shutter repo](https://github.com/shutter-network/shutter), MIT). An encrypted-mempool tool, not a file time-lock.

**Verdict:** decentralised trust at the price of token economics, operator trust and immature or licence-incompatible SDKs, solving a problem sealdrop's users do not have (distrust of a release service the *sender* chose). The spec's non-goal "no blockchain or wallet-core" stands.

### 2c. Time-lock encryption (drand / tlock)

[tlock](https://github.com/drand/tlock) (Apache-2.0/MIT, reviewed by Kudelski) encrypts to a future drand round on the 3-second "quicknet" chain; decrypting earlier fails with "too early to decrypt". The README's guarantee is explicitly one-directional: "you are guaranteed that your timelocked data cannot be decrypted earlier than what you intended." Nothing in tlock makes data inaccessible *after* a time; once the round's signature is published it is public forever. tlock also only "timelock-encrypts a random symmetric key" and recommends layering age on top, so it composes cleanly with sealdrop if a "not before" (embargo) feature is ever wanted. A "not after" cannot be approximated by tlock alone; combined with 2a the service could additionally refuse to release before a tlock round, giving an embargo-plus-expiry window. Low cost, no new trust beyond the League of Entropy threshold.

### 2d. Hardware-backed local enforcement (TPM / Secure Enclave)

A TPM 2.0 can seal a key to a policy that compares against its own `Clock`, `Time`, `resetCount` and `restartCount` ([tpm2_policycountertimer](https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_policycountertimer.1/)); the man page's example seals an object "only for first minute of TPM restart". The TPM's `Clock` can be advanced but the reference implementation of `TPM2_ClockSet` rejects a `newTime` below the current clock with `TPM_RC_VALUE` ([ClockSet.c, TCG Part 3 reference code](https://android.googlesource.com/platform/external/tpm2/+/refs/heads/main/ClockSet.c)); NV counter indexes are monotonic. So in principle: seal the file key to `Clock <= first_unlock_clock + window`.

Caveats that make this unsuitable as the primary control:
- TPM `Clock` counts TPM uptime, not wall time; it is not a trusted calendar.
- A VM's vTPM is state the VM owner controls; snapshot and restore rewinds it.
- The plaintext is decrypted outside the TPM anyway; the TPM only guards the key.
- Apple's Secure Enclave documents anti-replay attempt counters but no trusted clock ([Apple Platform Security](https://support.apple.com/guide/security/secure-enclave-sec59b0b31ff/web)); there is no deadline primitive.
- [age-plugin-tpm](https://github.com/Foxboron/age-plugin-tpm) and [age-plugin-se](https://github.com/remko/age-plugin-se) exist as *recipients*; neither exposes time policies.

**Verdict:** defence in depth on managed corporate fleets; not a promise sealdrop can make to arbitrary recipients.

### 2e. Trusted time sources

- **Roughtime** returns a signed midpoint and radius bound to the client's nonce; Cloudflare runs a public server at `roughtime.cloudflare.com:2002` and chaining responses from several servers gives "signed evidence of the discrepancy" if one lies ([Roughtime protocol](https://roughtime.googlesource.com/roughtime/+/HEAD/PROTOCOL.md), [Cloudflare blog](https://blog.cloudflare.com/roughtime/)). Accuracy target is coarse ("within 10 seconds of real time").
- **RFC 3161** timestamp tokens prove "that a datum existed before a particular time"; the TSA "MUST NOT include any identification of the requesting entity" ([RFC 3161](https://www.rfc-editor.org/rfc/rfc3161.html)). Useful for receipts, not for enforcement.
- **NTS (RFC 8915)** authenticates the NTP server but "cryptographic means do not provide a feasible way to mitigate" delay attacks and users "are not fully protected against DoS attacks by on-path adversaries" ([RFC 8915](https://www.rfc-editor.org/rfc/rfc8915.html)).
- **drand rounds** can serve as a coarse public clock (round number maps to time) with signatures anyone can verify.

All of these let a *local* app detect clock tampering only while online. An offline attacker simply blocks the query; the app must then either refuse to open (which is just 2a with extra steps) or fall back to the local clock (which is no enforcement). Use them for the *server's* clock sanity and for receipts, not as the enforcement point.

## 3. Blockchain: the direct answer

**What a chain cannot do.** Everything written to a public chain is public. It cannot hold the file key, the passphrase, or anything secret. Smart contracts cannot keep a secret either; that is exactly why TACo and Lit exist as separate off-chain networks.

**What a chain can do here.** Two things: (1) act as a tamper-evident public log that "a key for package X was released at time T", and (2) supply a time source via block timestamps (which is what TACo's `TimeCondition` reads). Both are "proof of first unlock", not enforcement.

**The cheaper equivalent.** A signed receipt from the release service (`package_id`, `first_unlock_time`, `recipient_fingerprint`, service signature) gives the sender the same evidence, privately. If non-repudiation against the *service* is wanted, append the receipt hash to a transparency log such as Sigstore's Rekor, "an immutable, tamper-resistant ledger" that "can also be run on its own" and where "auditors can monitor the log for consistency, meaning that the log remains append-only" ([Rekor](https://docs.sigstore.dev/logging/overview/)), or countersign it with an RFC 3161 TSA.

**Recommendation:** no blockchain. It adds a token, a wallet, gas fees, public metadata about who opened what and when, and an unfamiliar trust model, in exchange for a property (public auditability of an unlock event) that neither senders nor recipients of consulting reports have asked for. The spec's non-goal stays.

## 4. "Copy before login": the direct answer

Two different events get conflated:

1. **Copying the ciphertext before first unlock.** With today's sealdrop (key on the recipient side: passphrase or private key) this is a real bypass: copy `.age` plus passphrase, open the copy whenever. With a timed-release recipient (section 5) it is harmless: the copy contains a wrapped key only the service can unwrap, and the service releases once, within its window. There is nothing to "prevent"; the copy is inert.
2. **Copying after decryption.** Unpreventable. The plaintext is in a file, in RAM, on screen. Save As, screenshot, phone camera, `cp`. Rights-management suites try and still rely on applications honouring rights (section 1). sealdrop must not claim otherwise.

**What sealdrop can promise:** "The encrypted package can be opened only during the window; copies of the package are useless after it; the sender receives a signed record of when it was first opened." **What it cannot promise:** anything about the plaintext after decryption.

## 5. Recommended design: a "timed release" recipient

Fits the existing architecture: age v1 format, signed manifest, Rust core, Tauri app, plugin stanzas. Keeps every current non-goal.

**Package format.** A new recipient type as an age plugin stanza: recipients `age1sealdrop1...` (Bech32 HRP `age1name`), the plugin emits a `recipient-stanza` with "a correctly-wrapped file key", and "age clients are required to ignore stanzas that they do not understand" ([C2SP age-plugin](https://github.com/C2SP/C2SP/blob/main/age-plugin.md)). The `age` crate's `Recipient` ("can wrap an opaque file key to a recipient stanza") and `Identity` traits ([docs.rs/age](https://docs.rs/age/latest/age/)) let the Rust core implement it natively; an `age-plugin-sealdrop` binary keeps `rage`/`age` CLI interop. Plain `age -d` correctly fails on such a file, which is the point.

**Double wrap, so the service never sees the file key.** At seal: generate random `K_release`; wrap the age file key with it, and encrypt that stanza to the recipient's normal age key or generated passphrase. Deposit `K_release` on the service under `package_id` with `window` and `recipient_fingerprint`. At open: the recipient unlocks locally with their key/passphrase, the app requests `K_release` (one-time token from the manifest, optional recipient signature), the service returns it once, records `first_unlock` on its own clock (sanity-checked against Roughtime), refuses after `first_unlock + window`, then deletes the row. The service learns package ID, time and recipient fingerprint; never the file key or plaintext.

**Recipient app behaviour.** `K_release` and the file key live only in `zeroize`d memory. Plaintext goes to a per-session temp directory and is best-effort removed on close (the docs label the overwrite pass cosmetic, citing NIST above). The manifest records `window` and `release_service` so `sealdrop verify` shows them before any network call. No daemon, no local timer: the service is the only enforcement point.

**Release service options.**
1. **Self-hostable single binary in the repo (recommended).** Rust (`axum` + SQLite), Apache-2.0, Docker image. `PUT /v1/release` (sealer deposits `K_release` + policy), `POST /v1/release/{id}/unlock` (returns `K_release` once, inside window), `GET /v1/release/{id}/receipt`. Rows deleted on expiry; no plaintext ever present; rate-limited; TLS required. The sender's organisation runs it, matching the spec's escrow model.
2. **Sender's own machine, magic-wormhole-style.** No server, but "both clients must be left running until the transfer has finished" ([magic-wormhole](https://magic-wormhole.readthedocs.io/en/latest/welcome.html)): the sender must be online at first unlock and cannot enforce a multi-day window after it. A "release now, in person" mode only.
3. **Yopass as a stopgap.** Post `K_release` with one-time retrieval and an absolute TTL. Gives single release and "not after absolute time", but *not* "window after first open", and a third party becomes the enforcement point. Acceptable for 0.x with the limitation stated in the UI.

**Unlock receipt (replaces blockchain).** `{package_id, first_unlock, recipient_fingerprint, window}` signed with the service's Ed25519 key (`minisign`/`ed25519-dalek`, already in the stack), verified and stored by the sender's app beside the manifest. Optional later: RFC 3161 countersignature or a hash in self-hosted Rekor.

**UI copy (must not overstate).** On seal: "Timed release: the recipient can open this package only within [window] after they first open it. After that the package is permanently unopenable, and you receive a signed record of when it was opened. This does not protect the contents once decrypted: the recipient can save, copy or photograph them during the window." On open: "This package expires [window] after first open. Expiry applies to the encrypted package only; nothing can recall a file after it has been decrypted." Keep this distinct from the *advisory* expiry date in spec section 4.3.

**Implementation cost.**

| Component | Size | Notes |
|---|---|---|
| Plugin stanza + `Recipient`/`Identity` impl in Rust core | Small | reuse `age` crate traits; CCTV vectors still pass for other stanzas |
| `age-plugin-sealdrop` binary for CLI interop | Small | thin wrapper over the core |
| Release service (Rust, SQLite, TLS, rate limiting, Roughtime check) | Medium | the real work: auth tokens, deletion, abuse, ops docs, threat model |
| Receipt signing and verification | Small | existing signing code |
| Tauri UI: seal options, open flow, temp-file handling, honest copy | Medium | network call is a new trust boundary; must be opt-in and visible |
| Docs, test matrix (offline open, replay, clock skew, double unlock) | Small-Medium | security tests first, per spec section 10 |

**Spec changes.** Add "timed release" as section 5.5 (opt-in; release service URL in the manifest), add the service to the architecture table and the 10.9 review scope, and amend non-goal 1 to: "No DRM, screenshot or forwarding prevention. Timed release limits when the *encrypted package* can be opened; it cannot recall decrypted content."

## 6. Sources

- Microsoft Purview usage rights: https://learn.microsoft.com/en-us/purview/rights-management-usage-rights
- NIST SP 800-88 Rev. 1 (section 2.4 quote on flash/wear levelling): https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-88r1.pdf
- Wei et al., "Reliably Erasing Data From Flash-Based Solid State Drives", FAST '11: https://www.usenix.org/legacy/events/fast11/tech/full_papers/Wei.pdf
- Yopass: https://github.com/jhaals/yopass
- PrivateBin: https://github.com/PrivateBin/PrivateBin
- Bitwarden Send (about): https://bitwarden.com/help/about-send/ and lifespan: https://bitwarden.com/help/send-lifespan/
- Proton Drive password/expiry links: https://proton.me/support/password-protect-files-proton-drive
- OnionShare features and advanced (scheduled start/stop): https://docs.onionshare.org/2.6/en/features.html, https://docs.onionshare.org/2.6/en/advanced.html
- TACo docs: https://docs.taco.build/ ; taco-web SDK (GPL-3.0, org inactive): https://github.com/nucypher/taco-web ; TimeCondition page (404 at time of writing, unverified): https://docs.threshold.network/app-development/threshold-access-control-tac/conditions/timecondition
- Lit Protocol developer docs: https://developer.litprotocol.com/
- Shutter Network: https://github.com/shutter-network/shutter
- tlock (drand time-lock): https://github.com/drand/tlock ; drand overview: https://drand.love/docs/overview/
- tpm2_policycountertimer: https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_policycountertimer.1/ ; TPM2_ClockSet reference code: https://android.googlesource.com/platform/external/tpm2/+/refs/heads/main/ClockSet.c
- Apple Secure Enclave: https://support.apple.com/guide/security/secure-enclave-sec59b0b31ff/web
- age-plugin-tpm: https://github.com/Foxboron/age-plugin-tpm ; age-plugin-se: https://github.com/remko/age-plugin-se
- Roughtime protocol: https://roughtime.googlesource.com/roughtime/+/HEAD/PROTOCOL.md ; Cloudflare Roughtime: https://blog.cloudflare.com/roughtime/
- RFC 3161: https://www.rfc-editor.org/rfc/rfc3161.html
- RFC 8915 (NTS): https://www.rfc-editor.org/rfc/rfc8915.html
- Sigstore Rekor: https://docs.sigstore.dev/logging/overview/
- magic-wormhole: https://magic-wormhole.readthedocs.io/en/latest/welcome.html
- C2SP age plugin spec: https://github.com/C2SP/C2SP/blob/main/age-plugin.md
- `age` crate (Recipient/Identity traits): https://docs.rs/age/latest/age/

**Unverified:** Lit Protocol per-request pricing (pricing pages returned 404); TACo `TimeCondition` comparator semantics (page moved); whether NIST SP 800-88 Rev. 2 (reported September 2025) changes the flash wording quoted from Rev. 1; TCG normative prose for `TPM2_ClockSet` (only the reference implementation was checked).
