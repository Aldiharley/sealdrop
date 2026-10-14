# Final whole-branch review: sealdrop package format v1 (`bed28ac..6893c19`)

Reviewer: final cross-cutting pass, 14 Oct 2026. Read: design, plan header + Global Constraints, the
full ledger, the whole spec (982 lines), harness, generator, CI, vectors README, keys README,
README/CONTRIBUTING diff, and the code the findings touch (`pack.rs`, `extract.rs`, `release.rs`,
`seal.rs`, `open.rs`, `crypt.rs`, `manifest.rs`, CLI `open.rs`). Checks I ran:

- `cargo test -p sealdrop-core --features test-support --test format_vectors`: 2/2 pass, with Go age v1.3.2 present.
- `cargo clippy -p sealdrop-core --all-targets --features test-support -- -D warnings`: clean.
- A Python cross-check of every bundle vector. For all 9, `package_id` and `plaintext_tar_sha256` equal the manifest. `ciphertext.sha256` and `size` match the package bytes in 8, and differ only in `ciphertext-tampered`, which is the intent.
- `age -d` on `recipient-x25519` and `armored-x25519`. Both tars hash to `49d7765c…`, which equals `expected.plaintext_tar_sha256`.
- Stock age on the three `n/a` vectors that carry a package: `manifest-tampered` and `manifest-wrong-comment` open (exit 0); `ciphertext-tampered` is rejected ("failed to decrypt and authenticate payload chunk").
- `gh run list`: CI is green on 6893c19.

## Verdict

**Ready to publish after one fix wave.** No Critical findings. The spec is accurate against the code and
unusually honest about the reference's limits. It cross-references consistently. Its §11 schema matches
all 18 `vector.json` files and the harness. Before third parties are invited to implement it, though:

- The two timed-release success vectors cannot be passed by a decoder that follows the spec.
- The project's own docs advertise a post-quantum recipient type (`age1pq`) that the reference does not support.
- The encoder can still produce packages that its own decoder refuses.

## Strengths

- Every normative value I spot-checked matches the code: the limits, the Argon2id bounds and step order, the URL rules, the minisign legacy refusal (`manifest.rs:86`, `allow_legacy=false`), the `resolve_signer` exact-match rule, the base64 engines, the serde behaviour (unknown keys ignored, duplicates rejected) and the retention disclosure text in the CLI and desktop app.
- The quirks of the reference are documented rather than hidden: the two-pass hash (§5.4 step 6), duplicate tar entries, `+`/leading zeros, case collisions and the `a:b:443` URL case. Appendix A maps every rule to code.
- The vectors are real bundles under their real names. The harness presents them under those names and proves the `stock_age` claims against Go age in CI on Linux and Windows. `.gitattributes` keeps the CRLF armor vector byte-exact.

## Findings

### Critical

None.

### Important (in the wave)

**I1. A conforming decoder cannot pass the timed-release vectors.**
- Files: `spec/sealdrop-format-v1.md:882-884`; `spec/vectors/README.md:61-66`; `crates/sealdrop-core/src/seal.rs:133-140`; `crates/sealdrop-core/tests/format_vectors_gen.rs:216-223`.
- Both `timed-release-*` headers name the service `memory://spec.vectors`. §4.2 decode step 4 requires a header error when the service fails §7.1, and §7.1 says production clients MUST NOT accept `memory://`.
- Both manifests also carry `release.service_key: "memory"`, which breaks §5.2 ("the service's minisign public key") and §7.2 ("MUST check that it parses as a minisign public key").
- So a third party has to add a non-conforming test mode in two places before it can pass two of its "success" vectors. People will notice this on day one.
- Fix:
  - In `seal::test_support`, add a per-thread intercept: `intercept_deposits(url, service_key)`. `deposit_key` checks it before `release::deposit` (test builds only). It remembers `K_release` and returns the registered key.
  - The generator registers `https://release.invalid` (RFC 6761: it never resolves) with `keys/service.pub`'s base64.
  - Delete the two `timed-release-*` directories and rerun the generator without `SEALDROP_VECTORS_FORCE`, which leaves the other 16 untouched.
  - Rewrite §11's bullet and the vectors README section. Harnesses inject the unlock response from `inputs.k_release` and MUST NOT contact the network. They do not check the unlock token, because the vector has no service-side `unlock_token_hash`; this also closes the deferred "VectorFetch token note".
  - Drop the `memory://` sentence from §11.
  - `validate_service_url` needs no change, because an https URL passes in every build.

**I2. The reference's docs advertise `age1pq…`; the hybrid type it implements is `age1tagpq1…` (ledger item 2(c)).**
- Files: `README.md:361`, `README.md:386`; `crates/sealdrop-cli/src/commands/seal.rs:34`; `apps/desktop/src/screens/Seal.tsx:583`; `apps/desktop/src/lib/mock.ts:149`; `TECH_SPEC.md:94`.
- `crypt.rs:46` uses `age::tagpq` (HRP `age1tagpq`, stanza `mlkem768p256tag`, confirmed in age-0.12.1 `native/tagpq.rs:21-23`).
- `age1pq1…` is age v1.3's native ML-KEM-768+X25519 type, the one the 19 skipped CCTV vectors use. The reference falls through to the plugin parser and treats it as plugin `pq`.
- README:361 says "sealdrop can encrypt *to* `age1pq` recipients", which is false. TECH_SPEC:94 claims age v1.3.0 `age1pq` support.
- Fix (docs only):
  - Say `age1tagpq1…` (age's tagged ML-KEM-768+P-256 type, encrypt-only in sealdrop).
  - Say native `age1pq1…` keys from `age-keygen -pq` are not supported yet.
  - Fix the CLI help line, the desktop placeholder and the mock classifier (`startsWith("age1tagpq1")`).
- `docs/design/brief.md:360,364` is historical design text; leave it or annotate it.
- Spec §4, lines 228-229: reword the note. `age1pq1…` is age's native `mlkem768x25519` type; the reference does not support it and its parser treats the string as plugin `pq`; encoders MUST NOT record such a recipient as `hybrid-pq`.

**I3. The encoder does not enforce the decoder's limits: packages that seal but cannot be opened (ledger 2(a) and 2(f)).**
- File: `crates/sealdrop-core/src/pack.rs:195-207`.
- `meta.json` over 1 MiB (roughly 7 000+ files) seals and then fails with "meta.json too large".
- The same happens for more than 100 000 entries (empty directories inflate the count without growing `meta.json`), and for more than 64 GiB in total or in one file.
- For a timed package this is unrecoverable: the recipient can start the window and still cannot open the package.
- Fix: in `write_plan`, after `meta_bytes` is built and before the first `append_data`, return an error if any of these holds:
  - `meta_bytes.len() > extract::META_MAX_BYTES`;
  - the entry count (meta + directories + files, counted the way `extract` counts) exceeds `Limits::default().max_entries`;
  - the total size exceeds `max_bytes`;
  - any file exceeds `max_file_bytes`.
- The error message should say what to do (split the folder or archive it first). `seal`'s `Cleanup` guard already removes the partial package. The deposit happens after `pack` (`seal.rs:250-254`), so no service record is orphaned.
- Test: add a limits-parameterised helper so a unit test can trip each cap cheaply.
- Spec: remove Appendix C rows **a** and **c**. Because v0.2.1 is tagged and the status line says "matches sealdrop 0.2.1", also change the status line and the Appendix C heading to the next release (0.2.2), with one sentence: "sealdrop 0.2.1 lacked the encoder checks of §3.3 and §6." The format itself is unchanged.

**I4. §1 goal 2 overstates interop.**
- File: `spec/sealdrop-format-v1.md:24-26`.
- It says the container "MUST be extractable by any ustar tar reader", but §3.1 writes GNU `L` long-name entries, which are not ustar.
- Fix: "…by any tar reader that supports ustar and GNU long-name (`L`) entries (GNU tar, bsdtar and the common libraries do)".

**I5. The trailing-slash trap for third-party encoders (ledger 2(b), wording only).**
- File: `spec/sealdrop-format-v1.md:109-110`.
- The rule reads like an encoder note, with the decoder side implicit through §3.4.
- Go `archive/tar` (`FileInfoHeader`), Python `tarfile`, GNU tar and bsdtar all append `/` to directory names. An encoder built on any of them produces packages that every conforming decoder rejects.
- Fix:
  - Say it outright: decoders MUST reject an entry whose name ends in `/` (§3.4, empty component).
  - Add: "Common tar libraries append `/` to directory names; encoders MUST strip it or omit directory entries for non-empty directories."
- The code change is deferred; see the triage table.

### Minor (in the wave; each is a line or two)

- **M1** `spec:92-94`, deferred minor: §2.3 has no `expect` value for decryption failure, no matching keys or release error. Add: "No v1 vector exercises these three classes. `header failure` covers header and excessive-work errors."
- **M2** `spec:550-551`, deferred minor: "no entry's effective size can differ" overclaims. Use "is intended not to differ; §6.2 step 5.5 checks it".
- **M3** `spec:13-14` and `974-982`, deferred minor: the abstract promises that Appendix C lists every shortfall from a MUST, but three are inline only: `+`/leading zeros (§4.1), extra real stanzas not rejected (§4.1, §4.2) and duplicate tar entries (§6.2). Add three rows. Alternatively, state the decoder obligation as MAY at each site and soften the abstract.
- **M4** `spec:352-354`: "MUST contain a `sealdrop-release` stanza only if the manifest has a `release` object" can be read as "if and only if". Reword: "If the header contains a `sealdrop-release` stanza, the verified manifest MUST have a `release` object with equal `release_id` and `service`; otherwise refuse. A `release` object without a stanza is not an error in the reference." CLI `open.rs:60-66` checks only the forward direction.
- **M5** `spec:872-874` and three `vector.json` files, together with the deferred "stock_age on package-less vectors": §11 defines `n/a` as "no package to try". Yet `manifest-tampered` and `manifest-wrong-comment` (stock age opens both) and `ciphertext-tampered` (stock age rejects it) carry a package and say `n/a`.
  - Set them to `opens`, `opens` and `rejects`, in the generator literals and in the three `vector.json` files. These are JSON-only edits: do not regenerate the ciphertexts.
  - In the harness, assert `stock_age == "n/a"` if and only if `files.package` is absent.
- **M6** `spec:877-878`: §11 does not say what the receipt inputs stand for. Add: "`inputs.service_key`, `expected.release_id` and `expected.package_sha256` stand for the verified manifest's `release.service_key`, `release.release_id` and `ciphertext.sha256` (§8.2). `inputs.signer_key` is the key the harness trusts (§5.4 step 2)."
- **M7** `spec:897`: the regenerate command lacks `SEALDROP_VECTORS_FORCE=1`, so it silently does nothing on a checkout that has vectors. Add the variable or point to `spec/vectors/README.md`.
- **M8** `spec:406`: §5.2 should say that readers MUST accept unknown `kind` values and that `hybrid-pq` means `mlkem768p256tag` only. A native `mlkem768x25519` kind can then be added later as a compatible change (§10). The reference already stores `kind` as a `String`.
- **M9** `crates/sealdrop-core/tests/format_vectors.rs:148` and `270-283`: the harness oracle is weak.
  - `header failure` matches any `Error::Decrypt(_)`, so a wrong-passphrase failure would pass. Narrow it to `age::DecryptError::InvalidHeader | ExcessiveWork { .. }`.
  - No test checks `expected.plaintext_tar_sha256`, which is the main known-answer value for third parties. In the `opens` branch, assert that the SHA-256 of age's stdout equals it (I verified both X25519 vectors by hand).
- **M10** `.github/workflows/ci.yml:23`, deferred minor: clippy never sees `format_vectors.rs` or `format_vectors_gen.rs` because both are gated on `test-support`. Add `cargo clippy -p sealdrop-core --all-targets --features test-support -- -D warnings`; I ran it and it passes today.

### Minor (deferred, recorded)

- **D1** `manifest.rs:58-69`: an oversize, unparseable or wrong-`format` manifest returns `Error::Manifest`, not the "verification error" §5.4 names. No vector exercises it. Map it to `Error::Verify` inside `verify_with` next time `open.rs` is touched.
- **D2** The harness accepts any extraction error for the `tar-reject-*` vectors, so a vector could pass for the wrong reason. Adding an `expected.reason` needs a §11 schema addition, so do it in a later vector revision.
- **D3** §9 case-insensitive collisions: success is reported while a file is silently lost. This is already on the project's deferred list and documented honestly; it is the most serious reference shortcoming left, so give it a task of its own.

## Triage

| Item | Decision | Minimal fix / reason |
|---|---|---|
| 2(a) `pack` allows `meta.json` > 1 MiB | **Must-fix** | I3. Check in `write_plan` before writing. Remove Appendix C row a and move the status line to 0.2.2. The failure is silent and can be permanent for timed packages. |
| 2(b) GNU `dir/` rejected by `check_path` | **Must-fix (spec wording); defer the code** | I5. Encoders MUST NOT write the slash, so relaxing decoders later (accept one trailing `/` on type-5 entries only) is a compatible change with no new identifier. Widening the extractor deserves its own tested change. Track it as a 0.3 item. |
| 2(c) README/CLI/desktop say `age1pq…` | **Must-fix** | I2. Docs, help text, desktop placeholder and mock, TECH_SPEC, spec note at lines 228-229. Refusing `age1pq1` and `age1tag1` in `Recipient::parse` with a clear message is deferred: today it already fails, just with a confusing plugin-not-found error. |
| 2(d) `open` hashes, then decrypts in a second pass | **Defer** | The spec states this exactly (§5.4 step 6, SHOULD). Exploiting it needs local write access to the package during `open`. The proper fix is to hash while decrypting and gate the §6.3 placement on the hash; that changes the `open`/`extract` interfaces and needs its own task. |
| 2(e) `https://a:b:443` passes as host `a:b` | **Defer** | Harmless: ureq rejects it, and §7.1 documents it. The later fix is one line (reject `:` in an unbracketed host) plus a reword of §7.1 step 3. Tightening a client later is compatible. |
| 2(f) encoder ignores the §6 limits | **Must-fix** | Folded into I3 (same place, same test). Remove Appendix C row c. |
| T1 Appendix C completeness | **In wave** | M3. |
| T1 §2.3 `expect` mapping | **In wave** | M1. |
| T1 §6.1 "can differ" | **In wave** | M2. |
| T3 VectorFetch ignores the unlock token | **In wave** | Folded into I1's §11 rewrite. |
| T3 `stock_age` not validated on package-less vectors | **In wave** | M5. |
| T3 `rejects` checks the exit code only | **Defer** | Matching on Go age's stderr wording would make CI depend on the text of another project's error messages. The exit code is the claim §11 makes. |
| T3 CI clippy lacks `test-support` | **In wave** | M10. Verified clean. |

Order for the wave:
1. I3 (code and test).
2. I1 (seam, regenerate the two timed vectors, update the docs).
3. M5 and M9 (harness and vector JSON).
4. I2 (docs).
5. All spec text together: I4, I5, M1-M4, M6-M8, Appendix C, status line.
6. M10 (CI).
7. Rerun `format_vectors` with `SEALDROP_REQUIRE_AGE=1`.
