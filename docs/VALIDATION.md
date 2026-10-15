Evidence for 0.2.x is at tag v0.2.2 (`docs/VALIDATION.md` there).

# Validation evidence for sealdrop 0.3.0

Everything below comes from commands run on branch `feat/0.3-pq-commitment` for this document, at commit `afc7921` (`chore: 0.3.0; regenerate spec vectors`) with only documentation edits on top (Windows 11, `cargo` 1.96.0, `rustc` 1.96.0, Node 20.18.0, Go `age` v1.3.2). Paths in the manual session are shortened; the long `age1pq1…` recipient is cut with `…` (it is public, about 1,900 characters). No secret line (identity file contents, passphrase, deposit token) appears anywhere in this file. The Code Reviewer and Reality Checker passes are separate and are not recorded here.

0.3.0 adds native `age1pq1…` identities and recipients, the post-quantum-must-not-mix rule, the manifest `key_commitment`, case-collision refusal, a hidden CLI passphrase prompt, desktop support for all of these, a revised format spec and 20 vectors. The desktop installers, the real-app runs and the screenshots from 0.2 were not repeated; see "Not re-run for 0.3".

## Summary

| Command | Result |
|---|---|
| `cargo fmt --all --check` | pass (no output, exit 0) |
| `cargo clippy --workspace --all-targets -- -D warnings` | pass (`Finished`, no warnings) |
| `cargo test --workspace` (`SEALDROP_REQUIRE_AGE=1`, Go `age` on `PATH`) | pass: 193 passed, 0 failed, 0 ignored; no line containing "warning" |
| CCTV (`--test cctv`) | `CCTV: total=147 passed=147 failed=0` (no skips) |
| Interop (`--test interop_age`) | 5 passed, 0 failed (4 run the Go CLI, 1 uses the age crate for scrypt) |
| Spec vectors (`--test format_vectors`) | 3 passed: 20 vectors `ok`, 12 `stock_age` claims checked against Go age |
| `cargo deny check licenses advisories` | `advisories ok, licenses ok` (one warning: unused license allowance) |
| `npm test` (apps/desktop) | 10 tests, 4 suites, 10 pass, 0 fail |
| `npm run build` (apps/desktop) | pass (`tsc --noEmit && vite build`, `built in 388ms`) |
| Manual PQ session (CLI) | seal to `age1pq1…` from a classical store, `verify` shows `post-quantum: yes`, `open` with the PQ store restores the files, Go `age -d` lists the same package; mixing is refused with exit 3 |

## Tests per crate

From `cargo test --workspace > test.log 2>&1` with `SEALDROP_REQUIRE_AGE=1` and `$HOME/go/bin` on `PATH`. The log has no line containing "warning" and 193 lines matching `^test .* ok$`.

| Crate | Test binary | Passed |
|---|---|---|
| sealdrop-cli | unit (`src/main.rs`) | 10 |
| sealdrop-cli | `tests/cli.rs` | 16 |
| sealdrop-core | unit (`src/lib.rs`) | 108 |
| sealdrop-core | `tests/cctv.rs` | 1 (runs the 147 CCTV vectors, see below) |
| sealdrop-core | `tests/format_vectors.rs` | 3 (20 vectors, `stock_age` claims, version parsing) |
| sealdrop-core | `tests/format_vectors_gen.rs` | 0 (the regeneration test is `#[ignore]`d and needs `--features test-support`) |
| sealdrop-core | `tests/interop_age.rs` | 5 |
| sealdrop-core | `tests/malicious_tar.rs` | 15 |
| sealdrop-core | `tests/no_memory_seam.rs` | 1 |
| sealdrop-core | `tests/roundtrip_prop.rs` | 1 |
| sealdrop-desktop | unit (`src/main.rs`) | 19 |
| sealdrop-release | unit (lib and main) | 0 |
| sealdrop-release | `tests/cli.rs` | 2 |
| sealdrop-release | `tests/service.rs` | 12 |
| Doc-tests | sealdrop_core, sealdrop_release | 0 |
| **Total** | | **193** (10+16+108+1+3+5+15+1+1+19+2+12) |

The `test result` lines from the log, in order (executable hash suffixes dropped, the crate added in parentheses; counts and timings are as printed):

```
Running unittests src\main.rs (sealdrop-cli)        test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
Running tests\cli.rs (sealdrop-cli)                 test result: ok. 16 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 3.41s
Running unittests src\lib.rs (sealdrop-core)        test result: ok. 108 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 24.03s
Running tests\cctv.rs                               test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 18.60s
Running tests\format_vectors.rs                     test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 25.99s
Running tests\format_vectors_gen.rs                 test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
Running tests\interop_age.rs                        test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 10.91s
Running tests\malicious_tar.rs                      test result: ok. 15 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.06s
Running tests\no_memory_seam.rs                     test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
Running tests\roundtrip_prop.rs                     test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 2.25s
Running unittests src\main.rs (sealdrop-desktop)    test result: ok. 19 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.08s
Running unittests src\lib.rs (sealdrop-release)     test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
Running unittests src\main.rs (sealdrop-release)    test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
Running tests\cli.rs (sealdrop-release)             test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.29s
Running tests\service.rs                            test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
Doc-tests sealdrop_core                             test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
Doc-tests sealdrop_release                          test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

## CCTV vectors

```
$ cargo test -p sealdrop-core --test cctv -- --nocapture 2>&1 | grep -E "total|passed|skipped|failed|SKIP"
CCTV: total=147 passed=147 failed=0
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 18.22s
```

147 vectors, 147 passed, 0 failed, and no `SKIPPED` line. In 0.2 the 19 native post-quantum (`mlkem768x25519`) vectors were skipped because the age crate has no identity type for them; sealdrop's own `pq` module now supplies it.

## Interop with stock age

```
$ age --version
v1.3.2
$ SEALDROP_REQUIRE_AGE=1 cargo test -p sealdrop-core --test interop_age -- --nocapture 2>&1 | grep -iE "^test |skipping|result"
test sealdrop_decrypts_what_stock_age_encrypted_to_pq ... ok
test stock_age_decrypts_recipient_mode_and_tar_extracts ... ok
test stock_age_decrypts_pq_recipient_package ... ok
test scrypt_mode_opens_with_the_age_crate_not_the_go_cli ... ok
test stock_age_rejects_argon2id_package ... ok
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 10.51s
```

- Go `age` v1.3.2 opens a recipient-mode package (`stock_age_decrypts_recipient_mode_and_tar_extracts`) and a package sealed to a sealdrop-generated `age1pq1…` identity (`stock_age_decrypts_pq_recipient_package`), and refuses an Argon2id package (`stock_age_rejects_argon2id_package`).
- The other direction: sealdrop opens a file that Go `age` encrypted to a sealdrop PQ recipient (`sealdrop_decrypts_what_stock_age_encrypted_to_pq`, the raw age layer).
- scrypt mode is verified with the age crate only: the Go CLI reads a passphrase only from a terminal, so the test cannot drive it. It shows format conformance, not independent interop.
- No "skipping" line appears. The manual PQ session below also runs Go `age -d` on a package.

## Spec vectors

```
$ SEALDROP_REQUIRE_AGE=1 cargo test -p sealdrop-core --test format_vectors -- --nocapture
running 3 tests
test version_parsing ... ok
age   argon2id-reject-p-too-large: rejects
age   argon2id-reject-t-too-large: rejects
age   armored-x25519: opens
age   ciphertext-tampered: rejects
age   commitment-mismatch: opens
age   manifest-tampered: opens
age   manifest-wrong-comment: opens
age   passphrase-argon2id-compat: rejects
age   recipient-pq: opens
age   recipient-x25519: opens
age   timed-release-passphrase: rejects
age   timed-release-x25519: rejects
test stock_age_claims ... ok
ok    argon2id-reject-p-too-large
ok    argon2id-reject-t-too-large
ok    armored-x25519
ok    ciphertext-tampered
ok    commitment-mismatch
ok    manifest-tampered
ok    manifest-wrong-comment
ok    passphrase-argon2id-compat
ok    passphrase-scrypt
ok    receipt-valid
ok    receipt-wrong-key
ok    recipient-pq
ok    recipient-x25519
ok    tar-reject-long-name-bomb
ok    tar-reject-pax-size
ok    tar-reject-symlink
ok    tar-reject-traversal
ok    tar-reject-unlisted-file
ok    timed-release-passphrase
ok    timed-release-x25519
test all_format_vectors ... ok
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 26.11s
```

(The tests run in parallel, so the `age` lines and the `ok` lines were interleaved in the real output; they are regrouped here, and the `Compiling`/`Running` header lines are omitted.) 20 vectors passed the reference implementation. The 12 `age` lines are the `stock_age` claims checked against Go age v1.3.2 ("opens" for 6 vectors, "rejects" for 6). The other 8 are not driven through the Go CLI: the two receipt vectors and the five `tar-reject-*` vectors carry `stock_age: n/a` (no package for age to read), and `passphrase-scrypt` carries `opens-interactive` (the Go CLI reads a passphrase only from a terminal). The vector manifests were regenerated after the version bump with `SEALDROP_VECTORS_FORCE=1 cargo test -p sealdrop-core --features test-support --test format_vectors_gen -- --ignored regenerate_format_vectors` (1 passed), and every manifest now reads `"tool": "sealdrop 0.3.0"`.

## clippy, fmt, deny

```
$ cargo fmt --all --check; echo "fmt exit=$?"
fmt exit=0

$ cargo clippy --workspace --all-targets -- -D warnings
    Checking sealdrop-core v0.3.0 (M:\Projects\sealdrop\crates\sealdrop-core)
   Compiling sealdrop-desktop v0.3.0 (M:\Projects\sealdrop\apps\desktop\src-tauri)
    Checking sealdrop-release v0.3.0 (M:\Projects\sealdrop\crates\sealdrop-release)
    Checking sealdrop-cli v0.3.0 (M:\Projects\sealdrop\crates\sealdrop-cli)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 10.52s

$ cargo deny check licenses advisories
warning[license-not-encountered]: license was not encountered
  --> M:\Projects\sealdrop\deny.toml:2:116
   unmatched license allowance "Apache-2.0 WITH LLVM-exception"

advisories ok, licenses ok
```

(The clippy dependency `Checking` lines are omitted, and the deny warning's box drawing is condensed.)

## Desktop front end

```
$ cd apps/desktop && npm test
...
    # Subtest: generate_identity honours pq
    ok 4 - generate_identity honours pq
    # Subtest: verify and open expose post_quantum
    ok 5 - verify and open expose post_quantum
...
# tests 10
# suites 4
# pass 10
# fail 0
# cancelled 0
# skipped 0
# todo 0

$ cd apps/desktop && npm run build
...
dist/assets/mock-ZSo4xQWK.js                                  8.20 kB │ gzip:   3.48 kB
dist/assets/webview-BjKnOuh1.js                              16.34 kB │ gzip:   3.51 kB
dist/assets/index-DHVYEJIU.js                               341.12 kB │ gzip: 106.49 kB
✓ built in 388ms
```

`npm test` bundles `src/lib/format.pq.test.ts` with rolldown and runs it on Node's built-in test runner (Node 20.18.0). `npm run build` is `tsc --noEmit && vite build`. The `rolldown` native binding workaround from 0.2 was already in `node_modules`, and `package.json` and the lockfile were not changed by running these (the version lines were edited by hand). The Rust side of the desktop app (19 unit tests, clippy) is in the tables above.

## RNG audit

Every random source in `crates/sealdrop-core/src` and `crates/sealdrop-release/src`, found with `grep -rnE "rand::rng\(\)|OsRng|rand_core06|getrandom|new_v4|generate_unencrypted_keypair|fill_bytes"` and checked against the dependency sources in the Cargo registry (`age` 0.12.1, `rand` 0.9.5, `rand_core` 0.6.4, `uuid` 1.28.0, `minisign` 0.10.0). Test-only call sites are not listed.

| Where | Source | Used for | On RNG failure |
|---|---|---|---|
| `age` 0.12.1, `keys.rs:21` (`new_file_key`) | `rand::rngs::OsRng` (rand 0.8, rand_core 0.6, getrandom 0.2) | the 16-byte age file key | panics: `rand_core-0.6.4/src/os.rs:61-65`, `fill_bytes` calls `try_fill_bytes` and panics on `Err` |
| `age` 0.12.1, `native/x25519.rs:70`, `native/scrypt.rs:142`, `protocol.rs:31` | the same `OsRng` | X25519 identity generation and ephemeral keys, scrypt salt, payload nonce | panics, same code path |
| `pq::Identity::generate`, `crates/sealdrop-core/src/pq.rs:108-110` | `rand_core06::OsRng.fill_bytes` | the 32-byte seed of a new `age1pq1…` identity | panics (same `OsRng`); the `expect("32 bytes")` on the next line is about the seed length, not randomness |
| `pq::Recipient::wrap_file_key`, `pq.rs:90` | `rand_core06::OsRng` passed to `hpke_seal` | the ML-KEM-768 + X25519 encapsulation randomness | panics (same `OsRng`) |
| `release::Deposit::new`, `crates/sealdrop-core/src/release.rs:131-132` | `rand::rng().fill_bytes` (rand 0.9) | the 32-byte release key and the 32-byte unlock token | panics: `ThreadRng` initialisation panics with "could not initialize ThreadRng" (`rand-0.9.5/src/rngs/thread.rs:123-124`) and reseeding panics with "Reseeding RNG failed" (`rand-0.9.5/src/rngs/reseeding.rs:217`) |
| `release::Deposit::new`, `release.rs:134` | `uuid::Uuid::new_v4` (getrandom 0.4) | the release id | panics: "could not retrieve random bytes for uuid" (`uuid-1.28.0/src/rng.rs:57-59`) |
| `release` stanza wrapping, `release.rs:211` | `rand::rng().fill_bytes` | the 12-byte nonce of the wrapped inner stanzas | panics (same `ThreadRng`) |
| `argon2id::Recipient::wrap_file_key`, `crates/sealdrop-core/src/argon2id.rs:107` | `rand::rng().fill_bytes` | the Argon2id salt | panics (same `ThreadRng`) |
| `passphrase::generate`, `crates/sealdrop-core/src/passphrase.rs:61` | `rand::rng()` with `random_range` | the generated EFF / BIP-39 words | panics (same `ThreadRng`) |
| `seal.rs:324` | `uuid::Uuid::new_v4` | the package id | panics (same `uuid` code) |
| `extract.rs:492` | `uuid::Uuid::new_v4` | a suffix for the `.old` backup folder name (not secret) | panics (same `uuid` code) |
| `KeyStore::generate`, `crates/sealdrop-core/src/keys.rs:218` | `minisign::KeyPair::generate_unencrypted_keypair` (getrandom, `minisign-0.10.0/src/keypair.rs:31,34`) | the minisign signing key | returns `Err`, which `keys.rs:218-219` maps to `Error::KeyStore` and the caller reports; nothing is written after it |
| `sealdrop-release keygen`, `crates/sealdrop-release/src/main.rs:92` | the same minisign call | the service signing key | returns `Err`, propagated with `?`, so the command exits non-zero before writing a key file |
| `Db::create_token`, `crates/sealdrop-release/src/db.rs:55` | `rand::RngCore::fill_bytes(&mut rand::rng(), ...)` | the deposit token | panics (same `ThreadRng`) |

No call site catches a randomness error, substitutes a default, or retries with a weaker source: where the library can return an error (minisign) it is propagated, and everywhere else the library panics, which stops the operation before any key or ciphertext that depended on it is written. The CLI and the desktop app both call these same functions. `grep` finds no use of `thread_rng`, a seeded RNG (`seed_from_u64`, `StdRng`) or a time-based value outside tests.

## Manual PQ session

Run with the built CLI through `cargo run -q -p sealdrop-cli --` (abbreviated `sealdrop` below). Two throwaway key stores were selected with `SEALDROP_HOME`: `<pq store>` and `<classic store>`, both in the session scratchpad. The input folder `in` holds `readme.txt` and `docs/q3.txt`. The identity files were never printed. The PQ recipient is cut to its first characters with `…`; the full public string was used on the command lines.

```
$ SEALDROP_HOME=<pq store> sealdrop keygen --pq
age1pq1gtqs4znx26382ja9kv94q25x20emtug4te2ec3w5kwesw6rmwcs5fv6jwuuyvjw7xpq29ckfhjqxst392vfffgnzwez…
RWTeSNsNPLZzY+yh2gEU6jJlobHcKPq4uGUQKyrZ1ksG1tf04OFG5t3n
identity written to <pq store> (kind: pq)
post-quantum identity: senders need sealdrop 0.3 or age 1.3 or newer
share the first line (your recipient) with senders; the second is your signer key
[exit=0]

$ SEALDROP_HOME=<classic store> sealdrop keygen
age1ecz8607pe7q6asmk4zafnzc53j5cuqdpkdv89zylhur7n34c8a2qpm3qxy
RWSWvmJ1lM7QPSFkBUg6Xp2SMDTzM1TAdBU5BG3sV114yJsyP+oN3rAO
identity written to <classic store> (kind: x25519)
share the first line (your recipient) with senders; the second is your signer key
[exit=0]

$ SEALDROP_HOME=<classic store> sealdrop seal in -r age1pq1gtqs4znx26382ja9kv…  -o out
packing \\?\...\pqsession\in
encrypted 6886 bytes
sealed: ...\pqsession\out\in.sealdrop.age
manifest: ...\pqsession\out\in.manifest.json
signature: ...\pqsession\out\in.manifest.json.minisig
package id: 809d9548-d65c-4c8b-b481-387a3db018df
post-quantum: yes
note: your own identity is classical (x25519), so it was not added to this post-quantum package; create a post-quantum identity with `keygen --pq` to include yourself
ciphertext sha256: 1c670d9b21473414bdd7d230b0f3c3af1066b0c4b261de7fe4ec116f4455d961
[exit=0]

$ SEALDROP_HOME=<classic store> sealdrop verify out/in.sealdrop.age
OK: signature valid, ciphertext hash matches
package id: 809d9548-d65c-4c8b-b481-387a3db018df
signer: RWSWvmJ1lM7QPSFkBUg6Xp2SMDTzM1TAdBU5BG3sV114yJsyP+oN3rAO (self)
created: 2026-10-15T15:39:39Z
post-quantum: yes
recipient: pq 33d614989203d12f
[exit=0]

$ grep -o '"key_commitment": *"[0-9a-f]\{8\}' out/in.manifest.json
"key_commitment": "317c1cdf...
```

The first `open` with the PQ store failed because the receiver had not yet trusted the sender's signer key, which is the intended behaviour for an unknown signer:

```
$ SEALDROP_HOME=<pq store> sealdrop open out/in.sealdrop.age -o restored
verifying manifest
error: verification failed: signer RWSWvmJ1lM7QPSFkBUg6Xp2SMDTzM1TAdBU5BG3sV114yJsyP+oN3rAO is not trusted; add it with `sealdrop trust add <name> RWSWvmJ1lM7QPSFkBUg6Xp2SMDTzM1TAdBU5BG3sV114yJsyP+oN3rAO` or pass --signer
[exit=2]

$ SEALDROP_HOME=<pq store> sealdrop trust add sender RWSWvmJ1lM7QPSFkBUg6Xp2SMDTzM1TAdBU5BG3sV114yJsyP+oN3rAO
trusted sender
[exit=0]

$ SEALDROP_HOME=<pq store> sealdrop open out/in.sealdrop.age -o restored
verifying manifest
extracting to ...\pqsession\restored
restored: ...\pqsession\restored\in (2 files, 24 bytes)
verified: signer RWSWvmJ1lM7QPSFkBUg6Xp2SMDTzM1TAdBU5BG3sV114yJsyP+oN3rAO (sender)
post-quantum: yes
[exit=0]
$ find restored -type f; cat restored/in/docs/q3.txt
restored/in/docs/q3.txt
restored/in/readme.txt
quarterly numbers
```

Stock Go age on the same package, with the PQ store's identity file (`age` v1.3.2):

```
$ age -d -i <pq store>/identity.txt out/in.sealdrop.age | tar -t
sealdrop/meta.json
sealdrop/payload/in
sealdrop/payload/in/docs
sealdrop/payload/in/docs/q3.txt
sealdrop/payload/in/readme.txt
[exit=0]
```

The PQ-must-not-mix rule, from the same session:

```
$ SEALDROP_HOME=<classic store> sealdrop seal in -r <pq recipient> -r <classic recipient> --no-self -o out2
error: policy refused: post-quantum recipients cannot be mixed with classical ones (classical: 90ce9a5173ad4db7); seal them separately
[exit=3]
```

The passphrase prompt was not part of this session (stdin was not a terminal), so the hidden prompt itself was not exercised.

## Not re-run for 0.3

These were validated for 0.2 and are recorded in `docs/VALIDATION.md` at tag v0.2.2. They were not repeated for this document, and nothing here should be read as a 0.3 result for them:

- `cargo tauri build` (exe, MSI and NSIS installers) and the artefact sizes.
- The real desktop runs over CDP (`npx tauri dev` against a real `sealdrop-release`, and the release exe), including the Keys and Seal screens with a post-quantum identity.
- The manual CLI timed-release session against a live `sealdrop-release` (open before expiry exit 0, after expiry exit 2). Timed release is covered here only by the automated tests in the tables above (`sealdrop-release` `tests/service.rs` and `tests/cli.rs`, the `timed-release-*` spec vectors).
- The seven screenshots in `docs/design/screenshots/`. The Keys-screen image is to be refreshed separately for the post-quantum identity badge.
- Hardware keys: there is still no run against a physical key.

## Known limitations observed

- **Hidden passphrase prompt not exercised at a terminal.** `open` hides what you type when stdin is a terminal (`rpassword`, `crates/sealdrop-cli/src/commands/open.rs:176-181`) and reads one visible line otherwise (`open.rs:182`). The automated tests and this session use the non-terminal path; typing a passphrase at a real console was not tested.
- **Timed-release packages do not open in stock age.** By design; stock age reports "no identity matched any of the recipients" (recorded in the 0.2 evidence).
- **Case-insensitive destinations.** The refusal on open depends on probing the destination folder (`destination_is_case_insensitive`, `crates/sealdrop-core/src/extract.rs:374`). It is covered by unit tests; it was not run on a macOS volume.
- **`age1tagpq1…` is encrypt-only.** There is no identity type for it, so sealdrop cannot open such packages.
- **Node 20 workaround.** Node here is 20.18.0, below the 20.19 that Vite asks for. The build and `npm test` ran despite the warning.
- **`cargo deny` warning.** The allow list has an unused entry (`Apache-2.0 WITH LLVM-exception`). The check still reports `advisories ok, licenses ok`.
- **No external audit** of sealdrop, and no independent review of its ML-KEM-768 + X25519 code beyond the CCTV vectors and the Go age interop above.
