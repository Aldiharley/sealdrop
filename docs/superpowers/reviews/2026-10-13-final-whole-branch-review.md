# sealdrop 0.2: final whole-branch review

Range `ede3fc1..bce77ea` (73 commits, `main`). Reviewed against the spec
(`docs/superpowers/specs/2026-10-13-sealdrop-core-cli-desktop-design.md`), the plan's Global
Constraints and file map, `docs/VALIDATION.md` and the deferred items in `progress.md`.
Source was read directly: core, CLI, release service, Tauri commands and the React screens
that touch secrets and timing. CI is green on `bce77ea` (`gh run list`).

One reproduction was run, to settle the Critical finding below. It used the existing
`target/release` binaries and a scratch key store and service in the session scratchpad. The
repository tree was not modified.

## Summary verdict

**Not ready to call 0.2 done.** The crypto glue, verify-before-decrypt, URL validation,
receipts and extraction are solid. One mode, timed release combined with a passphrase, is
broken end to end. Every attempt to open such a package starts the irreversible window and
then fails, and the desktop app can never open it. Nine Important items follow. Most are
small, contained fixes. Two are gaps in the evidence: interop and a real desktop run.

Counts: Critical 1, Important 9, Minor 11 new (plus the deferred list, triaged below).

## Strengths

- **Verify before decrypt, on one handle.** `open::open` hashes and decrypts the same `File`
  (`open.rs:143-161`), so the path cannot be swapped between check and use. The manifest
  signature is bound to `package_id` through the signed trusted comment and to the bare
  ciphertext file name (`open.rs:83-102`). CLI, desktop and core all reach decrypt only
  through this path.
- **Timed-release stanza wraps only the file key.** The inner stanzas are AEAD-encrypted under
  `K_release` with a fresh random nonce per wrap, and a test proves the nonce is new each time.
  The label set `{"sealdrop-release"}` stops it being mixed with other recipients, and inner
  scrypt keeps age's own "scrypt alone" rule. Argon2id uses a fresh 16-byte salt, a domain tag,
  and refuses out-of-bounds parameters before any derivation.
- **Network hygiene.** The service URL and release id are validated before any request:
  https only, or http to loopback; no userinfo, `?`, `#` or `\`; the id must be a canonical
  UUID. These checks run again inside `Identity::unwrap_stanza`, because the values come from
  the file. Redirects are disabled and a test shows the redirect target is never contacted.
  `memory://` is compiled out of production builds, and a test proves it.
- **Receipts are pinned.** `verify_receipt_for` pins the service key recorded in the manifest,
  the release id, the package hash and the signed trusted comment. `receipt fetch` verifies
  the manifest before the deposit token goes to the service the manifest names.
- **Service.** The window is enforced on the service clock only. The first unlock is a
  conditional `UPDATE ... WHERE first_unlock IS NULL`, then a re-read. Expired keys are nulled
  both on access and by a sweeper. `secure_delete` is on. Deposit tokens are stored hashed.
  Bodies are capped at 16 KiB. The key file and database are created owner-only.
- **Extraction.** `GuardedReader` watches the raw tar stream and refuses PAX `size=`, GNU
  sparse entries, global headers and oversized extension headers before the tar crate buffers
  them. Files are written to a temp dir, hashed while written, and the temp dir is removed on
  any failure. Windows aliasing rules are enforced (trailing dot or space, reserved names,
  `:`, `\`).
- **Tests exercise real behaviour.** The CLI end-to-end test runs the real `sealdrop-release`
  service in-process. The CCTV harness is strict: exceptions are pinned by vector name, only
  hybrid vectors may be skipped, and the payload hash is checked even on payload failure.
  The property test compares the extracted tree byte for byte.
- **Desktop.** The command layer refuses relative paths. The viewing root is random and
  owner-only. There is no http, fs or shell plugin. The CSP is strict. The countdown runs from
  `remaining_secs` on a monotonic timer, with stale detection after sleep. The timed-release
  honesty sentences appear verbatim (`Seal.tsx:58`, `Open.tsx:29`, `Verify.tsx:26`). The
  replace-identity flow needs a typed confirmation.
- **Secret hygiene.** `Settings` `Debug` redacts the token. Invalid-recipient errors redact
  pasted secrets. Key files are written atomically.

## Critical

### C1. Timed release with a passphrase cannot be opened, and each attempt starts the window

- **Where:** `probe.rs:107-109`; `open.rs:162-164`, `188-191`; CLI `commands/open.rs:72-80`;
  desktop `Open.tsx:81`, `185`, `217`.
- **Cause:** `needs_passphrase` is computed from the outer age header. In a timed package the
  scrypt or Argon2id stanza is inside the encrypted `sealdrop-release` body, so the probe
  reports `needs_passphrase = false`.
  - The CLI therefore never prompts.
  - The desktop never shows the passphrase field and sends `passphrase: null`.
  - The core builds the wrapper with only the X25519 identity. It calls the service, which
    records the first unlock, and then fails with `No matching keys`.
- **Reproduced:** `seal --passphrase --expire-after 10m`, then `open`. The output was
  `error: decryption failed: No matching keys found`, exit 1. `receipt fetch` then showed
  `first opened ... unlock count: 1`. The window had started.
- **Who is affected:** both the CLI (`--passphrase --expire-after`) and the desktop
  (passphrase mode plus the Timed release toggle) seal this combination. The spec names it
  explicitly ("or a generated passphrase via scrypt/Argon2id").
  - In the desktop app the recipient can never open it. With an identity they burn the window
    and fail. Without one they are blocked by `keyPkgNoIdentity`.
  - On the CLI only `--passphrase-stdin` works, and nothing tells the user that.
  - For a short window this means permanent loss of access.
- **Fix:**
  1. Derive "needs passphrase" from the verified manifest as well: `recipients[0].kind` is
     `scrypt` or `argon2id`. Expose that from `verify` and the desktop `probe` or `verify`
     output, and prompt for it in the CLI.
  2. In the core `open`, when the package is timed, the verified manifest says passphrase, and
     no passphrase was given, return "this package needs a passphrase" **before** any network
     call.
  3. Under `--skip-verify` there is no signed hint. Either always offer the passphrase field for
     timed packages, or refuse timed and skip-verify without a passphrase. The CLI could ask
     "passphrase (leave empty if this package was sealed to your key)".
  4. Add CLI and desktop `open_impl` tests for timed plus passphrase, including the assertion
     that no unlock happens when the passphrase is missing.

## Important

### I1. Seal can produce a package that `open` will always refuse

- **Where:** `pack.rs:80-104`, `153-162`.
- **Three causes, one result.** In each case `seal` reports success, and the deposit is
  already made for timed packages.
  1. **Names that extraction refuses.** Spec 4.1 says meta paths "must pass the same checks
     as extraction". `pack` never calls `check_path`. A Linux or macOS folder containing
     `What is this?.pdf`, `a:b`, `"final".docx`, `notes.` or `CON.txt` seals cleanly, but
     extraction applies `check_path` on every OS and refuses the whole package (`BadPath`).
  2. **Files that change between the hash pass and the write pass.** `append_data` copies
     whatever the file holds now, but the header carries the pass-1 size. A growing log file
     breaks the tar framing. A same-size edit fails with `HashMismatch` at open. This is the
     deferred Task 2 item.
  3. **Lossy non-UTF-8 names.** Two names can map to the same lossy string, so meta gets a
     duplicate path and extraction refuses it with `DuplicatePath`.
- **Fix:** in pass 1, run `check_path(&format!("{PAYLOAD_PREFIX}{rel}"))` and refuse
  non-UTF-8 names, with an error that names the file. In pass 2, wrap the reader in
  `.take(fe.size)` through a `HashingWriter`, and fail on a short read or a hash that
  differs from pass 1.

### I2. `--overwrite` deletes the old tree before the rename; a failed rename loses both

- **Where:** `extract.rs:399-407`.
- **Failure:** `remove_dir_all(final_path)` runs, then `rename(staged, final_path)` fails.
  On Windows this happens readily: AV scanning just-written files, or Explorer holding a
  handle. The error returns early and the `TempDir` drop deletes the staged copy. The old
  data is gone and the new data is gone. `remove_dir_all` can also fail half-way. For timed
  packages the user may not be able to re-open once the window passes. The desktop "Save to…"
  and CLI `--overwrite` both reach this.
- **Fix:**
  1. Rename `final_path` to a sibling `.sealdrop-old-<rand>` in the same `out_dir`.
  2. Rename the staged tree into place.
  3. On success, remove the backup (best effort).
  4. On failure, rename the backup back and keep the staged tree, using `TempDir::keep()` /
     `into_path()`, and put its path in the error.

  Use `symlink_metadata` instead of `exists()`. This also closes the deferred
  symlink-following note.

### I3. Unverified, attacker-controlled strings reach the terminal and a suggested command line

- **Where:** core `open.rs:33-35` and `52-54`; CLI `verify.rs:26,35`, `open.rs` (service),
  `seal.rs:194`, `receipt.rs` `print`.
- **Failure:** `resolve_signer` runs **before** the signature check. It puts `doc.signer`
  from an unverified manifest into the error text: "signer {raw} is not trusted; add it with
  `sealdrop trust add <name> {raw}`". The CLI prints that to stderr.
  - A crafted manifest can carry ANSI escapes or newlines. These can overwrite the error with
    a fake "OK: signature valid".
  - Worse, the raw value lands inside a command the user is told to paste, so shell
    metacharacters ride along.
  - The deferred "service printed raw" item is the same class. The fields printed after
    verification (`classification`, `service`, `expires`, and receipt fields under TOFU
    `receipt verify`) are sender-controlled. They are lower risk but use the same fix.
  - The desktop is safe here: React escapes text, and `untrusted_signer` parses the key first.
- **Fix:**
  1. In `resolve_signer`, parse `manifest_signer` with `PublicKey::from_base64`. If it does not
     parse, return a generic "manifest signer is not a valid key" without echoing it. If it
     does, echo the re-encoded `to_base64()` string.
  2. Add one CLI helper that replaces control and bidi characters (`char::is_control`,
     U+202A..U+202E, U+2066..U+2069) before printing any manifest or receipt string.

### I4. The CLI panics on a closed stdout pipe (exit 101)

- **Where:** every `println!` in `crates/sealdrop-cli/src/commands/*`.
- **Evidence:** `sealdrop recipient | head -1` panicked with os error 232 (`VALIDATION.md`).
  Any script that pipes `verify`, `seal` or `trust list` into `head` or a closed reader gets a
  panic message and exit 101. That breaks the documented 0/1/2/3 contract and `pipefail`
  scripts.
- **Fix:** write through `writeln!(std::io::stdout().lock(), ...)` returning `io::Result`.
  In `main`, map `ErrorKind::BrokenPipe` to a quiet exit 0, or 1, as documented. On Unix you
  may also restore `SIGPIPE` to default; Windows still needs the explicit handling. Add an
  assert_cmd test that closes stdout early.

### I5. The rate limiter becomes a global switch behind the reverse proxy the spec requires

- **Where:** `routes.rs:18-30`; `main.rs` (`into_make_service_with_connect_info`).
- **Failure:** the limiter keys on the TCP peer. Spec 5.5 says "TLS is terminated by a
  reverse proxy", so every request arrives from the proxy address and all users share one
  bucket: 60 burst, 0.5/s refill. One client sending about one request per second keeps the
  whole service at 429. Every recipient's in-window unlock then fails, which denies timed
  windows to everyone. A missing `ConnectInfo` also falls back to 127.0.0.1.
- **Fix:** add `--trusted-proxy <cidr>`. When the peer is trusted, key on the right-most
  untrusted `X-Forwarded-For` entry. Otherwise key on the peer. Allow `--rate-capacity 0` to
  mean "disabled, the proxy limits". Task 17 must document this in the Caddy example.

### I6. Undisclosed hard deadline: unopened timed packages die after `retention_days`

- **Where:** `db.rs:170-180`; `main.rs` `--retention-days` (default 90).
- **Failure:** a deposit that is never unlocked has its key nulled and then its row deleted
  90 days after sealing. A recipient who opens on day 91 gets "release not found at service".
  - The seal copy is verbatim "can open this only within [window] after they first open it",
    which implies no such deadline. That makes it an honesty defect in a tool whose value is
    honesty.
  - Spec 5.5 only sets retention for *receipt rows*.
- **Fix:**
  1. Return `retain_until` (or `retention_days`) in the 201 deposit response and record it in
     the manifest's `release` block.
  2. Print it in CLI seal and verify output, and show it on the desktop seal success and
     verify screens, for example "must be first opened by 2027-01-11 (service retention)".
  3. Make unlock answer 410 with a clear reason for purged rows (see M5), and document it in
     the README.

### I7. CI never runs clippy or tests on the desktop crate

- **Where:** `.github/workflows/ci.yml`. The rust job passes
  `--exclude sealdrop-desktop` to both clippy and test, and the desktop job only runs
  `cargo build`.
- **Impact:** the 15 command-layer tests run only on a developer machine. These cover the
  absolute-path guard, the untrusted-signer parsing, temp-root cleanup and the settings
  validation. Spec 12 asks for `cargo clippy --all-targets -D warnings` and
  `cargo test --workspace`.
- **Fix:** in the Windows desktop job, after `npm run build`, add
  `cargo clippy -p sealdrop-desktop --all-targets -- -D warnings` and
  `cargo test -p sealdrop-desktop`.

### I8. The scrypt interop claim is overstated

- **Where:** `tests/interop_age.rs:99-144`.
- **Problem:** `stock_age_decrypts_scrypt_mode` never runs stock age. It decrypts with the
  `age` crate, the same implementation that wrote the file. `VALIDATION.md` reports
  "Interop 3/3" without that caveat. Spec 11 requires "stock age decrypts ... a scrypt-mode
  package".
- **Fix:** add a roughly 20-line Go helper. It can live under `crates/sealdrop-core/tests/go/`
  or `testkit-tools/`; `testkit/` is the vendored subtree, so keep it out of there. The helper
  calls `age.NewScryptIdentity(pass)` and `age.Decrypt`; run it with `go run` in the interop
  test, since CI already has Go. If that is deferred, at minimum rename the test, correct
  `VALIDATION.md`, and state the gap in the README.

### I9. The desktop app has never run against its real backend

- **Evidence:** `VALIDATION.md`: "Desktop app not run ... exercised only in browser mock
  mode."
- **Problem:** the IPC contract has only been checked by reading the code. That includes
  camelCase command arguments, snake_case `req` fields, the `dialog:default` permission, the
  drag-drop paths, the `progress` events and temp-folder deletion on close. I checked the
  argument names by reading and they look consistent, but nothing has exercised them.
- **Fix:** smoke-test the built `sealdrop-desktop.exe`, or `cargo tauri dev`, with the real
  service:
  - seal in recipient, passphrase and timed modes;
  - verify an untrusted signer, then trust it;
  - open to a folder and to the temp folder, then close the app and confirm the temp folder
    is gone;
  - fetch a receipt.

  Record the results in `VALIDATION.md`. Run it after C1 is fixed; it would have found C1.

## Minor (new; not in the deferred list)

| # | Where | Failure scenario | Fix |
|---|---|---|---|
| M1 | CLI `open.rs:72-80` | For non-timed passphrase packages the prompt comes **before** verification, so the user types the passphrase for a package that then fails verification. | Verify first, as the timed branch does, then prompt. |
| M2 | CLI `open.rs` prompt | The prompt echoes the passphrase into terminal scrollback (disclosed in help; deferred as "0.2"). | Use `rpassword` (Apache-2.0/MIT). |
| M3 | CLI `seal.rs:116-120` | `seal` with no `-r` and no `--passphrase` exits 3 (policy). Spec 8 calls it a usage error. | Exit 1, or amend the spec and docs to say 3. |
| M4 | `keys.rs:156-176`, CLI `keygen --force` | Replacing the identity destroys the old secret key with no backup. Packages sealed to it become unopenable. | Rename the old files to `*.bak-<timestamp>` before writing. |
| M5 | `routes.rs` unlock, `db.rs` purge | After the retention purge, unlock answers 404 and the client says "release not found", not "expired". | Keep a tombstone row, or answer 410 for purged ids. |
| M6 | CLI `seal` vs service `routes.rs:96` | A window over 366 days is accepted by the CLI and desktop, then fails as "deposit failed: http status 400". | Validate the window client-side with the same bound and a clear message. |
| M7 | `release.rs:341,354`; service `routes.rs` | `k_release` travels as plain `String` in the deposit body and unlock response; it is not zeroized. | Use `Zeroizing<String>` in those structs. |
| M8 | `argon2id.rs` Desktop profile | 2 GiB per derivation; Rust OOM aborts the process (desktop crash) on low-RAM machines, on both encrypt and decrypt. | Document it; consider checking available memory before choosing `High`. |
| M9 | `tests/service.rs:121-131` | The "key is gone after 410" check only proves the receipt lacks the key, which is always true. The unlock-path `delete_key` is never asserted. | Assert `get_release(id).k_release.is_none()` after the 410. |
| M10 | `tests/interop_age.rs` | Spec 11's "stock `age -d` fails on a timed-release file" is shown only in the manual session. | Add a fourth interop test. |
| M11 | `extract.rs:327` | `create_dir_all(out_dir)` runs before the `Exists` check, so a refused open leaves an empty folder. | Check first, then create. |

## Deferred-minors triage

| Item (task) | Decision | Reason |
|---|---|---|
| `sealdrop recipient \| head -1` panics on BrokenPipe (16) | **Must fix** (I4) | Panic and exit 101 break the exit-code contract; documented usage pattern. |
| Focus ring on programmatic heading focus in screenshots (16) | **Must fix before Task 17 screenshots** (cosmetic) | One CSS rule (`h1[tabindex="-1"]:focus{outline:none}` or `:focus-visible` only). README images depend on it. Not a correctness issue. |
| Seal-passphrase QR below the fold at 760 px (16) | **Must fix before Task 17 screenshots** (cosmetic) | Same reason; a layout or screenshot-size change. |
| `pack.rs` size change between hash and write pass (2) | **Must fix** (I1) | Seal reports success on an unopenable package. |
| Lossy non-UTF-8 names may collide (2) | **Must fix** with I1 | Same root cause; refuse non-UTF-8 at pack. |
| Overwrite deletes before rename / races `exists()` (3) | **Must fix** (I2) | Data loss on the error path. |
| `exists()` follows symlinks (3) | Fix with I2 | Same lines; `symlink_metadata`. |
| CLI/desktop print signed manifest `service` raw (11) | **Must fix** (I3) | Folded into the broader unverified-signer echo, which is the real hole. Desktop is safe (React escapes). |
| Desktop CI job red until Task 15 (1) | Closed | CI green at `bce77ea`. |
| `age@latest` unpinned in CI (1, 10) | Defer | Pin `@v1.3.2` when convenient; a moving reference only risks flakiness. |
| Actions pinned by tag, not SHA (1) | Defer | Supply-chain hardening for a later release. |
| `.env.example` ignored (1) | Defer | Add a negation when one is needed. |
| `pack(".")` has no file name (2, 9) | Closed | CLI and desktop canonicalize. |
| Missing tests: symlink skip, empty root, nested empty dirs; walkdir error kind (2) | Defer | Behaviour is correct by reading; nice-to-have. |
| Case-insensitive collisions / duplicate tar entries (3) | Defer | Needs a hostile *trusted* sender, who controls content anyway. |
| Directory entries unrestricted (3) | Defer | Bounded by the entry limit. |
| Reserved names COM0/LPT0/CONIN$/CONOUT$, superscript digits; DEL 0x7f (3) | Defer (cheap; do it if touching `check_path` for I1) | No write outside the temp dir is possible. |
| Leftover `.sealdrop-*` dir if killed (3) | Defer | Cosmetic. |
| GuardedReader `max_input_bytes` / base-256 tests; PAX `size=` over-refusal; test name (3) | Defer | Test polish; over-refusal is deliberate. |
| Passphrase `Debug` forwards; `SecretString` realloc; word-list rebuild (4) | Defer | No current leak path. |
| Hybrid round trip; scrypt max-logN enforcement untested; plugin case; `large_enum_variant` (5) | Defer | Coverage polish. |
| Argon2id message wording; lenient `+5`; `with_params` unbounded; AEAD not key-committing; 2 GiB alloc; `Key::from` stack copy (6, 8) | Defer | Header MAC covers key commitment; OOM is noted as M8. |
| Probe wrong-arity release stanza skipped; dead `end>HEADER_MAX` (7) | Defer | The core `Identity` rejects arity ≠ 4 with `InvalidHeader`. |
| Settings serde errors echo values; one corrupt `trusted/*.pub` fails all; `save_settings` dir not 0700; `release_token` plain `String` (7, 14) | Defer | Local-file robustness; the token stays on disk at 0600. |
| `generate` not atomic across files; empty `.tmp` on perm failure; `valid_name` allows CON/NUL (7) | Defer | Rare; `trust add CON` on old Windows writes to the console device; fix with M4. |
| `MemoryFetch` simplistic; `Recipient::new` infallible; deposit non-201 untested; https to private IPs; port digits (8) | Defer | The header is bound by the signed hash unless `--skip-verify`; the fixed path limits SSRF value. |
| Redirect test accept without timeout (8) | Defer | Only hangs if validation changes. |
| Extract not drained to EOF (9) | Defer | Matters only under `--skip-verify`; meta hashes still bind the content. |
| `create_new` then `fs::write` by path; orphan deposit on local failure; `expires` unvalidated; manifest read uncapped in `open` (9) | Defer | Low impact; capped read is a one-liner (`read_small`). |
| Silent skip of corrupt key line; empty `out_dir` left; `test_support` thread-local (9) | Defer | Diagnosability only (see M11). |
| Negative CCTV expectations aliased (10) | Defer | Documented, as the README permits. |
| Scrypt never opened by an independent implementation (10) | **Must fix or disclose** (I8) | The evidence currently overclaims. |
| Stale doc lines; Windows CI age path (10) | Closed / Defer | Windows CI is green with `SEALDROP_REQUIRE_AGE=1`. |
| 404-before-token leak; any token reads any receipt; `token new` replaces; blocking SQLite under std `Mutex`; no graceful shutdown or header timeouts; retention purge untested (12) | Defer, except retention, which is **I6** | Single-org deployment; the proxy provides timeouts. Retention semantics must be disclosed. |
| Rollback journal vs `secure_delete`; limiter map growth; `--rate-capacity 0`; key/pub match not checked; no schema migration; Unix asserts Linux-only (12) | Defer, except `--rate-capacity 0`, which is folded into **I5** | |
| `Error::Extract` exits 1; symlinked input takes target name; Windows `\\?\` in output; bech32 inline (11) | Defer | Cosmetic; `\\?\` could be stripped with `dunce` later. |
| Interactive prompt echoes (11) | Defer (M2) | Disclosed in help. |
| No `--qr` rendering test; timed packages hashed twice (11) | Defer | Performance only. |
| No list of sent packages; first-run banner layout (13) | Defer | Manifest picker is acceptable for 0.2. |
| `get_settings` returns the token; header/manifest cross-check duplicated (14) | Defer | The WebView is trusted under a strict CSP; move the cross-check into core alongside the C1 fix. |
| `UnlockResponse.now` required; env overrides settings; `saved_to ""`; RUSTSEC-2024-0370 ignore; engines `>=22`; doc wording; temp removal not retried; UI must pass absolute paths (14) | Defer | Absolute paths are enforced server-side. |
| Seal.tsx and Open.tsx size; mock chunk ships; clipboard note; Open host line from the unsigned header; countdown after sleep; no frontend tests (15) | Defer | Mock is unreachable in the Tauri WebView; the host line is labelled unverified; stale detection exists. |

## Spec gaps

| Spec § | Requirement | Status |
|---|---|---|
| 4.1 | Meta paths pass the extraction checks | **Not enforced at pack time** (I1). |
| 5.5 | Passphrase inner recipients under timed release | **Seals but cannot open** (C1). |
| 5.5 | Retention 90 days for receipt rows | Extended to purge never-unlocked deposits; **undisclosed** (I6). |
| 5.5 | Per-IP rate limiting behind a TLS reverse proxy | Per-peer only; collapses to global behind a proxy (I5). |
| 5.5 / 1 | README with a Caddy example and a Docker image | Task 17 (README). No `Dockerfile` exists yet; track it there. |
| 8 | Usage error for seal without `-r` or `--passphrase` | Exits 3 rather than 1 (M3). |
| 8 | Exit codes 0/1/2/3 only | A BrokenPipe panic exits 101 (I4). |
| 9 | Tauri `http` capability scoped to the service URL | Replaced by **no** http capability; networking is in Rust via ureq. Stricter; justified. |
| 9 | Keys shows receipts for packages the user sent | Manifest picker rather than a list. Acceptable; deferred. |
| 1, 11 | All 147 CCTV vectors run | 128 run, 19 hybrid skipped (age 0.12.1 has no hybrid identity). Justified, asserted and reported. |
| 11 | Stock age decrypts a scrypt package | **Not done**; the test uses the age crate (I8). |
| 11 | Stock `age -d` fails on a timed-release file | Manual evidence only (M10). |
| 11 | Service test: after 410 "the key row is gone" | Not directly asserted (M9). |
| 11 | Desktop screens exercised in the in-app browser | Mock mode only; the real app was never launched (I9). |
| 12 | `cargo clippy --all-targets` and `cargo test --workspace` in CI | Desktop crate excluded (I7). |
