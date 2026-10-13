# Validation evidence for sealdrop 0.2.0

Toolchain gates, tests, CCTV, interop, the desktop build, the two regenerated screenshots and the real desktop runs were re-run on branch `main` at commit `10cf7bd` (the final-review fix wave; the docs-only commit that updates this file sits on top). The manual CLI timed-release session further down was recorded earlier, at `6913101`, and is kept as it was (Windows 11, `cargo` 1.96.0, Node 20.18.0, Go `age` v1.3.2, `tauri-cli` 2.11.2). Everything below comes from commands run for this document. The Code Reviewer and Reality Checker passes are separate and are not recorded here.

## Summary

| Command | Result |
|---|---|
| `cargo fmt --all --check` | pass (no output, exit 0) |
| `cargo clippy --workspace --all-targets -- -D warnings` | pass (`Finished`, no warnings) |
| `cargo test --workspace` (`SEALDROP_REQUIRE_AGE=1`) | pass: 145 passed, 0 failed, 0 ignored |
| `cargo deny check licenses advisories` | `advisories ok, licenses ok` (one warning: unused license allowance) |
| CCTV (`--test cctv`) | `total=147 passed=128 skipped=19 failed=0` |
| Interop (`--test interop_age`) | 3 passed, 0 failed. Recipient-mode packages opened by stock age (2 tests run the Go CLI); scrypt-mode verified with the age crate only |
| `npm run build` (apps/desktop) | pass (needs the Node 20 workaround below) |
| `cargo tauri build` | pass: exe, MSI and NSIS installer produced |
| Manual timed-release run | open before expiry exit 0; open after expiry exit 2, "expired" |
| Screenshots | 7 PNGs, each 1120x760 (`seal-passphrase.png` and `open-timed.png` regenerated at `10cf7bd`) |
| Desktop, real app | `npx tauri dev` driven over CDP (seal, probe, verify, open, receipt, temp-folder removal on close); release exe started and answered for 10 s |
| `sealdrop recipient \| true` | exit 0, nothing on stderr (was exit 101, panic) |

## Tests per crate

From `cargo test --workspace 2>&1 | tee $TEMP/sealdrop-test.log`, with `SEALDROP_REQUIRE_AGE=1` and Go `age` on `PATH`. The log has no line containing "warning", and 145 lines matching `^test .* ok$`.

| Crate | Test binary | Passed |
|---|---|---|
| sealdrop-cli | unit (`src/main.rs`) | 6 |
| sealdrop-cli | `tests/cli.rs` | 13 |
| sealdrop-core | unit (`src/lib.rs`) | 75 |
| sealdrop-core | `tests/cctv.rs` | 1 (runs the 147 CCTV vectors, see below) |
| sealdrop-core | `tests/interop_age.rs` | 3 |
| sealdrop-core | `tests/malicious_tar.rs` | 15 |
| sealdrop-core | `tests/no_memory_seam.rs` | 1 |
| sealdrop-core | `tests/roundtrip_prop.rs` | 1 |
| sealdrop-desktop | unit (`src/main.rs`) | 16 |
| sealdrop-release | unit (lib and main) | 0 |
| sealdrop-release | `tests/cli.rs` | 2 |
| sealdrop-release | `tests/service.rs` | 12 |
| Doc-tests | sealdrop_core, sealdrop_release | 0 |
| **Total** | | **145** (6+13+75+1+3+15+1+1+16+2+12) |

The `test result` lines from the log, in order (executable hash suffixes dropped, the crate added in parentheses; counts and timings are as printed):

```
Running unittests src\main.rs (sealdrop-cli)        test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
Running tests\cli.rs (sealdrop-cli)                 test result: ok. 13 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 3.28s
Running unittests src\lib.rs (sealdrop-core)        test result: ok. 75 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 23.56s
Running tests\cctv.rs                               test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 17.64s
Running tests\interop_age.rs                        test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 10.55s
Running tests\malicious_tar.rs                      test result: ok. 15 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.07s
Running tests\no_memory_seam.rs                     test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
Running tests\roundtrip_prop.rs                     test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.91s
Running unittests src\main.rs (sealdrop-desktop)    test result: ok. 16 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.87s
Running unittests src\lib.rs (sealdrop-release)     test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
Running unittests src\main.rs (sealdrop-release)    test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
Running tests\cli.rs (sealdrop-release)             test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.31s
Running tests\service.rs                            test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
Doc-tests sealdrop_core                             test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
Doc-tests sealdrop_release                          test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

## CCTV vectors

```
$ cargo test -p sealdrop-core --test cctv -- --nocapture 2>&1 | grep -E "total|passed|skipped|failed"
CCTV: total=147 passed=128 skipped=19 failed=0
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 17.87s
```

147 vectors, 128 passed, 19 skipped, 0 failed. The 19 skipped are the hybrid (`age1pq`) vectors, and the run prints the reason for each one, for example:

```
SKIPPED hybrid_uppercase (expect=no match): identity type not supported by age 0.12.1: the first argument in the mlkem768x25519 stanza is uppercase
```

## Interop with stock age

```
$ age --version
v1.3.2
$ SEALDROP_REQUIRE_AGE=1 cargo test -p sealdrop-core --test interop_age -- --nocapture 2>&1 | grep -iE "test |skipping|result"
test stock_age_decrypts_recipient_mode_and_tar_extracts ... ok
test scrypt_mode_opens_with_the_age_crate_not_the_go_cli ... ok
test stock_age_rejects_argon2id_package ... ok
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 10.55s
```

Interop: recipient-mode packages opened by stock age (2 tests run the Go `age` CLI: the recipient-mode decrypt and the refusal of an Argon2id package); scrypt-mode verified with the age crate only. The Go CLI reads a passphrase only from a terminal and has no non-interactive input, so the scrypt test decrypts with the `age` crate, the same implementation that wrote the file; it shows format conformance, not independent interop. No "skipping" line appears. The manual session below also has stock `age -d | tar -t` listing a recipient-mode package, and failing on a timed-release package (by design, see the limitations).

## clippy, fmt, deny

```
$ cargo fmt --all --check; echo "fmt exit=$?"
fmt exit=0

$ cargo clippy --workspace --all-targets -- -D warnings
    Checking sealdrop-core v0.2.0 (M:\Projects\sealdrop\crates\sealdrop-core)
    Checking sealdrop-release v0.2.0 (M:\Projects\sealdrop\crates\sealdrop-release)
    Checking sealdrop-desktop v0.2.0 (M:\Projects\sealdrop\apps\desktop\src-tauri)
    Checking sealdrop-cli v0.2.0 (M:\Projects\sealdrop\crates\sealdrop-cli)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 11.98s

$ cargo deny check licenses advisories
warning[license-not-encountered]: license was not encountered
  --> M:\Projects\sealdrop\deny.toml:2:116
   unmatched license allowance "Apache-2.0 WITH LLVM-exception"

advisories ok, licenses ok
```

(Both outputs are trimmed to the relevant lines: the clippy dependency `Checking` lines are omitted, and the deny warning's box drawing is condensed.)

## Desktop build

```
$ cd apps/desktop && npm i --no-save --force @rolldown/binding-win32-x64-msvc && npm run build
found 0 vulnerabilities
dist/assets/webview-BjKnOuh1.js                              16.34 kB │ gzip:   3.51 kB
dist/assets/index-D3afWirr.js                               339.23 kB │ gzip: 105.87 kB
(plus index.html, CSS, fonts and small chunks)
✓ built in 235ms

$ cd apps/desktop && cargo tauri build      (tauri-cli 2.11.2, 4m03s)
warning: sealdrop-desktop@0.2.0: STATIC_VCRUNTIME is deprecated; use build.windows.staticVCRuntime in tauri.conf.json or tauri_build::WindowsAttributes::static_vc_runtime instead.
    Finished `release` profile [optimized] target(s) in 3m 49s
       Built application at: M:\Projects\sealdrop\target\release\sealdrop-desktop.exe
     Running candle for "M:\\Projects\\sealdrop\\target\\release\\wix\\x64\\main.wxs"
     Running light to produce M:\Projects\sealdrop\target\release\bundle\msi\sealdrop_0.2.0_x64_en-US.msi
     Running makensis to produce M:\Projects\sealdrop\target\release\bundle\nsis\sealdrop_0.2.0_x64-setup.exe
    Finished 2 bundles at:
        M:\Projects\sealdrop\target\release\bundle\msi\sealdrop_0.2.0_x64_en-US.msi
        M:\Projects\sealdrop\target\release\bundle\nsis\sealdrop_0.2.0_x64-setup.exe
```

The bundles land in the workspace `target/`, not under `apps/desktop/src-tauri/target/`.

| Artefact | Path | Size (bytes) |
|---|---|---|
| App exe | `target/release/sealdrop-desktop.exe` | 13,198,336 (rebuilt at `10cf7bd` with `npx tauri build`) |
| MSI installer | `target/release/bundle/msi/sealdrop_0.2.0_x64_en-US.msi` | 5,058,560 (rebuilt at `10cf7bd`) |
| NSIS installer | `target/release/bundle/nsis/sealdrop_0.2.0_x64-setup.exe` | 3,586,397 (rebuilt at `10cf7bd`) |
| CLI | `target/release/sealdrop.exe` | 4,893,184 |
| Release service | `target/release/sealdrop-release.exe` | 4,624,384 |

The installers were built but not installed. The app exe they ship was started directly (see "Desktop (real app)").

## Desktop (real app)

Both runs used a throwaway key store (`SEALDROP_HOME` in the session scratchpad) and WebView2's DevTools port (`WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS=--remote-debugging-port=...`), driven by a small Node script over CDP that calls the real Tauri commands through `window.__TAURI_INTERNALS__.invoke` and reads the rendered screen. Every process started was stopped by PID afterwards.

### `npx tauri dev` against a real `sealdrop-release` on `127.0.0.1:8789`

The dev log ends with `Running M:\Projects\sealdrop\target\debug\sealdrop-desktop.exe` and contains no `panic`. The CDP target was `http://localhost:1420/`, title `sealdrop`, with `__TAURI_INTERNALS__` present. Results (paths shortened, deposit token never printed):

| Step | Result |
|---|---|
| `get_identity` on an empty key store | `exists: false` |
| `generate_identity` | `exists: true`, recipient `age1k8e4j53m...`, signer `RWTzxNBT4hoZ...` |
| `set_settings` (release service URL and deposit token) | ok |
| `seal`, passphrase mode, timed release 600 s | ok: 2 files, passphrase of 6 words, 77.5 bits, `release.service = http://127.0.0.1:8789` |
| `probe` on that package | `needs_passphrase: true`, `inner_kind: "scrypt"`, timed release shown |
| `verify` | `ok: true`, `trusted_as: "self"`, recipients `[{kind: "scrypt"}]` |
| `open_package` without the passphrase | error `this package needs a passphrase` |
| `receipt_fetch` right after | `first_unlock: null`, `unlock_count: 0` (the failed open never reached the service) |
| `open_package` with the passphrase, temp folder | ok: `...\Temp\sealdrop-view-aOhvyx\1\report-q3`, `remaining_secs: 600` |
| `receipt_fetch` again | `unlock_count: 1`, `pinned: true` |
| Open screen, package picked through the real UI | the passphrase field is shown; delivery record "Signature valid. Signed by you.", "Opens with a passphrase" |
| `seal`, recipient mode (own recipient), no timer | ok |
| `probe` | `needs_passphrase: false`, `inner_kind: "x25519"` |
| `open_package` to a chosen folder | ok, files restored |
| `open_package` to the temp folder | ok: `...\Temp\sealdrop-view-aOhvyx\2\report-q3` |
| Close the window (`taskkill /PID`, no `/F`) | process gone; `Test-Path $env:TEMP\sealdrop-view-aOhvyx` is `False` |
| Console errors seen over CDP | 0 |

### Release exe

```
started PID 21776 (target\release\sealdrop-desktop.exe, built by `npx tauri build`)
alive after 10 s: True; responding: True; window title: 'sealdrop'
CDP target: http://tauri.localhost/ | sealdrop
isTauri: true
get_identity: {"exists":true,"recipient":"age1k8e4j53mxl3x..."}
page: "Seal\nLock a file or folder, sign it, and get a delivery record.\nIdentity ready\nWHAT TO SEND\n..."
taskkill /PID 21776 -> process gone
```

## CLI closed-pipe check

```
$ for i in $(seq 1 30); do ./target/debug/sealdrop recipient | true; ...; done
30 runs of 'sealdrop recipient | true': nonzero exits=0
$ ./target/debug/sealdrop recipient 2>err.txt | true      # new build
new debug binary exit 0, stderr bytes: 0
$ ./target/release/sealdrop.exe recipient | true          # binary built before the fix, for comparison
old release binary exit 101
thread 'main' (3164) panicked at ...\std\src\io\stdio.rs:1165:9:
failed printing to stdout: The pipe is being closed. (os error 232)
```

## Manual timed-release session

Recorded at `6913101`, before the fix wave (so it still shows the closed-pipe panic, since fixed, and lacks the retention sentence `seal` now prints for timed packages). CLI against the real `sealdrop-release` service on `127.0.0.1:8787`, built with `cargo build --release -p sealdrop-cli -p sealdrop-release`. Only the deposit token is redacted (`<token>`); the Windows temp directory is written as `$TEMP`. The keys and passphrase belong to a throwaway identity that was deleted afterwards. Times are UTC. The session ran as three scripts: setup through open (1), a plain-package interop check (2), and the open after expiry (3). The server stayed up between them (shell PID 1162, Windows PID 38468) and was killed afterwards.

### 1. Keygen, serve, seal, verify, open, receipt, passphrase package

```
# started 18:37:30Z
$ ./target/release/sealdrop-release keygen --dir $TEMP/sealdrop-rel
service key: RWQz/y2hfkp+N3U5lpc4X1DRf8BUU7h4XYBsCdS+xnqEQeXZl7dVU1Xf
[exit=0]
store this token securely; it is shown once
$ TOKEN=$(sealdrop-release token new alice --db $R/releases.db)   # value redacted -> <token>
$ sealdrop-release serve --db $R/releases.db --dir $R --listen 127.0.0.1:8787 &   # PID 1162
$ ./target/release/sealdrop keygen
age15m80eks8a3ednhtxupcsc9klhlkuv9mrc2mnuvn833q7ccdc8qaswhnfxj
RWQcskbnJFu1QW9biKXiHZW9pclL0FawnvJlCuDvZVuRidHGDEXSQreY
identity written to $TEMP/sealdrop-home
share the first line (your recipient) with senders; the second is your signer key
[exit=0]
$ REC=$(sealdrop recipient | head -1)   # age15m80eks8a3ednhtxupcsc9klhlkuv9mrc2mnuvn833q7ccdc8qaswhnfxj
$ ./target/release/sealdrop seal ./README.md -r age15m80eks8a3ednhtxupcsc9klhlkuv9mrc2mnuvn833q7ccdc8qaswhnfxj --expire-after 2m --release-service http://127.0.0.1:8787 -o $TEMP/sealdrop-b
packing \\?\M:\Projects\sealdrop\README.md
encrypted 3612 bytes
contacting release service http://127.0.0.1:8787
sealed: $TEMP/sealdrop-b\README.md.sealdrop.age
manifest: $TEMP/sealdrop-b\README.md.manifest.json
signature: $TEMP/sealdrop-b\README.md.manifest.json.minisig
package id: 1e796c60-1ea9-4a16-b50b-4378679d497c
ciphertext sha256: 69afeac58086a58b5d429533d3e5023faa7dba7d7610b4e9dd5c695cd4824d28
Timed release: 2m after first open, enforced by http://127.0.0.1:8787
This does not protect the contents once decrypted.
[exit=0]
# sealed 18:37:33Z
README.md.manifest.json
README.md.manifest.json.minisig
README.md.sealdrop.age
$ ./target/release/sealdrop verify $TEMP/sealdrop-b/README.md.sealdrop.age
OK: signature valid, ciphertext hash matches
package id: 1e796c60-1ea9-4a16-b50b-4378679d497c
signer: RWQcskbnJFu1QW9biKXiHZW9pclL0FawnvJlCuDvZVuRidHGDEXSQreY (self)
created: 2026-10-13T18:37:33Z
timed release: 2m after first open via http://127.0.0.1:8787
recipient: x25519 dc66d60a95854b42
[exit=0]
$ ./target/release/sealdrop open $TEMP/sealdrop-b/README.md.sealdrop.age -o $TEMP/sealdrop-r
This package uses timed release: 2m after first open, enforced by http://127.0.0.1:8787
Opening it starts or continues the window on the service's clock.
verifying manifest
contacting release service http://127.0.0.1:8787
extracting to $TEMP/sealdrop-r
restored: $TEMP/sealdrop-r\README.md (1 files, 22 bytes)
verified: signer RWQcskbnJFu1QW9biKXiHZW9pclL0FawnvJlCuDvZVuRidHGDEXSQreY (self)
first opened 2026-10-13T18:37:33Z - expires 2026-10-13T18:39:33Z (service clock)
Expiry applies to the encrypted package only; nothing can recall a file after it has been decrypted.
[exit=0]
$ ./target/release/sealdrop receipt fetch $TEMP/sealdrop-b/README.md.manifest.json
release: 89be4b2d-74cf-41a9-9b3f-c224cbb540d5
package sha256: 69afeac58086a58b5d429533d3e5023faa7dba7d7610b4e9dd5c695cd4824d28
first opened: 2026-10-13T18:37:33Z (service clock), expires 2026-10-13T18:39:33Z
unlock count: 1
service key: RWQz/y2hfkp+N3U5lpc4X1DRf8BUU7h4XYBsCdS+xnqEQeXZl7dVU1Xf
saved: $TEMP/sealdrop-b\README.md.receipt.json
[exit=0]
$ ./target/release/sealdrop seal ./LICENSE --passphrase -o $TEMP/sealdrop-p
packing \\?\M:\Projects\sealdrop\LICENSE
encrypted 14518 bytes
sealed: $TEMP/sealdrop-p\LICENSE.sealdrop.age
manifest: $TEMP/sealdrop-p\LICENSE.manifest.json
signature: $TEMP/sealdrop-p\LICENSE.manifest.json.minisig
package id: b68f557f-11d6-474e-841c-98c602c485ce
ciphertext sha256: d5333472d8c721ef8b555c995222dede577c1757ccf6f4d31480f665d1252258
passphrase: willed recycler arson ripping baking custard
entropy: 77.5 bits - send it on a different channel from the file
[exit=0]
$ age -d -i $SEALDROP_HOME/identity.txt README.md.sealdrop.age | tar -t | head
tar: This does not look like a tar archive
tar: Exiting with failure status due to previous errors
[exit=1]
```

The last command (stock `age -d | tar -t` against the timed-release package) failed. Timed-release packages wrap the key for the release service, so stock age cannot open them; the exact error is shown below. The interop line on a plain package follows.

### 2. Stock age on a plain recipient package, and on the timed package

```

thread 'main' (44436) panicked at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library\std\src\io\stdio.rs:1165:9:
failed printing to stdout: The pipe is being closed. (os error 232)
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
# plain (non-timed) package for the stock-age interop line
$ ./target/release/sealdrop seal ./LICENSE -r age15m80eks8a3ednhtxupcsc9klhlkuv9mrc2mnuvn833q7ccdc8qaswhnfxj -o $TEMP/sealdrop-c
packing \\?\M:\Projects\sealdrop\LICENSE
encrypted 14662 bytes
sealed: $TEMP/sealdrop-c\LICENSE.sealdrop.age
manifest: $TEMP/sealdrop-c\LICENSE.manifest.json
signature: $TEMP/sealdrop-c\LICENSE.manifest.json.minisig
package id: 7825e31c-4d46-4d53-bc4b-fd4f58b4b880
ciphertext sha256: 622c5df9ec0a99cd5cad4dfd832413d2860faaaba93ea6a712c415a0c5f35130
[exit=0]
$ age -d -i $SEALDROP_HOME/identity.txt $TEMP/sealdrop-c/LICENSE.sealdrop.age | tar -t | head
sealdrop/meta.json
sealdrop/payload/LICENSE
[exit=0]
# and the same stock age against the timed-release package (by design it cannot open it)
$ age -d -i $SEALDROP_HOME/identity.txt $TEMP/sealdrop-b/README.md.sealdrop.age | tar -t | head
tar: This does not look like a tar archive
tar: Exiting with failure status due to previous errors
[age exit=1]
# now 18:37:57Z
```

The `thread 'main' panicked ... failed printing to stdout` message at the top came from `sealdrop recipient | head -1` in my script, where `head` closed the pipe. It is listed under the limitations.

The exact stock-age error on the timed package, from a direct run to a file:

```
$ age -d -i $SEALDROP_HOME/identity.txt $TEMP/sealdrop-b/README.md.sealdrop.age > plain.bin
age: error: no identity matched any of the recipients
age: report unexpected or unhelpful errors at https://filippo.io/age/report
exit=1
```

### 3. Open after the window has closed (more than 2 minutes after first open)

```
# now 18:39:46Z (> 2 minutes after first open at 18:37:33Z)
$ sealdrop open $TEMP/sealdrop-b/README.md.sealdrop.age -o $TEMP/sealdrop-r2; echo "exit=$?"
This package uses timed release: 2m after first open, enforced by http://127.0.0.1:8787
Opening it starts or continues the window on the service's clock.
verifying manifest
contacting release service http://127.0.0.1:8787
error: this package has expired at the release service and can no longer be opened
exit=2
```

Exit code 2 and the message "this package has expired at the release service and can no longer be opened". The output directory was not created: `ls $TEMP/sealdrop-r2` reported "No such file or directory". The brief mentions a 410; I did not capture the raw HTTP status, so I do not claim one here. The service log contained only its startup line (`sealdrop-release listening listen=127.0.0.1:8787`).

## Screenshots

Captured from the mock-mode dev server (`npm run dev`, `http://localhost:1420`) with `npx -y playwright@1 screenshot --viewport-size=1120,760 --wait-for-timeout=2500`. Each file is 1120x760 and above 20 KB. Each one was viewed. `seal-passphrase.png` and `open-timed.png` were regenerated at `10cf7bd` after the heading focus ring was removed and the passphrase tile moved first (with `--wait-for-timeout=1500` the Open capture still showed "Contacting…", so 2500 was used, as originally).

| File | URL query | Size | What it shows |
|---|---|---|---|
| `docs/design/screenshots/seal.png` | `?screen=seal` | 167,454 B | Empty Seal form |
| `docs/design/screenshots/seal-passphrase.png` | `?screen=seal&state=success` | 186,959 B | Passphrase words, QR and entropy line first, then the Sealed result; Sending it and Timed release tiles (including the retention sentence) on the right |
| `docs/design/screenshots/open.png` | `?screen=open` | 73,412 B | Empty Open drop zone |
| `docs/design/screenshots/open-timed.png` | `?screen=open&state=success` | 139,297 B | Opened package (no focus ring on "Opened."), "Contents match the signed record", countdown "9 m 41 s" |
| `docs/design/screenshots/verify.png` | `?screen=verify&state=success` | 165,427 B | "Signature valid" result with signer and receipt check |
| `docs/design/screenshots/keys.png` | `?screen=keys&state=success` | 182,456 B | Identity, trusted signers, receipts |
| `docs/design/screenshots/settings.png` | `?screen=settings` | 202,361 B | Release service, Argon2id toggle, output, network, about |

Every screen shows its intended state; none shows an error or an empty state where a success state was requested. The data is the mock data built into the front end, and the images are not of the packaged app.

The README banner and the app icon are generated images in `docs/design/assets/` (`banner.png`, `icon.png`); its README records the Higgsfield job ids. The Tauri icon set in `apps/desktop/src-tauri/icons/` was regenerated from `icon.png` with `npx tauri icon`.

## Known limitations observed

- **Node 20 workaround.** Node here is 20.18.0. Vite prints "Vite requires Node.js version 20.19+ or 22.12+", and the build needs `npm i --no-save --force @rolldown/binding-win32-x64-msvc` first. `package.json` and the lockfile were not changed. The build and the dev server worked despite the warning.
- **Closed-pipe panic fixed.** `sealdrop recipient | head -1` (or `| true`) used to panic with exit 101; since `c9274f0` it exits 0 quietly (see "CLI closed-pipe check").
- **Timed-release packages do not open in stock age.** The stock-age run above fails with "no identity matched any of the recipients". The Settings screen already says this ("Argon2id and timed release packages need sealdrop"). Recipient-mode packages are the ones the interop tests show opening in stock age; scrypt-mode is checked with the age crate only (the Go CLI cannot take a passphrase non-interactively).
- **Passphrase prompt only partly exercised.** The CLI e2e test `timed_release_with_passphrase_prompts_and_never_unlocks_without_it` shows `open` prompting for a timed passphrase package (it reads stdin) and opening with `--passphrase-stdin`. A typed interactive passphrase at a real terminal was not tested; the help text says the prompt shows what you type.
- **`cargo tauri build` warning.** `STATIC_VCRUNTIME is deprecated; use build.windows.staticVCRuntime in tauri.conf.json ...`. The build succeeded.
- **`cargo deny` warning.** The allow list has an unused entry (`Apache-2.0 WITH LLVM-exception`). The check still reports `advisories ok, licenses ok`.
- **Screenshot cosmetics fixed.** The passphrase tile is now first (above the fold at 760 px) and programmatically focused headings carry `.no-ring`, so neither regenerated screenshot shows a focus ring.
- **Installers not installed.** The dev app and the release exe were run (see "Desktop (real app)"); the MSI and NSIS installers themselves were built but not installed. The real-app run drove the commands over CDP and checked one screen (Open) in the real UI; the other screens were exercised in mock mode only. Argon2id sealing and the expired-window path were not repeated in the real app (both are covered by core and CLI tests).
