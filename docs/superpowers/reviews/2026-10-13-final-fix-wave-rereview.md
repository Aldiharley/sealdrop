# sealdrop 0.2: final-review fix wave, re-review

- **Range:** `df56606..be33150` (12 commits). Checkout at `be33150`, working tree clean.
- **Read:** the review diff (binary icon and screenshot hunks skipped), `final-review.md` C1 and I1–I9, `fix-wave-report.md`, and the current `open.rs`, `extract.rs`, `seal.rs` and desktop `commands.rs` / `Open.tsx` around the changes.
- **Ran (read-only):** `cargo test -p sealdrop-core --lib` filtered to the new tests. 15 passed, 60 filtered out, so 75 core unit tests, which matches the report. I did not re-run the workspace or CI. The 145 total and the green CI run `38454574673` are taken from the report.

## Per-finding verdict

| # | Verdict | Evidence |
|---|---|---|
| C1 | **ADDRESSED** (one residual, see N1) | See C1 below. |
| I1 | **ADDRESSED** | See I1 below. |
| I2 | **ADDRESSED** | See I2 below. |
| I3 | **ADDRESSED** | See I3 below. |
| I4 | **ADDRESSED** | See I4 below. |
| I5 | **ADDRESSED** | See I5 below. |
| I6 | **ADDRESSED** (minimum option) | See I6 below. |
| I7 | **ADDRESSED** | See I7 below. |
| I8 | **ADDRESSED** (rename-and-disclose path) | See I8 below. |
| I9 | **ADDRESSED** | See I9 below. |
| Cosmetics | **ADDRESSED** | See Cosmetics below. |

### C1: timed release with a passphrase

- **Core: signed data decides when verifying.**
  - `crates/sealdrop-core/src/open.rs:194-202` takes the inner kind from `verify_report.manifest` when verification runs.
  - It reads the unverified sidecar (`unverified_inner_kind`, `:131-144`, capped at 1 MiB) only when `skip_verify` is set.
  - Without a passphrase it refuses before the identity, wrapper or fetch is built (`:226-243`).
- **Proof that no fetch happens.** `timed_release_with_passphrase_opens_and_missing_passphrase_never_unlocks` uses `NoNetwork`, which panics if called, for both `skip_verify=false` (a verified, self-trusted manifest) and `true`. It also checks that no output folder is created. I ran this test and it passed.
- **CLI.** `crates/sealdrop-cli/src/commands/open.rs:41-91`:
  - The inner kind comes from the verified manifest in the timed branch, and from the unverified manifest only under `--skip-verify`.
  - It prompts when the kind is scrypt or Argon2id.
  - The e2e test `timed_release_with_passphrase_prompts_and_never_unlocks_without_it` runs against the in-process service. After the refused open, the receipt says "not yet opened"; after the open with the passphrase it shows "unlock count: 1".
- **Desktop.**
  - `ProbeOut.inner_kind` was added, and `probe_impl` lives at `apps/desktop/src-tauri/src/commands.rs:286-301`.
  - `Open.tsx:83-84` computes `needsPass`.
  - A recipient-key package reports `x25519`. Its `needs_passphrase` stays false, and the real-app run confirms this (`probe` → `x25519`, no passphrase). So the desktop still does not ask for a passphrase on recipient-key packages.

### I1: pack admitted names that extraction refuses

- `pack.rs:355-365` calls `crate::extract::check_path` on `PAYLOAD_PREFIX + rel`. That is the same function and the same prefix that extract uses at `extract.rs:312-314` and `:348`, so the two cannot drift.
- The check covers the root (`:390`) and every directory and file (`:414`).
- Non-UTF-8 names are refused at `:327-334` and `:341`.
- Size and content race:
  - `:522-536` reads through `.take(size)` and a hashing reader.
  - It then fails on any of three conditions: a short read, an extra byte, or a hash that differs from pass 1.
  - `seal.rs:233-240`'s `Cleanup` removes the partial package, and the deposit happens after `pack`, so nothing is left behind.
- The size-race test is deterministic. It calls `plan()`, rewrites the file, then calls `write_plan()`, and covers a file that grew, one that shrank and a same-size edit, plus the unchanged case.

### I2: `--overwrite` deleted the old tree before the rename

The new `replace()` is at `extract.rs:418-444`. It works in this order:

1. Rename the target to `<target>.sealdrop-old-<12 hex>`.
2. Rename the staged tree in.
3. Remove the backup, best effort.

If step 2 fails, it renames the backup back and calls `TempDir::keep()`.

- **The backup name already exists:** step 1 fails before anything has moved. The temp dir then drops and the old tree is untouched, so this is safe.
- **Existence checks** use `symlink_metadata`.
- **Tests** cover two cases:
  - On success the old tree is replaced and nothing parked is left.
  - On a failed move the old tree is restored and nothing parked is left.

### I3: attacker-controlled strings reached the terminal

- **`resolve_signer`** (`open.rs:26-61`) parses the signer first. An invalid signer gets a generic message with no echo and no hint.
- **Could the hint name a different key than the manifest's?** No. The hint is `parse(manifest_signer).to_base64()`, which is the manifest's own key in canonical form.
- **`sanitize`** (`sealdrop-core/src/text.rs`) uses `char::is_control` (C0, DEL and C1) plus bidi, zero-width and separator characters. The test shows it keeps accented letters, CJK and Arabic.
- **CLI:** `key_display` and `sanitize` are applied in `verify.rs`, `open.rs`, `receipt.rs`, `seal.rs`, the progress line and the final error (`main.rs:177`).
- **Desktop:** `release_out`, `ProbeRelease` and the `contacting` progress detail are sanitized.
- **ESC-sequence test:** `manifest_strings_are_sanitized_before_printing`.

### I4: panic on a closed stdout pipe

- `out!`, `write_line` and `is_quiet_exit` are in `main.rs:10-16`, `:83-101` and `:174`.
- A grep of `crates/sealdrop-cli/src` finds no `println!` or `print!` left. Only `eprintln!` remains, plus the prompt's `eprint!`.
- There is a unit test with `BrokenPipe` and disk-full writers, and the manual `| true` evidence is in VALIDATION.md.

### I5: global rate limiter behind a proxy

- `routes.rs:40-54` uses the FIRST entry of `X-Forwarded-For`, parsed as `IpAddr`.
- If the header is absent or not an IP address, it falls back to the peer.
- The header is ignored unless `trust_proxy` is set (`AppState::trusting_proxy`, `main.rs serve --trust-proxy`).
- Two axum-test tests cover this, and the README has the Caddy example and the warning.

### I6: undisclosed retention deadline

- The CLI prints the sentence in `seal.rs:193`, for timed packages only. Both cases are tested.
- The desktop shows `RETENTION_SENTENCE` in the Timed release tile (`Seal.tsx` around `:836` in the diff).
- `brief.md` has the copy row.
- The service README "Retention" section has the cross-link paragraph.
- The fuller fix the review offered (`retain_until` in the deposit response and the manifest) is deferred, and the report says so.

### I7: CI skipped desktop clippy and tests

- `.github/workflows/ci.yml` gives the toolchain `components: clippy`.
- After `npm run build` it runs `cargo clippy -p sealdrop-desktop --all-targets -- -D warnings` and `cargo test -p sealdrop-desktop`.
- Each step has the same `hashFiles` guard as its neighbours.
- The YAML is consistent. The report says CI was green; I did not check that myself.

### I8: overstated scrypt interop claim

- The test is now `interop_age.rs:106-112` `scrypt_mode_opens_with_the_age_crate_not_the_go_cli`, with an honest doc comment. It no longer has a bogus `age_available` skip.
- VALIDATION.md is corrected in four places:
  - the summary row;
  - the interop section;
  - the limitations;
  - the HEAD note (`10cf7bd` plus the docs commit; the manual session is marked as recorded at `6913101`).
- It also quotes the CCTV skip reason and mentions the assets.
- The README makes no interop claim, so it needs no change.
- Spec 11 asks for stock age to decrypt scrypt, and that remains a disclosed gap.

### I9: desktop never run against its real backend

VALIDATION.md has a "Desktop (real app)" section with two parts:

- **`tauri dev`:** a step table against the real service, including the C1 path with `receipt_fetch` showing `unlock_count 0` and then 1, and temp-folder removal on close.
- **Release exe:** it was launched and stayed responsive for 10 s.

Not covered, against the review's list: the untrusted-signer → trust flow and drag-drop in the real UI. Only the Open screen was driven in the real UI. The report and VALIDATION.md state these limits.

### Cosmetics

- **Focus ring:** `.no-ring` (`neu.css:209`) is applied to every `tabIndex=-1` heading, which are `PageHead`, `Tile` with `headingFocusable`, "Sealed." and "Opened.". A grep found none missed.
- **Seal success layout:** the passphrase tile is first.
- **Screenshots:** the two are regenerated, and the sizes match VALIDATION.md.
- **Icons:** the Tauri set is regenerated.
- **Placeholder:** `icon-placeholder.png` is deleted. Its only remaining mention is the assets README sentence saying it was removed.

## New breakage in the fix diff

No Critical or Important issues.

| # | Sev | Where | Issue |
|---|---|---|---|
| N1 | Minor (C1 residual) | `open.rs:194-199`, CLI `commands/open.rs:43-44`, desktop `commands.rs:289-293` | **What happens:** a timed passphrase package opened with `--skip-verify` / "skip check" when the `.manifest.json` is absent (the recipient has only the `.age`) gets `inner_kind = None`. No prompt is shown and no desktop field appears. If an identity exists, the core contacts the service, which starts the window, and then fails with "No matching keys".<br>**CLI:** it can still be opened with an explicit `--passphrase-stdin`, which the core accepts.<br>**Desktop:** it cannot be opened at all, because the field stays hidden.<br>**Fix:** review step 3 offered two options: always offer the passphrase for timed packages under skip-verify when there is no manifest hint, or refuse timed + skip-verify + no passphrase + no manifest. Neither was taken. |
| N2 | Minor | `main.rs:174` with `seal.rs:194-205` | Example: `sealdrop seal --passphrase … \| head -1` or `\| grep -m1 sealed:`. The pipe closes before the `passphrase:` line, `out!` returns `StdoutClosed`, and the process exits **0**. The package exists, but nobody ever saw its only key. Before the fix this was exit 101: the same loss, but loud. For `seal`, a closed stdout should probably be exit 1, or the passphrase should go out before the other lines. |
| N3 | Minor | `extract.rs:428-436` | **Wrong path:** on a failed move the error says "the new copy is in {kept}". `kept` is the `.sealdrop-*` temp dir; the tree is at `kept/<root>`.<br>**Silent leftover:** when the best-effort removal of the backup fails (`:441`), the old tree stays as `<root>.sealdrop-old-*` with no message to the user. |
| N4 | Minor (test strength) | `crates/sealdrop-cli/tests/cli.rs` (new C1 e2e) | The check that stderr contains "passphrase" is already satisfied by the prompt text itself. The no-unlock guarantee is actually shown by the follow-up receipt check ("not yet opened"), which is sufficient. |
| N5 | Minor (cosmetic) | `text.rs:650` | `sanitize` replaces U+200C/U+200D (ZWNJ and ZWJ). These are legitimate in Persian and Indic names and in emoji sequences, so such names show `?` in CLI output, including the `restored:` path. This is display only. |

There are no new `unwrap`s on untrusted data. The `[..12]` slice of a UUID's simple form is always in range.

## Out-of-scope observations

- **Case-only name collisions (pre-existing, not part of I1).** A folder sealed on Linux can hold `A.txt` and `a.txt`. `check_path` and the `DuplicatePath` map are case-sensitive. Extracting on Windows or macOS writes both into the same file, and every per-entry hash check passes, so one file is lost silently. Consider a case-folded duplicate check, either in `extract`, or at seal time with a clear error.
- **`--trust-proxy` with other proxies.** The README covers Caddy, which overwrites `X-Forwarded-For` when `trusted_proxies` is not set. It does not warn that proxies which append, such as nginx `$proxy_add_x_forwarded_for` or Caddy with `trusted_proxies`, make the first entry client-controlled.
- **`eprintln!` on a closed stderr** can still panic. This is rare and was not in scope.

## Verdict

**APPROVED.** C1 and I1–I9 are all addressed and the cosmetics are done. The fix diff introduces no Critical or Important breakage.

The fixes worth considering before release are:

- **N1:** a timed passphrase package with skip-verify and no manifest can still start the window without a passphrase. On the desktop it cannot be opened at all.
- **N2:** `seal` exits 0 when stdout closes before the passphrase is printed.
