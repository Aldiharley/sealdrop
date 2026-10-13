# SDD ledger — plan: docs/superpowers/plans/2026-10-13-sealdrop-0.2.md
Task 1: implemented c14e5e4; review found 3 Important plan-mandated defects (gitignore negation order, CI PATH env override, deny.toml missing CDLA-Permissive-2.0) — controller accepted all three as plan bugs; plan text to be amended. Minor (deferred): desktop CI job red until Task 15 (guard added in fix round), age@latest unpinned, actions pinned by tag, .env.example ignored.
Task 1: fix round 1/5 (4 addressed, 0 open; commits c14e5e4..f5258d9)
Task 1: complete (commits ba68795..f5258d9, review clean)
Task 2: complete (commits 970ffec..1f808bc, review clean)
Task 2: minor (deferred): pack.rs file-size change between pass 1 and 2 not detected (use .take(fe.size) and error on short read); lossy non-UTF-8 names may collide; pack(".") fails because file_name() is None (CLI/Task 11 must canonicalize input); missing tests for symlink skip / empty root / nested empty dirs; walkdir errors lose io::ErrorKind.
Task 3: implemented 414734d + 503ba45 (pre-review hardening: Windows alias chars, DuplicatePath); review: 2 Important (unbounded tar extension headers -> GuardedReader; missing limit/cleanup tests), fix round 1 dispatched.
Task 3: minor (deferred): overwrite path deletes old tree before rename and races exists() check; exists() follows symlinks (use symlink_metadata); case-insensitive FS collisions (r/a vs r/A) and duplicate tar entries for one path accepted; directory entries unrestricted; reserved-name list omits COM0/LPT0/CONIN$; DEL (0x7f) not rejected; leftover .sealdrop-* dir if process killed.
Task 3: fix round 1/5 (2 Important + minors addressed, 0 open; commits 503ba45..1d14e5b)
Task 3: complete (commits 1f808bc..1d14e5b, review clean)
Task 3: minor (deferred): GuardedReader max_input_bytes branch untested; base-256 size decoding / >=8 GiB untested; PAX payload containing literal "size=" over-refused (deliberate); test name round_trips_long_names_through_pax_headers misleading (GNU L).
Task 4: pre-review fix 9fcd1ee (zeroize words); complete (commits 1d14e5b..9fcd1ee, review clean)
Task 4: minor (deferred): Zeroizing<Vec<String>> Debug forwards — never log p.words; SecretString::from(String) may realloc on into_boxed_str; generate() rebuilds the word Vec per call.
Task 5: fix round 1/5 (2 Important + minors addressed, 0 open; commits 749cdee..606f48b)
Task 5: complete (commits edd4619..606f48b, review clean)
Task 5: minor (deferred): hybrid (age1pq) parse branch has no round-trip test (no public tagpq identity); SCRYPT_MAX_DECRYPT_LOG_N enforcement untested; plugin Display keeps input case so fingerprints can differ by case; large_enum_variant allowed rather than boxed; kind()/plugin_name() asserts could move to parses_plugin_recipient_name.
Task 6: implemented 68c7056; review Approved-with-Important (zeroize gaps on decrypt, Params::new rejects -> InvalidHeader, exact-variant tests) — fix round 1 dispatched.
Task 6: minor (deferred): log2_ceil-based ExcessiveWork message misleading when t/p caused refusal; parse::<u32> lenient ("+5"); with_params unbounded (caller can make unreadable files); AEAD not key-committing (same as age scrypt; header MAC mitigates); 2 GiB alloc failure behaviour unverified.
Task 6: fix round 1/5 (3 Important addressed, 0 open; commits 68c7056..3d472c1)
Task 6: complete (commits 8c0d085..3d472c1, review clean)
Task 6: minor (deferred): Key::from(*key) leaves an unzeroized GenericArray copy on stack (wrap+unwrap); BadParams mapping unreachable/untested after up-front check.
Task 7: implemented 7da452a; review: 4 Important (probe panic on crafted armor; generate overwrites lone identity.txt; secret hygiene overstated; release-stanza parse untested) + security minors (trusted name allow-list) — fix round 1 dispatched.
Task 7: minor (deferred): release-stanza with wrong arity silently skipped / duplicates last-wins; probe end>HEADER_MAX check dead (armored effective limit ~48 KiB); serde_json settings errors may echo scalar values; one corrupt trusted/*.pub fails trusted() for all; save_settings creates dir without 0700 pre-keygen; release_token not a zeroizing type; manifest from_json does not validate package_id/hashes/file shapes (Task 9 must validate ciphertext.file); verify() does not bind trusted comment to package_id (Task 9 must).
Task 7: fix round 1/5 (4 Important + 2 minors addressed, 0 open; commits 7da452a..e4325ea)
Task 7: complete (commits e25e103..e4325ea, review clean)
Task 7: minor (deferred): empty .tmp left if set_permissions fails on Unix; valid_name permits CON/NUL names; generate not atomic across the two files; save_settings/Settings.release_token plain String; Unix 0600 test unverified on this host (CI ubuntu will run it).
Task 8: implemented 37ebd49; review: 2 Important (unvalidated service URL/release_id -> SSRF; verify_receipt(None) TOFU undocumented) — fix round 1 dispatched (also: deposit returns service_key to pin in manifest; timeouts; wrap caps). Design note: age adds *-grease stanzas; "exactly one stanza" means exactly one real stanza.
Task 8: minor (deferred): Key::from(*k) stack copy (same as Task 6); MemoryFetch ignores service/release_id and models no window/count; no last_unlock test; 64-cap enforced after serde alloc (bounded by header size + AEAD).
Task 8: fix round 1/5 (2 Important + minors addressed, 1 open — ureq follows redirects, defeats loopback-only http rule; commits 37ebd49..33ed0e5)
Task 8: minor (deferred): memory:// accepted by production validator (no transport, harmless); Recipient::new infallible (seal validates first); deposit non-201/missing-key paths untested until Task 12; https to private IP literals allowed by policy; port digits unbounded (99999).
Task 8: fix round 2/5 (1 addressed, 0 open; commits 33ed0e5..3f7e3b8)
Task 8: complete (commits 089c8f5..3f7e3b8, review clean)
Task 8: minor (deferred): redirect test's accept thread has no timeout (hang only if a future validation change rejects the test URL).
Task 9: implemented 8afa9e4; review: 1 Important (memory:// deposit shortcut ungated in production) + security minors (TOCTOU hash/decrypt, out_dir inside input, swallowed key errors) — fix round 1 dispatched.
Task 9: minor (deferred): extract never drains reader to EOF (matters only under skip_verify); create_new handle dropped then fs::write by path; signing keys loaded after deposit (orphan deposit on local failure); input "." has no file name (CLI must canonicalize); expires unvalidated/advisory; manifest read without size cap in open (from_json caps at 1 MiB after read).
Task 9: fix round 1/5 (1 Important + 4 minors addressed, 0 open; commits 8afa9e4..7911dbd)
Task 9: complete (commits 3f7e3b8..7911dbd, review clean)
Task 9: minor (deferred): corrupt AGE-SECRET-KEY line + plugin line silently skipped (diagnosability); create_dir_all(out_dir) before the inside-input guard leaves an empty dir; pre-existing-manifest test covers only the pre-check path; verify_with relies on callers for offset 0; test_support is thread-local (consumer tests must seal and read on one thread).
Plan change: Task 12 (service) executes BEFORE Task 11 (CLI); CLI e2e timed-release test runs the real service in-process; no crate enables test-support, so no_memory_seam stays live under --workspace.
Task 10: implemented 18fd5de (testkit subtree) + 357e760 (tests); CCTV 128/147 pass, 19 hybrid-PQ skipped (age 0.12.1 has no tagpq::Identity); interop 3/3 vs Go age v1.3.2. Pre-review fix dispatched: leading whitespace before armor (armor_whitespace_outside). Note for README: sealdrop keygen makes X25519 identities only; it can encrypt TO age1pq recipients but cannot act as a PQ recipient until the age crate ships a PQ identity.
Task 10: pre-review fix 978174c (leading whitespace before armor); review: 1 Important (proptest self-referential) + minors — fix round 1 dispatched.
Task 10: minor (deferred): negative CCTV expectations aliased to any setup error (README-permitted); scrypt output never opened by an independent implementation (Go CLI has no non-interactive passphrase flag) — state in README; only binary recipient-mode checked against stock age.
Task 10: fix round 1/5 (1 Important + 3 minors addressed, 0 open; commits 978174c..d3eba1b)
Task 10: complete (commits 7911dbd..d3eba1b, review clean)
Task 10: minor (deferred): age@latest unpinned in CI; stale doc lines in interop_age.rs; Windows CI age-on-PATH path unverified until first windows run.
Task 12: implemented 22fe7fc; review: 2 Important (service.key/db default perms + silent keygen overwrite; README rate-limit claim wrong) + hardening minors — fix round 1 dispatched.
Task 12: minor (deferred): 404-before-token existence leak (UUID ids); any deposit token can fetch any receipt (no per-token scoping); token new <name> silently replaces; blocking SQLite behind std Mutex (poison on panic); no graceful shutdown / header timeouts (rely on proxy); retention purge untested beyond the new orphan test.
Task 12: fix round 1/5 (2 Important + minors addressed, 0 open; commits 22fe7fc..5738797)
Task 12: complete (commits d3eba1b..5738797, review clean)
Task 12: minor (deferred): rollback journal not covered by secure_delete (consider journal_mode=MEMORY, note in README); limiter map can exceed threshold under /64 rotation; --rate-capacity 0 unvalidated; load_signer does not check key/pub match; schema has no migration (unreleased); Unix 0600 asserts run only on Linux CI.
Task 11: implemented b22a770; review: 4 Important (clap usage exits 2; open notice lacks window; unverified header text printed; receipt token-gate untested) + minors — fix round 1 dispatched.
Task 11: minor (deferred): Error::Extract exits 1 (arguably policy); symlinked input takes target name; interactive prompt echoes (0.2); Windows stderr shows \?\ canonical path; bech32 pinned inline not via workspace.
Task 11: fix round 1/5 (4 Important + minors addressed, 0 open; commits b22a770..305957b)
Task 11: complete (commits 5738797..305957b, review clean)
Task 11: minor (deferred): open.rs/verify.rs print the signed manifest's service raw (sanitize); no --qr rendering test; timed packages hashed twice (CLI verify + core verify).
Task 13: implemented 16e2805 (brief + tokens; .aa contrast layer adopted as mandatory); review: 6 Important (passphrase reveal unmet; network copy contradicts spec; skip-verify integrity line; unpinned receipt "verified"; hardware-only rule under-specified; Keys countdown has no clock) — fix round 1 dispatched with the backend contract decided by the controller.
Task 13: minor (deferred): no list of sent timed packages (0.2 uses a manifest picker); first-run banner may push the primary action below 760px.
Task 13: fix round 1/5 (5 addressed, 3 open — seal-success wireframe missing; "nothing leaves the computer" residual; countdown source says expires_at; new: seal-side signature wording unimplementable; commits 16e2805..3a81d07); fix round 2 dispatched.
Task 13: fix round 2/5 (6 addressed, 2 open + 1 minor — settings purpose sentence contradicts Network tile (controller wording), section 10 bullet still says expires_at, "Signed by a key you haven't trusted" label; commits 3a81d07..33e0c38); fix round 3 dispatched.
Task 13: fix round 3/5 (3 addressed, 0 open; commits 33e0c38..8830cf1)
Task 13: complete (commits 855a811..8830cf1, review clean)
Task 14: implemented 967be76 (service `now` plumbing) + 7560440 (Tauri shell + commands); review: 1 Important (predictable /tmp view root) + minors (absolute-path guard, Node 22 CI, zeroized passphrase arg, CLI-flavoured hints) — fix round 1 dispatched.
Task 14: minor (deferred): get_settings returns the plaintext token (UI must use a password input; consider has_token later); header-vs-manifest cross-check duplicated from CLI (move into core later); UnlockResponse.now required (fails closed vs pre-0.2 service); SEALDROP_RELEASE_TOKEN env silently overrides settings; receipt_verify returns saved_to "" (UI types must tolerate); deny.toml ignore for RUSTSEC-2024-0370 (gtk3 build-time macro).
Task 14: fix round 1/5 (1 Important + 4 minors addressed, 0 open; commits 7560440..d1043f6)
Task 14: complete (commits 8830cf1..d1043f6, review clean)
Task 14: minor (deferred): engines >=22 looser than Vite's >=22.12; remove_view_dir doc says "folders"; failed temp removal not retried; UI must always pass absolute paths.
Task 15: implemented 7692c95 (five screens, mock mode, real app driven end-to-end incl. timed release); review: 2 Important (field errors not announced; Open expected-signer mismatch shows tamper copy) + minors — fix round 1 dispatched.
Task 15: minor (deferred): Seal.tsx 872 lines / Open.tsx 721 (split later); mock chunk ships in release bundle (dead code); CopyButton clipboard-clear note inline only; Open host line from unsigned header (backend cross-checks); Countdown lags after system sleep (display only); no frontend tests (none required).
Task 15: fix round 1/5 (2 Important + minors addressed, 1 new open — Open "Check again" calls receipt_fetch (sender token) — controller's own suggestion was wrong; commits 7692c95..1f0bc3d); fix round 2 dispatched.
Task 15: fix round 2/5 (1 addressed, 0 open; commits 1f0bc3d..6913101)
Task 15: complete (commits d1043f6..6913101, review clean)
Task 16: evidence + screenshots bce77ea (129 tests; CCTV 128/147; interop 3/3; MSI/NSIS/exe built; timed expiry proven). Findings for the final fix wave: `sealdrop recipient | head -1` panics on closed stdout pipe (os error 232) — handle BrokenPipe; programmatic heading focus shows a focus ring in screenshots (seal-passphrase, open-timed) — suppress outline on tabindex=-1 headings; seal-passphrase QR below the fold at 760px (layout).
Assets: Higgsfield icon generated (job 4e0a2a9f-c5a7-4c35-a2fd-b5d0e2ac903f, nano_banana_pro 1:1 1k) -> docs/design/assets/icon.png (1024x1024). Banner job running. Fix-wave UI item: on Seal success, render the passphrase tile FIRST (above the result tile) so it is above the fold at 760px; suppress the focus ring on programmatically-focused tabindex=-1 headings.
Reality check: 20/20 claims confirmed (reality-check.md). Final whole-branch review (final-review.md): Critical 1 (timed+passphrase packages unopenable — probe cannot see inner stanzas, no prompt), Important 9 (pack skips check_path/size race/non-UTF-8; extract --overwrite deletes before rename; raw manifest strings echoed; CLI BrokenPipe panic; rate limiter global behind proxy; retention purge undisclosed; CI excludes desktop clippy/test; scrypt interop never runs stock age; real desktop run not in evidence) + cosmetics. ONE fix wave dispatched.
Final fix wave: df56606..be33150 (12 commits; C1 + I1–I9 + cosmetics + icons; 145 tests; CI green). Scoped re-review dispatched.
Final re-review (final-rereview.md): APPROVED; 0 not addressed; Minor residuals N1 (timed passphrase w/o manifest under skip-verify) and N2 (seal passphrase lost on early pipe close) — small follow-up dispatched to the same implementer (controller judgement: cheap, user-facing, no further waves after this). Parked (deferred, ruling: cross-platform edge, documented in README limitations): folder with A.txt and a.txt sealed on Linux loses one on case-insensitive filesystems.
N1/N2 fixed: be33150..0017922 (149 tests, CI green). Task 17 (README/SECURITY/CONTRIBUTING) dispatched to Developer Advocate.
N1/N2 re-check: both ADDRESSED. Parked (ruling: requires the recipient to delete the manifest AND answer the optional prompt wrongly; spec-conformant; documented): no-manifest timed passphrase package + empty answer with an identity present contacts the service before decryption fails.
Task 16: complete (bce77ea + fix waves)
Task 17: complete (f012180 README/SECURITY/CONTRIBUTING)
PLAN COMPLETE — final review clean after one fix wave; reports copied to docs/superpowers/reviews/; workspace deleted.
