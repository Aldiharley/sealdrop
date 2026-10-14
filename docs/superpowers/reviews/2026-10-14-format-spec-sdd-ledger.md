# SDD ledger — plan: docs/superpowers/plans/2026-10-14-format-spec.md
Task 1: implemented 7a78284 (spec 898 lines + CC0). Author found bugs (code untouched): encoder does not cap meta.json at 1 MiB (9000-file folder seals but cannot open) — FIX WAVE; GNU `dir/` trailing-slash names rejected on extract (document or accept) — FIX WAVE decide; README/CLI help say `age1pq…` but hybrid recipients are `age1tagpq1…` and `age1pq1…` parses as plugin "pq" — FIX WAVE docs.
Task 1: review: 0 value mismatches (40+ checked); 6 Important wording/consistency (timed-release overstatement, two-pass hash/decrypt claim, abstract vs encoder gaps -> Appendix C, Unicode whitespace rule, error taxonomy, §11 consistency) — fix round 1 dispatched.
Task 1: minor (deferred to code): open() hashes then decrypts in two passes (in-place rewrite between passes defeats the check) — consider hash-while-decrypt; validate_service_url lets `https://a:b` through via rsplit_once; encoder does not enforce §6 limits.
Task 1: fix round 1/5 (6 Important + minors addressed, 0 open; commits 7a78284..4bb07c6)
Task 1: complete (commits bed28ac..4bb07c6, review clean)
Task 1: minor (deferred): abstract says Appendix C lists every shortfall but three are inline-only (+/leading zeros accepted; extra real stanzas not rejected; duplicate tar entries not rejected) — add rows; §2.3 classes decryption-failure/no-matching-keys/release-error have no `expect` value (say so); §6.1 "can differ" → "is intended not to differ".
Task 2: implemented 3277f5f; review: 2 Important (vector file names vs manifest ciphertext.file; receipt `expected` keys outside §11) + minors — fix round 1 dispatched.
Task 2: minor (deferred): none beyond those folded into the fix round.
Task 2: fix round 1/5 (2 Important + minors addressed; 2 open items ruled benign — receipt signature bytes differ only via minisign's timestamped untrusted comment (Task 3 verifies cryptographically); README:40 stale path folded into Task 3; commits 3277f5f..8454317)
Task 2: complete (commits 4bb07c6..8454317, review clean)
Task 3: complete (commits 8454317..6893c19, review clean)
Task 3: minor (deferred): VectorFetch ignores the unlock token (by design; say so in §11); stock_age unvalidated on package-less vectors; `rejects` checks exit code only; CI clippy lacks --features test-support.
Final review (final-review.md): 0 Critical, 5 Important (timed vectors not passable by spec-following decoders; age1pq docs wrong; encoder lacks meta/§6 limits; "any ustar reader" overclaim; trailing-slash wording), 10 minors in wave, 3 deferred (two-pass hash; a:b:443; rejects stderr; refuse age1pq1 in parser). ONE fix wave dispatched; version → 0.2.2.
Fix wave: 6893c19..03be36a (I1–I5, M1–M10, rustls advisory bump; 156 tests). Scoped re-review: all addressed, no new breakage. Deferred: two-pass hash in open; validate_service_url a:b:443; `rejects` stderr check; refuse age1pq1 in parser; per-vector header-failure class (needs §11 field); trailing-slash code relaxation.
PLAN COMPLETE.
