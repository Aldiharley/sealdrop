# Contributing to sealdrop

Thanks for helping. Bug reports, tests and small fixes are the most useful. For anything large, open an issue first so we can agree on the approach. For security problems, do not open an issue: see [SECURITY.md](SECURITY.md).

## Layout

| Path | What it is |
|---|---|
| `crates/sealdrop-core/` | Library: packing, age encryption, manifest, extraction, keys, policy |
| `crates/sealdrop-cli/` | The `sealdrop` binary |
| `crates/sealdrop-release/` | The `sealdrop-release` key-release service (axum + SQLite) |
| `apps/desktop/` | Tauri 2 app (`src-tauri/` Rust side, `src/` React UI) |
| `testkit/` | C2SP CCTV age test vectors |
| `docs/` | Design spec, research, validation evidence, design assets |

The design spec is [docs/superpowers/specs/2026-10-13-sealdrop-core-cli-desktop-design.md](docs/superpowers/specs/2026-10-13-sealdrop-core-cli-desktop-design.md). Read it before changing formats or the extraction rules.

## Dev setup

You need:

- **Rust**, stable (`rust-toolchain.toml` pins `stable` with `rustfmt` and `clippy`; the minimum is 1.85).
- **Node 22.12 or newer** for the desktop app. Vite needs it. Older Node may print a warning and the build can fail on optional native bindings.
- **Go `age`** for the interop tests. Install it with `go install filippo.io/age/cmd/age@latest` and make sure `age` is on your `PATH`. Without it the interop tests skip, unless you set `SEALDROP_REQUIRE_AGE=1`, in which case they fail. CI sets it, and you should too.
- **Tauri CLI** to build the desktop bundle: `cargo install tauri-cli --version "^2" --locked`.
- Optional: `cargo-deny` for the licence and advisory check.

```sh
git clone https://github.com/Aldiharley/sealdrop
cd sealdrop
cargo build --workspace --exclude sealdrop-desktop
```

## Tests

Run these before you push. They are what CI runs.

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --exclude sealdrop-desktop -- -D warnings
SEALDROP_REQUIRE_AGE=1 cargo test --workspace --exclude sealdrop-desktop
cargo deny check licenses advisories
```

On PowerShell, set the variable first: `$env:SEALDROP_REQUIRE_AGE = "1"`.

The desktop crate needs the built front end, so CI checks it in a separate job:

```sh
cd apps/desktop
npm ci
npm run build
cd ../..
cargo clippy -p sealdrop-desktop --all-targets -- -D warnings
cargo test -p sealdrop-desktop
```

To build the installers: `cd apps/desktop && cargo tauri build`.

For the UI in a browser with built-in sample data (this is how the README screenshots are made): `cd apps/desktop && npm run dev`, then open `http://localhost:1420/?screen=seal` (other screens: `open`, `verify`, `keys`, `settings`; add `&state=success` for the result states).

Notes on the suites:

- `crates/sealdrop-core/tests/cctv.rs` runs all 147 CCTV vectors. 19 hybrid post-quantum vectors are skipped and print the reason. A change that makes a vector fail, or that changes the skipped count, needs an explanation in the PR.
- `crates/sealdrop-core/tests/malicious_tar.rs` has a hand-built archive for each extraction rule. Add one for any rule you add or change.
- `crates/sealdrop-core/tests/format_vectors.rs` runs every vector in `spec/vectors/` against the reference implementation, and checks the `stock_age` claims with the Go `age` binary. It needs no feature (it is part of `cargo test --workspace`); to run it alone and require Go `age`: `SEALDROP_REQUIRE_AGE=1 cargo test -p sealdrop-core --test format_vectors`.
- New behaviour needs a test written first.

### Regenerating the format test vectors

The vectors in `spec/vectors/` are committed. Regenerate them only when the format spec changes, with:

```sh
SEALDROP_VECTORS_FORCE=1 cargo test -p sealdrop-core --features test-support --test format_vectors_gen -- --ignored regenerate_format_vectors
```

Without `SEALDROP_VECTORS_FORCE=1` the generator keeps every vector directory that already exists. The generator needs the `test-support` feature for its in-process deposit intercept (the timed-release vectors name `https://release.invalid`). Ciphertexts change on every regeneration (age uses fresh randomness, and manifests carry new timestamps and package ids) but what each vector tests does not, so review the diff for semantics, not bytes. Run `format_vectors` afterwards and commit the regenerated files together.

### Running the release service locally

The service tests (`crates/sealdrop-release/tests/`) and the CLI timed-release tests (`crates/sealdrop-cli/tests/cli.rs`) start the service in-process on `127.0.0.1` with a random port. You do not need to run anything yourself for `cargo test`.

To try timed release by hand, run a local service and use a throwaway key store:

```sh
cargo build --release -p sealdrop-cli -p sealdrop-release
mkdir -p /tmp/rel
./target/release/sealdrop-release keygen --dir /tmp/rel
./target/release/sealdrop-release token new me --db /tmp/rel/releases.db   # prints the deposit token once
./target/release/sealdrop-release serve --listen 127.0.0.1:8787 --db /tmp/rel/releases.db --dir /tmp/rel &

export SEALDROP_HOME=/tmp/sealdrop-home          # throwaway keys
export SEALDROP_RELEASE_TOKEN=<token printed above>
./target/release/sealdrop keygen
./target/release/sealdrop seal ./some-file -r "$(./target/release/sealdrop recipient | head -1)" \
  --expire-after 2m --release-service http://127.0.0.1:8787 -o /tmp/out
./target/release/sealdrop open /tmp/out/some-file.sealdrop.age -o /tmp/restored
```

The client only accepts `https://` service addresses, or `http://` to loopback. Details of the service are in [crates/sealdrop-release/README.md](crates/sealdrop-release/README.md).

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org): `type: short summary` in the imperative, with a body when the reason is not obvious.

Types in use: `feat`, `fix`, `docs`, `test`, `chore`, `ci`. Example: `fix: timed passphrase without manifest`.

One logical change per commit. Keep `main` green: fmt, clippy and tests pass on every commit.

## Pull requests

- Describe what changed and why, and how you tested it.
- Do not add dependencies without a reason. `deny.toml` limits licences, and new crates are checked by `cargo deny`.
- Keep documentation true to the code. If you change a flag, an exit code or a limit, update the README in the same PR. Do not add claims the tests do not back.
- Never commit key files, identities, tokens or `.age`/`.minisig` files outside `testkit/` (`.gitignore` blocks them; do not force-add).

## Licence

By contributing you agree that your contribution is licensed under the [Apache License 2.0](LICENSE).
