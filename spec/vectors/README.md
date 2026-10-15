# sealdrop package format v1: test vectors

Machine-readable vectors for `spec/sealdrop-format-v1.md` (section 11). Each directory holds a
`vector.json` (schema in section 11 of the spec) and the files it names. The vectors are CC0, like the spec.

There are 20 vectors: valid packages (X25519, post-quantum `recipient-pq`, armored, scrypt and Argon2id
passphrases, two timed-release packages), header and verification failures (out-of-range Argon2id
parameters, tampered or re-signed manifest, flipped ciphertext byte, and `commitment-mismatch`, a
correctly signed manifest whose `key_commitment` does not match the file key), raw tar archives the
extractor must refuse, and two receipts. Every valid package's manifest carries `key_commitment`
(spec §5.2).

`commitment-mismatch` passes verification on its own (signature, trusted comment and ciphertext hash
are all right); it must fail only when opening, once the file key is unwrapped (spec §5.4 step 7).
`recipient-pq` is sealed to `keys/pq-identity.txt` (`age1pq1…`, stanza `mlkem768x25519`); its
`vector.json` has `"min_age": "1.3.0"`, and the conformance test skips its stock-age claim, with a
message, when the installed `age` is older.

## Keys are test-only

Everything under `keys/` (the age identity, the post-quantum identity `keys/pq-identity.txt`, the
minisign signer key, the service key pair) is public test material under CC0. Every passphrase,
`K_release` and identity inside a `vector.json` is likewise test data. Never use any of it to
protect real data. See `keys/README.md`.

## Running the conformance test against the reference

```
cargo test -p sealdrop-core --test format_vectors
```

No feature and no network are needed. With the Go `age` binary on `PATH` the test also proves
every `stock_age` claim; set `SEALDROP_REQUIRE_AGE=1` to make a missing binary an error.

## Regenerating (maintainers only)

```
SEALDROP_VECTORS_FORCE=1 cargo test -p sealdrop-core --features test-support \
  --test format_vectors_gen -- --ignored regenerate_format_vectors
```

Without `SEALDROP_VECTORS_FORCE=1` the generator keeps every vector directory that already exists;
it always reuses the committed keys. The generator (only) needs the `test-support` feature, for the
in-process deposit intercept that the timed-release vectors are sealed with. Ciphertexts are not reproducible byte for byte (age uses fresh randomness
for every file key, salt and ephemeral key, and the manifest carries timestamps and a new
`package_id`), so regenerating changes the files in every vector but not what they test.

## Trying a vector with stock age

```
age -d -i keys/store/identity.txt recipient-x25519/report.sealdrop.age | tar -t
```

lists `sealdrop/meta.json` first. With age 1.3.0 or later,

```
age -d -i keys/pq-identity.txt recipient-pq/report.sealdrop.age | tar -t
```

does the same for the post-quantum package. The Argon2id and timed-release packages are refused by
stock age ("no identity matched any of the recipients"), as the `stock_age` field of each vector
says.

## Preserving bytes

The vectors are byte-exact. `.gitattributes` marks `spec/vectors/**` as `-text` so git never
converts line endings; keep that rule if you vendor the directory. In particular
`armored-x25519/report.sealdrop.age` contains CRLF line endings (the age armor writer emits
them), and its hash is recorded in the signed manifest, so copying the vectors outside git
(archives, other VCS, editors that normalise newlines) must preserve every byte.

## Bundle file names

Packages are stored under the bundle's real names (`report.sealdrop.age`,
`report.manifest.json`, `report.manifest.json.minisig`), because the manifest records
`ciphertext.file` and a decoder compares it with the package's name (spec §5.4 step 5). A harness
must present them to the decoder under exactly those names.

## Timed-release vectors

The two `timed-release-*` packages look exactly like production output. Their headers and
manifests name the service `https://release.invalid`, which passes the service-URL rules (spec §7.1)
in every build but never resolves (RFC 6761), and their manifests record `keys/service.pub` as
`release.service_key`. The generator intercepted the deposit in-process instead of calling a
service.

A harness must not contact any network. When the decoder sends the unlock request (spec §4.2 step
7), the harness answers it itself: a 200 response whose `k_release` is the vector's
`inputs.k_release`. It cannot check the unlock token, since a vector carries no service-side
`unlock_token_hash`. Receipt checking against the service key is covered by `receipt-valid` and
`receipt-wrong-key`.
