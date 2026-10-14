# sealdrop package format v1: test vectors

Machine-readable vectors for `spec/sealdrop-format-v1.md` (section 11). Each directory holds a
`vector.json` (schema in section 11 of the spec) and the files it names. The vectors are CC0, like the spec.

There are 18 vectors: valid packages (X25519, armored, scrypt and Argon2id passphrases, two timed-release
packages), header and verification failures (out-of-range Argon2id parameters, tampered or re-signed
manifest, flipped ciphertext byte), raw tar archives the extractor must refuse, and two receipts.

## Keys are test-only

Everything under `keys/` (the age identity, the minisign signer key, the service key pair) is public
test material under CC0. Every passphrase, `K_release` and identity inside a `vector.json` is likewise
test data. Never use any of it to protect real data. See `keys/README.md`.

## Running the conformance test against the reference

```
cargo test -p sealdrop-core --features test-support --test format_vectors
```

The `test-support` feature enables the `memory://spec.vectors` transport used by the timed-release
vectors; no network is contacted.

## Regenerating (maintainers only)

```
SEALDROP_VECTORS_FORCE=1 cargo test -p sealdrop-core --features test-support \
  --test format_vectors_gen -- --ignored regenerate_format_vectors
```

Without `SEALDROP_VECTORS_FORCE=1` the generator keeps every vector directory that already exists and
reuses the committed keys. Ciphertexts are not reproducible byte for byte (age uses fresh randomness
for every file key, salt and ephemeral key, and the manifest carries timestamps and a new
`package_id`), so regenerating changes the files in every vector but not what they test.

## Trying a vector with stock age

```
age -d -i keys/store/identity.txt recipient-x25519/package.sealdrop.age | tar -t
```

lists `sealdrop/meta.json` first. The Argon2id and timed-release packages are refused by stock age
("no identity matched any of the recipients"), as the `stock_age` field of each vector says.
