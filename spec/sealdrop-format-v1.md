# sealdrop package format v1

- **Status:** Stable — matches sealdrop 0.2.1
- **Licence:** CC0 1.0 Universal (see [`LICENSE`](LICENSE)). The reference implementation's code is Apache-2.0.
- **Reference implementation:** https://github.com/Aldiharley/sealdrop

**Abstract.** A sealdrop package is a tar archive with a fixed layout, encrypted as one age v1
file, and delivered next to a JSON manifest signed with minisign. The manifest records the
SHA-256 of the exact ciphertext, so a recipient can check what was delivered before decrypting
anything. Two optional age stanzas are defined: `sealdrop-argon2id` (Argon2id passphrases) and
`sealdrop-release` (timed release, where a key-release service hands out a second key only
during a window that starts at the first unlock). This document also defines the HTTP protocol
of that service and the signed receipts it issues. Every rule here describes what the reference
implementation does; Appendix A names the code for each one.

## 1. Scope and goals

Goals:

1. Any regular file, or any folder of regular files and directories, is restored exactly: the
   same names, the same bytes, the same directory tree.
2. Interoperability. A package whose age header contains only standard age stanzas MUST be
   decryptable by any conforming age v1 implementation, and the decrypted container MUST be
   extractable by any ustar tar reader.
3. Proof of what was delivered: a signed manifest binds the ciphertext's SHA-256 and size.
4. Optional timed release: the encrypted package can be opened only during a window enforced by
   a key-release service.

Non-goals:

- No DRM, screenshot or forwarding prevention. Timed release limits when the *encrypted package* can be opened; it cannot recall decrypted content.
- No new ciphers. Every primitive is age's, minisign's, SHA-256, Argon2id or ChaCha20-Poly1305.
- Nothing below the age layer. The age file format itself is unchanged.

Out of scope: command-line flags, user interfaces, local key storage, deposit-token issuance.

## 2. Conventions

- The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED,
  MAY and OPTIONAL are to be interpreted as described in RFC 2119 and RFC 8174 when, and only
  when, they appear in all capitals.
- **base64** means RFC 4648 section 4 (standard alphabet `A–Z a–z 0–9 + /`) **without `=`
  padding**, everywhere in this document except inside minisign keys and signatures, which use
  minisign's own encoding (padded where needed). Decoders MUST reject padded or non-canonical
  input where this document says base64.
- **SHA-256** values (`sha256` fields and similar) are 64 lowercase hexadecimal characters.
- **Timestamps** are RFC 3339 in UTC with a `Z` suffix and whole seconds:
  `YYYY-MM-DDTHH:MM:SSZ`, for example `2026-10-14T12:21:14Z`.
- **UUIDs** are RFC 9562 UUIDs in lowercase hyphenated form (36 characters). The reference
  generates version 4. A *canonical* UUID is one that equals its own lowercase hyphenated
  rendering.
- **age** means age v1 as specified by C2SP: https://github.com/C2SP/C2SP/blob/main/age.md.
  "Stanza", "file key", "recipient", "identity", "header" and "grease" have the meanings given
  there.
- **minisign** means https://jedisct1.github.io/minisign/. A minisign public key is 42 bytes
  (`Ed`, 8-byte key id, 32-byte Ed25519 key) encoded in standard base64: 56 characters that
  start with `RW`.
- **JSON** is RFC 8259, UTF-8. "Pretty JSON" means two-space indentation as produced by the
  reference (`serde_json` pretty printer); where bytes are signed, the signed bytes are what
  counts, not any re-serialisation.
- `KiB`, `MiB` and `GiB` are powers of 1024.

## 3. Plaintext container

The plaintext is a tar archive (the *container*). It is encrypted as described in §4.

### 3.1 Tar encoding

- Every entry header MUST be a POSIX ustar header (magic `ustar\0`, version `00`).
- A path that does not fit the 100-byte `name` field is split at a `/` across the `prefix`
  (≤ 155 bytes) and `name` fields. If no split fits, the encoder writes a GNU long-name entry
  (a GNU-format header of type `L`, name `././@LongLink`, payload = path + NUL) immediately
  before the entry. The reference does exactly this; decoders MUST accept both forms.
  Encoders MUST NOT write PAX headers (`x`, `g`).
- Regular files have type `0` and mode `0644`. Directories have type `5` and mode `0755`.
  Directory names MUST NOT end with `/`; the reference decoder rejects such a name as a bad
  path (§3.4, empty component).
- uid and gid are 0 and owner names are empty; mtime is the time of sealing. Decoders MUST NOT
  apply modes, owners or times from the archive (the reference creates files with the
  platform's default permissions).
- The archive ends with two 512-byte zero blocks. It is not padded to a record size. No other
  entry types are produced (§3.5).

### 3.2 Entry order

1. `sealdrop/meta.json`, a regular file, MUST be the first entry.
2. Folder packages only: a directory entry for `sealdrop/payload/<root>`, then one directory
   entry for every subdirectory (empty ones included).
3. One regular-file entry for every file listed in `meta.json`, at
   `sealdrop/payload/<path>`.

Within steps 2 and 3, the reference emits entries in depth-first pre-order of the input tree,
with siblings sorted by name (byte-wise on the UTF-8 name). This order is the order of
`meta.json`'s `files` array. Note that this is not the same as sorting full paths: `a/b`
comes before `a.txt` because the directory `a` sorts before `a.txt`. Decoders MUST NOT depend on
any order other than `sealdrop/meta.json` being first.

A single-file package has no directory entries: its only payload entry is
`sealdrop/payload/<root>`.

### 3.3 `meta.json`

Pretty JSON, at most 1 MiB (1 048 576 bytes). Encoders MUST NOT produce a larger `meta.json`;
decoders MUST reject one.

| Field | Type | Meaning |
|---|---|---|
| `format` | string | MUST be `sealdrop/1`. Decoders MUST reject any other value. |
| `tool` | string | Producer name and version, e.g. `sealdrop 0.2.1`. Informational. |
| `created` | string | Timestamp (§2) of sealing. Informational. |
| `root` | string | The file name (single-file package) or folder name (folder package). One path component. |
| `files` | array | One object per regular file, in entry order (§3.2). Directories are not listed. |
| `files[].path` | string | Path relative to `sealdrop/payload/`, `/`-separated. Its first component MUST equal `root`. For a single-file package it equals `root`. |
| `files[].size` | integer | Size in bytes. |
| `files[].sha256` | string | SHA-256 of the file's bytes. |

Each `path` MUST appear at most once in `files`. Readers MUST ignore unknown fields.

Example (folder `report` holding `a.txt` and `sub/b.html`):

```json
{
  "format": "sealdrop/1",
  "tool": "sealdrop 0.2.1",
  "created": "2026-10-14T12:21:14Z",
  "root": "report",
  "files": [
    {
      "path": "report/a.txt",
      "size": 18,
      "sha256": "4c694ad7a5ea27610e73d5dca732d67b51100682543877a8a882584667371a9d"
    },
    {
      "path": "report/sub/b.html",
      "size": 10,
      "sha256": "11e6d60e8d8b1830e6ebe95ad0d470f546936d07a5109b8b2004e3f81fbdf847"
    }
  ]
}
```

Its tar entries, in order, are: `sealdrop/meta.json`, `sealdrop/payload/report`,
`sealdrop/payload/report/sub`, `sealdrop/payload/report/a.txt` and
`sealdrop/payload/report/sub/b.html`.

### 3.4 Path rules

These rules apply to every tar entry path other than `sealdrop/meta.json`, and to `root` and
every `files[].path` (each prefixed with `sealdrop/payload/` for the check). An encoder MUST NOT
produce a path that breaks them; a decoder MUST reject the package if any path breaks them.

A path is valid only if all of the following hold:

1. It is valid UTF-8.
2. It contains no NUL, no `\` and no `:` anywhere, and does not start with `/`.
3. It starts with `sealdrop/payload/` and something follows that prefix.
4. Splitting the remainder on `/` gives components that are each:
   - not empty, not `.` and not `..`;
   - not ending in a space (U+0020) or a dot (`.`);
   - free of every byte below 0x20 and of `<` `>` `"` `|` `?` `*`;
   - not a reserved Windows device name: take the part of the component before its first `.`,
     convert ASCII letters to upper case, and reject it if it equals `CON`, `PRN`, `AUX`,
     `NUL`, `COM1`–`COM9` or `LPT1`–`LPT9` (so `con`, `CON.txt` and `lpt1.tar.gz` are all
     rejected; `CONSOLE` is not).
5. Its first component after the prefix equals `root`.

`root` MUST additionally contain no `/`.

### 3.5 Encoder obligations

- Symbolic links inside an input folder MUST NOT be packed; the reference skips them silently,
  together with any other entry that is neither a regular file nor a directory. (A symbolic
  link given as the input itself is followed.) Hard-linked files are packed as independent
  regular files; tar hard-link entries are never written.
- Names that are not valid Unicode MUST be refused, not converted.
- Every listed file MUST be written exactly once, and nothing unlisted may be written.
- The encoder hashes every file before writing the archive (so `meta.json` can come first). It
  MUST then verify, while writing, that each file still has the recorded size and SHA-256, and
  MUST fail without producing a package if any file changed.

## 4. Encryption

The container is encrypted as one age v1 file, in binary form or in age's ASCII armor
(`-----BEGIN AGE ENCRYPTED FILE-----`). Nothing below the age layer is changed.

Standard recipient types an encoder MAY use:

| Manifest `kind` (§5.2) | Recipient string | age stanza tag |
|---|---|---|
| `x25519` | `age1…` | `X25519` |
| `hybrid-pq` | `age1tagpq1…` (age's hybrid ML-KEM-768 + P-256 *tagged* type, as implemented by the Rust `age` crate 0.12) | `mlkem768p256tag` |
| `plugin:<name>` | `age1<name>1…` | defined by the plugin |
| `scrypt` | passphrase | `scrypt` |

Note: in the reference, a recipient string starting `age1pq1` is parsed as a plugin recipient
for a plugin named `pq`, not as a native type.

The reference's age library (Rust `age` 0.12) appends one random `*-grease` stanza to every
header that has no `scrypt` stanza. Where this document says a stanza MUST "stand alone", grease
stanzas are not counted: only real stanzas are.

Decoders MUST tolerate leading ASCII whitespace (space, tab, CR, LF) before an armored file.
The ciphertext hash (§5) is computed over the file exactly as stored, whitespace included.

scrypt decoders SHOULD refuse a work factor (log2 N) above 22, as the reference does.
The reference encoder writes log2 N = 18 by default and 20 for its "high" profile, and never
above 22.

Header size (probe limit 65 536 bytes): before decrypting, the reference reads the first
65 537 bytes of the package file, armor-decodes them if the file is armored, and rejects the
package unless the header's end marker `\n---` occurs in the result at an offset of at most
65 536.
Encoders SHOULD keep the binary header, up to and including the `---` line, within 46 KiB
(47 104 bytes), which fits in both binary and armored form.

### 4.1 `sealdrop-argon2id` (OPTIONAL, non-standard)

A passphrase stanza using Argon2id instead of scrypt. Stock age cannot open these files: it
reports that no identity matched. The stanza is `-> sealdrop-argon2id <salt> <t> <m_kib> <p>`
followed by the body in base64, wrapped as age requires. Real example (compat profile):

```
-> sealdrop-argon2id YnAJIDLb1hItlvySQRk99Q 3 262144 4
nbjyXgbJmRv8hMgWn0tLBRnD4JttiRooWBEILOVygdM
```

Encoding:

1. `salt` = 16 random bytes; the argument is its base64 (22 characters).
2. `t`, `m_kib`, `p` are written as plain decimal integers (iterations, memory in KiB, lanes).
3. `key` = Argon2id (RFC 9106), version `0x13`, 32-byte output, with
   password = the passphrase's UTF-8 bytes (no normalisation, no trimming),
   salt′ = the 17 ASCII bytes `sealdrop-argon2id` followed by the 16-byte salt (33 bytes),
   iterations `t`, memory `m_kib`, parallelism `p`, no secret, no associated data.
4. `body` = ChaCha20-Poly1305 (RFC 8439) with key `key`, nonce = 12 zero bytes, no associated
   data, plaintext = the 16-byte age file key. The body is 32 bytes (16 ciphertext + 16 tag).
   A zero nonce is safe because every key is derived from a fresh salt.

Encoder profiles:

| Profile | `t` | `m_kib` | `p` |
|---|---|---|---|
| desktop (RFC 9106 first recommendation) | 1 | 2097152 (2 GiB) | 4 |
| compat (RFC 9106 second recommendation) | 3 | 262144 (256 MiB) | 4 |

Decoding, in this order:

1. Ignore stanzas whose tag is not `sealdrop-argon2id`.
2. Header error if the argument count is not 4 or the body is not exactly 32 bytes.
3. Header error if the salt does not decode as base64 to exactly 16 bytes.
4. Header error if `t`, `m_kib` or `p` is not a decimal integer in 1…4294967295 (zero,
   negative, non-numeric and out-of-range values are all header errors).
5. Header error if `m_kib` < 8 or `m_kib` < 8 × `p`.
6. Excessive-work error (no derivation is attempted) if `t` > 10, `m_kib` > 2097152 or `p` > 8.
7. Derive `key` as above and decrypt the body. If decryption fails (for example, a wrong
   passphrase), or the plaintext is not 16 bytes, the stanza fails with a decryption failure.

The reference parser also accepts a leading `+` and leading zeros in step 4. Encoders MUST
NOT write them.

Stand-alone rule: the stanza MUST be the only real stanza in the header. The reference
declares the age label set `{"sealdrop-argon2id"}`, which makes age refuse to combine it with
any other recipient. The manifest records it as kind `argon2id` (§5.2).

### 4.2 `sealdrop-release` (timed release)

The real recipients' stanzas are hidden inside one stanza, encrypted under a 32-byte release
key `K_release` that only the key-release service (§7) holds. The stanza is
`-> sealdrop-release <release_id> <service> <nonce> <unlock_token>` followed by the body in
base64. Real example (service `http://127.0.0.1:18787`):

```
-> sealdrop-release 44901bca-60ab-41e1-9afc-7a3740556d82 aHR0cDovLzEyNy4wLjAuMToxODc4Nw fSueRybXvBC3IPh7 lOs2Jlo4cZnxMG2gjNDpbayR8fmcU5bEcGLQDjBmDW8
ZPiBWqVnRQh8hVMiJPaQLrT50EAsnTBT5oEzgjPPxZvMR/hW0RafLSmLOarVcxYo
EYsATO01YkiTQXPwUFB6OOxL25kNpLbVKKUmUhAeevgsHKLHxeBEZbmyHu53+Q68
+dO5WoRYvtkWkDewjXU9+A4HAT9IBog/YfK08GmwqRkd1dbo3IN9T8EgEjByvW8D
EXLj5SsgeJJG2Q
```

Arguments:

| # | Name | Content |
|---|---|---|
| 1 | `release_id` | Canonical UUID (§2), random, generated per package. |
| 2 | `service` | base64 of the service base URL as UTF-8, after §7.1 validation (trailing `/` removed). |
| 3 | `nonce` | base64 of 12 random bytes. |
| 4 | `unlock_token` | base64 of 32 random bytes. |

Encoding:

1. Generate `K_release` (32 random bytes), the unlock token (32 random bytes), the nonce and the
   `release_id`.
2. Wrap the file key with each real recipient — any §4 standard kind, or §4.1 — exactly as age
   would. Collect the resulting stanzas in order. Every real recipient wraps the SAME file key.
   The inner set MUST itself obey age's rules (an `scrypt` or `sealdrop-argon2id` stanza is the
   only inner stanza).
3. Serialise them as compact JSON, `{"stanzas":[{"tag":…,"args":[…],"body":"<base64>"}, …]}`,
   where `tag` and `args` are copied verbatim and `body` is the stanza body in base64. Real
   example (decrypted):
   ```json
   {"stanzas":[{"tag":"X25519","args":["pu2m+fd5cHIMWfWp3jHAh4fqnmwYBbuBzqhqsCimGAc"],"body":"2z1KhKpKxcK+7/QJHrD4LKyQMTUzf8nMvj/Sja2qIR0"}]}
   ```
   No grease is added inside.
4. Limits: at least 1 and at most 64 inner stanzas; the JSON is at most 65 536 bytes. An
   encoder MUST fail rather than exceed them. The header-size rule of §4 is tighter in
   practice: a body near the JSON limit makes the header too large to open.
5. `body` = ChaCha20-Poly1305 with key `K_release`, the 12-byte nonce, no associated data,
   plaintext = the JSON.
6. Deposit `K_release` with the service (§7.2) before publishing the manifest.

Stand-alone rule: the stanza MUST be the only real stanza in the header (label set
`{"sealdrop-release"}`). No inner stanza may appear in the header in the clear. The sender's
own key is NOT added to a timed package unless the sender lists it explicitly. The reference
decoder does not itself reject extra real stanzas next to a `sealdrop-release` stanza.

Decoding, in this order:

1. If the decoder verified the manifest (§5.4): the header MUST contain a `sealdrop-release`
   stanza only if the manifest has a `release` object, and the stanza's `release_id` and
   decoded `service` MUST equal `release.release_id` and `release.service`. Otherwise refuse.
2. If the package's inner key is a passphrase (the manifest's `recipients[0].kind` is `scrypt`
   or `argon2id`), the passphrase MUST be obtained before any request. Decoders MUST NOT start
   the window by fetching first and asking afterwards.
3. Header error if the argument count is not 4.
4. Header error if `service` does not decode (base64, then UTF-8) or fails §7.1 validation.
5. Header error if `release_id` is not a canonical UUID.
6. Header error if `nonce` does not decode to exactly 12 bytes.
7. Only now, POST the unlock request (§7.3), sending argument 4 verbatim as `unlock_token`.
   Any status other than 200 is an error; the response's `k_release` MUST decode to 32 bytes.
8. Decrypt the body with `K_release` and the nonce. Failure is a decryption failure.
9. Header error if the plaintext exceeds 65 536 bytes, is not the JSON above, holds more than
   64 stanzas, or any `body` is not valid base64.
10. Unwrap the inner stanzas with the local identities and passphrase, as age would for a
    header. If none matches, report "no matching keys".

Security: the unlock token is in the clear. Anyone holding the file can trigger the first
unlock (and so start, and use up, the window), but cannot read the content without an inner
key or passphrase. Stock age rejects timed packages (no identity matches).

## 5. Delivery bundle

### 5.1 File names

For an input named `<name>` (file or folder name, extension included), a bundle is three files
in one directory:

| File | Content |
|---|---|
| `<name>.sealdrop.age` | The package (§3, §4), binary or armored. |
| `<name>.manifest.json` | The manifest (§5.2). |
| `<name>.manifest.json.minisig` | The minisign signature of the manifest (§5.3). |

A decoder derives the manifest and signature names from the package file name: remove a
trailing `.sealdrop.age` if present (otherwise use the whole name), then append
`.manifest.json` and `.manifest.json.minisig`.

### 5.2 Manifest

Pretty JSON, at most 1 MiB. Readers MUST ignore unknown fields.

| Field | Type | Required | Meaning |
|---|---|---|---|
| `format` | string | yes | MUST be `sealdrop-manifest/1`. |
| `package_id` | string | yes | Canonical UUID, random per package. |
| `tool` | string | yes | Producer, e.g. `sealdrop 0.2.1`. Informational. |
| `created` | string | yes | Timestamp of signing. Informational. |
| `ciphertext.file` | string | yes | Bare file name of the package, e.g. `report.sealdrop.age`. |
| `ciphertext.size` | integer | yes | Package size in bytes. |
| `ciphertext.sha256` | string | yes | SHA-256 of the package file's bytes. |
| `plaintext_tar_sha256` | string | yes | SHA-256 of the container (§3) before encryption. |
| `recipients` | array | yes | One entry per real recipient (see below). |
| `recipients[].kind` | string | yes | `x25519`, `hybrid-pq`, `plugin:<name>`, `scrypt` or `argon2id`. |
| `recipients[].fingerprint` | string | yes | First 16 hex characters of the SHA-256 of the recipient string's UTF-8 bytes; the empty string for `scrypt` and `argon2id`. |
| `signer` | string | yes | The signer's minisign public key (56 characters). Not trusted by itself (§5.4). |
| `classification` | string | no | Free text chosen by the sender. |
| `expires` | string | no | Advisory date, normally `YYYY-MM-DD`. Never enforced; readers MUST NOT rely on its format. |
| `release` | object | timed only | Present only for timed-release packages. |
| `release.service` | string | timed only | Service base URL, as in the stanza. |
| `release.release_id` | string | timed only | As in the stanza. |
| `release.window_secs` | integer | timed only | Window length in seconds, ≥ 1. |
| `release.service_key` | string | timed only | The service's minisign public key, returned by the deposit (§7.2). Pins receipt verification (§8). |
| `notes` | string | yes | The fixed text below. |

Optional fields are omitted when absent (never `null`). For a timed package, `recipients`
describes the inner recipients. A passphrase package has exactly one entry. In a recipient
package, the reference lists the given recipients in order, de-duplicated, and then the
sender's own recipient if it was added (it is never added to passphrase or timed packages).

`notes` is exactly:

```
expires is advisory and is not enforced by any software; release.window_secs is enforced by the named service for the encrypted package only
```

Real example (recipient package):

```json
{
  "format": "sealdrop-manifest/1",
  "package_id": "a160500c-d16c-4855-be1c-0242df964ea0",
  "tool": "sealdrop 0.2.1",
  "created": "2026-10-14T12:21:14Z",
  "ciphertext": {
    "file": "report.sealdrop.age",
    "size": 5450,
    "sha256": "b5698d0a3da2ac22a461229e17e098661bd4de57ad3346cdafa61c93d4057be7"
  },
  "plaintext_tar_sha256": "8653db2d526188896b03f4d696553fda25b96db632603b8d9d6b07cef806dbc1",
  "recipients": [
    {
      "kind": "x25519",
      "fingerprint": "e8f174dbb97b1119"
    }
  ],
  "signer": "RWTqDtEnIqzb7foMovgjNAJrJ/WeHwJSN8LHO32Z0oIkQJBBRyeLLTMp",
  "classification": "confidential",
  "expires": "2026-12-31",
  "notes": "expires is advisory and is not enforced by any software; release.window_secs is enforced by the named service for the encrypted package only"
}
```

The recipient here is `age145ngzusvw3tyuumz6nvt3wxjnauzuhlllkdpnvhpw63fcqnsr5dqyjcmrp`;
SHA-256 of that string begins `e8f174dbb97b1119`. A timed package of the same folder carries,
between `signer` and `notes`:

```json
  "release": {
    "service": "http://127.0.0.1:18787",
    "release_id": "44901bca-60ab-41e1-9afc-7a3740556d82",
    "window_secs": 600,
    "service_key": "RWQLKpS0ZIpbCffR/lb9Vo25wkCW5NVnF2yWyXjKfCEbwkluzGlRYRU4"
  },
```

### 5.3 Signature

- Algorithm: minisign, prehashed (signature algorithm `ED`, BLAKE2b-512 of the message signed
  with Ed25519). Decoders MUST reject legacy (`Ed`, non-prehashed) signatures.
- Message: the EXACT bytes of `<name>.manifest.json` as stored. No canonicalisation.
- Trusted comment: exactly `sealdrop manifest <package_id>`.
- The untrusted comment is not meaningful (the reference writes `signature from rsign secret
  key`).

Real example (for the manifest above):

```
untrusted comment: signature from rsign secret key
RUTqDtEnIqzb7bYuwLLzDkKYi4GwCqhIsnGDXSi05ifpRz3q85nHqWgVidlEhuc8J4/qcAHKsqZSP4JDuZ4w7c/pxoizZodFTgM=
trusted comment: sealdrop manifest a160500c-d16c-4855-be1c-0242df964ea0
5xriZNzT0NendlETpZKp2D8rrY5VC9ykuuWDUM607HAyvIqFUg+1awlhd5B3VC/z7Xln0UjcG+iMpEDxFiVjCQ==
```

### 5.4 Verification algorithm

A decoder MUST run these steps, in this order, before decrypting anything, before contacting
any release service, and before touching any key material. Any failure stops the process with
a verification error.

1. Read `<name>.manifest.json` and `<name>.manifest.json.minisig` (§5.1). Reject a manifest
   larger than 1 MiB. Parse it as JSON; `format` MUST equal `sealdrop-manifest/1`.
2. Resolve the signer key. The manifest's `signer` field is NOT trusted by itself; it only
   names the key to look for. It MUST parse as a minisign public key. If the user supplied a
   key explicitly, that key MUST equal `signer` character for character and is the only
   candidate. Otherwise use the user's own signing key if it equals `signer`, else a key in
   the user's trust store whose base64 equals `signer`. If none applies, refuse.
3. Verify the minisign signature (§5.3) over the exact manifest bytes with that key.
4. The signed trusted comment MUST equal `sealdrop manifest ` followed by `package_id`.
5. `ciphertext.file` MUST contain no `/` and no `\`, and MUST equal the package's bare file
   name.
6. Compute the SHA-256 and the byte count of the whole package file. Both MUST equal
   `ciphertext.sha256` and `ciphertext.size`. The bytes that are hashed MUST be the bytes that
   are then decrypted: the reference hashes and decrypts through one open file handle, so the
   path cannot be swapped in between.

Decoders MAY also compare the SHA-256 of the decrypted container with `plaintext_tar_sha256`;
the reference does not.

### 5.5 Missing manifest

If the manifest or signature is absent or fails §5.4, a decoder MUST refuse to open the
package unless the user explicitly chooses to skip verification. When verification is skipped,
the decoder MUST label the result as unverified, and MUST treat every value read from the
header or the unverified manifest (service URL, release id, recipient kind) as untrusted.

## 6. Extraction requirements

Decoders that extract a container MUST apply this section. Limits are those of the reference;
a decoder MAY use lower limits.

| Limit | Value |
|---|---|
| `meta.json` size | 1 MiB (1 048 576 bytes) |
| Entries, `meta.json` and directories included | 100 000 |
| Total bytes of regular files | 64 GiB (68 719 476 736 bytes) |
| Bytes of one regular file | 64 GiB |
| Payload of one tar extension entry (`L`, `K`, `x`, `g`) | 1 MiB |
| Raw tar stream consumed, headers and padding included | 65 GiB (69 793 218 560 bytes) |

### 6.1 Stream guard

Before the tar parser sees a 512-byte header block, the decoder MUST inspect it on the raw
stream and:

1. Skip the check for an all-zero block (end of archive).
2. Reject an `L`, `K`, `x` or `g` entry whose declared size exceeds 1 MiB.
3. Reject a PAX global header (`g`).
4. Reject a GNU sparse entry (`S`).
5. For a PAX extended header (`x`), collect its payload and reject it if the payload contains
   the bytes `size=` anywhere (a match on bytes, deliberately broader than parsing records).
6. Stop with an error once more than 65 GiB of raw stream has been read.

The size field is parsed as the tar crate does: GNU base-256 if the high bit of its first byte
is set (the last 8 bytes, big-endian), otherwise octal up to the first NUL, surrounding spaces
trimmed. Payloads are padded to 512 bytes. These rules make the guard's view of entry
boundaries match the parser's: no entry's effective size may differ from its header size.

### 6.2 Extraction algorithm

1. The first entry MUST be a regular file named exactly `sealdrop/meta.json`; otherwise
   reject. Reject it if its header size or its content exceeds 1 MiB.
2. Parse `meta.json` (§3.3). `format` MUST be `sealdrop/1`. `root` MUST contain no `/` and
   MUST pass §3.4. Every `files[].path` MUST pass §3.4, including the first-component rule.
   Reject duplicate paths in `files`.
3. If the target `<destination>/<root>` exists (any kind of entry, a dangling symbolic link
   included) and the user did not ask to overwrite, refuse before extracting any entry.
4. Create a temporary directory inside the destination directory (the reference names it
   `.sealdrop-<random>`), so the final rename stays on one volume.
5. For every further entry (the count, which includes `meta.json`, MUST NOT exceed 100 000):
   1. The path MUST pass §3.4 (prefix, components, first component equal to `root`).
   2. A directory (type `5`) is created in the temporary tree and nothing else is done.
   3. Any type other than a regular file (`0` or NUL) or a directory MUST be rejected. This
      includes symbolic links (`2`), hard links (`1`), character and block devices, FIFOs,
      contiguous files (`7`) and any vendor type. (`L`, `K` and `x` entries are consumed by
      the tar parser and modify the next entry; §6.1 bounds them.)
   4. A regular file MUST be listed in `meta.json`; reject unlisted files.
   5. The header `size` field MUST equal the entry's effective size.
   6. The size MUST equal the listed `size`, MUST NOT exceed the per-file limit, and the
      running total MUST NOT exceed 64 GiB.
   7. Write the file into the temporary tree while hashing it. The written byte count and the
      SHA-256 MUST equal the listed values; otherwise reject.
6. Every file listed in `meta.json` MUST have been seen; reject if any is missing.
7. Move `<temp>/<root>` into place (§6.3).

Any rejection aborts extraction. Nothing is moved into place, and the temporary directory is
removed.

A file entry that appears twice is not rejected by the reference; each occurrence is verified
against `meta.json` in turn and the last one is kept. Encoders MUST NOT write duplicates (§3.5).

### 6.3 Placing the result

- If the target does not exist, rename `<temp>/<root>` to `<destination>/<root>`.
- If it exists and the user asked to overwrite:
  1. rename the existing target to a sibling named `<root>.sealdrop-old-<random>` (the
     reference uses 12 random hex characters);
  2. rename the new tree into place;
  3. delete the parked copy.
  If step 2 fails, rename the parked copy back and keep the new tree where it is, reporting
  both paths. The old data is never deleted before the new tree is in place.

## 7. Release service protocol v1

A key-release service holds `K_release` for each timed package and hands it out only during the
window. All bodies are JSON. Clients send `Content-Type: application/json`; the reference
service does not require it. Error responses carry a short `text/plain` body that is not
normative.

### 7.1 Service URL (client rules)

The base URL comes from the sender or from a file header, so a client MUST validate it before
building any request from it:

1. Reject it if it contains whitespace, a control character, `?`, `#`, `@` or `\`.
2. It MUST have the form `<scheme>://<authority>[/<path>]` with a non-empty authority (the
   text up to the first `/` after `://`).
3. The authority is `<host>[:<port>]`, where an IPv6 host is written in brackets
   (`[::1]:8787`). The host MUST be non-empty. A port, if present, MUST be 1 to 5 ASCII digits.
4. The scheme MUST be `https`, or `http` only when the host is exactly `localhost`,
   `127.0.0.1` or `[::1]`. Schemes and hosts are compared case-sensitively.
5. Remove trailing `/` characters. Endpoints are formed by appending `/v1/…` to the result.

The reference accepts an in-process `memory://` scheme in test builds only. Production clients
MUST NOT accept it.

Clients MUST NOT follow HTTP redirects; a 3xx response is an error. Clients SHOULD apply a
timeout (the reference: 30 seconds for the whole request).

### 7.2 Deposit

```
PUT /v1/releases/{release_id}
Authorization: Bearer <deposit token>
```

The deposit token is an opaque string issued by the operator. The scheme name `Bearer` is
matched case-insensitively. Request body:

```json
{"k_release":"/3qhO3wU7I6EXoCHoWRi/GYVnBsJa4z7Tbhm9JkAHoQ","window_secs":600,"unlock_token_hash":"11b2f9b23ea7635a81e21c8eb4b6902fcc8fb2261cc2689ca787c6f96f60c553","package_sha256":"aba8fccab6a4d2e06132cee581534f4f8ff7a4185a02cc61a616e0db002ad29e"}
```

| Field | Content |
|---|---|
| `k_release` | base64 of the 32-byte release key. |
| `window_secs` | Window length in seconds: 1 to 31 622 400 (366 days). |
| `unlock_token_hash` | SHA-256 (hex) of the raw 32-byte unlock token (not of its base64). |
| `package_sha256` | SHA-256 of the package file, equal to the manifest's `ciphertext.sha256`. |

Success: `201 Created`, body `{"service_key":"RWQLKpS0ZIpbCffR/lb9Vo25wkCW5NVnF2yWyXjKfCEbwkluzGlRYRU4"}`
(the service's minisign public key). The client MUST check that it parses as a minisign public
key and records it in the manifest as `release.service_key`. Any status other than 201 is a
failed deposit, and the client MUST NOT produce a bundle.

Errors, in the order the reference checks them: `429` rate limited; `413` body over 16 KiB;
`401` missing or unknown token; `400` body is not the JSON above; `400` id longer than 64
characters or containing anything other than `A–Z a–z 0–9 -` (clients always send a canonical
UUID); `400` `k_release` not base64 of 32 bytes; `400` `unlock_token_hash` or `package_sha256`
not 64 lowercase hex characters; `400` `window_secs` out of range; `409` the id already exists
(nothing is changed).

### 7.3 Unlock

```
POST /v1/releases/{release_id}/unlock
```

No authorization header. Body: `{"unlock_token":"lOs2Jlo4cZnxMG2gjNDpbayR8fmcU5bEcGLQDjBmDW8"}`
(argument 4 of the stanza, verbatim).

Success: `200 OK`:

```json
{"k_release":"/3qhO3wU7I6EXoCHoWRi/GYVnBsJa4z7Tbhm9JkAHoQ","first_unlock":"2026-10-14T12:21:31Z","expires_at":"2026-10-14T12:31:31Z","now":"2026-10-14T12:21:31Z"}
```

Rules:

1. The service checks, in order: `400` body is not that JSON; `404` unknown id; `403` the token
   is not valid base64, or the SHA-256 of its decoded bytes is not the stored
   `unlock_token_hash`.
2. The first successful call sets `first_unlock` to the service clock and
   `expires_at = first_unlock + window_secs`, atomically: a concurrent first call that loses
   sees, and returns, the stored values.
3. While `now < expires_at` (service clock, whole seconds), every call with the right token
   succeeds and returns the same `first_unlock` and `expires_at`. Each success increments the
   release's unlock count.
4. Once `now ≥ expires_at`, the service MUST delete `K_release` and answer `410 Gone`, and
   keeps answering 410 until the record is purged (then 404).
5. `now` is the service clock at the moment of the response.

### 7.4 Receipt

```
GET /v1/releases/{release_id}/receipt
Authorization: Bearer <deposit token>
```

Success: `200 OK`, body `{"receipt_json":"<string>","signature":"<minisign signature box>"}`
(§8). Errors: `401` missing or unknown token, `404` unknown id. A receipt is served for as long
as the record exists, including after the key was deleted. In the reference, any valid deposit
token can fetch the receipt of any release id.

Before sending its deposit token to the service named in a manifest, a sender tool SHOULD
verify that manifest (§5.4), as the reference does.

### 7.5 Service duties

- **Clock.** The window is enforced only against the service's own clock; no client-supplied
  time is trusted. The host MUST run NTP or an equivalent time sync.
- **Secrets at rest.** Unlock tokens and deposit tokens are stored only as SHA-256 hashes.
  `K_release` is never logged and never appears in receipts.
- **Key deletion.** A key is deleted on the first unlock attempt at or after `expires_at`, and
  a sweep that runs at least every 60 seconds deletes the key of every release whose window
  has passed. Records without keys are kept for receipts during the retention period.
- **Retention.** Records are purged a retention period after their window ends. A release that
  was never unlocked is purged, key included, a retention period after the deposit. The
  operator default is 90 days (configurable from 1 to 3650). A timed package that is never
  opened therefore stops working at that point ("release not found"). Senders MUST be told
  this.
- **Rate limiting.** Requests are rate-limited per client address (reference: token bucket,
  burst 60, refill 0.5 per second, answering 429). The `X-Forwarded-For` header (its first
  address) is used only when the operator opts in because the service sits behind a proxy
  that sets that header itself; otherwise the TCP peer address is used.
- **Body limit.** Request bodies over 16 KiB are rejected with 413.

### 7.6 Health

`GET /healthz` → `200 OK`, body `ok`. No authorization.

### 7.7 Status summary

| Status | Deposit | Unlock | Receipt |
|---|---|---|---|
| 200 | — | key returned | receipt returned |
| 201 | stored | — | — |
| 400 | invalid body or field | invalid body | — |
| 401 | bad or missing token | — | bad or missing token |
| 403 | — | wrong unlock token | — |
| 404 | — | unknown id | unknown id |
| 409 | id exists | — | — |
| 410 | — | window has passed | — |
| 413 | body > 16 KiB | body > 16 KiB | — |
| 429 | rate limited | rate limited | rate limited |

## 8. Receipts

### 8.1 Format

`receipt_json` is a string holding pretty JSON with these fields, in this order:

| Field | Type | Meaning |
|---|---|---|
| `release_id` | string | The release id. |
| `package_sha256` | string | As deposited. |
| `first_unlock` | string or `null` | Service time of the first unlock; `null` if never unlocked. |
| `expires_at` | string or `null` | End of the window; `null` if never unlocked. |
| `unlock_count` | integer | Number of successful (200) unlock responses. |
| `service_key` | string | The service's minisign public key. |
| `now` | string | Service clock when the receipt was issued. Readers MUST accept its absence (receipts made before sealdrop 0.2) and treat it as empty. |

`signature` is a minisign signature box (prehashed) over the EXACT UTF-8 bytes of
`receipt_json`, with trusted comment `sealdrop receipt <release_id>`.

Real example (the HTTP body, as returned):

```json
{"receipt_json":"{\n  \"release_id\": \"44901bca-60ab-41e1-9afc-7a3740556d82\",\n  \"package_sha256\": \"aba8fccab6a4d2e06132cee581534f4f8ff7a4185a02cc61a616e0db002ad29e\",\n  \"first_unlock\": \"2026-10-14T12:21:31Z\",\n  \"expires_at\": \"2026-10-14T12:31:31Z\",\n  \"unlock_count\": 2,\n  \"service_key\": \"RWQLKpS0ZIpbCffR/lb9Vo25wkCW5NVnF2yWyXjKfCEbwkluzGlRYRU4\",\n  \"now\": \"2026-10-14T12:21:31Z\"\n}","signature":"untrusted comment: signature from rsign secret key\nRUQLKpS0ZIpbCcGF1YZeKXYy/HQ7vb7539arYneZmKgBsCJYF6CF7td5134CFk2Tjb8YaPcYYxthS2svTOI65tDBZnYmsSkBwQk=\ntrusted comment: sealdrop receipt 44901bca-60ab-41e1-9afc-7a3740556d82\nwoYDrZTjyoGrkCQwxB+EBeYXRrx5fsTQOA6cPFA0jqqb4174fQ8EAjH9FctoWNe8yIWf6XBhX4/46AEMXgDuCw==\n"}
```

The reference saves this object, pretty-printed, as `<name>.receipt.json`.

### 8.2 Verification

A sender tool MUST verify a receipt against a manifest it has verified (§5.4), in this order:

1. Parse `receipt_json` as JSON with the fields above.
2. Its `service_key` MUST equal the manifest's `release.service_key`, character for character.
3. Verify `signature` (prehashed only) over the exact bytes of `receipt_json` with that key.
4. `release_id` MUST equal the manifest's `release.release_id`.
5. `package_sha256` MUST equal the manifest's `ciphertext.sha256`.
6. The signed trusted comment MUST equal `sealdrop receipt ` followed by `release_id`.

The key MUST come from the signed manifest, never from the receipt alone. Checking a receipt
only against the key it carries (trust on first use) proves nothing, since anyone can sign a
receipt with their own key; it is NOT conforming for sender tools. A tool MAY offer such an
integrity-only check if it labels the result as not pinned.

## 9. Security considerations

- **What the hash binding proves.** age's payload encryption (ChaCha20-Poly1305) is not
  key-committing (Len, Grubbs and Ristenpart, "Partitioning Oracle Attacks", USENIX Security
  2021), so a ciphertext alone does not pin down a single plaintext under every possible key.
  The signed manifest fixes the exact ciphertext bytes (SHA-256 and size) and the container's
  SHA-256. Sender and recipient can therefore show which ciphertext was delivered, and a
  decoder that compares `plaintext_tar_sha256` can show which plaintext it obtained.
- **The unlock token is visible.** It is in the header by design. Holding it lets anyone start
  the window (denial of the window), not read the content.
- **What the service learns.** The release id, the package's SHA-256, the window, the deposit
  and unlock times, the unlock count and client addresses. It never sees the file key, the file,
  its name or any plaintext; `K_release` alone unwraps nothing.
- **Limits of timed release.** It cannot recall plaintext once decrypted. The recipient's clock
  is irrelevant; only the service clock counts. The service must be reachable during the
  window, and must still hold the record (§7.5 retention). A compromised or colluding service
  can release the key at any time.
- **Argon2id.** With the reference's parameter bounds, Argon2id adds little over scrypt at
  log2 N = 18 for passphrases of 6 or more random words, and it costs interoperability: stock
  age cannot open such files. Encoders SHOULD default to scrypt.
- **Case-insensitive file systems.** Two paths that differ only in case (`a.txt`, `A.txt`) pass
  §3.4 but name the same file on such file systems. The reference then writes the second file
  over the first: extraction succeeds and reports two files, but one file remains, under the
  first name, with the second file's content. Decoders on case-insensitive file systems SHOULD
  reject packages whose paths collide when compared case-insensitively.
- **Signer keys.** The manifest names its signer but does not authenticate it. Recipients
  SHOULD confirm a signer key out of band before trusting it.
- **Unverified opening.** When verification is skipped (§5.5), header values reach the network
  layer. §7.1 validation and the no-redirect rule bound what a hostile header can make the
  client contact.

## 10. Versioning

The version anchors are:

| Identifier | Where |
|---|---|
| `sealdrop/1` | `meta.json` `format` |
| `sealdrop-manifest/1` | manifest `format` |
| `sealdrop-argon2id` | age stanza tag |
| `sealdrop-release` | age stanza tag |
| `/v1/` | release service paths |
| `sealdrop manifest <package_id>`, `sealdrop receipt <release_id>` | trusted comments |

- An incompatible change requires a new identifier (for example `sealdrop/2`).
- Adding optional JSON fields is a compatible change. Readers MUST ignore unknown JSON fields.
- Unknown stanza tags are ignored by age semantics: an identity skips stanzas it does not
  recognise, and decryption fails only if no stanza matches.

## 11. Test vectors

Vectors live in `spec/vectors/<name>/`: one directory per vector, holding `vector.json` and
the files it names. `vector.json` has exactly this schema:

```json
{ "name": "recipient-x25519", "expect": "success",
  "stock_age": "opens" | "opens-interactive" | "rejects" | "n/a",
  "inputs": { "identity": "AGE-SECRET-KEY-1…", "passphrase": "…", "k_release": "<b64>", "signer_key": "RW…", "service_key": "RW…" },
  "expected": { "package_id": "…", "plaintext_tar_sha256": "<hex>", "files": [ { "path": "…", "size": 0, "sha256": "<hex>" } ] },
  "files": { "package": "package.sealdrop.age", "manifest": "manifest.json", "signature": "manifest.json.minisig", "tar": "input.tar", "receipt": "receipt.json" },
  "comment": "…" }
```

- `name` equals the directory name.
- `expect` is one of `success`, `header failure`, `verify failure`, `extract failure`,
  `receipt ok`, `receipt failure`.
- `stock_age`: `opens` (stock age decrypts it with `inputs.identity`), `opens-interactive`
  (stock age decrypts it after prompting for `inputs.passphrase`), `rejects` (stock age refuses
  it), `n/a` (no package to try).
- Every key inside `inputs` and `files` is optional; a vector carries only what it needs.
  `inputs.k_release` stands in for the service in timed-release vectors. `files` values are
  file names inside the vector's directory.
- `expected` describes a successful open; it is omitted or partial for failure vectors.
- `comment` names the section of this document the vector exercises, e.g. `§4.1 step 6`.

The secrets in the vectors (one X25519 identity, the passphrase `spec vector passphrase`, one
`K_release` and unlock token, one signer key pair, one service key pair) are test material
only.

Running them against the reference, and regenerating them (maintainers only):

```
cargo test -p sealdrop-core --test format_vectors
cargo test -p sealdrop-core --features test-support -- --ignored regenerate_format_vectors
```

## Appendix A. Rules and their implementation

Paths are relative to the repository root. Core = `crates/sealdrop-core/src/`, service =
`crates/sealdrop-release/src/`, CLI = `crates/sealdrop-cli/src/commands/`.

| Rule | File | Function or item |
|---|---|---|
| §3.1 tar encoding, modes, long names | core `pack.rs`; tar crate 0.4 | `write_plan` (`tar::Header::new_ustar`); `Builder::append_data` → `prepare_header_path` |
| §3.2 entry order | core `pack.rs` | `plan` (`WalkDir::sort_by_file_name`), `write_plan` |
| §3.3 `meta.json` schema | core `pack.rs` | `Meta`, `FileEntry`, `META_FORMAT`, `META_PATH` |
| §3.4 path rules | core `extract.rs` | `check_path`, `WINDOWS_RESERVED` |
| §3.5 encoder checks | core `pack.rs` | `check_portable`, `utf8_name`, `plan`, `write_plan` |
| §4 recipients, kinds, fingerprints | core `crypt.rs` | `Recipient::{parse, kind, fingerprint}`, `to_age_recipients` |
| §4 armor, leading whitespace | core `crypt.rs` | `encrypt_writer`, `decrypt_reader`, `SkipLeadingWhitespace` |
| §4 scrypt bounds | core `crypt.rs` | `scrypt_recipient`, `scrypt_identity`, `SCRYPT_MAX_DECRYPT_LOG_N` |
| §4 header size | core `probe.rs` | `probe_bytes`, `HEADER_MAX` |
| §4.1 Argon2id stanza | core `argon2id.rs` | `Recipient::wrap_file_key`, `Identity::unwrap_stanza`, `derive`, `check_bounds`, `Profile::params`, `MAX` |
| §4.2 release stanza | core `release.rs` | `Recipient::wrap_file_key`, `Identity::unwrap_stanza`, `validate_service_url`, `validate_release_id`, `Deposit::new` |
| §4.2 decode step 1 | CLI `open.rs`; desktop `apps/desktop/src-tauri/src/commands.rs` | `run`; open command (manifest vs header check) |
| §4.2 decode step 2 | core `open.rs` | `open` (`timed_passphrase`), `is_passphrase_kind` |
| §5.1 file names | core `seal.rs` | `bundle_paths`, `seal` |
| §5.2 manifest | core `manifest.rs`; core `seal.rs` | `Manifest`, `NOTES`, `MANIFEST_FORMAT`, `Manifest::from_json`; `seal` |
| §5.3 signature | core `manifest.rs` | `sign`, `verify` |
| §5.4 verification | core `open.rs` | `verify_with`, `resolve_signer` |
| §5.5 skip verification | core `open.rs`; CLI `open.rs` | `open` (`skip_verify`); `run` |
| §6 limits | core `extract.rs` | `Limits::default`, `META_MAX_BYTES` |
| §6.1 stream guard | core `extract.rs` | `GuardedReader::{read, on_header}`, `parse_size`, `check_pax` |
| §6.2 extraction | core `extract.rs` | `extract` |
| §6.3 placing, overwrite | core `extract.rs` | `extract`, `replace`, `OLD_SUFFIX` |
| §7 routes, body limit | service `app.rs` | `build` |
| §7.1 URL rules, no redirects, timeout | core `release.rs` | `validate_service_url`, `agent` |
| §7.2 deposit | service `routes.rs`; core `release.rs` | `deposit`, `bearer`; `deposit` (client) |
| §7.3 unlock | service `routes.rs`, `db.rs`; core `release.rs` | `unlock`; `mark_first_unlock`, `bump_unlock_count`, `delete_key`; `HttpFetch::unlock` |
| §7.4 receipt endpoint | service `routes.rs`; core `release.rs`; CLI `receipt.rs` | `receipt`; `fetch_receipt`; `run` |
| §7.5 clock, hashed tokens | service `clock.rs`, `db.rs` | `SystemClock`, `fmt_unix`; `create_token`, `token_valid`, `insert_release` |
| §7.5 sweep, retention | service `db.rs`, `main.rs` | `sweep_expired_unix`; `main` (60-second interval, `--retention-days`) |
| §7.5 rate limiting | service `ratelimit.rs`, `routes.rs` | `Limiter::allow`; `rate_limit`, `client_ip` |
| §7.6 health | service `routes.rs` | `healthz` |
| §8.1 receipt format | core `release.rs` | `Receipt`, `SignedReceipt`, `sign_receipt` |
| §8.2 receipt verification | core `release.rs`; CLI `receipt.rs` | `verify_receipt_for`, `verify_receipt`; `run` |

## Appendix B. Differences from plain age

| Package | Stock age (`age -d`) | Notes |
|---|---|---|
| X25519 recipients | `age -d -i key.txt pkg.sealdrop.age \| tar -x` works | Restores `sealdrop/meta.json` and `sealdrop/payload/…` without sealdrop's checks. |
| Armored | Same as binary | age detects armor itself. |
| scrypt passphrase | Works after the passphrase prompt | |
| `hybrid-pq` (`age1tagpq1…`) | Needs an age implementation with that identity type | The reference can encrypt to it but has no identity for it. |
| Plugin recipients | Works with the same plugin installed | |
| `sealdrop-argon2id` | Fails: "no identity matched any of the recipients" (with `-i`); without `-i`, "identities are required" | Non-standard stanza. |
| `sealdrop-release` | Fails: "no identity matched any of the recipients" | The real stanzas are encrypted inside it. |

Manifest verification without sealdrop:

```
minisign -V -P <signer key> -m report.manifest.json
```

(`-p <file>` takes the key from a minisign public key file instead; the signature is read from
`report.manifest.json.minisig` by default). The signer key must come from somewhere trusted,
not from the manifest. Then check by hand that the printed trusted comment is
`sealdrop manifest <package_id>`, that `ciphertext.file` is the package's name, and that
`sha256sum report.sealdrop.age` and the file size match `ciphertext.sha256` and
`ciphertext.size`.
