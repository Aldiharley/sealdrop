# sealdrop-release

A small, self-hostable key-release service for sealdrop timed release. For each package it holds one
32-byte release key, hands it out only during a sender-chosen window that starts at the first
successful unlock, deletes it afterwards, and signs a receipt of what happened.

## Set it up

```sh
sealdrop-release keygen --dir /var/lib/sealdrop-release
sealdrop-release token new alice --db /var/lib/sealdrop-release/releases.db
sealdrop-release serve --db /var/lib/sealdrop-release/releases.db --dir /var/lib/sealdrop-release
```

`keygen` writes `service.key` and `service.pub` (a minisign key pair used to sign receipts) and prints
the public key. `token new` prints a sender's deposit token once; only its SHA-256 hash is stored.
Hand the token to the sender as `SEALDROP_RELEASE_TOKEN`. `serve` listens on `127.0.0.1:8787` by
default, so terminate TLS in front of it. A container image can be built with the `Dockerfile` in this
directory (run the build from the workspace root: `docker build -f crates/sealdrop-release/Dockerfile .`).

### Caddy

```
release.example.org {
    reverse_proxy 127.0.0.1:8787
}
```

Behind a proxy every request appears to come from the proxy's address, so the per-IP rate limit then
applies to all clients together. Raise `--rate-capacity` (default 60 requests per client, refilling at
one request per two seconds) to suit your traffic.

## API

| Method and path | Auth | Result |
| --- | --- | --- |
| `PUT /v1/releases/{id}` | Bearer deposit token | 201 with `{ "service_key": ... }`; 409 if the id exists |
| `POST /v1/releases/{id}/unlock` | the unlock token in the JSON body | 200 `{k_release, first_unlock, expires_at}`; 403 wrong token; 404 unknown id; 410 window passed |
| `GET /v1/releases/{id}/receipt` | Bearer deposit token | 200 signed receipt |
| `GET /healthz` | none | 200 |

Request bodies are limited to 16 KiB.

## Time

The window is enforced against the service's own clock and nothing a client sends is trusted as a time.
**The host must run NTP** (or equivalent time sync). A clock that jumps forward ends windows early; one
that jumps back extends them.

## What the service stores

- Per release: the release id, the SHA-256 hash of the unlock token, the window length, the package
  SHA-256, the release key (until the window ends), creation and first-unlock timestamps, the expiry,
  and an unlock count.
- Per sender: a token name and the SHA-256 hash of the deposit token.

It never sees the file key, the file, its name, or any plaintext. The release key it holds is only one
input to unwrapping the file key, and it is erased when the window passes. The unlock token and the
release key are never written to the log, and receipts do not contain the release key.

## Retention

A sweeper runs every minute and erases the release key of every release whose window has passed.
Release records (without keys) are kept for 90 days so senders can still fetch receipts, then removed.
Change this with `--retention-days`.
