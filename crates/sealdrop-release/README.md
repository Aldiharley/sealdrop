# sealdrop-release

A small, self-hostable key-release service for sealdrop timed release. For each package it holds one
32-byte release key, hands it out only during a sender-chosen window that starts at the first
successful unlock, deletes it afterwards, and signs a receipt of what happened.

## Set it up

Create the data directory private, and run every command below with a restrictive umask so
anything the service creates is owner-only:

```sh
umask 077
mkdir -p /var/lib/sealdrop-release
sealdrop-release keygen --dir /var/lib/sealdrop-release
sealdrop-release token new alice --db /var/lib/sealdrop-release/releases.db
sealdrop-release serve --db /var/lib/sealdrop-release/releases.db --dir /var/lib/sealdrop-release
```

`keygen` writes `service.key` and `service.pub` (a minisign key pair used to sign receipts) and prints
the public key. It creates both files owner-only (0600 on Unix) and refuses to run if either already
exists; `--force` replaces them, after which senders must pin the new service key. The database file is
likewise created 0600. `token new` prints a sender's deposit token once; only its SHA-256 hash is stored.
Hand the token to the sender as `SEALDROP_RELEASE_TOKEN`. `serve` listens on `127.0.0.1:8787` by
default, so terminate TLS in front of it. A container image can be built with the `Dockerfile` in this
directory (run the build from the workspace root: `docker build -f crates/sealdrop-release/Dockerfile .`).
The container binds `0.0.0.0:8787` inside its network namespace, so publish the port only to your proxy,
for example `-p 127.0.0.1:8787:8787`, never `-p 8787:8787`.

### Caddy

```
release.example.org {
    reverse_proxy 127.0.0.1:8787
}
```

and run the service with `--trust-proxy`:

```sh
sealdrop-release serve --trust-proxy --db /var/lib/sealdrop-release/releases.db --dir /var/lib/sealdrop-release
```

Let Caddy set `X-Forwarded-For` itself: do not configure `trusted_proxies` in front of it, so Caddy
replaces whatever a client sent with the real client address. With the Docker image, append the full
command, e.g. `docker run ... sealdrop-release serve --listen 0.0.0.0:8787 --db /data/releases.db --dir /data --trust-proxy`.

### Rate limiting

The limiter is a per-address token bucket (`--rate-capacity`, burst size, default 60;
`--rate-refill-per-sec`, default 0.5).

- **Without `--trust-proxy`** (the default) it keys on the TCP peer address and ignores
  `X-Forwarded-For`, which a client could forge. Behind a reverse proxy the peer is always the proxy, so
  every client would share one bucket and one busy client could hold the whole service at 429, denying
  every recipient's unlock.
- **With `--trust-proxy`** it keys on the first address in `X-Forwarded-For` (falling back to the peer if
  the header is missing or not an IP address). Use it only when the service is reachable solely through
  a proxy that sets that header, as in the Caddy example above; if clients can reach the service
  directly they can choose their own bucket.

## API

| Method and path | Auth | Result |
| --- | --- | --- |
| `PUT /v1/releases/{id}` | Bearer deposit token | 201 with `{ "service_key": ... }`; 409 if the id exists |
| `POST /v1/releases/{id}/unlock` | the unlock token in the JSON body | 200 `{k_release, first_unlock, expires_at}`; 403 wrong token; 404 unknown id; 410 window passed |
| `GET /v1/releases/{id}/receipt` | Bearer deposit token | 200 signed receipt |
| `GET /healthz` | none | 200 |

Errors common to the endpoints:

| Status | Meaning |
| --- | --- |
| 400 | Malformed JSON, or a deposit that fails validation: `k_release` must be 32 bytes in base64 without padding; `unlock_token_hash` and `package_sha256` must be 64 lowercase hex characters; `window_secs` between 1 second and 366 days; the id 1 to 64 characters of `A-Z a-z 0-9 -` |
| 401 | Missing or unknown deposit token (the `Bearer` scheme is case-insensitive) |
| 413 | Request body over 16 KiB |
| 429 | Rate limit exceeded |

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
input to unwrapping the file key, and it is removed when the window passes (SQLite `secure_delete`
overwrites the freed pages). The unlock token and the release key are never written to the log, and receipts do not contain the release key.

## Retention

A sweeper runs every minute and removes the release key of every release whose window has passed;
SQLite `secure_delete` is on, so freed pages are overwritten. Release records (without keys) are kept for
90 days so senders can still fetch receipts, then removed. A deposit that was never unlocked is removed,
key included, 90 days after it was created. Change the period with `--retention-days` (1 to 3650).

That last rule is a hard deadline for the recipient: a timed package that is never opened stops working
once its deposit is purged ("release not found"). `sealdrop seal` and the desktop app's Seal screen tell
the sender so ("If the package is never opened, the service forgets the key after its retention period
(operator default: 90 days)."); if you change `--retention-days`, tell your senders.
