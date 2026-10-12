# PrivateCaptcha edge sidecar

![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/PrivateCaptcha/edge-sidecar)

[![CI](https://github.com/PrivateCaptcha/edge-sidecar/actions/workflows/ci.yml/badge.svg)](https://github.com/PrivateCaptcha/edge-sidecar/actions/workflows/ci.yml) [![Go Lint](https://github.com/PrivateCaptcha/edge-sidecar/actions/workflows/golangci-lint.yml/badge.svg)](https://github.com/PrivateCaptcha/edge-sidecar/actions/workflows/golangci-lint.yml)

This is a sidecar process that can be used by [Caddy](docs/CADDY.md) (via `forward_auth`) and [nginx](docs/NGINX.md) (via `auth_request`) to protect an upstream with a CAPTCHA.

The application served by the HTTP server does not need any changes, the web server proxies application traffic, while the sidecar handles only `/auth`, `/__privatecaptcha/complete`, and `/healthz`.

CAPTCHA [settings](https://docs.privatecaptcha.com/docs/reference/property-settings/) (such as difficulty, compute-hard or memory-hard etc.) and [protection rules](https://docs.privatecaptcha.com/docs/reference/rules/) (e.g. based on IP, HTTP headers, Country, User-Agent and others) are configured in the [Portal](https://portal.privatecaptcha.com/), this sidecar receives only the Sitekey (aka widget ID) and an API key for verification.

## Usage

Web server | Link
--- | ---
Caddy | [guide](docs/CADDY.md)
nginx | [guide](docs/NGINX.md)

## Flow

```text
Browser -> proxy -> GET /auth
                     |
              +------+------+
              |             |
         valid cookie   missing/invalid cookie
              |             |
             204           401 + hosted gate HTML
              |             |
         application    solve captcha at the original URL
                            |
                 POST /__privatecaptcha/complete
                            |
                 official Go client -> authenticated /verify
                            |
                   validate returned edge JWT
                            |
                  Set-Cookie + 204 -> browser reload
```

Known-key JWT checks are local. Keys are fetched at startup, refreshed periodically, and refreshed once on an unknown `kid`. Failed refreshes retain cached keys. Gate HTML is cached according to upstream freshness, but browser challenges always use `Cache-Control: no-store`. Non-navigation requests get an empty `401`.

The hosted gate owns submission/reload JavaScript and CSP. The sidecar passes HTML/CSP through unchanged.

nginx uses a status-only auth subrequest, then a second internal `/auth` request on denial to return the full response at the original browser URL.

## Run

Build sidecar:
```
make build
```

Start:

```sh
PC_SITEKEY=YOUR_SITEKEY \
PC_API_KEY=YOUR_API_KEY \
PC_PROTECTED_ORIGIN=https://example.com \
PC_TRUSTED_PROXY_CIDRS=127.0.0.1/32 \
  ./bin/edge-sidecar
```

See [TESTING.md](docs/TESTING.md) for Docker setup.

## Configuration

| Setting | Default / requirement |
| --- | --- |
| `PC_SITEKEY`, `PC_API_KEY` | Required; API key belongs to the property's organization and has puzzle scope. |
| `PC_PROTECTED_ORIGIN` | Required HTTPS origin, including a non-default port. Property domain must match. |
| `PC_TRUSTED_PROXY_HOSTS` | Trusted internal proxy DNS names; Docker demos use `caddy` or `nginx`. |
| `PC_TRUSTED_PROXY_CIDRS` | Trusted socket-peer IPs/CIDRs; configure hosts, CIDRs, or both. |
| `PC_API_BASE_URL` | `https://api.privatecaptcha.com`; verification uses the official Go SDK. |
| `PC_ISSUER` | `https://api.privatecaptcha.com`; exact JWT issuer. |
| `PC_JWKS_URL` | `https://api.privatecaptcha.com/.well-known/jwks.json`; fixed URL, no redirects. |
| `PC_JWKS_REFRESH_INTERVAL` | `5m`; Go duration between `1s` and `24h`. |
| `PC_MAX_CONCURRENT_COMPLETIONS` | `512`; positive integer limiting concurrent completions per process. Saturation returns `429` with `Retry-After` before reading the form. |
| `PC_HOST`, `PC_PORT` | `localhost`, `8080`; demo binds privately on `0.0.0.0`. |
| `STAGE`, `PC_VERBOSE` | Shared logging settings. |

The property must have edge-tokens enabled. API verification uses HTTPS; loopback HTTP is supported for local JWKS fixtures. Fixed GET fetches retry transient failures with bounded backoff.

Send SIGHUP (`kill -HUP PID`) to reread a dotenv file (if you used `-env` argument with path to file) and apply validated settings to new requests (changing `PC_HOST` or `PC_PORT` requires a restart).

## Trust and token scope

```text
untrusted browser headers
         |
    proxy overwrites host/proto/method/URI/client-IP
         |
    sidecar checks actual proxy peer + configured origin
         |
    JWT: signature + issuer + aud=sitekey + signed hostname
```

Proxy headers describe the request; they do not authenticate the caller. Keep the sidecar private and trust only configured proxy peers. `X-Forwarded-For` identifies a browser IP, not the socket peer; the completion limiter uses the proxy's overwritten `X-PC-Client-IP` instead. Trusted proxy DNS results are cached for 10 seconds; expired results are never used after a failed lookup. Reloading clears this cache.

Current tokens use ES256, `typ=pc-edge+jwt`, `v=1`, `aud=<sitekey>`, and a signed `host` claim. Scheme/port are enforced separately through the configured origin. Cookie: `__Host-privatecaptcha-edge`, Secure, HttpOnly, SameSite=Lax, Path=/, no Domain, and lifetime no longer than JWT expiry.

Completion requires a same-origin POST, bounded form/proof sizes, and rate limits. Verification is never automatically retried because proofs can be single-use. Failures issue no cookie and expose only generic errors. Logs never contain API keys, proofs, JWTs, or cookie values.
