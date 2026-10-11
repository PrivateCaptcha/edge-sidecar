# PrivateCaptcha edge sidecar

Caddy `forward_auth` authorization with a hosted captcha fallback. The application
needs no changes; Caddy proxies application traffic, while the sidecar handles
only `/auth`, `/__privatecaptcha/complete`, and `/healthz`.

## Flow

```text
Browser -> Caddy -> GET /auth
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

Known-key JWT checks are local. Keys are fetched at startup, refreshed periodically,
and refreshed once on an unknown `kid`. Failed refreshes retain cached keys.
Gate HTML is cached according to upstream freshness, but browser challenges
always use `Cache-Control: no-store`. Non-navigation requests get an empty `401`.

The hosted gate owns submission/reload JavaScript and CSP. The sidecar passes
HTML/CSP through unchanged.

## Run

```sh
make build-edge-sidecar
PC_SITEKEY=YOUR_SITEKEY PC_API_KEY=YOUR_API_KEY \
    PC_PROTECTED_ORIGIN=https://example.com \
    PC_TRUSTED_PROXY_CIDRS=127.0.0.1/32 ./bin/edge-sidecar
```

See [TESTING.md](docs/TESTING.md) for Docker setup.

## Configuration

Uses the shared [environment configuration](../../pkg/config/env.go). `-env FILE`
or `-env stdin` loads dotenv values; restart to apply configuration changes.

| Setting | Default / requirement |
| --- | --- |
| `PC_SITEKEY`, `PC_API_KEY` | Required; API key belongs to the property's organization and has puzzle scope. |
| `PC_PROTECTED_ORIGIN` | Required HTTPS origin, including a non-default port. Property domain must match. |
| `PC_TRUSTED_PROXY_HOSTS` | Trusted internal proxy DNS names; Docker demo uses `caddy`. |
| `PC_TRUSTED_PROXY_CIDRS` | Trusted socket-peer IPs/CIDRs; configure hosts, CIDRs, or both. |
| `PC_API_BASE_URL` | `https://api.privatecaptcha.com`; verification uses the official Go SDK. |
| `PC_ISSUER` | `https://api.privatecaptcha.com`; exact JWT issuer. |
| `PC_JWKS_URL` | `https://api.privatecaptcha.com/.well-known/jwks.json`; fixed URL, no redirects. |
| `PC_JWKS_REFRESH_INTERVAL` | `5m`; Go duration between `1s` and `24h`. |
| `PC_HOST`, `PC_PORT` | `localhost`, `8080`; demo binds privately on `0.0.0.0`. |
| `STAGE`, `PC_VERBOSE` | Shared logging settings. |

The property must have edge-tokens enabled. API verification uses HTTPS; loopback HTTP is supported for local JWKS fixtures. Fixed GET fetches retry transient failures with bounded backoff.

## Trust and token scope

```text
untrusted browser headers
         |
    Caddy overwrites host/proto/method/URI/client-IP
         |
    sidecar checks actual proxy peer + configured origin
         |
    JWT: signature + issuer + aud=sitekey + signed hostname
```

Caddy's headers describe the request; they do not authenticate the caller.
Keep the sidecar private and trust only configured Caddy peers. `X-Forwarded-For`
identifies a browser IP, not the socket peer; the completion limiter uses Caddy's
overwritten `X-PC-Client-IP` instead.

Current tokens use ES256, `typ=pc-edge+jwt`, `v=1`, `aud=<sitekey>`, and a signed
`host` claim. Scheme/port are enforced separately through the configured origin.
Cookie: `__Host-privatecaptcha-edge`, Secure, HttpOnly, SameSite=Lax, Path=/,
no Domain, and lifetime no longer than JWT expiry.

Completion requires a same-origin POST, bounded form/proof sizes, and rate limits.
Verification is never automatically retried because proofs can be single-use.
Failures issue no cookie and expose only generic errors. Logs never contain
API keys, proofs, JWTs, or cookie values.
