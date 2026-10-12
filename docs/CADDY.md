# Caddy

Use the built-in [forward_auth](https://caddyserver.com/docs/caddyfile/directives/forward_auth)
directive with [`Caddyfile.example`](../docker/Caddyfile.example). The application
needs no changes.

## How it works

1. Caddy sends a bodyless `GET /auth` with the browser's cookie and original
   request metadata. A `204` allows the original request through to the application.
2. A `401` is returned to the browser with the sidecar's body and headers. Browser
   navigations receive hosted captcha HTML and CSP at the original URL;
   non-navigation requests receive an empty response.
3. `/__privatecaptcha/complete` bypasses auth and proxies directly to the sidecar.
   It verifies the proof, sets the edge cookie, and returns `204`. The hosted page
   reloads the original URL.

Caddy overwrites forwarded host, scheme, method, URI, and `X-PC-Client-IP`.
The sidecar validates the actual connection peer and configured HTTPS origin.
Keep it private and set `PC_TRUSTED_PROXY_HOSTS=caddy` in Docker, or configure
the Caddy peer CIDRs. Other `/__privatecaptcha/*` paths return `404`.

## Demo and tests

Configure the real property and hostname as described in [DOCKER.md](DOCKER.md).
Start the blocking demo in one terminal:

```sh
make validate-edge-docker EDGE_PROXY=caddy
make run-edge-docker EDGE_PROXY=caddy
```

In another terminal:

```sh
make test-e2e EDGE_PROXY=caddy
make reload-edge-docker EDGE_PROXY=caddy
make stop-edge-docker EDGE_PROXY=caddy
```

Compose file: [`docker-compose.caddy.yml`](../docker/docker-compose.caddy.yml).
The demo uses Caddy's internal CA; use normal HTTPS certificates in production.
The same [E2E suite](TESTING.md) runs against Caddy and nginx.
