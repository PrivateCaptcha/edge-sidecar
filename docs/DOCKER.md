# Full-flow edge-sidecar sample

The Compose demos run [Caddy](CADDY.md) or [nginx](NGINX.md), the same Go sidecar,
and the same tiny application. Both use the configured existing PrivateCaptcha API
for hosted gate HTML, puzzles, verification, and JWKS. There is no local replacement
challenge page, API mock, or additional PrivateCaptcha server.

Deploy the reviewed `pkg/api/gate.go` change before this sidecar: the hosted page
now owns completion fetch/reload and its CSP. The sidecar no longer injects a bridge.

## Configure and start

From the repository root:

```sh
make setup-edge-docker
```

Edit `docker/.env`, created from [`docker/.env.example`](../docker/.env.example):

- Set `PC_SITEKEY` and an API key with puzzle-verification scope in `PC_API_KEY`.
  The API key must belong to the property's organization.
- The property must be enabled and have edge-token issuance enabled.
- Its domain must match `PC_EDGE_HOST`. The default is
  `edge.privatecaptcha.test`; change it to your property's domain if needed.
- For a different PrivateCaptcha deployment, set the API base, issuer, and JWKS
  URL together. The configured API must publish the keys used to sign its tokens.

`docker/.env` is ignored by Git. This project's Compose file does not read the
main server's `docker/pc.env` or start its database services.

Add a local hosts entry for the chosen domain. For the default:

```text
127.0.0.1 edge.privatecaptcha.test
```

Then start the sample in a terminal that stays attached to the containers:

```sh
make run-edge-docker
```

Caddy is the default (`EDGE_PROXY=caddy`) and uses
[`docker-compose.caddy.yml`](../docker/docker-compose.caddy.yml). To run nginx:

```sh
make run-edge-docker EDGE_PROXY=nginx
```

nginx uses [`docker-compose.nginx.yml`](../docker/docker-compose.nginx.yml).
Pass `EDGE_PROXY=nginx` to all Docker and test targets when using that demo.
Both demos publish the same configured port; stop the current demo before
switching proxies. `make validate-edge-docker EDGE_PROXY=nginx` checks its Compose
configuration without starting containers.

Startup is blocking and streams container logs. Use another terminal for tests,
reloads, and stop commands. Detached startup and `--wait` are rejected by the
Makefile because `--wait` also implies detached mode.

Open `https://edge.privatecaptcha.test:8443/private?demo=1` using your configured
hostname and port. Caddy uses its internal CA for local HTTPS. To export its CA:

```sh
docker compose --env-file docker/.env -f docker/docker-compose.caddy.yml cp \
    caddy:/data/caddy/pki/authorities/local/root.crt /tmp/privatecaptcha-edge-root.crt
```

Trust that local CA in the browser used for testing. The exported root can also
be passed to `curl --cacert /tmp/privatecaptcha-edge-root.crt`.

The nginx demo generates a self-signed certificate for `PC_EDGE_HOST`, retained
in its own TLS volume and renewed when expired or the hostname changes. Export it:

```sh
docker compose --env-file docker/.env -f docker/docker-compose.nginx.yml cp \
    nginx:/etc/nginx/tls/server.crt /tmp/privatecaptcha-edge-nginx.crt
```

Trust that certificate for manual browser testing, or pass it to `curl --cacert`.
Playwright accepts either demo's certificate. HTTPS is necessary for the `Secure`,
host-prefixed edge cookie.

## Expected flow

1. A browser navigation without the edge cookie returns `401` containing the
   PrivateCaptcha-hosted gate, at the original `/private?demo=1` URL.
2. Solving submits the proof to the same-origin `/__privatecaptcha/complete`.
   The web server proxies that path directly to the sidecar, bypassing auth.
3. The sidecar calls authenticated `/verify`, validates the returned edge JWT,
   and sets the Secure/HttpOnly/SameSite=Lax cookie with an empty `204`.
4. The browser reloads the original URL and sees "application reached".
5. Subsequent valid-cookie requests verify locally without fetching gate HTML
   or calling `/verify` again.

Non-navigation requests without a valid cookie receive a simple `401` instead
of HTML. Use a fresh browser context to repeat the no-cookie test.

Compose creates its default network and assigns container addresses automatically.
There are no configured subnets or static container IPs. The sidecar uses
`PC_TRUSTED_PROXY_HOSTS=caddy` or `nginx`, resolves that Compose service name, and
compares the result with the actual connection peer. It resolves on each request
so the proxy can be recreated with a different address; DNS failure denies access.
The sidecar has no published host port. The demo HTTPS and Caddy admin ports are
published on host loopback only.

If updating from the static-network sample, recreate this demo without deleting
its certificate volumes:

```sh
make stop-edge-docker
make run-edge-docker
```

## Reload and inspect

The demos mount their checked-in proxy configurations, so editing them does not
require an image rebuild. For Caddy, validate and reload inside the running container:

```sh
docker compose --env-file docker/.env -f docker/docker-compose.caddy.yml exec caddy \
    caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
make reload-edge-docker
```

The loopback admin API also allows a reload without a host Caddy installation:

```sh
curl --fail -H 'Content-Type: text/caddyfile' \
    --data-binary @docker/Caddyfile http://127.0.0.1:2019/load
```

For nginx, reload re-renders the mounted template and validates it before applying:

```sh
make reload-edge-docker EDGE_PROXY=nginx
```

After Go changes, stop the current demo and rebuild it in the foreground:

```sh
make stop-edge-docker
make run-edge-docker
```

To stop the sample:

```sh
make stop-edge-docker
```
