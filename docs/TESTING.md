# Testing

Run commands from the repository root.

## Unit tests

```sh
make test-unit
```

## Docker demo

Requires Docker. Both demos run a proxy, the sidecar, and a small
application against the real PrivateCaptcha API.

```sh
make setup-edge-docker
```

Edit the ignored `docker/.env`:

- Set `PC_SITEKEY` for an enabled property with edge tokens enabled, and
  `PC_API_KEY` to its organization's API key with puzzle scope.
- Set `PC_EDGE_HOST` to the property's domain; `PC_EDGE_PORT` defaults to `8443`.

Map that hostname to `127.0.0.1` in your hosts file, for example
`127.0.0.1 edge.privatecaptcha.test`.

Caddy is the default. Replace `caddy` with `nginx` in all commands to use nginx;
run one stack at a time because both use the same port.

Start the stack in one terminal and leave it running:

```sh
make validate-edge-docker EDGE_PROXY=caddy
make run-edge-docker EDGE_PROXY=caddy
```

For manual testing, open `https://<PC_EDGE_HOST>:<PC_EDGE_PORT>/private`.
Caddy uses an internal CA; nginx uses a self-signed certificate. A manual browser
needs the demo CA/certificate trusted or an exception.

After editing proxy configuration, run `make reload-edge-docker EDGE_PROXY=caddy`.

## End-to-end tests

The Playwright suite uses headless Chromium to solve the hosted captcha and check
completion, cookies, request forwarding, and denials against either proxy. Requires
Node.js 22+ and the running demo above; Playwright accepts its local TLS certificates.

Run in another terminal, using the same `EDGE_PROXY` as the running stack:

```sh
make setup-e2e
make test-e2e EDGE_PROXY=caddy
```

On Linux, add `PLAYWRIGHT_INSTALL_FLAGS=--with-deps` to `make setup-e2e`.
Reports are in `playwright-report/`, traces in `test-results/`.
CI tests both proxies; configure repository secrets `PC_SITEKEY`, `PC_API_KEY`,
and variable `PC_EDGE_HOST` for the test property.

Stop the demo when finished:

```sh
make stop-edge-docker EDGE_PROXY=caddy
```
