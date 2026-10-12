# Testing

## Unit tests

```sh
make test-unit
```

## End-to-end tests

The Playwright suite requires Node.js 22+ and the running
[Docker demo](./DOCKER.md), configured with a real property and API key.
The test machine must resolve the property's hostname to the proxy host.

```sh
make setup-e2e
make test-e2e
```

The same `e2e/edge-sidecar.spec.js` runs against both demos. With nginx running:

```sh
make test-e2e EDGE_PROXY=nginx
```

`EDGE_PROXY` selects Docker tooling; tests use the configured origin. Run one demo
at a time, or set `E2E_BASE_URL` to the specific running demo you want to test.

The runner reads `PC_EDGE_HOST` and `PC_EDGE_PORT` from `docker/.env` by default.
`EDGE_DOCKER_ENV` selects another env file, and `E2E_BASE_URL` overrides the test
origin. Both demos' local TLS certificates are accepted by the test browser and
HTTP client.

To use an already installed Google Chrome for local tests:

```sh
E2E_BROWSER_CHANNEL=chrome make test-e2e EDGE_PROXY=nginx
```

The default and CI continue to use Playwright's bundled Chromium. See
[browser channels](https://playwright.dev/docs/browsers#google-chrome--microsoft-edge).

The core suite checks a real hosted captcha solve, completion and cookie
attributes, reload with the original query/fragment, authorized GET/POST traffic,
and denial after clearing the cookie. It also checks POST body/method/URI
preservation, application-generated `401` responses, and WebSocket upgrade-header
forwarding. Separate HTTP tests cover unauthenticated WebSocket upgrades and other
requests, invalid cookies, spoofed forwarded headers, POST
navigation detection, AJAX/htmx denial, reserved helper routes, and completion
validation failures.

For Linux CI, install Chromium's system dependencies during setup:

```sh
make setup-e2e PLAYWRIGHT_INSTALL_FLAGS=--with-deps
CI=1 E2E_BASE_URL=https://edge.privatecaptcha.test:8443 make test-e2e
```

Tests use one headless Chromium worker and isolated cookie contexts. Pass runner
options through `EXTRA_E2E_FLAGS`, for example `make test-e2e EXTRA_E2E_FLAGS=--headed`.
The HTML report is written to `playwright-report/`, with failure traces in
`test-results/`.

The E2E matrix in `.github/workflows/ci.yml` validates, builds, and starts each
Docker demo independently. Compose stays attached and blocking while the test
runner waits for readiness and runs the same suite alongside it, then stops the
stack. Container logs stream directly into the job; failures also include
proxy-specific Playwright artifacts.

Configure these GitHub Actions repository settings:

- Secrets `PC_SITEKEY` and `PC_API_KEY` for the test property.
- Variable `PC_EDGE_HOST` matching the property's domain; defaults to
  `edge.privatecaptcha.test`.

CI maps that hostname to loopback and uses port `8443`. Credentials are supplied
through the environment. The E2E job runs on pushes and same-repository pull
requests, where repository secrets are available.
