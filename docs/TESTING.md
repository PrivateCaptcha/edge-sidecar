# Testing

## Unit tests

```sh
make test-unit
```

## End-to-end tests

The Playwright suite requires Node.js 22+ and the running
[Docker demo](./DOCKER.md), configured with a real property and API key.
The test machine must resolve the property's hostname to the Caddy host.

```sh
make setup-e2e
make test-e2e
```

The runner reads `PC_EDGE_HOST` and `PC_EDGE_PORT` from `docker/.env` by default.
`EDGE_DOCKER_ENV` selects another env file, and `E2E_BASE_URL` overrides the test
origin. The local Caddy CA is accepted by the test browser and HTTP client.

The core suite checks a real hosted captcha solve, completion and cookie
attributes, reload with the original query/fragment, authorized GET/POST traffic,
and denial after clearing the cookie. Separate HTTP tests cover unauthenticated
requests, invalid cookies, and key completion validation failures.

For Linux CI, install Chromium's system dependencies during setup:

```sh
make setup-e2e PLAYWRIGHT_INSTALL_FLAGS=--with-deps
CI=1 E2E_BASE_URL=https://edge.privatecaptcha.test:8443 make test-e2e
```

Tests use one headless Chromium worker and isolated cookie contexts. Pass runner
options through `EXTRA_E2E_FLAGS`, for example `make test-e2e EXTRA_E2E_FLAGS=--headed`.
The HTML report is written to `playwright-report/`, with failure traces in
`test-results/`.

The E2E job in `.github/workflows/ci.yml` builds and starts the Docker demo, waits
for the sidecar, runs the suite, and stops the stack. Failures include container
logs and downloadable Playwright artifacts.

Configure these GitHub Actions repository settings:

- Secrets `PC_SITEKEY` and `PC_API_KEY` for the test property.
- Variable `PC_EDGE_HOST` matching the property's domain; defaults to
  `edge.privatecaptcha.test`.

CI maps that hostname to loopback and uses port `8443`. Credentials are supplied
through the environment. The E2E job runs on pushes and same-repository pull
requests, where repository secrets are available.
