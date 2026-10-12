# nginx

Use [`nginx.conf.example`](../docker/nginx.conf.example) with
[`nginx-sidecar.conf`](../docker/nginx-sidecar.conf). nginx must include
[ngx_http_auth_request_module](https://nginx.org/en/docs/http/ngx_http_auth_request_module.html)
(`nginx -V` shows its build flags). nginx Plus is not required.

## How it works

1. `auth_request` calls the internal `/__privatecaptcha/auth` location, which sends
   a bodyless `GET /auth` to the sidecar. It suppresses `Accept`, so a denial does
   not prepare HTML that the auth subrequest would discard. A `204` allows the
   original request through to the application.
2. On `401`, `error_page` internally routes to `/__privatecaptcha/gate`. This makes
   a second bodyless `GET /auth`, preserving browser headers, and returns the full
   response. Navigation requests receive hosted HTML and CSP; other requests
   receive an empty `401`. The browser URL never changes.
3. `/__privatecaptcha/complete` bypasses auth and forwards the proof to the sidecar.
   Its `Set-Cookie` and `204` reach the browser unchanged, then the hosted page reloads.

The original method is saved before the auth check because an
[error_page redirect](https://nginx.org/en/docs/http/ngx_http_core_module.html#error_page)
can change POST to GET. Auth requests omit the body and `Content-Length`, while
authorized application requests retain their method, URI, and body. Application
errors pass through without invoking the gate, and completion is never retried.
WebSocket upgrade headers are forwarded to the application after authorization;
the auth subrequests remain ordinary HTTP requests. Configure application ping
frames or `proxy_read_timeout` for WebSockets that can remain idle for over 60s.

nginx overwrites the forwarded metadata and client IP. Keep the sidecar private
and set `PC_TRUSTED_PROXY_HOSTS=nginx` in Docker, or configure its actual peer CIDRs.
Auth/gate helper locations are internal; other `/__privatecaptcha/*` paths return
`404`. Apply the auth directives to every application-serving location if you
extend the example. The example assumes nginx terminates HTTPS directly.

## Demo and tests

Configure the real property and hostname as described in [DOCKER.md](DOCKER.md).
Start the blocking demo in one terminal:

```sh
make validate-edge-docker EDGE_PROXY=nginx
make run-edge-docker EDGE_PROXY=nginx
```

In another terminal:

```sh
make test-e2e EDGE_PROXY=nginx
make reload-edge-docker EDGE_PROXY=nginx
make stop-edge-docker EDGE_PROXY=nginx
```

Compose file: [`docker-compose.nginx.yml`](../docker/docker-compose.nginx.yml).
The demo image generates a self-signed certificate and renders `${PC_*}` values
using nginx's Docker entrypoint. For production, replace those template values,
install the snippet at its configured include path, and provide normal HTTPS
certificates. The same [E2E suite](TESTING.md) runs against nginx and Caddy.
