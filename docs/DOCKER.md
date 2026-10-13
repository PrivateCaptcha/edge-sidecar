# Docker

Use the [Caddy](CADDY.md) or [nginx](NGINX.md) guide for proxy configuration. The [Caddy](../docker/docker-compose.caddy.yml) and [nginx](../docker/docker-compose.nginx.yml) Compose examples build the sidecar from [Dockerfile](../docker/Dockerfile) and run it alongside a proxy and demo application.

## Container configuration

- Put the proxy, sidecar, and application on a shared Docker network. Use service names as upstreams (`privatecaptcha-authorizer:8080` and `app:8080` in the examples); loopback addresses only reach the current container.
- Bind the sidecar with `PC_HOST=0.0.0.0` and `PC_PORT=8080`, already set by the Dockerfile. Keep sidecar and application ports unpublished; browser traffic goes through the proxy's published HTTPS port.
- Set `PC_TRUSTED_PROXY_HOSTS=caddy` or `PC_TRUSTED_PROXY_HOSTS=nginx` instead of pinning container IPs. The sidecar resolves the service name and checks the connection peer IP against it.
- Set `PC_PROTECTED_ORIGIN` to the browser-facing HTTPS origin, including any non-default port. The examples derive it from `PC_EDGE_HOST` and `PC_EDGE_PORT`, not from a container address.

## Local demo

From the repository root, run `make setup-docker`, then edit the ignored `docker/.env`: set `PC_SITEKEY` for an enabled property with edge tokens enabled, `PC_API_KEY` with puzzle scope, and `PC_EDGE_HOST` to the property's domain. `PC_EDGE_PORT` defaults to `8443`. Map the hostname to `127.0.0.1` in your hosts file.

```sh
make validate-docker EDGE_PROXY=caddy
make run-docker EDGE_PROXY=caddy
```

Leave the stack running and open `https://<PC_EDGE_HOST>:<PC_EDGE_PORT>/private`. The demo uses the real PrivateCaptcha API. Trust the local certificate or add a browser exception: Caddy uses an internal CA, nginx a self-signed certificate.

Replace `caddy` with `nginx` to test nginx. Run one stack at a time because both use the same port. Stop it with `make stop-docker EDGE_PROXY=caddy`.

See [Testing](TESTING.md) for configuration reloads and Playwright end-to-end tests against either stack.
