# Caddy

Use the built-in [forward_auth](https://caddyserver.com/docs/caddyfile/directives/forward_auth) directive to authorize requests before forwarding them to your application. Caddy serves the hosted captcha response at the original URL when access is denied; the application needs no changes.

## How it works

1. Caddy sends a bodyless `GET /auth` with the browser's cookie and original request metadata. A `204` allows the original request through to the application.
2. A `401` is returned to the browser with the sidecar's body and headers. Browser navigations receive hosted captcha HTML and CSP at the original URL; non-navigation requests receive an empty response.
3. `/__privatecaptcha/complete` bypasses auth and proxies directly to the sidecar. It verifies the proof, sets the edge cookie, and returns `204`. The hosted page reloads the original URL.

For challenged navigations, the sidecar caches the incoming referrer and sets an opaque, short-lived context cookie. On the first matching authorized reload, `copy_headers X-PC-Referer>Referer` restores the application's `Referer` header. Other authorized requests retain their incoming referrer. See [referrer preservation](../README.md#referrer-preservation) for cache scope and limits.

Caddy overwrites forwarded host, scheme, method, URI, and `X-PC-Client-IP`. The sidecar validates the actual connection peer and configured HTTPS origin. Keep it private and trust Caddy's actual peer IP/CIDR, or use `PC_TRUSTED_PROXY_HOSTS=caddy` for a container deployment. Other `/__privatecaptcha/*` paths return `404`.

## Configure the sidecar

This example protects `https://example.com`, with the sidecar on `127.0.0.1:8080` and your application on `127.0.0.1:9000`. Configure the sidecar with:

```dotenv
PC_HOST=127.0.0.1
PC_PORT=8080
PC_SITEKEY=YOUR_SITEKEY
PC_API_KEY=YOUR_API_KEY
PC_PROTECTED_ORIGIN=https://example.com
PC_TRUSTED_PROXY_CIDRS=127.0.0.1/32
```

Use an enabled property for `example.com` with edge tokens enabled, and an API key with puzzle scope. See [configuration](../README.md#configuration) for all settings.

## Caddyfile example

Use this layout for your site's Caddyfile block, replacing the domain and upstream addresses. Caddy manages the site's HTTPS certificates automatically.

```caddyfile
example.com {
    @public path /.well-known /.well-known/* /robots.txt /favicon.ico *.xml *.rss *.atom

    route {
        # Public paths — bypass all verification
        handle @public {
            reverse_proxy 127.0.0.1:9000
        }

        # PrivateCaptcha completion endpoint
        handle /__privatecaptcha/complete {
            reverse_proxy 127.0.0.1:8080 {
                header_up X-Forwarded-Host {http.request.hostport}
                header_up X-Forwarded-Proto {scheme}
                header_up X-PC-Client-IP {remote_host}
                transport http {
                    dial_timeout 5s
                    response_header_timeout 12s
                }
            }
        }

        # Protected website
        handle {
            forward_auth 127.0.0.1:8080 {
                uri /auth?
                copy_headers X-PC-Referer>Referer
                header_up X-Forwarded-Host {http.request.hostport}
                header_up X-Forwarded-Proto {scheme}
                header_up X-Forwarded-Uri {uri}
                header_up X-Forwarded-Method {method}
                header_up X-PC-Client-IP {remote_host}
                transport http {
                    dial_timeout 5s
                    response_header_timeout 12s
                }
            }

            reverse_proxy 127.0.0.1:9000
        }
    }
}
```

Keep application handlers inside the final `handle` block, after `forward_auth`.

The trailing `?` in `uri /auth?` clears the query string only on the auth request. The full original URI remains in `X-Forwarded-Uri`, and the application receives the original path and query string, including tracking parameters.

```sh
caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile
```

For separate hosts or containers, replace the loopback addresses with private upstream addresses. An environment-based version is in [`Caddyfile.example`](../docker/Caddyfile.example).
