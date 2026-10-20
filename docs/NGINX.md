# nginx

Use `auth_request` to authorize requests before forwarding them to your application. nginx must include [ngx_http_auth_request_module](https://nginx.org/en/docs/http/ngx_http_auth_request_module.html) (`nginx -V` shows its build flags). nginx Plus and application changes are not required.

## How it works

1. `auth_request` calls the internal `/__privatecaptcha/auth` location, which sends a bodyless `GET /auth` to the sidecar. It suppresses `Accept`, so a denial does not prepare HTML that the auth subrequest would discard. A `204` allows the original request through to the application.
2. On `401`, `error_page` internally routes to `/__privatecaptcha/gate`. This makes a second bodyless `GET /auth`, preserving browser headers, and returns the full response. Navigation requests receive hosted HTML and CSP; other requests receive an empty `401`. The browser URL never changes.
3. `/__privatecaptcha/complete` bypasses auth and forwards the proof to the sidecar. Its `Set-Cookie` and `204` reach the browser unchanged, then the hosted page reloads.

For challenged navigations, the sidecar caches the incoming referrer and sets an opaque, short-lived context cookie. `auth_request_set` captures `X-PC-Referer` from successful auth responses, and `proxy_set_header Referer` restores the application's referrer on the first matching authorized reload. Other authorized requests retain their incoming referrer. See [referrer preservation](../README.md#referrer-preservation) for cache scope and limits.

The original method is saved before the auth check because an [error_page redirect](https://nginx.org/en/docs/http/ngx_http_core_module.html#error_page) can change POST to GET. Auth requests omit the body and `Content-Length`, while authorized application requests retain their method, URI, and body. Application errors pass through without invoking the gate, and completion is never retried. WebSocket upgrade headers are forwarded to the application after authorization; the auth subrequests remain ordinary HTTP requests. Configure application ping frames or `proxy_read_timeout` for WebSockets that can remain idle for over 60s.

nginx overwrites the forwarded metadata and client IP. Keep the sidecar private and trust nginx's actual peer IP/CIDR, or use `PC_TRUSTED_PROXY_HOSTS=nginx` for a container deployment. Auth/gate helper locations are internal; other `/__privatecaptcha/*` paths return `404`.

## Configure the sidecar

This example protects `https://example.com`, with nginx terminating HTTPS, the sidecar on `127.0.0.1:8080`, and your application on `127.0.0.1:9000`.

Configure the sidecar with:

```dotenv
PC_HOST=127.0.0.1
PC_PORT=8080
PC_SITEKEY=YOUR_SITEKEY
PC_API_KEY=YOUR_API_KEY
PC_PROTECTED_ORIGIN=https://example.com
PC_TRUSTED_PROXY_CIDRS=127.0.0.1/32
```

Use an enabled property for `example.com` with edge tokens enabled, and an API key with puzzle scope. See [configuration](../README.md#configuration) for all settings.

For systemd, save these settings as `/etc/edgesidecar/example.conf` and run `edge-sidecar@example.service` using the [template service guide](SYSTEMD.md). Give each additional instance a distinct listening address/port combination and nginx upstream name, and use that site's instance for the auth, gate, and completion upstreams.

## nginx configuration example

Save this shared snippet as `/etc/nginx/snippets/privatecaptcha-sidecar.conf`:

```nginx
proxy_http_version 1.1;
proxy_set_header Connection "";
proxy_set_header X-Forwarded-Host $http_host;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header X-PC-Client-IP $remote_addr;
proxy_connect_timeout 5s;
proxy_read_timeout 12s;
proxy_buffer_size 8k;
proxy_cache off;
proxy_intercept_errors off;
```

Add the following inside nginx's `http` context, for example in `/etc/nginx/conf.d/privatecaptcha.conf`. Replace the domain, upstream addresses, and certificate paths with your deployment's values.

`/.well-known`, `/.well-known/*`, `/robots.txt`, `/favicon.ico`, and paths ending in `.xml`, `.rss`, or `.atom` bypass auth and proxy directly to the application.

```nginx
map $http_upgrade $pc_connection_upgrade {
    default upgrade;
    ''      '';
}

upstream privatecaptcha_authorizer {
    server 127.0.0.1:8080;
}

upstream privatecaptcha_app {
    server 127.0.0.1:9000;
}

server {
    listen 443 ssl;
    server_name example.com;
    ssl_certificate /etc/nginx/tls/server.crt;
    ssl_certificate_key /etc/nginx/tls/server.key;

    location = /__privatecaptcha/complete {
        auth_request off;
        client_max_body_size 1m;
        include /etc/nginx/snippets/privatecaptcha-sidecar.conf;
        proxy_next_upstream off;
        proxy_pass http://privatecaptcha_authorizer;
    }

    location = /__privatecaptcha/auth {
        internal;
        auth_request off;
        include /etc/nginx/snippets/privatecaptcha-sidecar.conf;
        proxy_method GET;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Forwarded-Method $pc_original_method;
        proxy_set_header X-Forwarded-Uri $request_uri;
        proxy_set_header Accept "";
        proxy_pass http://privatecaptcha_authorizer/auth;
    }

    location = /__privatecaptcha/gate {
        internal;
        auth_request off;
        include /etc/nginx/snippets/privatecaptcha-sidecar.conf;
        proxy_method GET;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Forwarded-Method $pc_original_method;
        proxy_set_header X-Forwarded-Uri $request_uri;
        proxy_pass http://privatecaptcha_authorizer/auth;
    }

    location ^~ /__privatecaptcha/ {
        return 404;
    }

    # Public paths bypass verification.
    location ~ ^/(?:\.well-known(?:/|$)|robots\.txt$|favicon\.ico$)|\.(?:xml|rss|atom)$ {
        auth_request off;
        proxy_intercept_errors off;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $pc_connection_upgrade;
        proxy_set_header Host $http_host;
        proxy_set_header X-Forwarded-Host $http_host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_pass http://privatecaptcha_app;
    }

    location / {
        set $pc_original_method $request_method;
        auth_request /__privatecaptcha/auth;
        auth_request_set $pc_referer $upstream_http_x_pc_referer;
        error_page 401 = /__privatecaptcha/gate;
        proxy_intercept_errors off;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $pc_connection_upgrade;
        proxy_set_header Host $http_host;
        proxy_set_header Referer $pc_referer;
        proxy_set_header X-Forwarded-Host $http_host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_pass http://privatecaptcha_app;
    }
}
```

Repeat `set $pc_original_method`, `auth_request`, `auth_request_set`, `proxy_set_header Referer`, and `error_page` in every protected application-serving location you add. Public locations use `auth_request off` instead. The `^~` on `/__privatecaptcha/` keeps reserved paths out of the public regex location; exact auth, gate, and completion locations still take precedence.

```sh
nginx -t && nginx -s reload
```

For separate hosts or containers, replace the loopback addresses with private upstream addresses. Environment-based examples: [`nginx.conf.example`](../docker/nginx.conf.example) and [`nginx-sidecar.conf`](../docker/nginx-sidecar.conf).
