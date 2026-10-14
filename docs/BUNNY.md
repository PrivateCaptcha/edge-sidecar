# PrivateCaptcha for Bunny CDN — User Manual

PrivateCaptcha Bunny Middleware protects an existing Bunny Pull Zone with a CAPTCHA before visitors can access your website. Visitors solve the challenge once, receive a secure browser cookie, and can browse until their **edge token expires**. No application changes are required.

## 1. Prerequisites

- A Bunny **Pull Zone** serving your website's HTTPS hostname (not only a static-assets hostname)
- A PrivateCaptcha property for that hostname, with [Edge protection](https://docs.privatecaptcha.com/docs/reference/edge-protection/) enabled
- The property's **sitekey** and a PrivateCaptcha API key authorized to call `/verify` (see [Getting started](https://docs.privatecaptcha.com/docs/getting-started/) tutorial)

## 2. Install in Bunny

1. In the [Bunny dashboard](https://dash.bunny.net/), create an **Edge Script -> Middleware** script and attach it to the website's existing Pull Zone.
2. Paste the contents of [`bunny-middleware.js`](./bunny-middleware.js) into the script editor
3. Configure the following **environment variables** (save `PC_API_KEY` as an **Environment Secret**):

   ```dotenv
   PC_SITEKEY=your-sitekey
   PC_PROTECTED_ORIGIN=https://www.example.com
   PC_API_KEY=your-secret-api-key
   ```

   The protected origin must match the browser's exact HTTPS origin, including `www` (or a nondefault port).
4. In the Pull Zone, enable **General -> Origin -> Run script before cache**. If this is not enabled, CDN cache hits might bypass CAPTCHA checks for the duration of `Cache-Control` header.
5. Publish the script and test it on a staging hostname first.

> Make sure your Pull zone does **NOT** block `POST` requests (in _"Security -> General"_).

### Optional settings

Unset or empty settings use these defaults:

| Environment variable | Default |
| --- | --- |
| `PC_API_BASE_URL` | `https://api.privatecaptcha.com` |
| `PC_ISSUER` | `https://api.privatecaptcha.com` |
| `PC_JWKS_URL` | `https://api.privatecaptcha.com/.well-known/jwks.json` |
| `PC_JWKS_REFRESH_INTERVAL_MS` | `300000` (5 minutes) |
| `PC_BYPASS_PREFIXES` | `/.well-known/` |

**Note:** Bypassed paths and `OPTIONS` requests are not CAPTCHA-protected. Review bypasses for your application.

## 3. Verify that it works

1. Open a protected page in a fresh private browser window. You should see a PrivateCaptcha challenge while the address bar retains the original URL.
2. Solve the challenge. In browser DevTools -> **Network**, confirm `POST /__privatecaptcha/complete` returns **204** and has a `Set-Cookie` header for `__Host-privatecaptcha-edge`.
3. The page should reload into your website. Navigate to another page on the **same hostname**; you should **not** be challenged again while the token is valid.
4. Open the page without the cookie, including after warming Bunny's cache, and confirm the challenge still appears.

## 4. Troubleshooting

| Symptom | What to check |
| --- | --- |
| `PrivateCaptcha is not configured` (503) | All three required settings are present; publish the updated script. |
| `Unrecognized hostname` (421) | `PC_PROTECTED_ORIGIN` exactly matches the browser origin, including `www` and HTTPS. |
| `Verification failed` (403) | Open Bunny script logs. The `verify_response` event records HTTP status, `success`, numeric PrivateCaptcha `code`, and `code_name`; inspect `completion_rejected` as well. |
| Challenge repeats on every page | Confirm `Set-Cookie` is delivered, the cookie is stored and included in the next request, the hostname stays the same, and the token has not expired. Check `edge_token_rejected` logs. |
| Website loads without a challenge | Confirm the script is attached to the correct Pull Zone and **Run script before cache** is enabled. |
| `PrivateCaptcha challenge unavailable` (503) | Check `gate_page_*` logs and connectivity to the PrivateCaptcha `/gate/page` endpoint. |

Do **not** log or share API keys, captcha solutions, JWTs, or cookie values. Protect the website's origin against direct access that bypasses Bunny. Use Bunny security/rate-limiting controls for `/__privatecaptcha/complete` and keep personalized application responses out of shared CDN caches.

For implementation details, build instructions, and full security notes, see the [project README](../README.md).
