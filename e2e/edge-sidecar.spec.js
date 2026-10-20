const { test, expect } = require('@playwright/test');

const completePath = '/__privatecaptcha/complete';
const cookieName = '__Host-privatecaptcha-edge';
const applicationText = 'PrivateCaptcha edge demo: application reached.';
const trackingQuery = 'utm_source=newsletter&utm_medium=email&utm_campaign=fall%20sale&tag=a&tag=b&empty=&flag&plus=a+b&literal=a%2Bb&return=%2Faccount%3Fx%3D1%26y%3D2';

test('solving the hosted challenge authorizes the original URL and subsequent requests', async ({ page, context, baseURL }) => {
  test.setTimeout(120_000);
  const protectedPath = `/private?${trackingQuery}&long=${'a'.repeat(2100)}#resume`;
  const protectedURL = new URL(protectedPath, baseURL);
  const pageErrors = [];
  page.on('pageerror', error => pageErrors.push(error.message));

  const originalReferer = 'https://referrer.example/';
  const challenge = await page.goto(protectedPath, { referer: originalReferer });
  expect(challenge.status()).toBe(401);
  expect(challenge.headers()['cache-control']).toBe('no-store');
  expect(challenge.headers()['content-security-policy']).toBeTruthy();
  await expect(page.locator('#gate-form')).toBeVisible();

  const [completion, application] = await Promise.all([
    page.waitForResponse(response => new URL(response.url()).pathname === completePath && response.request().method() === 'POST', { timeout: 120_000 }),
    page.waitForResponse(response => response.request().isNavigationRequest() && new URL(response.url()).pathname === protectedURL.pathname, { timeout: 120_000 }),
    page.getByRole('checkbox', { name: 'Click to verify' }).click(),
  ]);
  expect(completion.status()).toBe(204);
  expect(completion.headers()['cache-control']).toBe('no-store');
  expect(application.status()).toBe(200);
  expect(application.headers()['x-demo-uri']).toBe(protectedURL.pathname + protectedURL.search);
  expect(await application.request().headerValue('referer')).toBeNull();
  expect(application.headers()['x-demo-referer']).toBe(originalReferer);
  await expect(page).toHaveURL(protectedURL.href);
  await expect(page.locator('body')).toHaveText(applicationText);

  const cookies = (await context.cookies())
    .filter(cookie => cookie.name === cookieName)
    .map(({ name, domain, path, secure, httpOnly, sameSite, expires }) => ({ name, domain, path, secure, httpOnly, sameSite, expires }));
  expect(cookies).toHaveLength(1);
  expect(cookies[0]).toMatchObject({
    name: cookieName,
    domain: protectedURL.hostname,
    path: '/',
    secure: true,
    httpOnly: true,
    sameSite: 'Lax',
  });
  expect(cookies[0].expires).toBeGreaterThan(Date.now() / 1000);

  const reload = await page.reload();
  expect(reload.status()).toBe(200);
  expect(reload.headers()['x-demo-referer']).not.toBe(originalReferer);
  await expect(page).toHaveURL(protectedURL.href);
  await expect(page.locator('body')).toHaveText(applicationText);

  const authorizedPath = protectedURL.pathname + protectedURL.search;
  const referer = new URL('/referring-page?source=original', baseURL).href;
  for (const method of ['GET', 'POST']) {
    const response = await context.request.fetch(authorizedPath, {
      method,
      headers: { Accept: 'application/json', Referer: referer },
      data: method === 'POST' ? 'marker=playwright' : undefined,
    });
    expect(response.status()).toBe(200);
    expect(response.headers()['x-demo-method']).toBe(method);
    expect(response.headers()['x-demo-uri']).toBe(authorizedPath);
    expect(response.headers()['x-demo-host']).toBe(protectedURL.host);
    expect(response.headers()['x-demo-referer']).toBe(referer);
    expect(await response.text()).toBe(applicationText);
  }

  const echoPath = '/echo?return=%2Faccount&demo=playwright';
  const echoBody = 'marker=playwright&value=original-post-body';
  const echo = await context.request.post(echoPath, {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'X-Forwarded-Host': 'attacker.example',
      'X-Forwarded-Proto': 'http',
      'X-Forwarded-Method': 'DELETE',
      'X-Forwarded-Uri': '/forged',
      'X-PC-Client-IP': 'invalid',
    },
    data: echoBody,
  });
  expect(echo.status()).toBe(200);
  expect(echo.headers()['x-demo-method']).toBe('POST');
  expect(echo.headers()['x-demo-uri']).toBe(echoPath);
  expect(await echo.text()).toBe(echoBody);

  const upgrade = await context.request.get('/private?demo=websocket-upgrade', {
    headers: {
      Connection: 'Upgrade',
      Upgrade: 'websocket',
      'Sec-WebSocket-Version': '13',
      'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
    },
  });
  expect(upgrade.status()).toBe(200);
  expect(upgrade.headers()['x-demo-upgrade']).toBe('websocket');
  expect(upgrade.headers()['x-demo-connection'].toLowerCase()).toContain('upgrade');

  const applicationDenial = await context.request.get('/unauthorized', {
    headers: {
      Accept: 'text/html',
      'Sec-Fetch-Mode': 'navigate',
      'Sec-Fetch-Dest': 'document',
    },
  });
  expect(applicationDenial.status()).toBe(401);
  expect(applicationDenial.headers()['content-type']).toBe('text/plain; charset=utf-8');
  expect(await applicationDenial.text()).toBe('PrivateCaptcha edge demo: application unauthorized.');

  await context.clearCookies();
  const denied = await page.reload();
  expect(denied.status()).toBe(401);
  await expect(page.locator('#gate-form')).toBeVisible();
  expect(pageErrors).toEqual([]);
});

test('non-navigation requests without a cookie are denied without gate HTML', async ({ request }) => {
  for (const method of ['GET', 'POST']) {
    const response = await request.fetch('/private', {
      method,
      headers: { Accept: 'application/json' },
      data: method === 'POST' ? 'marker=unauthorized' : undefined,
    });
    expect(response.status()).toBe(401);
    expect(response.headers()['cache-control']).toBe('no-store');
    expect(response.headers()['set-cookie']).toBeUndefined();
    expect(await response.body()).toHaveLength(0);
  }
});

test('an invalid edge cookie does not authorize application access', async ({ request }) => {
  const response = await request.get('/private', {
    headers: { Cookie: `${cookieName}=invalid` },
  });
  expect(response.status()).toBe(401);
  expect(response.headers()['cache-control']).toBe('no-store');
  expect(response.headers()['set-cookie']).toBeUndefined();
  expect(await response.body()).toHaveLength(0);
});

test('unauthenticated WebSocket upgrades are denied without gate HTML', async ({ request }) => {
  const response = await request.get('/private?demo=websocket-denial', {
    headers: {
      Connection: 'Upgrade',
      Upgrade: 'websocket',
      'Sec-WebSocket-Version': '13',
      'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
    },
  });
  expect(response.status()).toBe(401);
  expect(response.headers()['cache-control']).toBe('no-store');
  expect(await response.body()).toHaveLength(0);
});

test('an unauthenticated POST never becomes a GET navigation challenge', async ({ request }) => {
  const response = await request.post('/private?demo=post-navigation', {
    headers: {
      Accept: 'text/html',
      'Sec-Fetch-Mode': 'navigate',
      'Sec-Fetch-Dest': 'document',
      'X-Forwarded-Method': 'GET',
    },
    data: 'marker=unauthorized',
  });
  expect(response.status()).toBe(401);
  expect(response.headers()['cache-control']).toBe('no-store');
  expect(response.headers()['set-cookie']).toBeUndefined();
  expect(await response.body()).toHaveLength(0);
});

test('browser navigation uses proxy metadata instead of spoofed forwarded headers', async ({ request }) => {
  const response = await request.get('/private?demo=spoofed-headers', {
    headers: {
      Accept: 'text/html',
      'Sec-Fetch-Mode': 'navigate',
      'Sec-Fetch-Dest': 'document',
      'X-Forwarded-Host': 'attacker.example',
      'X-Forwarded-Proto': 'http',
      'X-Forwarded-Method': 'POST',
      'X-Forwarded-Uri': '/forged',
      'X-PC-Client-IP': 'invalid',
    },
  });
  expect(response.status()).toBe(401);
  expect(response.headers()['cache-control']).toBe('no-store');
  expect(response.headers()['content-security-policy']).toBeTruthy();
  expect(response.headers()['set-cookie']).toBeUndefined();
  expect(await response.text()).toContain('id="gate-form"');
});

test('AJAX and htmx requests do not receive gate HTML', async ({ request }) => {
  for (const headers of [
    { 'X-Requested-With': 'XMLHttpRequest' },
    { 'HX-Request': 'true' },
  ]) {
    const response = await request.get('/private', {
      headers: { Accept: 'text/html', ...headers },
    });
    expect(response.status()).toBe(401);
    expect(response.headers()['cache-control']).toBe('no-store');
    expect(await response.body()).toHaveLength(0);
  }
});

test('auth helpers and unknown reserved routes are not public endpoints', async ({ request }) => {
  for (const path of ['/__privatecaptcha/auth', '/__privatecaptcha/gate', '/__privatecaptcha/unknown']) {
    const response = await request.get(path);
    expect(response.status()).toBe(404);
    expect(response.headers()['set-cookie']).toBeUndefined();
    expect(await response.text()).not.toContain(applicationText);
  }
});

for (const { name, status, headers } of [
  { name: 'missing Origin', status: 403, headers: () => ({}) },
  { name: 'cross-origin submission', status: 403, headers: () => ({ Origin: 'https://attacker.example' }) },
  { name: 'unsupported content type', status: 415, headers: origin => ({ Origin: origin, 'Content-Type': 'application/json' }) },
  { name: 'empty proof', status: 400, headers: origin => ({ Origin: origin }) },
  { name: 'spoofed proxy headers', status: 400, headers: origin => ({
    Origin: origin,
    'X-Forwarded-Host': 'attacker.example',
    'X-Forwarded-Proto': 'http',
    'X-PC-Client-IP': 'invalid',
  }) },
]) {
  test(`completion rejects ${name} without issuing a cookie`, async ({ request, baseURL }) => {
    const response = await request.post(completePath, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        ...headers(new URL(baseURL).origin),
      },
      data: 'private-captcha-solution=',
    });
    expect(response.status()).toBe(status);
    expect(response.headers()['cache-control']).toBe('no-store');
    expect(response.headers()['set-cookie']).toBeUndefined();
  });
}
