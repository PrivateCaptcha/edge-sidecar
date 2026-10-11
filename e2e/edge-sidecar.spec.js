const { test, expect } = require('@playwright/test');

const completePath = '/__privatecaptcha/complete';
const cookieName = '__Host-privatecaptcha-edge';
const applicationText = 'PrivateCaptcha edge demo: application reached.';

test('solving the hosted challenge authorizes the original URL and subsequent requests', async ({ page, context, baseURL }) => {
  test.setTimeout(120_000);
  const protectedPath = '/private?demo=playwright&return=%2Faccount#resume';
  const protectedURL = new URL(protectedPath, baseURL);
  const pageErrors = [];
  page.on('pageerror', error => pageErrors.push(error.message));

  const challenge = await page.goto(protectedPath);
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
  await expect(page).toHaveURL(protectedURL.href);
  await expect(page.locator('body')).toHaveText(applicationText);

  for (const method of ['GET', 'POST']) {
    const response = await context.request.fetch('/private?demo=playwright-authorized', {
      method,
      headers: { Accept: 'application/json' },
      data: method === 'POST' ? 'marker=playwright' : undefined,
    });
    expect(response.status()).toBe(200);
    expect(await response.text()).toBe(applicationText);
  }

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

for (const { name, status, headers } of [
  { name: 'missing Origin', status: 403, headers: () => ({}) },
  { name: 'cross-origin submission', status: 403, headers: () => ({ Origin: 'https://attacker.example' }) },
  { name: 'unsupported content type', status: 415, headers: origin => ({ Origin: origin, 'Content-Type': 'application/json' }) },
  { name: 'empty proof', status: 400, headers: origin => ({ Origin: origin }) },
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
