const { existsSync } = require('node:fs');
const { resolve } = require('node:path');
const { defineConfig } = require('@playwright/test');

const envFile = resolve(__dirname, process.env.EDGE_DOCKER_ENV || 'docker/.env');
if (existsSync(envFile)) {
  process.loadEnvFile(envFile);
}

module.exports = defineConfig({
  testDir: './e2e',
  timeout: 30_000,
  globalTimeout: 180_000,
  expect: { timeout: 10_000 },
  forbidOnly: Boolean(process.env.CI),
  workers: 1,
  reporter: [['list'], ['html', { open: 'never' }]],
  use: {
    browserName: 'chromium',
    channel: process.env.E2E_BROWSER_CHANNEL,
    baseURL: process.env.E2E_BASE_URL || `https://${process.env.PC_EDGE_HOST || 'edge.privatecaptcha.test'}:${process.env.PC_EDGE_PORT || '8443'}`,
    ignoreHTTPSErrors: true,
    trace: 'retain-on-failure',
  },
});
