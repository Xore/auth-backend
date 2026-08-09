import { defineConfig, devices } from '@playwright/test';

// #102: renders the real theme against a real disposable Keycloak instance
// (test/docker-compose.test.yml, pinned to keycloak.lock's exact
// image+digest), never a mock. No production credentials, no external
// IdPs (both required by #102's own acceptance criteria) -- the realm and
// users are throwaway fixtures created fresh per run.
const BASE_URL = process.env.KEYCLOAK_TEST_BASE_URL ?? 'http://127.0.0.1:8180';

export default defineConfig({
  testDir: './specs',
  fullyParallel: false, // shared Keycloak instance/realm state across specs
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: process.env.CI ? [['html', { open: 'never' }], ['github']] : 'list',
  use: {
    baseURL: BASE_URL,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  expect: {
    // Historical six-viewport contract (#104) -- desktop tier used as the
    // default project; tablet/mobile/UHQ/4K covered by dedicated projects
    // below rather than every spec re-declaring a viewport.
    toHaveScreenshot: { maxDiffPixelRatio: 0.02 },
  },
  projects: [
    { name: 'desktop-1440', use: { ...devices['Desktop Chrome'], viewport: { width: 1440, height: 900 } } },
    { name: 'tablet-820', use: { ...devices['Desktop Chrome'], viewport: { width: 820, height: 1180 } } },
    { name: 'mobile-390', use: { ...devices['Desktop Chrome'], viewport: { width: 390, height: 844 } } },
    { name: 'iphone-393', use: { ...devices['Desktop Chrome'], viewport: { width: 393, height: 852 } } },
    { name: 'uhq-1920', use: { ...devices['Desktop Chrome'], viewport: { width: 1920, height: 1080 } } },
    { name: 'uhd-3840', use: { ...devices['Desktop Chrome'], viewport: { width: 3840, height: 2160 } } },
  ],
});
