import { test, expect, Page } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

const REALM = 'test-apiary';
const CLIENT_ID = 'theme-test-client';
const REDIRECT = `/realms/${REALM}/theme-test-landing`;

function authUrl(base: string) {
  const p = new URLSearchParams({
    client_id: CLIENT_ID,
    response_type: 'code',
    scope: 'openid',
    redirect_uri: base + REDIRECT,
  });
  return `/realms/${REALM}/protocol/openid-connect/auth?${p.toString()}`;
}

// #102's own acceptance criteria: fail on external requests (no CDN/font
// fetch) and console errors. Attached per-test so every spec below gets
// this for free without repeating the wiring.
function trackPageHealth(page: Page, baseURL: string) {
  const consoleErrors: string[] = [];
  const externalRequests: string[] = [];
  const baseOrigin = new URL(baseURL).origin;

  page.on('console', (msg) => {
    if (msg.type() === 'error') consoleErrors.push(msg.text());
  });
  page.on('pageerror', (err) => consoleErrors.push(String(err)));
  page.on('request', (req) => {
    const url = req.url();
    if (url.startsWith('data:') || url.startsWith('blob:')) return;
    if (!url.startsWith(baseOrigin)) externalRequests.push(url);
  });

  return {
    assertHealthy() {
      expect(consoleErrors, 'no console errors').toEqual([]);
      expect(externalRequests, 'no external/CDN requests -- theme must be fully local').toEqual([]);
    },
  };
}

test.describe('login page shell (#104 geometry, #98 branding)', () => {
  test('renders the centered shell with no split/artwork remnants', async ({ page, baseURL }) => {
    const health = trackPageHealth(page, baseURL!);
    await page.goto(authUrl(baseURL!));
    await page.waitForSelector('#username');

    // Real realm displayName, not hidden/faked CSS content (the bug #98
    // fixed, and the light-mode !important contrast bug found while
    // building this very test).
    await expect(page.locator('#kc-header-wrapper')).toHaveText('APIARY');
    await expect(page.locator('#kc-header-wrapper')).toBeVisible();

    // No split-screen grid, right-side artwork, or demo eyebrow (#104's
    // own acceptance criteria) -- the artwork asset doesn't exist at all
    // (removed in #104), and the shell must span full width, not 50%.
    // Full-width shell, not the old 50/50 split (which rendered .pf-v5-c-login
    // at exactly half the viewport). >=90% rather than exact equality: a
    // real vertical scrollbar legitimately shaves a few px off clientWidth
    // on some platforms, and that's not what this assertion is checking for.
    const shellWidth = await page.locator('.pf-v5-c-login').evaluate((el) => getComputedStyle(el).width);
    const viewportWidth = await page.evaluate(() => document.documentElement.clientWidth);
    expect(parseFloat(shellWidth)).toBeGreaterThan(viewportWidth * 0.9);

    // Card capped at 384px (#104's historical max-w-sm parity).
    const cardWidth = await page.locator('.pf-v5-c-login__main').evaluate((el) => el.getBoundingClientRect().width);
    expect(cardWidth).toBeLessThanOrEqual(384);

    // No horizontal overflow at this viewport (#104/#102 shared criterion).
    const hasOverflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth);
    expect(hasOverflow).toBe(false);

    health.assertHealthy();
    await expect(page).toHaveScreenshot('login-identity-step.png');
  });

  test('has no automatically detectable WCAG violations', async ({ page, baseURL }) => {
    await page.goto(authUrl(baseURL!));
    await page.waitForSelector('#username');
    const results = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa']).analyze();
    expect(results.violations, JSON.stringify(results.violations, null, 2)).toEqual([]);
  });
});

test.describe('#103 staged identity/credential interaction', () => {
  test('Enter key advances from identity to credential step and back via change', async ({ page, baseURL }) => {
    await page.goto(authUrl(baseURL!));
    const username = page.locator('#username');
    const password = page.locator('#password');

    await expect(username).toBeVisible();
    await expect(password).toBeHidden();

    await username.fill('test-user-no-totp');
    await username.press('Enter');

    await expect(password).toBeVisible();
    await expect(username.locator('xpath=ancestor::div[contains(@class,"pf-v5-c-form__group")]')).toBeHidden();
    await expect(page.locator('.kc-signing-in-as')).toBeVisible();
    await expect(page.locator('.kc-signing-in-as__who')).toHaveText('test-user-no-totp');
    // Real focus, not just visibility -- #102's own focus-placement requirement.
    await expect(password).toBeFocused();

    await page.locator('.kc-change-username').click();
    await expect(username).toBeVisible();
    await expect(password).toBeHidden();
    await expect(username).toBeFocused();
  });

  test('mouse click on Continue behaves the same as Enter', async ({ page, baseURL }) => {
    await page.goto(authUrl(baseURL!));
    await page.locator('#username').fill('test-user-no-totp');
    await page.locator('button[type="submit"], input[type="submit"]').click();
    await expect(page.locator('#password')).toBeVisible();
  });

  test('a server-rendered validation error is not hidden behind a staged step', async ({ page, baseURL }) => {
    await page.goto(authUrl(baseURL!));
    await page.locator('#username').fill('test-user-no-totp');
    await page.locator('#username').press('Enter');
    await page.locator('#password').fill('deliberately-wrong-password');
    await page.locator('input[type="submit"], button[type="submit"]').click();
    await page.waitForLoadState('networkidle');

    // Real Keycloak re-render with an error -- both fields must be visible
    // together, not hidden behind the identity step again.
    await expect(page.locator('#username')).toBeVisible();
    await expect(page.locator('#password')).toBeVisible();
  });

  test('theme toggle persists across reload', async ({ page, baseURL }) => {
    await page.goto(authUrl(baseURL!));
    const toggle = page.locator('#theme-toggle');
    await expect(toggle).toBeVisible();

    const before = await page.evaluate(() => document.documentElement.getAttribute('data-theme'));
    await toggle.click();
    const after = await page.evaluate(() => document.documentElement.getAttribute('data-theme'));
    expect(after).not.toBe(before);

    await page.reload();
    await page.waitForSelector('#username');
    const afterReload = await page.evaluate(() => document.documentElement.getAttribute('data-theme'));
    expect(afterReload).toBe(after);
  });

  test('JavaScript-disabled fallback still exposes a complete functional form', async ({ browser, baseURL }) => {
    const ctx = await browser.newContext({ javaScriptEnabled: false });
    const page = await ctx.newPage();
    await page.goto(authUrl(baseURL!));
    // Without JS, staging never happens -- both fields render together
    // (#104's own "JS-disabled mode exposes a complete functional Keycloak
    // form" acceptance criterion).
    await expect(page.locator('#username')).toBeVisible();
    await expect(page.locator('#password')).toBeVisible();
    await expect(page.locator('input[type="submit"], button[type="submit"]')).toBeVisible();
    await ctx.close();
  });
});

test.describe('#100 TOTP setup (mandatory, most-hit required action)', () => {
  test('renders the QR/secret setup form after first login', async ({ page, baseURL }) => {
    const health = trackPageHealth(page, baseURL!);
    await page.goto(authUrl(baseURL!));
    await page.locator('#username').fill('test-user-no-totp');
    await page.locator('#username').press('Enter');
    await page.locator('#password').fill('test-password-only');
    await Promise.all([
      page.waitForLoadState('networkidle'),
      page.locator('input[type="submit"], button[type="submit"]').click(),
    ]);

    await expect(page.locator('#kc-totp-secret-qr-code')).toBeVisible();
    await expect(page.locator('#totp')).toBeVisible();
    health.assertHealthy();
    await expect(page).toHaveScreenshot('totp-setup.png', {
      mask: [page.locator('#kc-totp-secret-qr-code'), page.locator('#kc-totp-secret-key')],
    });
  });
});
