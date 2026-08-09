import { test, expect, Page } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import fs from 'fs';
import path from 'path';

// #91: account console theme (keycloak.v3, accountTheme=apiary). Unlike
// login.spec.ts's target, this is a compiled React SPA (PatternFly v5) --
// no FreeMarker templates, only theme.properties' `styles=` CSS layered on
// top of the upstream bundle. See themes/apiary/account/resources/css/
// account.css's own header comment for why its rules mirror login.css's.

const REALM = 'test-apiary';
const ACCOUNT_URL = `/realms/${REALM}/account/`;

async function login(page: Page, baseURL: string, username: string) {
  await page.goto(baseURL + ACCOUNT_URL);
  await page.waitForSelector('#username');
  await page.locator('#username').fill(username);
  await page.locator('#username').press('Enter');
  await page.locator('#password').fill('test-password-only');
  await page.locator('input[type="submit"], button[type="submit"]').click();
  await page.waitForURL('**/account/**');
  await page.waitForSelector('.pf-v5-c-masthead');
  await page.waitForLoadState('networkidle');
}

// Same acceptance criteria as login.spec.ts's trackPageHealth: no console
// errors, no external/CDN requests. Kept local rather than shared -- each
// spec file in this project owns its own helpers (see login.spec.ts's own
// submit()/authUrl()), and the two suites' health-tracking needs already
// diverge slightly (login.spec.ts also filters out one synthetic
// test-harness URL that doesn't apply here).
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

test.describe('Personal info (#91)', () => {
  for (const theme of ['light', 'dark'] as const) {
    for (const viewport of [{ name: 'desktop', width: 1440, height: 900 }, { name: 'mobile', width: 390, height: 844 }]) {
      test(`renders correctly in ${theme} at ${viewport.name}`, async ({ browser, baseURL }) => {
        const ctx = await browser.newContext({ viewport, colorScheme: theme });
        const page = await ctx.newPage();
        const health = trackPageHealth(page, baseURL!);
        await login(page, baseURL!, 'test-user-consent');

        await expect(page.getByTestId('page-heading')).toHaveText('Personal info');
        await expect(page.locator('#username')).toHaveValue('test-user-consent');

        // #91 (found live auditing this suite): keycloak.v3 wraps the
        // masthead's real content in a `.pf-v5-c-toolbar` that carries its
        // own hardcoded near-black PatternFly default independent of the
        // masthead's own background, and the user-menu toggle hardcodes
        // white text -- both invisible/wrong in at least one theme unless
        // account.css explicitly overrides them (see that file's own
        // comments). Assert computed styles directly, not just "no visual
        // regression", so a future drift fails loudly here instead of only
        // being visible in a screenshot diff nobody looked closely at.
        const toolbarBg = await page.locator('.pf-v5-c-masthead .pf-v5-c-toolbar').first().evaluate((el) => getComputedStyle(el).backgroundColor);
        expect(toolbarBg, 'masthead toolbar must not paint over the themed masthead background').toBe('rgba(0, 0, 0, 0)');
        const menuToggleColor = await page.locator('.pf-v5-c-masthead .pf-v5-c-menu-toggle__text').first().evaluate((el) => getComputedStyle(el).color);
        expect(menuToggleColor, 'user-menu toggle text must not hardcode white').not.toBe('rgb(255, 255, 255)');

        // #91: the real APIARY brand mark (theme.properties' `logo=`),
        // not Keycloak's own default logo.svg. Header.tsx only exposes one
        // logo path, so light/dark is handled inside the SVG itself (see
        // img/apiary-mark.svg's own comment) -- assert the browser actually
        // decoded it (naturalWidth/Height), not just that an <img> tag with
        // some src exists, since a malformed inline SVG renders as a
        // "successful" zero-size broken image with no console error at all
        // (found live building this: an XML comment containing a literal
        // double hyphen silently broke the whole file this way).
        const brand = page.locator('.pf-v5-c-masthead img').first();
        await expect(brand).toHaveAttribute('src', /apiary-mark\.svg$/);
        const brandSize = await brand.evaluate((el: HTMLImageElement) => ({ w: el.naturalWidth, h: el.naturalHeight }));
        expect(brandSize, 'brand mark must actually decode, not just have a src').toEqual({ w: 64, h: 64 });

        const hasOverflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth);
        expect(hasOverflow, `${viewport.name} must not overflow horizontally`).toBe(false);

        health.assertHealthy();
        await expect(page).toHaveScreenshot(`account-personal-info-${theme}-${viewport.name}.png`);
        await ctx.close();
      });
    }
  }

  test('has no automatically detectable WCAG violations', async ({ page, baseURL }) => {
    await login(page, baseURL!, 'test-user-consent');
    const results = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa']).analyze();
    expect(results.violations, JSON.stringify(results.violations, null, 2)).toEqual([]);
  });

  // #91's own acceptance criteria explicitly calls for "validation, error"
  // state coverage, not just the default/happy-path render every other
  // test here checks. test-user-consent has no firstName/lastName set and
  // this clears the required Email field too, so submitting fails
  // validation on all three -- a real server round trip, not a simulated
  // client-side state.
  test('shows a themed validation error on save with missing required fields', async ({ page, baseURL }) => {
    // No trackPageHealth/assertHealthy here -- unlike every other test in
    // this file, a real server-rejected 400 is this test's own expected
    // outcome, not a health regression to flag.
    await login(page, baseURL!, 'test-user-consent');
    await page.locator('#email').fill('');
    await page.getByRole('button', { name: 'Save' }).click();

    await expect(page.locator('.pf-v5-c-alert.pf-m-danger')).toBeVisible();
    await expect(page.locator('.pf-v5-c-helper-text__item.pf-m-error, .pf-v5-c-form__helper-text.pf-m-error').first()).toBeVisible();
    await expect(page).toHaveScreenshot('account-personal-info-validation-error.png');

    // Restore state for any later test that reuses this fixture user.
    await page.locator('#email').fill('test-user-consent@example.invalid');
  });

  // The other, equally-real state #91's acceptance criteria names:
  // "success". A real save that the server actually accepts, not a
  // simulated success banner.
  test('shows a themed success alert on a real accepted save', async ({ page, baseURL }) => {
    await login(page, baseURL!, 'test-user-consent');
    await page.locator('#firstName').fill('Test');
    await page.locator('#lastName').fill('User');
    await page.getByRole('button', { name: 'Save' }).click();

    await expect(page.locator('.pf-v5-c-alert.pf-m-success')).toBeVisible();
    await expect(page).toHaveScreenshot('account-personal-info-success.png');
  });
});

test.describe('Account security (#91)', () => {
  test('Signing in shows the password credential and a passkey setup link', async ({ page, baseURL }) => {
    const health = trackPageHealth(page, baseURL!);
    await login(page, baseURL!, 'test-user-consent');
    await page.getByText('Account security', { exact: true }).click();
    await page.getByText('Signing in', { exact: true }).click();
    await expect(page.getByTestId('page-heading')).toHaveText('Signing in');
    await expect(page.getByText('My password')).toBeVisible();
    // "Set up Authenticator application" is a PatternFly `pf-m-link` --
    // still a real <button role="button">, not an <a role="link">, despite
    // looking identical to a link. The credential-type sections
    // (password/OTP/passkey) also each render only after their own async
    // data fetch resolves -- confirmed live, a fresh session can take
    // longer than the default 5s auto-retry (and longer than
    // `networkidle`, which resolved before this settled) before the
    // "Two-factor authentication" section appears at all.
    await expect(page.getByRole('button', { name: /Set up Authenticator application/i })).toBeVisible({ timeout: 15_000 });
    health.assertHealthy();
    await expect(page).toHaveScreenshot('account-signing-in.png');
  });

  test('Device activity lists the current session and offers sign-out', async ({ page, baseURL }) => {
    const health = trackPageHealth(page, baseURL!);
    await login(page, baseURL!, 'test-user-consent');
    await page.getByText('Account security', { exact: true }).click();
    await page.getByText('Device activity', { exact: true }).click();
    await expect(page.getByTestId('page-heading')).toHaveText('Device activity');
    await expect(page.getByText('Current session')).toBeVisible();
    // The session list itself loads via a separate async API call after the
    // page shell renders -- wait for it to settle before looking for a
    // button that's part of that list, not the shell.
    await page.waitForLoadState('networkidle');
    await expect(page.getByRole('button', { name: 'Sign out all devices' })).toBeVisible();
    health.assertHealthy();
  });
});

test.describe('Applications (#91)', () => {
  test('lists the Account Console client itself', async ({ page, baseURL }) => {
    const health = trackPageHealth(page, baseURL!);
    await login(page, baseURL!, 'test-user-consent');
    await page.getByText('Applications', { exact: true }).click();
    await expect(page.getByTestId('page-heading')).toHaveText('Application');
    // Despite the visual table styling (account.css's own `.pf-v5-c-table`
    // rules), this list is actually built from <li>/<div> rows, not a real
    // <table> -- no ARIA cell/row roles to match against. It's an <a> with
    // no `href` (client-side-routed instead), so it carries no implicit
    // "link" role either (confirmed live) -- text match is what's actually
    // reliable here.
    await expect(page.getByText('Account Console', { exact: true })).toBeVisible({ timeout: 15_000 });
    health.assertHealthy();
    await expect(page).toHaveScreenshot('account-applications.png');
  });
});

test.describe('Masthead user menu (#91)', () => {
  test('opens, is legible, and offers sign out', async ({ page, baseURL }) => {
    await login(page, baseURL!, 'test-user-consent');
    const toggle = page.locator('.pf-v5-c-masthead .pf-v5-c-menu-toggle').first();
    await toggle.click();
    const signOut = page.getByRole('menuitem', { name: 'Sign out' });
    await expect(signOut).toBeVisible();
    // Real Keycloak RP-initiated logout, not a client-side illusion.
    await Promise.all([page.waitForURL((url) => !url.toString().includes('/account/')), signOut.click()]);
    await expect(page.locator('#username')).toBeVisible();
  });
});

test.describe('Mobile sidebar toggle (#91)', () => {
  test('hamburger opens and closes the nav drawer', async ({ browser, baseURL }) => {
    const ctx = await browser.newContext({ viewport: { width: 390, height: 844 } });
    const page = await ctx.newPage();
    await login(page, baseURL!, 'test-user-consent');

    const nav = page.locator('.pf-v5-c-page__sidebar');
    await expect(nav).not.toHaveClass(/pf-m-expanded/);
    await page.locator('.pf-v5-c-masthead .pf-v5-c-button').first().click();
    await expect(nav).toHaveClass(/pf-m-expanded/);
    await expect(nav.getByText('Personal info', { exact: true })).toBeVisible();
    await ctx.close();
  });
});

// #91's own remaining acceptance criteria: "Upgrade compatibility check
// fails loudly when the pinned Keycloak templates change incompatibly."
// login theme has verify-keycloak-compat.sh (hashes real upstream FTL/CSS
// files) -- there is no equivalent for a compiled React SPA with no
// individually-fetchable template files. This is the account theme's
// actual analogue: every CSS selector account.css depends on must match at
// least one real element on the real pages this suite already visits. If a
// future Keycloak upgrade renames/restructures the account console's DOM,
// this fails here (with the exact selector that broke) instead of the
// theme silently rendering unstyled PatternFly defaults again, the same
// class of bug this suite's masthead/toolbar checks above found live.
// Selectors real, confirmed live not to be reachable from any page this
// realm's enabled features can actually render, so a zero match for these
// specifically is not a compatibility signal:
//   .pf-v5-c-nav__section-title -- only renders for a second-level nav
//     section (Groups/Resources), both realm-feature-gated and disabled in
//     this fixture -- a known, already-documented gap from #111 itself.
//   .pf-v5-c-card, .pf-v5-c-card__title, .pf-v5-c-check__label,
//   .pf-v5-c-input-group, .pf-m-control -- account.css's own header
//     comment keeps these identical to login.css's values "for
//     consistency", but every credential-editing action this realm exposes
//     (password change included -- confirmed live: clicking "Update" on
//     the password credential redirects out to the *login* theme's
//     UPDATE_PASSWORD required-action page, not a form rendered inside the
//     account console SPA) redirects to the login theme instead of
//     rendering one of these components here. Real, currently-dead
//     defensive CSS, not a broken selector -- distinct from the
//     `.pf-v5-c-table` rules #91 found and removed, which were dead
//     because they targeted a component this Keycloak version never uses
//     at all, not because the state that would use them is unreachable.
const KNOWN_UNREACHABLE_SELECTORS = new Set([
  '.pf-v5-c-nav__section-title',
  '.pf-v5-c-card',
  '.pf-v5-c-card__title',
  '.pf-v5-c-check__label',
  '.pf-v5-c-input-group',
  '.pf-m-control',
]);

test.describe('Account theme DOM-hook compatibility (#91, #101 analogue)', () => {
  test('every account.css selector matches a real element on a visited page', async ({ page, baseURL }) => {
    const cssPath = path.resolve(__dirname, '../../themes/apiary/account/resources/css/account.css');
    const css = fs.readFileSync(cssPath, 'utf8').replace(/\/\*[\s\S]*?\*\//g, '');
    // Extract simple class/ID selectors only (not combinators/pseudo-classes/
    // custom-property names) -- good enough to catch a renamed PatternFly
    // component class, which is the actual failure mode this guards
    // against. Comments stripped first -- confirmed live this file's own
    // prose ("keycloak.v3", "theme.properties", "login.css") otherwise
    // false-positives as bogus ".v3"/".properties"/".css" selectors.
    const selectors = new Set<string>();
    for (const m of css.matchAll(/[.#][a-zA-Z][\w-]*/g)) {
      if (m[0].startsWith('--')) continue; // not a selector, a custom property
      if (KNOWN_UNREACHABLE_SELECTORS.has(m[0])) continue;
      selectors.add(m[0]);
    }

    const seen = new Map<string, number>();
    async function visit() {
      for (const sel of selectors) {
        const count = await page.locator(sel).count();
        seen.set(sel, (seen.get(sel) ?? 0) + count);
      }
    }

    await login(page, baseURL!, 'test-user-consent');
    await visit();
    // Validation/error state -- .pf-v5-c-alert.pf-m-danger and the
    // .pf-m-error helper-text selectors only render here.
    await page.locator('#email').fill('');
    await page.getByRole('button', { name: 'Save' }).click();
    await visit();
    await page.locator('#email').fill('test-user-consent@example.invalid');
    // Success state -- .pf-v5-c-alert.pf-m-success only renders here.
    await page.locator('#firstName').fill('Test');
    await page.locator('#lastName').fill('User');
    await page.getByRole('button', { name: 'Save' }).click();
    await visit();

    await page.getByText('Account security', { exact: true }).click();
    await page.getByText('Signing in', { exact: true }).click();
    await visit();
    await page.getByText('Device activity', { exact: true }).click();
    await visit();
    await page.getByText('Applications', { exact: true }).click();
    await visit();

    const unmatched = [...seen.entries()].filter(([, count]) => count === 0).map(([sel]) => sel);
    expect(unmatched, 'CSS selector(s) in account.css matched zero elements across every page this suite visits -- Keycloak upgrade likely renamed/restructured the account console DOM').toEqual([]);
  });
});
