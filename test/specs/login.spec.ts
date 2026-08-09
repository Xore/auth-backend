import { test, expect, Page } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import * as OTPAuth from 'otpauth';
import { adminToken } from '../realm-admin';

const REALM = 'test-apiary';
const CLIENT_ID = 'theme-test-client';
const REDIRECT = `/realms/${REALM}/theme-test-landing`;

function authUrl(base: string, clientId = CLIENT_ID) {
  const p = new URLSearchParams({
    client_id: clientId,
    response_type: 'code',
    scope: 'openid',
    redirect_uri: base + REDIRECT,
  });
  return `/realms/${REALM}/protocol/openid-connect/auth?${p.toString()}`;
}

async function submit(page: Page) {
  await Promise.all([
    page.waitForLoadState('networkidle'),
    page.locator('input[type="submit"], button[type="submit"]').click(),
  ]);
}

// #106: login-config-totp.ftl's raw secret only renders in "unable to scan"
// (manual) mode -- the default view is QR-only. Realm's otpPolicyAlgorithm
// must match apiary-realm.json's real HmacSHA256 (fixtures/realm-export.json),
// not otpauth's SHA1 default, or the generated code is simply wrong.
async function completeTotpSetup(page: Page) {
  await Promise.all([page.waitForLoadState('networkidle'), page.locator('#mode-manual').click()]);
  const secret = (await page.locator('#kc-totp-secret-key').innerText()).trim();
  const totp = new OTPAuth.TOTP({ secret: OTPAuth.Secret.fromBase32(secret), digits: 6, period: 30, algorithm: 'SHA256' });
  await page.locator('#totp').fill(totp.generate());
  await page.locator('#userLabel').fill('test-device');
  await submit(page);
}

// #106/#107: registers/authenticates a real passkey credential via CDP's
// virtual authenticator (Playwright supports this directly) -- not a mock
// of the WebAuthn API, a real ceremony against Keycloak's own
// webauthnRegister.js/webauthnAuthenticate.js. `automaticPresenceSimulation`
// skips the (unautomatable) hardware user-presence gesture only; everything
// else is the real client<->RP handshake.
//
// navigator.credentials.create()/.get() resolve asynchronously *after* the
// click event handler returns -- those scripts only submit the form once
// that promise settles. Racing the click against
// `waitForLoadState('networkidle')` via Promise.all is wrong here:
// networkidle can (and did, confirmed live) resolve immediately since the
// ceremony itself makes no network request, completing the Promise.all
// well before the eventual form-submit navigation even starts. Sequential
// awaits, not concurrent, are required.
async function clickWebAuthnButton(page: Page, selector: string) {
  const before = page.url();
  await page.locator(selector).click();
  // A successful ceremony navigates away from the current required-action/
  // authenticate URL; a deliberately-failing one (webauthn-error's own
  // test) redraws the same URL with an error message instead. Wait for
  // either outcome explicitly rather than trusting networkidle alone,
  // which resolves on its own schedule unrelated to whether the
  // ceremony's promise -- let alone the eventual navigation -- has
  // actually settled (confirmed live: a bare networkidle wait after click
  // raced ahead of the real redirect often enough to be a real bug, not a
  // one-off flake).
  await page.waitForURL((url) => url.toString() !== before, { timeout: 10_000 }).catch(() => {});
  await page.waitForLoadState('networkidle');
}

// REDIRECT ("theme-test-landing") is a bare capture point for the auth
// code/session_state query string, not a real page -- it 404s, which is
// fine for tests that only inspect the URL after redirect, but a real
// browser 404 network error logs a delayed console message that can land
// on whatever `page.on('console')` listener happens to be attached by the
// time Chromium gets around to emitting it (confirmed live: a
// trackPageHealth() created for a later, unrelated step caught it). Stub it
// to a plain 200 wherever a test actually completes a login redirect.
async function stubLandingPage(page: Page) {
  await page.route('**/theme-test-landing*', (route) => route.fulfill({ status: 200, contentType: 'text/plain', body: 'ok' }));
}

// Deliberately NOT part of fixtures/realm-export.json: the real APIARY
// realm has internationalization off (no locale switcher), and
// Keycloak only shows one at all once 2+ locales are supported --
// baking this into the shared fixture would put a language dropdown on
// every other test's screenshot baseline, permanently diverging them from
// what production actually renders (confirmed live: the first version of
// this test did exactly that, and every unrelated baseline changed).
// Toggled on for the duration of this one test via the admin REST API
// instead, and always restored after, pass or fail.
async function withInternationalization(baseURL: string, fn: () => Promise<void>) {
  const token = await adminToken(baseURL);
  const authHeaders = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };
  const realmUrl = `${baseURL}/admin/realms/test-apiary`;

  // Keycloak's realm PUT replaces the whole representation, not a partial
  // patch -- GET the current realm and merge in just these fields, or
  // every other realm setting (TOTP policy, required actions, SMTP, ...)
  // would silently reset to Keycloak's defaults.
  const patch = async (fields: Record<string, unknown>) => {
    const getRes = await fetch(realmUrl, { headers: authHeaders });
    if (!getRes.ok) throw new Error(`failed to read realm before patching: ${getRes.status} ${await getRes.text()}`);
    const realm = await getRes.json();
    const res = await fetch(realmUrl, { method: 'PUT', headers: authHeaders, body: JSON.stringify({ ...realm, ...fields }) });
    if (!res.ok) throw new Error(`failed to update realm internationalization settings: ${res.status} ${await res.text()}`);
  };

  await patch({ internationalizationEnabled: true, supportedLocales: ['en', 'ar'], defaultLocale: 'en' });
  try {
    await fn();
  } finally {
    await patch({ internationalizationEnabled: false, supportedLocales: [], defaultLocale: 'en' });
  }
}

// Returns { cdp, authenticatorId } so a caller that needs a *second*, empty
// authenticator (webauthn-error's own test: the first authenticator, still
// attached, holds a real credential that would otherwise satisfy the later
// getAssertion call) can remove this one first via
// `cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId })`.
async function addVirtualAuthenticator(page: Page) {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  return { cdp, authenticatorId };
}

// #102's own acceptance criteria: fail on external requests (no CDN/font
// fetch) and console errors. Attached per-test so every spec below gets
// this for free without repeating the wiring.
//
// #107: also asserts zero real CSP violations. Chromium reports a
// `securitypolicyviolation` DOM event for every enforced-policy breach --
// that is the actual enforcement signal, not an incidental side effect of
// it also usually logging to the console (which the consoleErrors check
// above only catches by accident, not by design). Registered via
// addInitScript (awaited -- must be confirmed installed before the
// caller's next page.goto(), not raced against it) so it's listening
// before any theme script on the page runs, on every navigation this page
// object makes -- every existing call site below gets real CSP coverage
// for free, not just the dedicated tests in the "#107 CSP enforcement"
// block further down.
async function trackPageHealth(page: Page, baseURL: string) {
  const consoleErrors: string[] = [];
  const externalRequests: string[] = [];
  const baseOrigin = new URL(baseURL).origin;

  await page.addInitScript(() => {
    (window as any).__cspViolations = [];
    window.addEventListener('securitypolicyviolation', (e) => {
      (window as any).__cspViolations.push({ directive: e.violatedDirective, blockedURI: e.blockedURI });
    });
  });

  page.on('console', (msg) => {
    if (msg.type() !== 'error') return;
    // REDIRECT ("theme-test-landing") is a bare capture point for the auth
    // code/session_state query string, not a real theme page -- it 404s by
    // design. Keycloak's own template.ftl-injected session-polling
    // (authChecker.js's startSessionPolling/checkAuthSession) hits it from
    // a background iframe on its own schedule, independent of whichever
    // test's page.route() stub happens to be registered at that moment
    // (confirmed live: this fired across unrelated tests, not only ones
    // that complete a real login redirect). A 404 against this synthetic
    // test-harness URL is not a signal about the theme under test.
    if (msg.location().url.includes('theme-test-landing')) return;
    consoleErrors.push(msg.text());
  });
  page.on('pageerror', (err) => consoleErrors.push(String(err)));
  page.on('request', (req) => {
    const url = req.url();
    if (url.startsWith('data:') || url.startsWith('blob:')) return;
    if (!url.startsWith(baseOrigin)) externalRequests.push(url);
  });

  return {
    async assertHealthy() {
      expect(consoleErrors, 'no console errors').toEqual([]);
      expect(externalRequests, 'no external/CDN requests -- theme must be fully local').toEqual([]);
      const cspViolations = await page.evaluate(() => (window as any).__cspViolations ?? []);
      expect(cspViolations, 'no real CSP violations (securitypolicyviolation events)').toEqual([]);
    },
  };
}

// #107: real production CSP (confirmed live against the deployed realm,
// Keycloak's own unmodified default -- this repo's realm export carries no
// browserSecurityHeaders override): object-src and frame-ancestors are
// enforced, script-src is not restricted. Asserting the exact header value
// catches a realm misconfiguration that silently widens or drops it;
// asserting a deliberate object-src violation is actually blocked (not
// merely assumed from the header being present) proves enforcement, not
// just configuration.
const EXPECTED_CSP = "frame-src 'self'; frame-ancestors 'self'; object-src 'none';";

test.describe('#107 CSP enforcement', () => {
  test('login page sends the expected Content-Security-Policy header', async ({ page, baseURL }) => {
    const health = await trackPageHealth(page, baseURL!);
    const response = await page.goto(authUrl(baseURL!));
    await page.waitForSelector('#username');
    expect(response?.headers()['content-security-policy']).toBe(EXPECTED_CSP);
    await health.assertHealthy();
  });

  test('object-src is actually enforced, not just present in the header', async ({ page, baseURL }) => {
    const health = await trackPageHealth(page, baseURL!);
    await page.goto(authUrl(baseURL!));
    await page.waitForSelector('#username');

    // A real violation attempt, not a mock: an <object> element pointed at
    // a same-origin resource still trips object-src 'none' -- CSP's
    // object-src has no same-origin exception the way script-src's
    // 'self' would. Same-origin (not cross-origin) specifically so a
    // failure here can only mean object-src, never externalRequests/CORS.
    const violation = await page.evaluate(() => new Promise((resolve) => {
      window.addEventListener('securitypolicyviolation', (e) => resolve({
        directive: e.violatedDirective,
        blockedURI: e.blockedURI,
      }), { once: true });
      const obj = document.createElement('object');
      obj.data = window.location.origin + '/favicon.ico';
      document.body.appendChild(obj);
    }));

    expect(violation).toMatchObject({ directive: 'object-src' });
    // No health.assertHealthy() here: this test deliberately triggers a
    // real CSP violation, which assertHealthy()'s own "no violations"
    // check would then correctly fail on.
  });
});

test.describe('login page shell (#104 geometry, #98 branding)', () => {
  test('renders the centered shell with no split/artwork remnants', async ({ page, baseURL }) => {
    const health = await trackPageHealth(page, baseURL!);
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

    await health.assertHealthy();
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
    const health = await trackPageHealth(page, baseURL!);
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
    await health.assertHealthy();
    await expect(page).toHaveScreenshot('totp-setup.png', {
      mask: [page.locator('#kc-totp-secret-qr-code'), page.locator('#kc-totp-secret-key')],
    });
  });
});

test.describe('#106 email verification (default required action, VERIFY_EMAIL)', () => {
  test('renders the real "check your email" state, not the SMTP-failure fallback', async ({ page, baseURL }) => {
    const health = await trackPageHealth(page, baseURL!);
    await page.goto(authUrl(baseURL!));
    await page.locator('#username').fill('test-user-verify-email');
    await page.locator('#username').press('Enter');
    await page.locator('#password').fill('test-password-only');
    await submit(page);

    // Without a reachable SMTP server (docker-compose.test.yml's mailhog),
    // RequiredActionVerifyEmail throws before login-verify-email.ftl's own
    // content ever renders, falling back to the generic error.ftl "Failed
    // to send email" page instead -- confirmed live while auditing #106.
    await expect(page.locator('#kc-page-title')).toHaveText('Email verification');
    await expect(page.getByText('Click here', { exact: false })).toBeVisible();
    await health.assertHealthy();
    await expect(page).toHaveScreenshot('verify-email.png');
  });
});

test.describe('#106 consent (login-oauth-grant.ftl -- not reachable by any real client today)', () => {
  test('renders with theme-matched title and secondary button, not PatternFly defaults', async ({ page, baseURL }) => {
    const health = await trackPageHealth(page, baseURL!);
    await page.goto(authUrl(baseURL!, 'theme-test-consent-client'));
    await page.locator('#username').fill('test-user-consent');
    await page.locator('#username').press('Enter');
    await page.locator('#password').fill('test-password-only');
    await submit(page);

    // #kc-page-title wraps oauth-grant.ftl's own <p> -- the vendored
    // xore-theme.css's generic `p { color: var(--text-secondary) }` rule
    // beat the inherited h1 color here before #106's fix (confirmed live).
    const titleColor = await page.locator('#kc-page-title').evaluate((el) => getComputedStyle(el).color);
    const pColor = await page.locator('#kc-page-title p').evaluate((el) => getComputedStyle(el).color);
    expect(pColor).toBe(titleColor);

    // kcButtonSecondaryClass ("No") reads its visible border from a
    // PatternFly `::after` pseudo-element driven by CSS custom properties,
    // not the element's own border/background -- confirmed live that a
    // plain-property override is a no-op here.
    const noButton = page.getByRole('button', { name: 'No' });
    await expect(noButton).toBeVisible();
    const noBg = await noButton.evaluate((el) => getComputedStyle(el).backgroundColor);
    expect(noBg).not.toBe('rgba(0, 0, 0, 0)');

    await health.assertHealthy();
    await expect(page).toHaveScreenshot('consent.png');
  });
});

// Registers both TOTP and a passkey for `username`, then logs out --
// leaves the account ready for a fresh login where both are "applicable"
// alternatives. Each caller must pass its own dedicated fixture user: this
// mutates real server-side account state (required actions, credentials),
// so two tests sharing one username would contaminate each other (confirmed
// live: exactly this happened before splitting test-user-multi-factor into
// per-test accounts).
async function setupMultiFactorUser(page: Page, baseURL: string, username: string) {
  await page.goto(authUrl(baseURL));
  await page.locator('#username').fill(username);
  await page.locator('#username').press('Enter');
  await page.locator('#password').fill('test-password-only');
  await submit(page);
  await completeTotpSetup(page);
  await clickWebAuthnButton(page, '#registerWebAuthn');
  expect(page.url()).toContain('/theme-test-landing');

  await page.goto(`${baseURL}/realms/${REALM}/protocol/openid-connect/logout?client_id=${CLIENT_ID}&post_logout_redirect_uri=${encodeURIComponent(baseURL + REDIRECT)}`);
  await page.waitForLoadState('networkidle');
  const logoutConfirm = page.locator('#kc-logout');
  if (await logoutConfirm.isVisible().catch(() => false)) {
    await Promise.all([page.waitForLoadState('networkidle'), logoutConfirm.click()]);
  }
}

// These three tests mutate real server-side account state (completing
// required actions, registering credentials) against fixture usernames
// that are shared realm-wide -- unlike every other test in this file, which
// only ever renders/screenshots a page without submitting the action that
// would change it, safe to repeat identically across all six viewport
// projects against the one shared disposable Keycloak instance
// (playwright.config.ts has no per-project realm isolation). Re-running
// these same three across all six projects reruns the same mutations
// against the same accounts and the second project's attempt finds the
// required action already gone (confirmed live) -- so each runs once, on
// desktop-1440 only. Genuine cross-viewport coverage for these specific
// pages is #672's concern, not re-litigated here.
const STATEFUL_WEBAUTHN_PROJECT = 'desktop-1440';

test.describe('#106 WebAuthn/passkey required action (webauthn-register.ftl)', () => {
  test('completes a real registration ceremony via CDP virtual authenticator', async ({ page, baseURL }, testInfo) => {
    test.skip(testInfo.project.name !== STATEFUL_WEBAUTHN_PROJECT, 'stateful ceremony -- runs once, see comment above this describe block');
    await addVirtualAuthenticator(page);
    await stubLandingPage(page);
    const health = await trackPageHealth(page, baseURL!);
    await page.goto(authUrl(baseURL!));
    await page.locator('#username').fill('test-user-webauthn-register');
    await page.locator('#username').press('Enter');
    await page.locator('#password').fill('test-password-only');
    await submit(page);

    // Keycloak 26.7.1 has no separate webauthn-register-passwordless.ftl --
    // both the "webauthn-register" and "webauthn-register-passwordless"
    // required actions render this exact template (confirmed against the
    // pinned release's theme source tree; docs/PAGE-MATRIX.md's older
    // reference to a distinct passwordless template no longer applies).
    await expect(page.locator('#kc-page-title')).toHaveText('Passkey Registration');
    await health.assertHealthy();
    await expect(page).toHaveScreenshot('webauthn-register.png');

    await clickWebAuthnButton(page, '#registerWebAuthn');
    // A real, successful ceremony lands back at the client redirect with an
    // auth code -- not stuck on the required-action page or an error state.
    expect(page.url()).toContain('/theme-test-landing');
  });
});

test.describe('#106/#107 select-authenticator + WebAuthn authenticate/error (2+ applicable credentials)', () => {
  // Real trigger condition, not guessed: Keycloak's built-in `browser` flow
  // already ships a WebAuthn Authenticator ALTERNATIVE execution alongside
  // OTP Form, just DISABLED by default (global-setup.ts flips it on for
  // this disposable realm only -- the real APIARY realm has never enabled
  // it, see keycloak.lock's historical_reference_provenance note, so this
  // whole describe block exercises real markup for a state the production
  // realm doesn't currently reach). With 2+ applicable ALTERNATIVEs,
  // Keycloak auto-picks one to show directly and offers "Try another way"
  // as the explicit path to select-authenticator -- it is not itself the
  // default 2FA screen.
  test('select-authenticator renders a themed, legible credential picker', async ({ page, baseURL }, testInfo) => {
    test.skip(testInfo.project.name !== STATEFUL_WEBAUTHN_PROJECT, 'stateful ceremony -- runs once, see comment above the webauthn-register describe block');
    await addVirtualAuthenticator(page);
    await stubLandingPage(page);
    await setupMultiFactorUser(page, baseURL!, 'test-user-multi-factor');

    const health = await trackPageHealth(page, baseURL!);
    await page.goto(authUrl(baseURL!));
    await page.locator('#username').fill('test-user-multi-factor');
    await page.locator('#username').press('Enter');
    await page.locator('#password').fill('test-password-only');
    await submit(page);
    await expect(page.locator('#try-another-way')).toBeVisible();
    await Promise.all([page.waitForLoadState('networkidle'), page.locator('#try-another-way').click()]);

    await expect(page.locator('#kc-page-title')).toHaveText('Select login method');
    const items = page.locator('.select-auth-box-parent');
    await expect(items).toHaveCount(2);
    // Headline text must actually be legible against the theme's dark
    // surface -- keycloak.v2 ships this as a plain white PatternFly
    // data-list with no dark-mode awareness (#106, confirmed live).
    const headlineColor = await page.locator('.select-auth-box-headline').first().evaluate((el) => getComputedStyle(el).color);
    expect(headlineColor).not.toBe('rgb(255, 255, 255)');
    expect(headlineColor).not.toBe('');
    await health.assertHealthy();
    await expect(page).toHaveScreenshot('select-authenticator.png');

    // webauthn-authenticate.ftl's own credential list shares this exact markup.
    await Promise.all([
      page.waitForLoadState('networkidle'),
      page.locator('.select-auth-box-parent', { hasText: 'Passkey' }).click(),
    ]);
    await expect(page.locator('#authenticateWebAuthnButton')).toBeVisible();
    await expect(page).toHaveScreenshot('webauthn-authenticate.png');
  });

  test('webauthn-error renders a themed failure state with a working retry', async ({ page, baseURL }, testInfo) => {
    test.skip(testInfo.project.name !== STATEFUL_WEBAUTHN_PROJECT, 'stateful ceremony -- runs once, see comment above the webauthn-register describe block');
    // A dedicated fixture user (not the one the previous test mutates --
    // see setupMultiFactorUser's own note) whose passkey is registered on
    // the ceremony authenticator below, then abandoned: the *authenticate*
    // attempt further down uses a second, fresh virtual authenticator with
    // no stored credential for this user, so getAssertion genuinely fails,
    // driving the real webauthn-error.ftl path (not simulated/asserted
    // structurally only).
    const { cdp, authenticatorId } = await addVirtualAuthenticator(page);
    await stubLandingPage(page);
    await setupMultiFactorUser(page, baseURL!, 'test-user-multi-factor-2');

    // Detach the authenticator that holds the real credential and attach a
    // blank one -- otherwise the "authenticate" attempt below would just
    // succeed against the still-registered credential from setup.
    await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId });
    await addVirtualAuthenticator(page);

    const health = await trackPageHealth(page, baseURL!);
    await page.goto(authUrl(baseURL!));
    await page.locator('#username').fill('test-user-multi-factor-2');
    await page.locator('#username').press('Enter');
    await page.locator('#password').fill('test-password-only');
    await submit(page);
    await Promise.all([page.waitForLoadState('networkidle'), page.locator('#try-another-way').click()]);
    await Promise.all([
      page.waitForLoadState('networkidle'),
      page.locator('.select-auth-box-parent', { hasText: 'Passkey' }).click(),
    ]);
    await clickWebAuthnButton(page, '#authenticateWebAuthnButton');

    await expect(page.locator('#kc-page-title')).toHaveText('Passkey Error');
    await expect(page.locator('.pf-v5-c-alert.pf-m-danger')).toBeVisible();
    // template.ftl's own "Try another way" fallback (as opposed to
    // select-authenticator's own "Try Another Way" *button* shown earlier
    // in this same flow) is an <a href="javascript:...">, not a <button> --
    // real, differently-rendered markup, not a typo.
    const retry = page.getByRole('link', { name: 'Try Another Way' });
    await expect(retry).toBeVisible();
    await health.assertHealthy();
    await expect(page).toHaveScreenshot('webauthn-error.png');
  });
});

test.describe('#106 OAuth2 device flow (login-oauth2-device-verify-user-code.ftl -- not reachable by any real client today)', () => {
  test('renders the device code entry form via shell rules', async ({ page, baseURL }) => {
    const health = await trackPageHealth(page, baseURL!);
    await page.goto(`${baseURL}/realms/${REALM}/protocol/openid-connect/auth/device`);
    await expect(page.locator('#kc-page-title')).toHaveText('Device Login');
    await expect(page.locator('#device_user_code')).toBeVisible();
    await health.assertHealthy();
    await expect(page).toHaveScreenshot('device-code.png');
  });
});

test.describe('#107 RTL / 200% zoom / forced-colors', () => {
  test('renders correctly with dir="rtl" (Arabic locale)', async ({ page, baseURL }) => {
    await withInternationalization(baseURL!, async () => {
      const health = await trackPageHealth(page, baseURL!);
      // `ui_locales` (the OIDC-standard request parameter) is what
      // Keycloak's authorization endpoint actually honors here --
      // `kc_locale` (a plausible guess, since Keycloak does use that name
      // elsewhere, e.g. its account console) is silently ignored on this
      // endpoint and stays on defaultLocale (confirmed live: the first
      // version of this test used kc_locale and never actually got
      // dir="rtl").
      await page.goto(`${authUrl(baseURL!)}&ui_locales=ar`);
      await page.waitForSelector('#username');

      await expect(page.locator('html')).toHaveAttribute('dir', 'rtl');
      // Same overflow/centering criteria the LTR shell test applies (#104)
      // -- dir=rtl must not introduce a horizontal scrollbar or an
      // off-center card.
      const hasOverflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth);
      expect(hasOverflow).toBe(false);
      const cardBox = await page.locator('.pf-v5-c-login__main').boundingBox();
      const viewportWidth = await page.evaluate(() => document.documentElement.clientWidth);
      expect(cardBox).not.toBeNull();
      const cardCenter = cardBox!.x + cardBox!.width / 2;
      // Loose tolerance, not pixel-perfect centering: Arabic glyph metrics
      // and RTL layout can shift scrollbar presence/width by a few px
      // relative to the LTR baseline (confirmed live, ~7-8px, verified by
      // eye against the screenshot -- a genuinely centered card, not a
      // real off-center bug). This is a smoke check for a badly-broken
      // RTL layout (e.g. a stray physical `margin-left` fighting the flex
      // centering), not a sub-pixel assertion.
      expect(Math.abs(cardCenter - viewportWidth / 2)).toBeLessThan(16);

      await health.assertHealthy();
      await expect(page).toHaveScreenshot('login-rtl.png');
    });
  });

  test('reflows without clipping or overflow at 200% zoom', async ({ page, baseURL }) => {
    // Playwright has no direct "browser zoom" emulation; halving the CSS
    // viewport at the same DPR is the standard stand-in (200% zoom means
    // twice as many device pixels per CSS pixel, i.e. half as many CSS
    // pixels fit the same physical screen) -- same approach as this
    // project's own 4K-at-200%-scaling viewport tier (docs/PAGE-MATRIX.md
    // and keycloak.lock's viewport_contract both already treat "@2x
    // effective CSS px" this way for the UHQ tier).
    await page.setViewportSize({ width: 720, height: 450 });
    const health = await trackPageHealth(page, baseURL!);
    await page.goto(authUrl(baseURL!));
    await page.waitForSelector('#username');

    const hasOverflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth);
    expect(hasOverflow).toBe(false);
    // The card must stay fully within the reflowed viewport, not clipped
    // top/bottom/left/right.
    const cardBox = await page.locator('.pf-v5-c-login__main').boundingBox();
    expect(cardBox).not.toBeNull();
    expect(cardBox!.x).toBeGreaterThanOrEqual(0);
    expect(cardBox!.y).toBeGreaterThanOrEqual(0);
    expect(cardBox!.x + cardBox!.width).toBeLessThanOrEqual(720 + 1);

    await health.assertHealthy();
    await expect(page).toHaveScreenshot('login-200pct-zoom.png');
  });

  test('stays usable under forced-colors (Windows High Contrast) emulation', async ({ page, baseURL }) => {
    // Headless Chromium on Linux only partially emulates forced-colors:
    // `page.emulateMedia({ forcedColors: 'active' })` reliably flips the
    // `@media (forced-colors: active)` match (so author CSS scoped to that
    // query would apply), but does not reproduce the UA-level automatic
    // color-forcing algorithm real Windows High Contrast Mode performs on
    // every element -- confirmed live: an axe WCAG contrast scan under this
    // emulation reported this theme's own dark-mode tokens (e.g.
    // `#e9e6df` text) as failing against white, which is an artifact of
    // that gap (forced-colors is supposed to substitute a system palette
    // first), not a real finding reachable by an actual HCM user. A full
    // WCAG scan here would be noise, not signal; this checks what's
    // actually verifiable in this environment instead: the media query
    // genuinely engages, and the page stays functionally usable under it
    // (this theme has no `forced-colors` media rules of its own to
    // regression-test -- it currently relies entirely on the browser's own
    // automatic forcing for native form controls, which is a legitimate
    // baseline, not a gap by itself).
    await page.emulateMedia({ forcedColors: 'active' });
    await page.goto(authUrl(baseURL!));
    await page.waitForSelector('#username');

    const engaged = await page.evaluate(() => window.matchMedia('(forced-colors: active)').matches);
    expect(engaged).toBe(true);

    const health = await trackPageHealth(page, baseURL!);
    await page.locator('#username').fill('test-user-no-totp');
    await page.locator('#username').press('Enter');
    await page.locator('#password').fill('test-password-only');
    await submit(page);
    // Real Keycloak re-render, not a client-side illusion -- same
    // credentials the staged-interaction tests use, landing on the
    // mandatory TOTP setup page.
    await expect(page.locator('#kc-totp-secret-qr-code')).toBeVisible();
    await health.assertHealthy();
  });
});
