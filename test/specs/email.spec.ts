import { test, expect, APIRequestContext, Page } from '@playwright/test';

// #91: themes/apiary/email/html/template.ftl. Verifies a real sent email
// (via mailhog, docker-compose.test.yml's SMTP sink), not just that the
// template file parses -- the same "prove it against the real thing"
// standard as login.spec.ts/account.spec.ts. Nothing here is
// viewport/browser-rendering dependent (mailhog's message content doesn't
// change per project), so unlike account.spec.ts (#113) this is scoped to
// desktop-1440 to avoid uselessly re-running the exact same HTTP/API
// assertions six times over, not because of any known coverage gap.
test.beforeEach(({}, testInfo) => {
  test.skip(testInfo.project.name !== 'desktop-1440', 'email content has nothing viewport-dependent to re-run per project');
});

const MAILHOG_BASE = process.env.MAILHOG_TEST_BASE_URL ?? 'http://localhost:8025';

function decodeQuotedPrintable(input: string): string {
  return input
    .replace(/=\r?\n/g, '')
    .replace(/=([0-9A-Fa-f]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
}

async function clearMailhog(request: APIRequestContext) {
  await request.delete(`${MAILHOG_BASE}/api/v1/messages`);
}

async function waitForMessageTo(request: APIRequestContext, mailbox: string, timeoutMs = 15_000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const res = await request.get(`${MAILHOG_BASE}/api/v2/messages`);
    const body = await res.json();
    const match = (body.items ?? []).find((m: any) => m.To?.[0]?.Mailbox === mailbox);
    if (match) return match;
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`No email arrived for mailbox "${mailbox}" within ${timeoutMs}ms`);
}

// mailhog's Content.Body is the raw multipart/alternative MIME body
// Keycloak sent, quoted-printable encoded, text/plain part first. Pull the
// text/html part specifically -- that's the one this theme actually
// touches (text/template.ftl doesn't exist upstream; plain-text emails
// have no wrapper to theme, confirmed against the real base/email source).
function htmlPart(message: any): string {
  const raw: string = message.Content.Body;
  const sections = raw.split(/\r?\n--[^\r\n]*\r?\n/);
  const htmlSection = sections.find((s) => /^Content-Type: text\/html/im.test(s));
  if (!htmlSection) throw new Error('no text/html MIME part found in message body');
  const body = htmlSection.replace(/^[\s\S]*?\r?\n\r?\n/, '');
  return decodeQuotedPrintable(body);
}

async function triggerVerifyEmail(page: Page, baseURL: string) {
  await page.goto(baseURL + '/realms/test-apiary/account/');
  await page.waitForSelector('#username');
  await page.locator('#username').fill('test-user-verify-email');
  await page.locator('#username').press('Enter');
  await page.locator('#password').fill('test-password-only');
  await page.locator('input[type="submit"], button[type="submit"]').click();
}

test.describe('Branded email theme (#91)', () => {
  test('a real verification email renders the APIARY brand shell, not Keycloak\'s bare default', async ({ page, request, baseURL }) => {
    await clearMailhog(request);
    await triggerVerifyEmail(page, baseURL!);

    const message = await waitForMessageTo(request, 'test-user-verify-email');
    const html = htmlPart(message);

    // The real bug this suite would catch: base/email's own template.ftl
    // (what every email looked like before this theme existed) is
    // completely bare -- no branding, no header, no styling at all
    // (confirmed against the real upstream source for this pinned release,
    // see themes/apiary/email/html/template.ftl's own header comment).
    expect(html).toMatch(/resources\/[^/"]+\/email\/apiary\/img\/apiary-lockup-for-light\.png/);
    expect(html).toContain('apiary-email-card');
    expect(html).toContain('prefers-color-scheme: dark');
    expect(html).toContain("This message was sent by APIARY.");

    // The actual message content (from base's own message bundle, never
    // touched by this theme) must still be present and intact --
    // presentation-only, not a fork of the content, per #91's own
    // constraint.
    expect(html).toContain('Link to e-mail address verification');
    expect(html).toMatch(/href="[^"]*login-actions\/action-token/);

    // No raw/missing message keys or unresolved FreeMarker directives
    // should ever reach a sent email.
    expect(html).not.toMatch(/\$\{|<#|<\/#/);
    expect(html).not.toMatch(/\?\?\?/);
  });

  test('falls back to a plain text header, not a crash, when url is unavailable', async () => {
    // #91: url.resourcesUrl can be genuinely absent (ContextNotActiveException
    // per FreeMarkerEmailTemplateProvider's own source for this release --
    // e.g. an email triggered by a scheduled task with no active HTTP
    // request), not just a theoretical guard. There is no way to force that
    // code path from the outside through a real disposable Keycloak
    // instance (every email this realm can trigger happens inside an
    // authenticated request), so this is a static assertion on the
    // template's own guard rather than a live-triggered one -- still real
    // coverage: it fails if the <#if url??> guard is ever removed or
    // rewritten to assume url is always present.
    const fs = await import('fs');
    const path = await import('path');
    const template = fs.readFileSync(
      path.join(__dirname, '../../themes/apiary/email/html/template.ftl'),
      'utf-8',
    );
    expect(template).toMatch(/<#if url\?\?>/);
    expect(template).toMatch(/<#else>[\s\S]*APIARY[\s\S]*<\/#if>/);
  });
});
