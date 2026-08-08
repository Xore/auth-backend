// CommonJS, not the .mjs the rest of e2e/ uses, and self-contained (its own
// copies of test-env.mjs's constants and totp.mjs's code generator) rather
// than importing them: Playwright's config (playwright.config.ts) resolves
// `globalSetup` through its own CJS-oriented require() pipeline, and having
// this file (or anything it required) be real ESM broke loading -- not just
// this file, but *every* .mjs import anywhere in auth.spec.ts too, with a
// "Failed to load the ES module" / "Unexpected token 'export'" error, the
// moment globalSetup pointed at an ES module. Confirmed live: switching just
// this one file to .cjs + require()/module.exports, still pointed at from
// playwright.config.ts's globalSetup, fixed auth.spec.ts's own unrelated
// .mjs imports too -- so whatever the incompatibility is, it's project-wide
// once triggered, not local to whichever file first hits it.
const { chromium } = require("@playwright/test");
const crypto = require("node:crypto");
const path = require("node:path");

const PORT = 18081;
const BASE_URL = `http://127.0.0.1:${PORT}`;
const TEST_USERNAME = "admin";
const TEST_PASSWORD = "correct-horse-battery-staple-9432"; // gitleaks:allow -- fixed test-fixture password for the local e2e server only, not a real credential
const TEST_TOTP_SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32Decode(input) {
  const clean = input.toUpperCase().replace(/=+$/, "");
  let bits = "";
  for (const char of clean) {
    const val = BASE32_ALPHABET.indexOf(char);
    if (val < 0) throw new Error(`invalid base32 character: ${char}`);
    bits += val.toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return Buffer.from(bytes);
}

// RFC 6238 TOTP: 30s step, 6 digits, HMAC-SHA1 -- matches totp.go's own
// defaults, same as totp.mjs's totpCode() (kept in sync by hand since this
// file can't import that one -- see the top-of-file comment for why).
function totpCode(base32Secret, time) {
  const key = base32Decode(base32Secret);
  const counter = Math.floor(time / 1000 / 30);
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac("sha1", key).update(counterBuf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binCode =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return String(binCode % 1_000_000).padStart(6, "0");
}

const AUTH_STATE_PATH = path.join(__dirname, ".auth-state.json");

// One real username+password+TOTP login through the actual HTTP handlers
// (see auth.spec.ts's "login page"/"two-factor" describes, which drive the
// UI directly and don't need this) -- the "authenticated app shell",
// "admin users table", and "nested dialogs" describes all reuse this one
// session's cookie via test.use({ storageState: AUTH_STATE_PATH }) instead
// of each logging in fresh per viewport tier. See auth.spec.ts's own
// comment on why: users.go's replay protection is a monotonic "last
// accepted step" per user, and logging in 12+ times in quick succession
// (well under TOTP's own 30s step) made most of those logins either wait
// out a full step or, without careful pacing, hit a real "Invalid code."
module.exports = async function globalSetup() {
  const browser = await chromium.launch();
  const page = await browser.newPage();
  await page.goto(BASE_URL + "/_auth/login?rd=/auth/app");
  await page.locator("#u").fill(TEST_USERNAME);
  await page.locator("#btn-continue").click();
  await page.locator("#p").fill(TEST_PASSWORD);
  await page.locator("#login-form button[type=submit]").click();
  await page.locator(".verify-card").waitFor();
  await page.locator(".otp-box").first().click();
  await page.keyboard.type(totpCode(TEST_TOTP_SECRET, Date.now()));
  await page.locator("#code-submit").click();
  await page.locator("#settings-modal").waitFor();
  await page.context().storageState({ path: AUTH_STATE_PATH });
  await browser.close();
};
