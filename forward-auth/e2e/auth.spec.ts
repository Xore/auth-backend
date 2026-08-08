import { test, expect, type Page } from "@playwright/test";
import { freshTotpCode } from "./totp.mjs";
import { TEST_USERNAME, TEST_PASSWORD, TEST_TOTP_SECRET } from "./test-env.mjs";

// Same path global-setup.mjs writes to (kept as a plain string rather than
// an import from that file: importing it here pulled in its own
// "@playwright/test" import through the spec-file's CJS-oriented transform
// and broke loading every *other* relative .mjs import in this file with a
// "Failed to load the ES module" / "Unexpected token 'export'" error --
// confirmed live by removing just that one import and watching the exact
// same test-env.mjs import on the next line go back to working). Also not
// import.meta.url-derived, for the same reason: this .ts spec file is
// itself compiled to CommonJS by Playwright's own transform, where
// import.meta throws -- unlike global-setup.mjs, loaded directly as real
// ESM (no transform) since Playwright takes its globalSetup path as-is.
// Relative to this config's rootDir (forward-auth/, where
// playwright.config.ts lives), same as e.g. the webServer command below.
const AUTH_STATE_PATH = "e2e/.auth-state.json";

// #672 chunk 4: forward-auth has none of the login/2FA/app-settings surface
// area under any viewport test today (Go tests only -- see main_test.go --
// and no JS/browser test infra at all before this file). Same six tiers as
// Xore/APIARY's dashboard audit, for the same reason: real device widths
// this app is actually accessed from (an SSO gate in front of every
// protected service, so operators hit it from phones as often as desktops),
// not an arbitrary sample.
const viewports = {
  desktop: { width: 1440, height: 900 },
  tablet: { width: 820, height: 1180 },
  mobile: { width: 390, height: 844 },
  iphone: { width: 393, height: 852 },
  uhq: { width: 1920, height: 1080 },
  "4k": { width: 3840, height: 2160 },
} as const;

// Same detector as Xore/APIARY's dashboard.spec.ts (runLayoutChecks' own
// comment there has the full false-positive history: <option> elements,
// display:none ancestors, position:fixed offsetParent nulls). Scoped to a
// caller-supplied root rather than a fixed selector, since this app has
// three unrelated page shells (login, verify, app) instead of one.
async function clippedElements(page: Page, rootSelector: string): Promise<string[]> {
  return page.evaluate((selector) => {
    const problems: string[] = [];
    const root = document.querySelector(selector);
    if (!root) return problems;
    for (const el of root.querySelectorAll<HTMLElement>("*")) {
      if (el.tagName === "OPTION") continue;
      const style = getComputedStyle(el);
      if (style.display === "none" || style.visibility === "hidden") continue;
      if (el.offsetParent === null && style.position !== "fixed") continue;
      const hasOwnText = Array.from(el.childNodes).some(
        (n) => n.nodeType === Node.TEXT_NODE && (n.textContent ?? "").trim().length > 0,
      );
      if (!hasOwnText) continue;
      const rect = el.getBoundingClientRect();
      if (rect.width === 0 || rect.height === 0) {
        const cls = el.className ? `.${String(el.className).split(" ").join(".")}` : "";
        problems.push(`${el.tagName.toLowerCase()}${cls}: "${(el.textContent ?? "").trim().slice(0, 60)}"`);
      }
    }
    return problems;
  }, rootSelector);
}

async function checkNoPageOverflow(page: Page, label: string) {
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  expect(overflow, `${label} must not overflow horizontally`).toBeLessThanOrEqual(1);
}

// Every describe block below that needs a signed-in session uses
// test.use({ storageState: AUTH_STATE_PATH }) -- the one real username+
// password+TOTP login lives in global-setup.mjs, run once. This just
// navigates a page that already carries that session cookie straight to
// the app shell.
async function gotoAuthenticatedApp(page: Page) {
  await page.goto("/auth/app");
  await expect(page.locator("#settings-modal")).toBeVisible();
  // Same race Xore/APIARY's own command-palette test hit (see that spec's
  // comment): .modal.open's dialog-in animation applies its own transform
  // (a translateY, mid-keyframe) for the full 160ms --transition,
  // overriding .modal--permanent.open's static transform:none until the
  // animation actually finishes settling -- confirmed live, measuring
  // #settings-modal's rect any earlier caught a transient top: -449px
  // reading, correct (top: 0) once this elapses.
  await page.waitForTimeout(300);
}

test.describe("login page at every tier", () => {
  for (const [viewportName, viewport] of Object.entries(viewports)) {
    test(`login card renders within the viewport at ${viewportName}`, async ({ page }) => {
      await page.setViewportSize(viewport);
      await page.goto("/_auth/login");
      await expect(page.locator(".login-card")).toBeVisible();
      await checkNoPageOverflow(page, `login page at ${viewportName}`);
      const problems = await clippedElements(page, ".login-card");
      expect(problems, `login card at ${viewportName} has zero-size element(s) with real text`).toEqual([]);
      const rect = await page.locator(".login-card").evaluate((el) => el.getBoundingClientRect());
      expect(rect.left, `login card left edge clipped at ${viewportName}`).toBeGreaterThanOrEqual(0);
      expect(rect.right, `login card right edge overflows at ${viewportName}`).toBeLessThanOrEqual(viewport.width + 1);
    });
  }
});

test.describe("two-factor (verify) page at every tier", () => {
  for (const [viewportName, viewport] of Object.entries(viewports)) {
    test(`verify card renders within the viewport at ${viewportName}`, async ({ page }) => {
      await page.setViewportSize(viewport);
      await page.goto("/_auth/login");
      await page.locator("#u").fill(TEST_USERNAME);
      await page.locator("#btn-continue").click();
      await page.locator("#p").fill(TEST_PASSWORD);
      await page.locator("#login-form button[type=submit]").click();
      await expect(page.locator(".verify-card")).toBeVisible();
      await checkNoPageOverflow(page, `verify page at ${viewportName}`);
      const problems = await clippedElements(page, ".verify-card");
      expect(problems, `verify card at ${viewportName} has zero-size element(s) with real text`).toEqual([]);
      // All 6 otp-box inputs must stay individually reachable/tappable, not
      // just the card as a whole -- a card that fits but squeezes its boxes
      // into overlapping/zero-width cells would pass the card-rect check
      // above and still be unusable.
      const boxWidths = await page.locator(".otp-box").evaluateAll((els) => els.map((el) => el.getBoundingClientRect().width));
      for (const w of boxWidths) {
        expect(w, `an otp box collapsed to zero width at ${viewportName}`).toBeGreaterThan(0);
      }
    });
  }
});

test.describe("authenticated app/settings shell at every tier", () => {
  test.use({ storageState: AUTH_STATE_PATH });
  for (const [viewportName, viewport] of Object.entries(viewports)) {
    test(`settings modal (native <dialog>) renders within the viewport at ${viewportName}`, async ({ page }) => {
      await page.setViewportSize(viewport);
      await gotoAuthenticatedApp(page);
      await checkNoPageOverflow(page, `app shell at ${viewportName}`);
      const rect = await page.locator("#settings-modal").evaluate((el) => el.getBoundingClientRect());
      // .modal--permanent is inset:0/100vw/100dvh by design (it's the whole
      // app, not a centered dialog) -- this just confirms that variant
      // still actually fills the real viewport rather than clipping or
      // leaving a gap, since it's the one modal usage in this repo that
      // wasn't touched by the #672 upstream centering fix (see the theme
      // vendor-bump commit) and is worth its own direct check rather than
      // assuming that independence holds.
      // A couple of px of tolerance, not toBeCloseTo(0, 0)'s 0.5px --
      // confirmed live at uhq a genuine ~1.4px sub-pixel rect vs. reported
      // viewport-width rounding (not a real clip: full-page overflow above
      // already catches an actually mispositioned dialog at a whole-pixel
      // scale).
      expect(rect.left, `settings dialog left edge at ${viewportName}`).toBeGreaterThanOrEqual(-2);
      expect(rect.left, `settings dialog left edge at ${viewportName}`).toBeLessThanOrEqual(2);
      expect(rect.top, `settings dialog top edge at ${viewportName}`).toBeGreaterThanOrEqual(-2);
      expect(rect.top, `settings dialog top edge at ${viewportName}`).toBeLessThanOrEqual(2);
      expect(rect.width, `settings dialog width at ${viewportName}`).toBeGreaterThan(viewport.width - 4);
      await expect(page.locator(".settings-layout__sidebar")).toBeVisible();
      await expect(page.locator("#settings-content")).toBeVisible();
      const problems = await clippedElements(page, "#settings-content");
      expect(problems, `account pane at ${viewportName} has zero-size element(s) with real text`).toEqual([]);
    });
  }
});

test.describe("admin users table at every tier", () => {
  test.use({ storageState: AUTH_STATE_PATH });
  for (const [viewportName, viewport] of Object.entries(viewports)) {
    test(`admin-users pane renders within the viewport at ${viewportName}`, async ({ page }) => {
      await page.setViewportSize(viewport);
      await gotoAuthenticatedApp(page);
      await page.locator('#settings-nav .sidebar__item[data-pane="admin-users"]').click();
      await expect(page.locator('#settings-content[data-hp-pane="admin-users"]')).toBeVisible();
      // The row for the bootstrapped admin user is the one concrete piece
      // of real data guaranteed present in every run -- confirms the table
      // actually rendered content, not just an empty shell.
      await expect(page.getByText(TEST_USERNAME, { exact: false }).first()).toBeVisible();
      await checkNoPageOverflow(page, `admin-users pane at ${viewportName}`);
      const problems = await clippedElements(page, "#settings-content");
      expect(problems, `admin-users pane at ${viewportName} has zero-size element(s) with real text`).toEqual([]);
    });
  }
});

test.describe("nested edit-user + danger dialogs stay within the viewport at every tier", () => {
  test.use({ storageState: AUTH_STATE_PATH });
  for (const [viewportName, viewport] of Object.entries(viewports)) {
    test(`edit-user dialog at ${viewportName}`, async ({ page }) => {
      await page.setViewportSize(viewport);
      await gotoAuthenticatedApp(page);
      await page.locator('#settings-nav .sidebar__item[data-pane="admin-users"]').click();
      // The edit_user button isn't directly clickable: it lives inside a
      // native <details class="action-menu"><summary>...</summary> popover
      // per row, closed by default -- confirmed live, clicking it directly
      // timed out (present in the DOM, but display:none/zero-size until its
      // own <summary> is opened).
      await page.locator(`summary[aria-label="Actions for ${TEST_USERNAME}"]`).click();
      await page.locator(`button[data-act="edit_user"][data-user="${TEST_USERNAME}"]`).click();
      const editDialog = page.locator("#user-edit-backdrop .edit-dialog");
      await expect(page.locator("#user-edit-backdrop")).toHaveClass(/open/);
      const rect = await editDialog.evaluate((el) => el.getBoundingClientRect());
      expect(rect.left, `edit-user dialog left edge clipped at ${viewportName}`).toBeGreaterThanOrEqual(0);
      expect(rect.top, `edit-user dialog top edge clipped at ${viewportName}`).toBeGreaterThanOrEqual(0);
      expect(rect.right, `edit-user dialog right edge overflows at ${viewportName}`).toBeLessThanOrEqual(viewport.width + 1);
      expect(rect.bottom, `edit-user dialog bottom edge overflows at ${viewportName}`).toBeLessThanOrEqual(viewport.height + 1);

      // Stack a second dialog (danger-confirm) on top of the first without
      // confirming the action -- reset_totp is destructive but only takes
      // effect after clicking the danger dialog's own confirm button, which
      // this deliberately never does. Real nested-dialog scenario: the app
      // only ever opens danger-dialog from inside either the row menu or
      // this edit modal, never standalone.
      await page.locator('#ue-security-actions button[data-act="reset_totp"]').click();
      const dangerDialog = page.locator("#danger-dialog-backdrop .edit-dialog");
      await expect(page.locator("#danger-dialog-backdrop")).toHaveClass(/open/);
      const dangerRect = await dangerDialog.evaluate((el) => el.getBoundingClientRect());
      expect(dangerRect.left, `danger dialog left edge clipped at ${viewportName}`).toBeGreaterThanOrEqual(0);
      expect(dangerRect.top, `danger dialog top edge clipped at ${viewportName}`).toBeGreaterThanOrEqual(0);
      expect(dangerRect.right, `danger dialog right edge overflows at ${viewportName}`).toBeLessThanOrEqual(viewport.width + 1);
      expect(dangerRect.bottom, `danger dialog bottom edge overflows at ${viewportName}`).toBeLessThanOrEqual(viewport.height + 1);
    });
  }
});
