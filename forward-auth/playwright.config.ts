import { defineConfig, devices } from "@playwright/test";

const externalBaseURL = process.env.AUTH_E2E_BASE_URL;

export default defineConfig({
  testDir: "./e2e",
  outputDir: "./test-results",
  // Runs after webServer is confirmed up (Playwright starts webServer
  // first) and before any test file executes -- does one real login and
  // saves its session cookie so the "authenticated app shell"/"nested
  // dialogs" describe blocks can reuse it per-tier via test.use({
  // storageState }) instead of each logging in fresh (see global-setup.mjs
  // for why: TOTP's own monotonic replay protection made that both slow
  // and, without careful pacing, occasionally a genuine "Invalid code.").
  // .cjs, not .mjs -- see that file's own top-of-file comment for why
  // (an ESM globalSetup broke loading every unrelated .mjs import
  // elsewhere in this project too, not just within that one file).
  globalSetup: "./e2e/global-setup.cjs",
  timeout: 30_000,
  expect: { timeout: 5_000 },
  fullyParallel: false,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [["github"], ["html", { open: "never" }]] : "list",
  use: {
    baseURL: externalBaseURL || "http://127.0.0.1:18081",
    ...devices["Desktop Chrome"],
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  webServer: externalBaseURL
    ? undefined
    : {
        command: "node e2e/start-server.mjs",
        url: "http://127.0.0.1:18081/_auth/health",
        reuseExistingServer: !process.env.CI,
        timeout: 120_000,
      },
});
