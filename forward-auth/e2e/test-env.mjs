// Shared test-fixture constants for the #672 viewport audit -- split out
// from start-server.mjs so the spec file can import just these values
// without also re-running that file's top-level spawn(...) call (Playwright
// only ever runs start-server.mjs itself once, as the webServer command).
export const PORT = 18081;
export const BASE_URL = `http://127.0.0.1:${PORT}`;
export const TEST_USERNAME = "admin";
export const TEST_PASSWORD = "correct-horse-battery-staple-9432"; // gitleaks:allow -- fixed test-fixture password for the local e2e server only, not a real credential
// RFC 4648 base32, 20 bytes -- picked once, fixed, not a real secret.
export const TEST_TOTP_SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
