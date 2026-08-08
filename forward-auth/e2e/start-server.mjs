import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { PORT, TEST_USERNAME, TEST_PASSWORD, TEST_TOTP_SECRET } from "./test-env.mjs";

// A minimal, real (not stubbed) forward-auth instance for the #672 viewport
// audit. Every value below is a test-harness convenience, not a shortcut
// around real auth logic -- the e2e specs still drive an actual
// username+password+TOTP login through the real HTTP handlers.
//
//   - LISTEN_ADDR/AUTH_HOST: bound to 127.0.0.1 so Playwright's baseURL and
//     the server's own AUTH_HOST-based cookie/redirect checks agree without
//     needing a real domain or /etc/hosts entry.
//   - COOKIE_SECURE=false: the Secure cookie flag requires HTTPS, which this
//     harness deliberately doesn't set up (matches config.go's own
//     "development only" warning for this flag) -- without it, the session
//     cookie set after login would silently never reach the browser over
//     plain http, and every post-login page would appear to reject the
//     session for reasons unrelated to anything this audit is testing.
//   - MIN_DWELL_SECONDS=0: same test-speed exemption main_test.go's own
//     testConfig() uses for the anti-bot minimum form-fill time.
//   - TOTP_SECRET is a real, valid base32 secret (not a stub) -- the specs
//     compute real RFC 6238 codes against it, so the second-factor step
//     (verify.html, otherwise dead code in this audit) gets exercised for
//     real rather than skipped via REQUIRE_TOTP=false.
const root = mkdtempSync(join(tmpdir(), "forward-auth-e2e-"));
const dataDir = join(root, "data");
mkdirSync(dataDir, { recursive: true });

const child = spawn("go", ["run", "."], {
  // Unlike Xore/APIARY's dashboard/frontend (a subdirectory one level below
  // its Go module root), playwright.config.ts lives directly in
  // forward-auth/ -- the Go module root itself -- so Playwright's own cwd
  // when it runs this script (always the config file's directory) already
  // *is* the right place to `go run .` from. No "..".
  cwd: resolve("."),
  env: {
    ...process.env,
    LISTEN_ADDR: `127.0.0.1:${PORT}`,
    AUTH_HOST: "127.0.0.1",
    COOKIE_DOMAIN: "",
    COOKIE_SECRET: "e2e-test-cookie-secret-at-least-32-bytes-long",
    COOKIE_SECURE: "false",
    PASETO_KEY: randomBytes(32).toString("hex"),
    AUTH_USERNAME: TEST_USERNAME,
    AUTH_PASSWORD: TEST_PASSWORD,
    TOTP_SECRET: TEST_TOTP_SECRET,
    REQUIRE_TOTP: "true",
    MIN_DWELL_SECONDS: "0",
    USERS_FILE: join(dataDir, "users.json"),
    AUDIT_LOG: join(dataDir, "audit.jsonl"),
  },
  stdio: "inherit",
});

let stopping = false;
const stop = () => {
  if (stopping) return;
  stopping = true;
  child.kill();
  rmSync(root, { recursive: true, force: true });
};
process.on("SIGINT", stop);
process.on("SIGTERM", stop);
process.on("exit", () => rmSync(root, { recursive: true, force: true }));
child.on("exit", (code, signal) => {
  rmSync(root, { recursive: true, force: true });
  if (!stopping && code !== 0) {
    process.exitCode = code ?? (signal ? 1 : 0);
  }
});
