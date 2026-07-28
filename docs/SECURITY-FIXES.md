# Code Scanning: 9 Bug Fix Guide — Status (2026-07-28)

All nine CodeQL alerts from this guide are now **resolved**. This file is
kept as the closure record; the fixes live in the files noted per item.

| # | Alert | Status | Resolution |
|---|---|---|---|
| 1a | `script-src 'unsafe-inline'` | ✅ fixed | `script-src 'nonce-…'` per request (`secHeaders`, server.go); all inline handlers converted to `addEventListener`/delegation (Step 11) |
| 1b | `style-src 'unsafe-inline'` | ✅ fixed (2026-07-28) | Last inline style attributes removed: utility classes `u-mt8/12/14` in `ui/app.html`'s nonce'd style block, `qr.go` error uses `.status-err`; CSP is now `style-src 'self' 'nonce-…'` — no `unsafe-inline` anywhere |
| 2 | Hardcoded default credentials (×2) | ✅ fixed | `requireEnv("AUTH_USERNAME")` / `requireEnvFile("AUTH_PASSWORD")` — no defaults in source (config.go) |
| 3 | Hardcoded auth host | ✅ fixed | `getenv("AUTH_HOST", "")` + fatal when unset (config.go) |
| 4 | Unvalidated redirect in `/verify` | ✅ fixed | `orig` is piped through `safeRedirect()` before embedding in `rd=` (handlers.go) |
| 5 | CSRF token in JS variable | ✅ fixed (2026-07-28) | Token now delivered via `<meta name="csrf-token" content="…">` and read with `querySelector` in `ui/app.html`; no secret in a JS string literal |
| 6 | `rand.Read` error discarded (×2) | ✅ fixed | `newSID()` and `issueForm()` panic on `crypto/rand` failure, matching `randomBytes()` (token.go) |

## Notes

- The CSP nonce refactor mentioned as "most involved" was completed in
  roadmap Step 11; the remaining `style-src` half was closed together with
  item 5 above.
- Verified after the final two fixes: `go build`, `go vet`,
  `go test ./... -race -shuffle=on -count=1` — all green; no `style=`
  attributes or non-nonced `<style>` blocks remain in any served page.
