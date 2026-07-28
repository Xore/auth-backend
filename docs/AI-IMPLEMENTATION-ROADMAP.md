# AI Implementation Roadmap — auth-backend

> **Audience:** This document is written for modern AI coding assistants.
> Each step is self-contained and ends with a concrete verification test so the model can confirm
> correct completion before proceeding. Steps are ordered by dependency — never skip ahead.
>
> **Repository:** `Xore/auth-backend` — `forward-auth/` is the Go service. All source lives there.
>
> **Golden rule:** read the file before editing it. Use the exact structs, helper names, and
> patterns already present in the code. Never introduce a new pattern when an existing one fits.

---

## Quick-reference: guide map

| Guide | What it covers |
|---|---|
| [`THEME-GUIDE.md`](./THEME-GUIDE.md) | CSS design system (variables, components, dark mode) |
| [`UI-REDESIGN-GUIDE.md`](./UI-REDESIGN-GUIDE.md) | Login / enroll / password pages restyle |
| [`ADMIN-UI-GUIDE.md`](./ADMIN-UI-GUIDE.md) | Settings modal, admin panel, new Go routes |
| [`IMPROVEMENT-GUIDE.md`](./IMPROVEMENT-GUIDE.md) | Security gaps, missing features, priority matrix |
| [`TOKEN-HARDENING-GUIDE.md`](./TOKEN-HARDENING-GUIDE.md) | PASETO v4.local migration, key rotation |
| [`MTLS-SESSION-BINDING-GUIDE.md`](./MTLS-SESSION-BINDING-GUIDE.md) | mTLS session binding, cert thumbprint, Traefik config |
| [`CREDENTIAL-RECOVERY.md`](./CREDENTIAL-RECOVERY.md) | Admin-mediated recovery runbook (already complete) |

---

## How to read this roadmap

Each step follows this structure:

```
### Step N — Title
Phase:   UI | Security | Backend
Guide:   Which guide(s) this step implements
Reads:   Files to read before editing
Edits:   Files to create or modify
Blocked by: Steps that must be complete first

[Context paragraph — why this step matters]

**Implementation instructions** — precise, copy-paste-ready

**Verification** — how to confirm the step is done correctly
```

Steps in the same phase can be parallelised if there are no `Blocked by` dependencies.

---

## Implementation status

| Step | Status | Notes |
|---|---|---|
| Step 1 — CSS design system | ✅ done (2026-07-27) | `forward-auth/ui/theme.css`; dark-mode block, keyframes, mobile breakpoints |
| Step 2 — Restyle login/enroll/password | ✅ done (2026-07-27) | `page.go` on `theme.css`; `/static/` route via `static.go`; CSP `style-src 'self'` added |
| Step 3 — App shell page | ✅ done (2026-07-27) | `ui/app.html`, `apppage.go`, `/auth/app` route |
| Step 4 — Settings modal panes | ✅ done (2026-07-27) | Nav, `PANE_TEMPLATES`, loaders on `/api/state`, 5 s polling, sidebar search |
| Step 4b — Legacy admin panel restyle | ✅ done → ⚠️ superseded (2026-07-27) | Panel was restyled, then **deleted on user request**: all admin functions (create user, row actions, unlock, revoke) moved into the `/auth/app` shell; `/_auth/admin` now redirects there; `adminpage.go` removed |
| Step 5 — New Go routes | ✅ done (2026-07-27) | `/_auth/sessions/mine|trusted`, `/api/system`, `POST /api/sessions/{sid}/revoke`; `startedAt`, `ORG_ID`; panes fully wired to these APIs |
| Step 5b — Tailwind two-step login | ✅ done (2026-07-27) | See deviation notes below |
| Step 6 — Argon2id password hashing | ✅ done (2026-07-27) | PHC format, inline parser, bcrypt accepted + upgraded on login; bootstrap hashes with Argon2id |
| Step 7 — Common-password check | ✅ done (2026-07-27) | NCSC top-100k list (SecLists URL in roadmap 404s — used `100k-most-used-passwords-NCSC.txt`); binary +953 KB, exceeds the ≤500 KB note |
| Step 8 — Idle session timeout | ✅ done (2026-07-27) | `IDLE_TIMEOUT_MINUTES` (default 60, 0 disables); idle SIDs revoked + `idle_timeout` audit event; registry-missing sessions treated as no-idle-data |
| Step 9 — Persist throttle state | ✅ done (2026-07-27) | `throttle.json` load/persist (lockout trigger + SIGTERM), expired entries pruned. **Also fixed a pre-existing bug:** `locked()` pruned zero-`lockUntil` counting entries, so the fail counter reset every attempt and lockouts never engaged |
| Step 10 — Backup code regeneration | ✅ done (2026-07-27) | `POST /_auth/backup-codes` (session + form token), 8 new codes rendered, `DeviceGen++`; link in app-shell account pane. Codes are SHA-256-hashed in this repo (roadmap text says bcrypt) |
| Step 11 — CSP nonce | ✅ done (2026-07-27) | `script-src` was already nonce-only; **33 inline event-handler attributes were CSP-blocked and dead** — all converted to `addEventListener`/event delegation across 5 files; `style-src 'self' 'unsafe-inline'` per spec; passkeys page also restyled to the shared theme (Step-2 leftover) |
| Step 12 — Webhook enrichment + providers | ✅ done (2026-07-27) | `webhookPayload` + request_id/severity/timestamp; `WEBHOOK_PROVIDER=raw|slack|ntfy|gotify` with per-provider shapes; severity mapping; `TestWebhook*` tests |
| Step 13 — PASETO dep + key management | ✅ done (2026-07-27) | `zntr.io/paseto/v4` v1.4.0; `PASETO_KEY` (64 hex) or HKDF-derive from `COOKIE_SECRET`; bad length is fatal at load |
| Step 14 — PASETO payload + issue/parse | ✅ done (2026-07-27) | `sessionPayload` (iss/sub/iat/exp/jti/gen/flags), fail-closed claim checks, `forward-auth session v1` assertion; **fixed library panic on truncated tokens** (zntr v1.4.0 slices nonce unchecked) with a pre-decode shape guard |
| Step 15 — Switch issuance, dual parser | ✅ done (2026-07-27) | `setCookie` issues PASETO; legacy accepted via `parseSessionToken` with `legacy_token_verified` log; cookies now start `v4.local.` |
| Step 16 — PASETO key rotation | ✅ done (2026-07-27) | `PASETO_KEY_PREVIOUS` (comma-sep hex); old-key tokens verified then transparently re-issued under the current key (`session(w, r)` signature change) |
| Step 17 — Remove legacy HMAC path | ✅ done (2026-07-27) | `issueSession`/`parseSession`/`parseSessionToken` deleted; `mac`/`validMAC`/`macWith` kept (device/form/CSRF/pending still HMAC); explicit `PASETO_KEY` now **required** (note: guide §7.7 recommends derive-only — roadmap wins; recorded here) |
| Steps 18–20 — mTLS session binding | ⏭️ skipped (2026-07-28) | **Owner decision: mTLS client certs not wanted** — Phase 4 marked optional; criterion 7 void |
| Deploy — VPS production | ✅ done (2026-07-28) | Live at auth.xore.rocks; PASETO cookies verified; fixed container OOM (Argon2id 64 MiB vs 32M limit → 256M + `GOMEMLIMIT`) in repo and on VPS |
| Step 21 — Email self-service recovery | ✅ done (2026-07-28) | `/_auth/recover` (request + reset), HMAC token with password-hash fingerprint → single-use by construction, 15-min TTL, 3/hour per IP, `SMTP_URL` (`smtp://`+STARTTLS / `smtps://`), breach-list check on reset, generic anti-enumeration responses, "forgot password?" link when enabled |
| Step 23 — Redis backends | ✅ done (2026-07-28) | `ThrottleBackend`/`SessionBackend` interfaces; memory+JSON default unchanged; `redisBackends` (go-redis/v9) for both when `REDIS_URL` set; fail-open on Redis errors except `revoke()`; startup fails if Redis unreachable; miniredis tests |
| Step 24 — Risk-based authentication | ✅ done (2026-07-28) | Login history (25 records) in user store; score = unseen subnet /24-/64 (40) + unseen UA (30) + unseen hour w/ ≥5 samples (20); score > 50 overrides trusted device → TOTP page, `rba_totp_required` audit |
| Fix — modal click-through + post-login landing | ✅ done (2026-07-28) | Closed `.modal-backdrop`/`.modal` swallowed all clicks (invisible overlay) → `pointer-events`/`display:none` when closed; post-login fallback redirect is now `/auth/app` (was old `/_auth/ok` page) |

**Step 5b deviation notes (approved design):**
- Login is a **two-step UI** (username → password/passkey, client-side) followed by a
  **server-side 2FA page** (`ui/verify.html`) gated by a 5-minute HMAC pending cookie
  (`pend|exp|user|remember|mac`), instead of the guide's single-step form.
- Routes are under the repo's `/_auth/` prefix (`/_auth/totp`, `/_auth/sso`), not `/auth/*`.
- Tailwind is built locally with the pinned standalone CLI v3.4.17 (sha256-verified) into
  `ui/tailwind.min.css`; rebuild via `docker compose --profile build run --rm tailwind-build`.
- Deferred: Google OAuth button (Step 22), email magic-link/OTP mode + `/auth/resend` (Step 21).

---

## Phase 1 — UI Foundation

> Goal: establish the design system and restyle all existing pages before touching any security
> logic. A clean UI layer makes subsequent Go changes easier to review.

---

### Step 1 — Create the CSS design system

**Phase:** UI 
**Guide:** `THEME-GUIDE.md` §1–§12
**Reads:** `forward-auth/main.go` (to understand embed pattern), `THEME-GUIDE.md`
**Edits:** `forward-auth/ui/theme.css` *(create)*
**Blocked by:** nothing

The entire UI restyle depends on this file. It must be created first.

**Implementation instructions:**

1. Create the directory `forward-auth/ui/` if it does not exist.
2. Create `forward-auth/ui/theme.css` with exactly the token/variable definitions,
   component classes (`.btn`, `.card`, `.badge`, `.form-input`, `.data-table`, `.modal`,
   `.modal__sidebar`, `.modal__content`, `.sidebar__item`, `.sidebar__section-label`),
   dark-mode media query block, and mobile breakpoints described in `THEME-GUIDE.md`.
3. The CSS must use CSS custom properties (`--bg-primary`, `--text-primary`, `--accent`, etc.)
   as the single source of truth. No hardcoded hex colours outside the `:root` / `prefers-color-scheme` blocks.
4. Do **not** reference any external font CDN. Use `system-ui, -apple-system, sans-serif`.
5. Include the `@keyframes modal-in` and `@keyframes fade-in` animations used by the modal.

**Verification:**
- The CSS file exists at `forward-auth/ui/theme.css`.
- Running `grep -c 'var(--' forward-auth/ui/theme.css` returns ≥ 30.
- No `http://` or `https://` URLs appear in the file.
- The file contains `.modal__sidebar`, `.modal__content`, `.sidebar__item`, `.data-table`, `.badge--green`, `.badge--red`, `.badge--orange`, `.badge--blue`, `.badge--muted`.

---

### Step 2 — Restyle the login, enroll, and password pages

**Phase:** UI 
**Guide:** `UI-REDESIGN-GUIDE.md` §1–§6 
**Reads:** `forward-auth/page.go` (current templates), `UI-REDESIGN-GUIDE.md` 
**Edits:** `forward-auth/page.go` (or `forward-auth/ui/*.html` if templates are file-based) 
**Blocked by:** Step 1

Apply the shared-theme components to the three user-facing pages. The backend logic does not change.

**Implementation instructions:**

1. Read `forward-auth/page.go` fully before editing. Identify where `loginPage`, `enrollPage`,
   `passwordPage`, and `backupCodesPage` template strings are defined.
2. Replace the inline `<style>` blocks in each template with a single
   `<link rel="stylesheet" href="/static/theme.css">`.
3. Restyle the login form using `.card`, `.form-input`, `.btn`, `.btn-primary` as specified
   in `UI-REDESIGN-GUIDE.md §3`.
4. Restyle the TOTP enroll page using the QR card layout from `UI-REDESIGN-GUIDE.md §4`.
5. Restyle the password-change page using `UI-REDESIGN-GUIDE.md §5`.
6. Add a `/static/` file server route in `main.go`:
   ```go
   //go:embed ui
   var uiFS embed.FS
   // In main():
   mux.Handle("/static/", http.FileServer(http.FS(uiFS)))
   ```
7. Import `"embed"` at the top of `main.go` (or a new `static.go` file).
8. Preserve all existing form fields, hidden inputs (`ft`, `rd`, `website`), and POST action URLs.
   Change only the visual markup, never the form logic.

**Verification:**
- `go build ./...` in `forward-auth/` succeeds with zero errors.
- `go test ./...` passes (all existing tests green).
- The login page HTML contains `class="card"` and `class="form-input"` but does **not** contain
  a `<style>` block with colour definitions.
- `/static/theme.css` is served (verify with `curl -I http://localhost:4181/static/theme.css`).

---

### Step 3 — Build the app shell page

**Phase:** UI 
**Guide:** `ADMIN-UI-GUIDE.md` §1–§3, §12–§14 
**Reads:** `forward-auth/adminpage.go`, `forward-auth/main.go`, `ADMIN-UI-GUIDE.md` 
**Edits:** `forward-auth/ui/app.html` *(create)*, `forward-auth/main.go`, new `forward-auth/apppage.go` *(create)* 
**Blocked by:** Step 1

Create the `/auth/app` shell route that hosts the settings modal. This is the post-login
landing page.

**Implementation instructions:**

1. Create `forward-auth/ui/app.html` with:
   - `<link>` to `/static/theme.css`
   - Modal backdrop `<div class="modal-backdrop" id="settings-backdrop">`
   - `<dialog class="modal" id="settings-modal">` containing `.modal__sidebar` and `.modal__content`
   - `<aside class="modal__sidebar">` with search input and `<nav id="settings-nav">`
   - `<div class="modal__content" id="settings-content">` with close button
   - Go template variables injected as JS: `var IS_ADMIN = {{.IsAdmin}};`, `var CURRENT_USER = "{{.User}}";`, `var CSRF_TOKEN = "{{.CSRF}}";`
   - `openSettings()`, `closeSettings()`, `renderNav()`, `showPane()` JS functions
   - Esc key listener
   - Auto-open on load: `window.onload = () => openSettings('account');`
2. Create `forward-auth/apppage.go`:
   ```go
   package main
   import (...)
   type AppPageData struct {
       User    string
       IsAdmin bool
       CSRF    string
   }
   func (s *server) renderApp(w http.ResponseWriter, r *http.Request) {
       cl, u, ok := s.session(r)
       if !ok {
           http.Redirect(w, r, "https://"+s.cfg.authHost+"/_auth/login", http.StatusFound)
           return
       }
       secHeaders(w)
       appTmpl.Execute(w, AppPageData{
           User:    u.Username,
           IsAdmin: u.Role == "admin",
           CSRF:    s.cfg.csrfToken(cl.sid),
       })
   }
   ```
3. Embed the template:
   ```go
   var appTmpl = template.Must(template.New("app").Parse(string(mustReadUI("app.html"))))
   ```
   (Use the same embed pattern as existing templates in `page.go`.)
4. Register in `main.go`:
   ```go
   mux.HandleFunc("/auth/app", s.renderApp)
   ```

**Verification:**
- `GET /auth/app` without a session → redirects to `/_auth/login` (302).
- `GET /auth/app` with a valid session cookie → returns 200 HTML containing `id="settings-modal"`.
- `go build ./...` succeeds.

---

### Step 4 — Build the settings modal panes (UI-only, no new API)

**Phase:** UI 
**Guide:** `ADMIN-UI-GUIDE.md` §4–§11, §14–§15 
**Reads:** `forward-auth/adminpage.go` (existing pane HTML), `ADMIN-UI-GUIDE.md` 
**Edits:** `forward-auth/ui/app.html` 
**Blocked by:** Step 3

Add all sidebar nav items and right-pane HTML shells. Wire them to the existing
`/_auth/admin/api/state` JSON endpoint — **no backend changes yet**.

**Implementation instructions:**

1. Add `SETTINGS_NAV` and `ADMIN_NAV` JS arrays as specified in `ADMIN-UI-GUIDE.md §4–§5`.
   Use inline SVG icons (no external icon CDN).
2. Implement `renderNav()` so the sidebar renders both sections; admin section gated on `IS_ADMIN`.
3. Implement `PANE_TEMPLATES` object with static HTML skeletons for:
   - `account` (§6)
   - `sessions` (§7 — sessions table only; trusted devices table empty for now)
   - `admin-users` (§8)
   - `admin-logs` (§9)
   - `admin-sessions` (§10)
   - `admin-system` (§11 — all values show `–` until API exists)
4. Implement `showPane(id)` that injects the skeleton, re-inserts the close button, calls the loader.
5. Implement `loadAdminUsers(state)`, `loadAdminLogs(state)`, `loadAdminSessions(state)` that
   populate tables from `state` (fetched from `/_auth/admin/api/state`).
6. Implement 5-second polling: `setInterval(fetchState, 5000)` where `fetchState()` calls
   `/_auth/admin/api/state` and stores the result in a `state` variable.
7. Implement `filterSidebar(query)` as specified in `ADMIN-UI-GUIDE.md §15`.
8. Implement `copyToClipboard(text)` using the Clipboard API with a fallback.

**Verification:**
- Opening `/auth/app` as an admin shows both Settings and Administration sections in the sidebar.
- Clicking each admin pane renders a table (empty or populated).
- Opening `/auth/app` as a non-admin shows only the Settings section.
- Sidebar search input hides non-matching items.
- Esc closes the modal.

---

### Step 4b — Restyle the legacy admin panel to the shared theme

**Phase:** UI 
**Guide:** `THEME-GUIDE.md`, `ADMIN-UI-GUIDE.md`
**Reads:** `forward-auth/adminpage.go`, `forward-auth/ui/theme.css`
**Edits:** `forward-auth/adminpage.go` 
**Blocked by:** Step 1 (Step 4 recommended first — the app shell then shares the design language)

The legacy `/_auth/admin` panel still uses the previous dark palette (`baseCSS`,
which moved into `adminpage.go` during Step 2). Restyle it onto the shared design
system so the old panel and the new `/auth/app` shell look like one product.

**Implementation instructions:**

1. Read `forward-auth/adminpage.go` fully before editing. Keep every JS function,
   API call (`/_auth/admin/api/*`), CSRF wiring, and polling behaviour exactly
   as-is — this is a visual refactor only.
2. Replace the `baseCSS`-based `<style>` block with
   `<link rel="stylesheet" href="/static/theme.css">` plus a small nonce'd
   layout-only style block that references theme custom properties (no hex colours,
   mirroring the `pageCSS` pattern in `page.go`).
3. Map existing elements onto theme components: panels → `.card`, tables →
   `.data-table`, status pills → `.badge` variants, buttons → `.btn` family,
   inputs/selects → `.form-input`.
4. Remove the `baseCSS` constant from `adminpage.go` once nothing references it.
5. Keep the `{{ADMIN}}`, `{{CSRF}}`, `{{NONCE}}` placeholder contract unchanged.

**Verification:**
- `go build ./...` succeeds; `go test ./...` passes.
- `GET /_auth/admin` (admin session) returns HTML linking `/static/theme.css`
  and containing `class="card"` / `class="data-table"`, with no hex palette in the
  `<style>` block.
- Admin actions (create user, revoke session, toggle flags) still work against the
  unchanged JSON API.

---

### Step 5 — Add the new Go routes required by the UI

**Phase:** UI + Backend 
**Guide:** `ADMIN-UI-GUIDE.md` §11–§13 
**Reads:** `forward-auth/admin.go`, `forward-auth/sessions.go`, `forward-auth/main.go` 
**Edits:** `forward-auth/admin.go`, `forward-auth/main.go`, new `forward-auth/mysessions.go` *(create)* 
**Blocked by:** Step 3

Add the four backend routes the UI panes depend on.

**Implementation instructions:**

1. **`GET /_auth/sessions/mine`** — returns only the sessions belonging to the current user.
   ```go
   // mysessions.go
   func (s *server) handleMySessions(w http.ResponseWriter, r *http.Request) {
       cl, _, ok := s.session(r)
       if !ok { http.Error(w, "unauthorized", 401); return }
       sessions := s.reg.forUser(cl.user)       // add forUser() to sessionRegistry
       currentSID := cl.sid
       type mySession struct {
           ID      string    `json:"id"`
           IP      string    `json:"ip"`
           UA      string    `json:"ua"`
           Current bool      `json:"current"`
           Created time.Time `json:"created"`
           Updated time.Time `json:"last_seen"`
       }
       out := make([]mySession, 0, len(sessions))
       for _, sess := range sessions {
           out = append(out, mySession{
               ID: sess.SID, IP: sess.IP, UA: sess.UA,
               Current: sess.SID == currentSID,
               Created: sess.Created, Updated: sess.LastSeen,
           })
       }
       w.Header().Set("Content-Type", "application/json")
       json.NewEncoder(w).Encode(out)
   }
   ```
2. Add `forUser(username string) []sessionInfo` to `sessionRegistry` in `sessions.go`:
   ```go
   func (sr *sessionRegistry) forUser(username string) []sessionInfo {
       sr.mu.Lock(); defer sr.mu.Unlock()
       var out []sessionInfo
       for _, s := range sr.m {
           if s.User == username { out = append(out, *s) }
       }
       return out
   }
   ```
3. **`GET /_auth/sessions/trusted`** — returns the user's device trust cookies as a list.
   For now, return an empty array `[]` (device trust is cookie-based, not registry-stored).
4. **`GET /_auth/admin/api/system`** — returns `SystemInfo` struct as defined in
   `ADMIN-UI-GUIDE.md §11`. Add `startedAt time.Time` field to `server` struct, set it in `main()`.
5. **`POST /_auth/admin/api/sessions/{sid}/revoke`** — admin-only session revocation by SID.
   Gate behind `u.Role == "admin"` check and CSRF header.
6. Register all new routes in `main.go`.

**Verification:**
- `GET /_auth/sessions/mine` returns a JSON array (200) when logged in.
- `GET /_auth/sessions/mine` returns 401 when no session.
- `GET /_auth/admin/api/system` returns JSON with `auth_host`, `user_count`, `uptime`.
- `GET /_auth/admin/api/system` returns 403 for a non-admin session.
- `go test ./...` passes.

---

### Step 5b — Full Tailwind-based login/verify redesign with new routes

**Phase:** UI + Backend 
**Guide:** `UI-REDESIGN-GUIDE.md` §0–§16 (the large redesign deferred from Step 2) 
**Reads:** `forward-auth/ui/login.html`, `forward-auth/ui/verify.html`, `forward-auth/page.go`, `forward-auth/main.go`, `forward-auth/totp.go`, `forward-auth/notify.go` 
**Edits:** `forward-auth/ui/login.html`, `forward-auth/ui/verify.html`, `forward-auth/page.go`, `forward-auth/main.go`, `forward-auth/totp.go`, `forward-auth/notify.go`, `.env.example` 
**Blocked by:** Step 2

Step 2 restyled the existing inline templates only. This step implements the full
`UI-REDESIGN-GUIDE.md`: file-based templates (`ui/login.html`, `ui/verify.html`)
embedded via `//go:embed`, using the shared dark style (the same tokens as
`theme.css` and a Georgia serif headline), plus the supporting routes.

**Implementation instructions:**

1. Review `ui/login.html` and `ui/verify.html` (already present in the repo)
   against the shared theme baseline in guide §0 and fix any drift.
2. Embed templates per guide §3 (`//go:embed ui/*.html`, `template.ParseFS`,
   `tmplFuncs` with `seq`/`add` per §7).
3. Add `LoginPageData` / `VerifyPageData` structs (§4) and the `loginPage()` /
   `verifyPage()` render helpers (§5–§6), mapped onto this repo's existing
   `server`/`config` types — adapt the guide's `s.config.*` calls to the `s.cfg`
   patterns actually present.
4. Wire `POST /auth/totp` (§8), `POST /auth/resend` with rate limiting (§10),
   the optional Google OAuth button (§11) and the `SSO_URL` redirect (§12) — all
   gated behind env vars and hidden when unset. Add `GOOGLE_CLIENT_ID`,
   `GOOGLE_CLIENT_SECRET`, `SSO_URL` to `.env.example`.
5. Update CSP per §13 (prefer the pre-built Tailwind route from §15 over the CDN).
6. Preserve every existing security control: form token, honeypot, dwell time,
   throttle, TOTP replay protection. The new pages are a presentation layer over
   the same login pipeline.
7. Decide the cut-over: either the new pages replace the Step-2 templates outright,
   or they coexist behind a feature flag — do not leave two divergent login UIs.

**Verification:**
- `go build ./...` succeeds; `go test ./...` passes.
- The login page serves the file-based template (Google/SSO buttons hidden when env
  unset, lowercase `or` divider, three legal links, labelled email field).
- Full login flow (password → TOTP → session cookie) works end-to-end via the new pages.
- `POST /auth/resend` enforces its rate limit (429 after 3 requests / 10 min).

---

## Phase 2 — Security: Quick Wins (no token format change)

> Goal: address all 🔴 and 🟠 priority items from `IMPROVEMENT-GUIDE.md §6` that do **not**
> require changing the session token format. These are safe to ship before the PASETO migration.

---

### Step 6 — Argon2id password hashing with transparent upgrade

**Phase:** Security 
**Guide:** `IMPROVEMENT-GUIDE.md §2.1` 
**Reads:** `forward-auth/users.go` 
**Edits:** `forward-auth/users.go`, `forward-auth/go.mod` 
**Blocked by:** nothing (parallel with Phase 1)

**Implementation instructions:**

1. Add `golang.org/x/crypto` to `go.mod` if not already present: `go get golang.org/x/crypto`.
2. In `users.go`, replace `hashPassword` with Argon2id:
   ```go
   import "golang.org/x/crypto/argon2"
   const (argon2Time=3; argon2Memory=64*1024; argon2Threads=4; argon2KeyLen=32)
   func hashPassword(pw string) (string, error) {
       salt := make([]byte, 16)
       if _, err := rand.Read(salt); err != nil { return "", err }
       hash := argon2.IDKey([]byte(pw), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
       return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
           argon2Memory, argon2Time, argon2Threads,
           base64.RawStdEncoding.EncodeToString(salt),
           base64.RawStdEncoding.EncodeToString(hash)), nil
   }
   ```
3. Update `checkPassword` to:
   - Accept existing `$2a$` / `$2b$` bcrypt hashes (call `bcrypt.CompareHashAndPassword`).
   - Accept the new `$argon2id$` PHC format (parse and verify with `argon2.IDKey`).
   - On successful bcrypt login, re-hash with Argon2id and persist via `users.mutate`.
4. Write a PHC parser or use `github.com/alexedwards/argon2id` (prefer the inline parser to
   avoid a new dependency if the parsing logic is short).
5. Add `TestArgon2idRoundTrip` and `TestBcryptTransparentUpgrade` in `main_test.go`.

**Verification:**
- `go test -run TestArgon2id` passes.
- `go test -run TestBcrypt` passes (existing bcrypt hashes still accepted).
- `hashPassword("pw")` returns a string starting with `$argon2id$`.
- `go build ./...` succeeds.

---

### Step 7 — Common-password check

**Phase:** Security 
**Guide:** `IMPROVEMENT-GUIDE.md §2.2` 
**Reads:** `forward-auth/main.go` (password handler) 
**Edits:** `forward-auth/users.go` or new `forward-auth/pwcheck.go` *(create)*, `forward-auth/main.go` 
**Blocked by:** nothing

**Implementation instructions:**

1. Embed a top-100k common passwords list (plain text, one per line, lowercase).
   Source: `https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-100000.txt`
   Save as `forward-auth/data/common-passwords.txt` and embed:
   ```go
   //go:embed data/common-passwords.txt
   var commonPasswords string
   var commonPwSet map[string]struct{}
   func init() {
       commonPwSet = make(map[string]struct{})
       for _, line := range strings.Split(commonPasswords, "\n") {
           if p := strings.TrimSpace(line); p != "" { commonPwSet[p] = struct{}{} }
       }
   }
   func isCommonPassword(pw string) bool {
       _, ok := commonPwSet[strings.ToLower(pw)]
       return ok
   }
   ```
2. In the `s.password` handler (inside `main.go`), add before `hashPassword`:
   ```go
   if isCommonPassword(newPW) {
       s.renderPassword(w, cl.has("c"), "That password appears in breach lists — choose a unique one.")
       return
   }
   ```
3. Add `TestCommonPasswordRejected` and `TestUncommonPasswordAccepted` tests.

**Verification:**
- `POST /_auth/password` with `new1=password123` returns the form with an error message.
- `POST /_auth/password` with a 16-char random password succeeds.
- `go build ./...` succeeds (binary size increase ≤ 500 KB).

---

### Step 8 — Idle session timeout

**Phase:** Security 
**Guide:** `IMPROVEMENT-GUIDE.md §2.8` 
**Reads:** `forward-auth/sessions.go`, `forward-auth/main.go` 
**Edits:** `forward-auth/sessions.go`, `forward-auth/main.go` 
**Blocked by:** nothing

**Implementation instructions:**

1. Add `IDLE_TIMEOUT_MINUTES` env-var to `config` and `loadConfig` (default: 60):
   ```go
   idleTimeout: time.Duration(atoi(os.Getenv("IDLE_TIMEOUT_MINUTES"), 60)) * time.Minute,
   ```
2. Add `lastActive(sid string) time.Time` method to `sessionRegistry`:
   ```go
   func (sr *sessionRegistry) lastActive(sid string) time.Time {
       sr.mu.Lock(); defer sr.mu.Unlock()
       if s := sr.m[sid]; s != nil { return s.LastSeen }
       return time.Time{}
   }
   ```
3. In `server.session()`, after the successful registry lookup and before returning:
   ```go
   if s.cfg.idleTimeout > 0 {
       if last := s.reg.lastActive(cl.sid); !last.IsZero() &&
           time.Since(last) > s.cfg.idleTimeout {
           _ = s.reg.revoke(cl.sid)
           s.audit("idle_timeout", s.clientIP(r), cl.user, r)
           return sessionClaims{}, nil, false
       }
   }
   ```
4. Add `TestIdleSessionExpiry` test.

**Verification:**
- A session not seen for > `IDLE_TIMEOUT_MINUTES` returns `false` from `server.session()`.
- Setting `IDLE_TIMEOUT_MINUTES=0` disables the check (no idle rejection).
- `go test -run TestIdle` passes.

---

### Step 9 — Persist throttle state across restarts

**Phase:** Security 
**Guide:** `IMPROVEMENT-GUIDE.md §2.3` 
**Reads:** `forward-auth/main.go` (throttle struct) 
**Edits:** `forward-auth/main.go` 
**Blocked by:** nothing

**Implementation instructions:**

1. Add `persist(path string) error` and `load(path string) error` methods to `throttle`.
   Serialise the `map[string]*entry` to JSON (same atomic-write pattern as `sessionRegistry.saveLocked`).
2. Call `t.load(filepath.Join(dataDir, "throttle.json"))` in `main()` after `newThrottle`.
3. Call `t.persist(...)` on SIGTERM in the shutdown goroutine.
4. Call `t.persist(...)` each time a new lockout is triggered in `throttle.fail()`.
5. Prune expired entries before persist (don't write entries whose lockout has already cleared).

**Verification:**
- After 5 failed logins, kill and restart the server; the IP remains locked.
- `go test ./...` passes.

---

### Step 10 — Self-service backup code regeneration

**Phase:** Security 
**Guide:** `IMPROVEMENT-GUIDE.md §2.7` 
**Reads:** `forward-auth/main.go` (enroll handler), `forward-auth/users.go` 
**Edits:** `forward-auth/main.go`, `forward-auth/page.go` 
**Blocked by:** nothing

**Implementation instructions:**

1. Add `POST /_auth/backup-codes` handler:
   - Requires valid session (not flagged).
   - Requires POST with a valid form token (`s.cfg.checkForm`).
   - Calls `newBackupCodes(8)` and persists via `users.mutate`.
   - Bumps `u.DeviceGen++` to invalidate device-trust cookies.
   - Audits `"backup_codes_regenerated"` event.
   - Renders the new codes via `s.renderBackupCodes(w, plain)`.
2. Add a "Regenerate backup codes" link to the account settings pane in `app.html`.
3. Register: `mux.HandleFunc("/_auth/backup-codes", s.handleBackupCodes)`.

**Verification:**
- `POST /_auth/backup-codes` returns 8 new codes.
- Old codes are invalidated (bcrypt check fails for old code values).
- `go test ./...` passes.

---

### Step 11 — CSP nonce (remove unsafe-inline for scripts)

**Phase:** Security 
**Guide:** `IMPROVEMENT-GUIDE.md §2.6` 
**Reads:** `forward-auth/main.go` (`secHeaders` function), all page templates in `page.go` 
**Edits:** `forward-auth/main.go`, `forward-auth/page.go`, `forward-auth/ui/app.html` 
**Blocked by:** Step 2 (templates must be restyled first)

**Implementation instructions:**

1. Change `secHeaders` signature to return a nonce:
   ```go
   func secHeaders(w http.ResponseWriter) string {
       b := make([]byte, 16); _, _ = rand.Read(b)
       nonce := base64.StdEncoding.EncodeToString(b)
       h := w.Header()
       // ... existing headers ...
       h.Set("Content-Security-Policy", fmt.Sprintf(
           "default-src 'none'; style-src 'unsafe-inline'; img-src data:; "+
           "script-src 'nonce-%s'; connect-src 'self'; form-action 'self'; "+
           "base-uri 'none'; frame-ancestors 'none'", nonce))
       return nonce
   }
   ```
2. Update every handler that calls `secHeaders(w)` to capture the returned nonce:
   `nonce := secHeaders(w)`
3. Pass `nonce` into every page template that contains a `<script>` tag.
4. Add `nonce="{{.Nonce}}"` to every `<script>` tag in all templates.
5. Keep `style-src 'unsafe-inline'` for now (inline styles are used extensively;
   replacing them with nonce-gated `<style>` blocks is a future step).

**Verification:**
- `curl -I http://localhost:4181/_auth/login | grep Content-Security-Policy` shows
  `script-src 'nonce-` and does **not** show `'unsafe-inline'`.
- All pages still function (no `Refused to execute inline script` in browser console).
- `go test ./...` passes.

---

### Step 12 — Webhook payload enrichment + Ntfy/Slack/Gotify templates

**Phase:** Backend 
**Guide:** `IMPROVEMENT-GUIDE.md §3.6`, `§4.6` 
**Reads:** `forward-auth/notify.go` 
**Edits:** `forward-auth/notify.go`, `forward-auth/main.go` 
**Blocked by:** nothing

**Implementation instructions:**

1. Extend `webhookPayload` struct with `RequestID`, `Severity`, `Timestamp` fields.
2. Add `WEBHOOK_PROVIDER=raw|slack|ntfy|gotify` env-var to `config`.
3. Implement a `formatPayload(provider, payload)` switch that returns provider-specific JSON:
   - `slack`: wraps in `{"attachments":[{"text":...,"color":...}]}`
     (green=info, yellow=warn, red=critical)
   - `ntfy`: adds `Priority` header (`1`=min for info, `4`=high for critical) via HTTP headers
   - `gotify`: wraps in `{"title":...,"message":...,"priority":...}`
   - `raw`: existing flat JSON
4. Map severity: `login_ok`→info, `locked_out`/`bad_backup_code`→warn,
   `backup_code_used`/`enroll_ok`→critical.
5. Add `TestWebhookSlackFormat`, `TestWebhookNtfyFormat` tests.

**Verification:**
- `go test -run TestWebhook` passes.
- `WEBHOOK_PROVIDER=slack` produces `{"attachments":[...]}` shaped payload.

---

## Phase 3 — Token Hardening: PASETO v4.local Migration

> This is the most critical phase. Follow `TOKEN-HARDENING-GUIDE.md` exactly.
> Never attempt to compress multiple sub-steps into one commit.

---

### Step 13 — Add PASETO v4.local dependency and key management

**Phase:** Security/Token 
**Guide:** `TOKEN-HARDENING-GUIDE.md §1–§5` 
**Reads:** `forward-auth/go.mod`, `forward-auth/main.go` 
**Edits:** `forward-auth/go.mod`, `forward-auth/main.go` 
**Blocked by:** Steps 6–11 (all security quick wins should be green before touching tokens)

**Implementation instructions:**

1. Add the PASETO library: `go get github.com/o1ecc8b9/paseto` or whichever library
   `TOKEN-HARDENING-GUIDE.md` specifies. Read the guide for the exact import path.
2. Add key management fields to `config`:
   ```go
   pasetoKey    [32]byte   // XChaCha20-Poly1305 symmetric key for v4.local
   ```
3. Add `PASETO_KEY` env-var loading in `loadConfig`:
   ```go
   // PASETO_KEY must be exactly 64 hex chars (32 bytes)
   pasetoKeyHex := getenvFile("PASETO_KEY", "")
   if pasetoKeyHex == "" {
       // Derive from COOKIE_SECRET using HKDF-SHA256 so existing deployments
       // get a stable key without manual migration.
       pasetoKey, _ = deriveKey(c.secret, "paseto-v4-local")
   } else {
       decoded, err := hex.DecodeString(pasetoKeyHex)
       if err != nil || len(decoded) != 32 { /* config error */ }
       copy(pasetoKey[:], decoded)
   }
   ```
4. Implement `deriveKey(secret []byte, label string) ([32]byte, error)` using
   `golang.org/x/crypto/hkdf` with SHA-256.
5. Add `PASETO_KEY` to `validate()` checks.

**Verification:**
- `go build ./...` succeeds.
- `PASETO_KEY` not set → key derived from `COOKIE_SECRET` (log a notice, not an error).
- `PASETO_KEY=<63 hex chars>` → config validation error.

---

### Step 14 — Define PASETO session payload and issue tokens

**Phase:** Security/Token 
**Guide:** `TOKEN-HARDENING-GUIDE.md §6` 
**Reads:** `forward-auth/main.go` (`issueSession`, `sessionClaims`) 
**Edits:** `forward-auth/main.go` 
**Blocked by:** Step 13

**Implementation instructions:**

1. Define `sessionPayload` struct as specified in `TOKEN-HARDENING-GUIDE.md §6.3`:
   ```go
   type sessionPayload struct {
       Issuer    string `json:"iss"`
       Subject   string `json:"sub"`
       IssuedAt  int64  `json:"iat"`
       NotBefore int64  `json:"nbf,omitempty"`
       Expiry    int64  `json:"exp"`
       TokenID   string `json:"jti"`
       Gen       int    `json:"gen"`
       Flags     string `json:"flags,omitempty"`
   }
   ```
2. Implement `issueSessionPASETO(cl sessionClaims) (string, error)` using `pasetov4.Encrypt`.
   - Implicit assertion: `[]byte("forward-auth session v1")` (no cert binding yet — that comes in Step 19).
3. Implement `parseSessionPASETO(tok string) (sessionClaims, bool)` using `pasetov4.Decrypt`.
   - Verify `iss == cfg.authHost`.
   - Reject if `exp <= now`.
   - Reject if `iat > now + 30s` (clock skew guard).
   - Reject if `sub` or `jti` is empty.
4. **Do NOT change `setCookie` or the session validation path yet.** These two functions
   exist alongside the legacy HMAC functions. The switchover is Step 15.

**Verification:**
- Unit test: `issueSessionPASETO` → `parseSessionPASETO` round-trip returns identical claims.
- Unit test: token tampered by flipping one byte → `parseSessionPASETO` returns `false`.
- Unit test: expired token (exp in past) → returns `false`.
- `go test -run TestPASETO` passes.

---

### Step 15 — Switch issuance to PASETO; keep legacy verification

**Phase:** Security/Token 
**Guide:** `TOKEN-HARDENING-GUIDE.md §7` 
**Reads:** `forward-auth/main.go` (`setCookie`, `server.session`, `login` handler) 
**Edits:** `forward-auth/main.go` 
**Blocked by:** Step 14

This is the migration switchover. Issue all new tokens as PASETO; still verify both formats
during the transition window so existing sessions are not invalidated.

**Implementation instructions:**

1. Change `setCookie` to call `issueSessionPASETO` instead of `issueSession`.
2. Update `server.session()` to try PASETO first, fall back to HMAC:
   ```go
   var cl sessionClaims
   var ok bool
   if strings.HasPrefix(c.Value, "v4.local.") {
       cl, ok = s.cfg.parseSessionPASETO(c.Value)
   } else {
       // Legacy HMAC path — still accepted during transition
       cl, ok = s.cfg.parseSession(c.Value)
   }
   ```
3. Log a debug/info message when a legacy token is successfully verified
   (`"legacy_token_verified"`) so you can monitor migration progress in the audit log.
4. Do **not** remove `issueSession` or `parseSession` yet.

**Verification:**
- After login, the `xore_sso` cookie value starts with `v4.local.`.
- An existing HMAC cookie (if you have one) still grants access (backward compat).
- `go test ./...` passes.
- `go build ./...` succeeds.

---

### Step 16 — PASETO key rotation support

**Phase:** Security/Token 
**Guide:** `TOKEN-HARDENING-GUIDE.md §8` 
**Reads:** `forward-auth/main.go` (`oldSecrets` pattern) 
**Edits:** `forward-auth/main.go` 
**Blocked by:** Step 15

**Implementation instructions:**

1. Add `PASETO_KEY_PREVIOUS` env-var (comma-separated list of old 64-hex keys).
2. Add `oldPasetoKeys [][32]byte` to `config`.
3. Update `parseSessionPASETO` to try `pasetoKey` first, then each `oldPasetoKeys` entry
   in order on decryption failure.
4. On successful old-key verification, **re-issue the token** with the new key (transparent rotation):
   ```go
   // In server.session(), after old-key parse success:
   if usedOldKey {
       newTok, err := s.cfg.issueSessionPASETO(cl)
       if err == nil {
           s.setCookieValue(w, newTok, cl.exp) // re-sets cookie with new token
       }
   }
   ```
5. Update `validate()` to check each old key is exactly 32 bytes.

**Verification:**
- Token issued with key A is accepted after key B becomes primary and A is moved to `PASETO_KEY_PREVIOUS`.
- Token is re-issued with key B (new cookie set).
- `go test ./...` passes.

---

### Step 17 — Remove legacy HMAC token path (post-migration cleanup)

**Phase:** Security/Token 
**Guide:** `TOKEN-HARDENING-GUIDE.md §9` 
**Reads:** `forward-auth/main.go` 
**Edits:** `forward-auth/main.go` 
**Blocked by:** Step 16

> **Wait condition:** deploy Step 15, let it run for at least one full `SESSION_TTL_HOURS`
> cycle (all existing HMAC sessions will have expired naturally). Then run this step.

**Implementation instructions:**

1. Remove the `else { cl, ok = s.cfg.parseSession(c.Value) }` fallback from `server.session()`.
2. Remove `issueSession` and `parseSession` functions from `main.go`.
3. Remove `mac`, `validMAC`, `macWith` functions from `main.go` **only if** they are not
   used by other features (CSRF token, form token, device cookie). Check with
   `grep -n 'validMAC\|macWith\|c\.mac' forward-auth/main.go` before deleting.
4. Update `config.validate()` to require `PASETO_KEY` to be explicitly set (no longer derive silently).
5. Update `COOKIE_SECRET_PREVIOUS` deprecation notice in the log.

**Verification:**
- A raw `v2|...` HMAC cookie → `server.session()` returns `false` (no longer accepted).
- All PASETO tests still pass.
- `go test ./...` passes with no regressions.

---

## Phase 4 — mTLS Session Binding

> **Status: OPTIONAL — skipped by owner decision (2026-07-28).** mTLS client
> certificates are not wanted in this deployment. Steps 18–20 are retained for
> reference only; do not implement unless this decision is revisited.
> Completion criterion 7 (`forwardauth_cert_bound_sessions` metric) is
> correspondingly void.
>
> Implements `MTLS-SESSION-BINDING-GUIDE.md`. Each step maps to one Phase in that guide.

---

### Step 18 — Add cert thumbprint helpers (mtls.go)

**Phase:** Security/mTLS 
**Guide:** `MTLS-SESSION-BINDING-GUIDE.md §6.1` 
**Reads:** `forward-auth/main.go` (`trustedNets`, `clientIP`) 
**Edits:** new `forward-auth/mtls.go` *(create)* 
**Blocked by:** Step 15 (PASETO must be issuing tokens before adding cert binding)

**Implementation instructions:**

1. Create `forward-auth/mtls.go` with:
   - `certThumbprint(cert *x509.Certificate) string` — RFC 8705 `x5t#S256`
   - `parseCertHeader(encoded string) (*x509.Certificate, error)` — decodes Traefik's URL-encoded PEM header
   - `clientCertFromHeader(r *http.Request, trustedNets []*net.IPNet) *x509.Certificate` — validates peer is trusted before accepting the header
   - `pasetoAssertion(thumbprint string) []byte` — builds the implicit assertion bytes
2. Add a `clientCert(r *http.Request) *x509.Certificate` method on `*server` that:
   - Tries `r.TLS.PeerCertificates[0]` first (Phase 2 direct mTLS)
   - Falls back to `clientCertFromHeader(r, s.cfg.trustedNets)`
3. Imports needed: `crypto/sha256`, `crypto/tls`, `crypto/x509`, `encoding/base64`, `net/url`, `strings`, `net`.

**Verification:**
- Unit test: `certThumbprint(nil)` returns `""`.
- Unit test: `certThumbprint(cert)` matches `base64url(SHA-256(cert.RawSubjectPublicKeyInfo))`.
- Unit test: `parseCertHeader` decodes a known PEM block correctly.
- `go test -run TestMTLS` passes.
- `go build ./...` succeeds.

---

### Step 19 — Extend PASETO payload with cnf claim and cert binding

**Phase:** Security/mTLS 
**Guide:** `MTLS-SESSION-BINDING-GUIDE.md §6.2–§6.5` 
**Reads:** `forward-auth/main.go` (`issueSessionPASETO`, `parseSessionPASETO`, `server.session`, `server.login`) 
**Edits:** `forward-auth/main.go`, `forward-auth/sessions.go` 
**Blocked by:** Step 18

**Implementation instructions:**

1. Add `CertThumbprint string \`json:"cnf_x5t,omitempty"\`` to `sessionPayload`.
2. Add `certThumbprint string` field to `sessionClaims`.
3. Update `issueSessionPASETO(cl sessionClaims, thumbprint string)` to:
   - Store `thumbprint` in `sessionPayload.CertThumbprint`.
   - Use `pasetoAssertion(thumbprint)` as the implicit assertion bytes.
4. Update `parseSessionPASETO(tok string, thumbprint string)` to:
   - Decrypt using `pasetoAssertion(thumbprint)` as assertion.
   - After decrypt, if `pl.CertThumbprint != ""`, verify it matches `thumbprint`
     using `subtle.ConstantTimeCompare`.
   - Populate `sessionClaims.certThumbprint`.
5. Update `server.session()` to:
   - Extract thumbprint: `thumb := certThumbprint(s.clientCert(r))`
   - Pass `thumb` to `parseSessionPASETO`
6. Update `server.login()` to:
   - Extract thumbprint at login time
   - Pass to `setCookiePASETO(w, cl, thumb)` (new helper wrapping `issueSessionPASETO`)
7. Update `sessionInfo` in `sessions.go` with `CertBound bool \`json:"cert_bound"\``.
8. Update `reg.touch()` signature to accept `certBound bool`.

**Verification:**
- Unit test: token issued with thumbprint `"abc"` → verify with `"abc"` succeeds.
- Unit test: token issued with thumbprint `"abc"` → verify with `"xyz"` fails (wrong cert).
- Unit test: token issued with thumbprint `"abc"` → verify with `""` fails (no cert presented).
- Unit test: token issued with `""` → verify with `""` succeeds (unbound session, legacy compat).
- Unit test: token issued with `""` → verify with a thumbprint succeeds (unbound accepts any cert).
- `go test -run TestCertBound` passes.

---

### Step 20 — Traefik passTLSClientCert middleware + observability

**Phase:** Security/mTLS + Infra 
**Guide:** `MTLS-SESSION-BINDING-GUIDE.md §8`, `§11`, `§12` 
**Reads:** Traefik dynamic config files in the repo, `forward-auth/main.go` (metrics handler) 
**Edits:** Traefik dynamic config, `forward-auth/main.go` (metrics), `docker-compose.yml` 
**Blocked by:** Step 19

**Implementation instructions:**

1. Add the `pass-client-cert` Traefik middleware in the dynamic config:
   ```yaml
   http:
     middlewares:
       pass-client-cert:
         passTLSClientCert:
           pem: true
   ```
2. Attach `pass-client-cert` to the `auth-portal` router (not to downstream services).
3. Add `forwardauth_cert_bound_sessions` Prometheus gauge to the `metrics` handler:
   ```go
   _, _ = fmt.Fprintf(w,
       "# TYPE forwardauth_cert_bound_sessions gauge\n"+
       "forwardauth_cert_bound_sessions %d\n", s.reg.certBoundCount())
   ```
4. Add `certBoundCount() int` to `sessionRegistry`.
5. Add `REQUIRE_CLIENT_CERT` env-var to `config` (bool, default false). When true,
   `server.session()` rejects sessions where `thumb == ""` and `cl.certThumbprint == ""`:
   ```go
   if s.cfg.requireClientCert && cl.certThumbprint == "" && thumb == "" {
       return sessionClaims{}, nil, false
   }
   ```
6. Add cert init service to `docker-compose.yml` as shown in `MTLS-SESSION-BINDING-GUIDE.md §12`.

**Verification:**
- `/_auth/metrics` output contains `forwardauth_cert_bound_sessions`.
- `REQUIRE_CLIENT_CERT=true` + no client cert → `/_auth/verify` returns 302 (no access).
- `REQUIRE_CLIENT_CERT=false` (default) → cert-less sessions still work.
- `go test ./...` passes.

---

## Phase 5 — Future Features

> Items from `IMPROVEMENT-GUIDE.md §6` marked 🟢 Future. Implement in this order.

---

### Step 21 — Email-based self-service recovery

**Phase:** Backend 
**Guide:** `IMPROVEMENT-GUIDE.md §3.1` 
**Blocked by:** Phase 3 complete (PASETO tokens)

Add `POST /_auth/recover` (submit username) and `GET/POST /_auth/recover?token=…` (reset form).
Use the existing HMAC machinery for time-limited tokens (15-minute expiry). Add `SMTP_URL`
env-var. Rate-limit to 3 requests per IP per hour.

---

### Step 22 — OIDC upstream identity provider

**Phase:** Backend 
**Guide:** `IMPROVEMENT-GUIDE.md §3.4` 
**Blocked by:** Step 21

Add optional OIDC flow via `golang.org/x/oauth2` + `github.com/coreos/go-oidc/v3`.
Add `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_ALLOWED_DOMAINS` env-vars.
Local user store acts as allowlist.

---

### Step 23 — Redis-backed throttle and session registry

**Phase:** Backend 
**Guide:** `IMPROVEMENT-GUIDE.md §3.3` 
**Blocked by:** Step 22

Abstract `ThrottleBackend` and `SessionBackend` interfaces. Provide `MemoryThrottle` (current)
and `RedisThrottle` (active when `REDIS_URL` is set).

---

### Step 24 — Risk-Based Authentication

**Phase:** Security 
**Guide:** `IMPROVEMENT-GUIDE.md §4.1` 
**Blocked by:** Step 23 (RBA needs persistent login history, which needs Redis or DB)

Compute risk score from IP subnet novelty, user-agent novelty, and login time anomaly.
When score > 50 and device is trusted, demand TOTP anyway.

---

## Phase 6 — Code Structure: Declutter Go Files

> Goal: break the monolithic `main.go` and other large files into focused, single-responsibility
> files so that future features only require touching a small, well-scoped file rather than
> searching through thousands of lines. **No behaviour changes** — this is pure refactoring.
> Every extracted function/type must keep its exact existing signature.

---

### Step 25 — Split Go files into focused single-responsibility units

**Phase:** Backend / Refactor  
**Reads:** ALL Go files in `forward-auth/` before editing anything  
**Edits:** `forward-auth/main.go` and all files listed in the extraction plan below  
**Blocked by:** nothing (can run in parallel with any phase, but easiest after all tests are green)

`main.go` is currently ~36 KB and mixes config loading, token logic, brute-force throttling,
HTTP handlers, cookie helpers, and the server entry-point in one file. This makes every
AI-assisted edit risky because a small change requires reading (and potentially misediting)
thousands of lines.

The goal is a **zero-diff refactor**: move code into new files, keep every symbol name,
every function signature, and every test passing. Do not rename anything. Do not change
behaviour. Each new file must start with `package main`.

#### Current file inventory & sizes

| File | ~KB | Notes |
|---|---|---|
| `main.go` | 36 | config + tokens + throttle + handlers + server setup |
| `users.go` | 12 | user store, password hashing, TOTP helpers |
| `adminpage.go` | 18 | admin panel HTML template string |
| `page.go` | 18 | login / enroll / password HTML template strings |
| `passkeys.go` | 9 | passkey API handlers |
| `passkeypage.go` | 4 | passkey HTML template |
| `admin.go` | 9 | admin JSON API handlers |
| `sessions.go` | 4 | session registry |
| `audit.go` | 3 | audit ring + file logger |
| `notify.go` | 2 | webhook notifier |
| `totp.go` | 2 | TOTP validation helpers |
| `qr.go` | 1 | QR code generator |

#### Extraction plan for `main.go`

Extract the following groups into new files. Each extraction is one atomic commit.

**`forward-auth/config.go`** *(create)*
- `type config struct`
- `getenv()`, `getenvFile()`, `atoi()`
- `parseCIDRs()`
- `loadConfig()`
- `(config) validate()`
- All `defaultTrustedProxies` constant

**`forward-auth/token.go`** *(create)*
- `type sessionClaims struct`
- `(sessionClaims) has()`
- `newSID()`
- `(config) issueSession()`, `(config) parseSession()`
- `(config) mac()`, `macWith()`, `(config) validMAC()`
- `(config) csrfToken()`
- `(config) issueDevice()`, `(config) validDevice()`
- `(config) issueForm()`, `(config) checkForm()`
- `(config) totpURI()`

**`forward-auth/throttle.go`** *(create)*
- `type entry struct`
- `type throttle struct`
- `newThrottle()`
- `(throttle) locked()`, `(throttle) fail()`, `(throttle) pruneLocked()`, `(throttle) reset()`
- `(throttle) snapshot()` (if present)
- `min()` helper (if not already in another file)

**`forward-auth/server.go`** *(create)*
- `type server struct`
- `(server) clientIP()`
- `normalizeHost()`
- `(config) safeRedirect()`
- `secHeaders()`
- `(server) setCookie()`, `(server) clearCookie()`, `(server) setDeviceCookie()`
- `(server) trustedDevice()`
- `(server) session()`
- `(server) flagsFor()`
- `pendingRedirect()`
- `firstNonEmpty()`

**`forward-auth/handlers.go`** *(create)*
- `(server) verify()`
- `(server) login()`
- `(server) fail()`
- `(server) logout()`
- `(server) enroll()`
- `(server) password()`
- `(server) audit()`
- `(server) metrics()`

**`forward-auth/main.go`** *(keep — slim down to entry point only)*
- `func main()` — server construction, mux registration, signal handling
- `//go:embed` directives (must stay in the same file as the `embed.FS` variable they refer to,
  or move the `embed.FS` declaration into the new file that owns it)

#### Extraction plan for other large files

**`forward-auth/page.go`** — already focused on templates; no split needed unless it grows beyond
~25 KB after the UI restyle. If it does, split into `forward-auth/page_auth.go` (login/enroll/password)
and `forward-auth/page_backup.go` (backup codes / ok page).

**`forward-auth/adminpage.go`** — single large template string. No structural split needed;
keep as-is unless it exceeds ~30 KB.

**`forward-auth/users.go`** — already focused. If `hashPassword` + Argon2id (Step 6) pushes it
past ~20 KB, extract password helpers into `forward-auth/password.go`.

#### Implementation instructions

1. **Read every file** in `forward-auth/` before making any edits.
2. Work through the extraction plan **one file at a time**. After each new file is created:
   a. Remove the extracted declarations from their original location.
   b. Run `go build ./...` — must succeed with zero errors before proceeding.
   c. Run `go test ./...` — must pass before proceeding.
3. Do **not** rename any type, function, or variable. The only change is which `.go` file
   contains the declaration.
4. Do **not** add, remove, or reorder any import that is not necessitated by the move.
   Go will flag unused imports as errors; remove them from the source file after extraction.
5. If a helper is used by both the original file and a new file (e.g. `firstNonEmpty` used
   in handlers and the server), place it in the file that represents its primary concern
   (`server.go` for request-scoped helpers) and let the other files call it normally — they
   share the same package.
6. `//go:embed` directives must appear in the same file as the `var` they annotate. If you
   move an `embed.FS` variable into a new file, move its `//go:embed` directive with it.
7. After all extractions, verify the final state:
   ```
   wc -l forward-auth/main.go   # should be < 150 lines
   go build ./...
   go test ./...
   go vet ./...
   ```

**Verification:**
- `go build ./...` succeeds with zero errors after every individual extraction.
- `go test ./...` passes after every individual extraction.
- `go vet ./...` is clean at the end.
- `forward-auth/main.go` contains only `func main()` and embed declarations (< 150 lines).
- `forward-auth/config.go`, `forward-auth/token.go`, `forward-auth/throttle.go`,
  `forward-auth/server.go`, and `forward-auth/handlers.go` all exist and compile.
- No symbol has been renamed; no behaviour has changed.
- `grep -rn 'type config struct' forward-auth/` returns exactly one result (in `config.go`).
- `grep -rn 'type server struct' forward-auth/` returns exactly one result (in `server.go`).

---

## Completion criteria

The implementation is complete when all of the following are true:

1. `go test ./...` in `forward-auth/` reports 0 failures.
2. `go build ./...` produces no errors or warnings.
3. `go vet ./...` is clean.
4. The login page uses the shared theme and passes Chrome DevTools Lighthouse accessibility check ≥ 90.
5. All new session cookies start with `v4.local.`.
6. The admin panel System pane shows live data.
7. `/_auth/metrics` includes `forwardauth_cert_bound_sessions`.
8. Argon2id hashes are used for all new passwords.
9. Common passwords are rejected at `/_auth/password`.
10. Sessions idle longer than `IDLE_TIMEOUT_MINUTES` are automatically revoked.
11. `forward-auth/main.go` contains only `func main()` and embed declarations (< 150 lines).

---

## Quick reference: file map

| File | Purpose |
|---|---|
| `forward-auth/main.go` | Entry point only (after Step 25) |
| `forward-auth/config.go` | *(create in Step 25)* Config struct, env loading, validation |
| `forward-auth/token.go` | *(create in Step 25)* Session/device/form token issue + parse |
| `forward-auth/throttle.go` | *(create in Step 25)* Brute-force throttle |
| `forward-auth/server.go` | *(create in Step 25)* Server struct, cookie helpers, session validation |
| `forward-auth/handlers.go` | *(create in Step 25)* HTTP handlers (verify, login, logout, enroll, password, metrics) |
| `forward-auth/users.go` | User store, password hashing, TOTP |
| `forward-auth/sessions.go` | Session registry, revocation list |
| `forward-auth/admin.go` | Admin API handlers |
| `forward-auth/adminpage.go` | Admin panel HTML template |
| `forward-auth/page.go` | Login / enroll / password page templates |
| `forward-auth/notify.go` | Webhook notifier |
| `forward-auth/passkeys.go` | Passkey API handlers |
| `forward-auth/passkeypage.go` | Passkey HTML template |
| `forward-auth/totp.go` | TOTP validation helpers |
| `forward-auth/qr.go` | QR code generator |
| `forward-auth/audit.go` | Audit ring + file logger |
| `forward-auth/ui/theme.css` | *(create in Step 1)* CSS design system |
| `forward-auth/ui/app.html` | *(create in Step 3)* App shell + settings modal |
| `forward-auth/apppage.go` | *(create in Step 3)* `/auth/app` handler |
| `forward-auth/mtls.go` | *(create in Step 18)* mTLS cert helpers |
| `forward-auth/mysessions.go` | *(create in Step 5)* `/_auth/sessions/mine` handler |
| `forward-auth/pwcheck.go` | *(create in Step 7)* Common-password embed + check |
