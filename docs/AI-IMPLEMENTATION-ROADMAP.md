# AI Implementation Roadmap — auth-backend

> **Audience:** This document is written for an AI coding assistant (Claude, ChatGPT, Gemini, etc.).
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
| [`CLAUDE-THEME-GUIDE.md`](./CLAUDE-THEME-GUIDE.md) | CSS design system (variables, components, dark mode) |
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

## Phase 1 — UI Foundation

> Goal: establish the design system and restyle all existing pages before touching any security
> logic. A clean UI layer makes subsequent Go changes easier to review.

---

### Step 1 — Create the CSS design system

**Phase:** UI 
**Guide:** `CLAUDE-THEME-GUIDE.md` §1–§12 
**Reads:** `forward-auth/main.go` (to understand embed pattern), `CLAUDE-THEME-GUIDE.md` 
**Edits:** `forward-auth/ui/claude-theme.css` *(create)*  
**Blocked by:** nothing

The entire UI restyle depends on this file. It must be created first.

**Implementation instructions:**

1. Create the directory `forward-auth/ui/` if it does not exist.
2. Create `forward-auth/ui/claude-theme.css` with exactly the token/variable definitions,
   component classes (`.btn`, `.card`, `.badge`, `.form-input`, `.data-table`, `.modal`,
   `.modal__sidebar`, `.modal__content`, `.sidebar__item`, `.sidebar__section-label`),
   dark-mode media query block, and mobile breakpoints described in `CLAUDE-THEME-GUIDE.md`.
3. The CSS must use CSS custom properties (`--bg-primary`, `--text-primary`, `--accent`, etc.)
   as the single source of truth. No hardcoded hex colours outside the `:root` / `prefers-color-scheme` blocks.
4. Do **not** reference any external font CDN. Use `system-ui, -apple-system, sans-serif`.
5. Include the `@keyframes modal-in` and `@keyframes fade-in` animations used by the modal.

**Verification:**
- The CSS file exists at `forward-auth/ui/claude-theme.css`.
- Running `grep -c 'var(--' forward-auth/ui/claude-theme.css` returns ≥ 30.
- No `http://` or `https://` URLs appear in the file.
- The file contains `.modal__sidebar`, `.modal__content`, `.sidebar__item`, `.data-table`, `.badge--green`, `.badge--red`, `.badge--orange`, `.badge--blue`, `.badge--muted`.

---

### Step 2 — Restyle the login, enroll, and password pages

**Phase:** UI 
**Guide:** `UI-REDESIGN-GUIDE.md` §1–§6 
**Reads:** `forward-auth/page.go` (current templates), `UI-REDESIGN-GUIDE.md` 
**Edits:** `forward-auth/page.go` (or `forward-auth/ui/*.html` if templates are file-based) 
**Blocked by:** Step 1

Apply the Claude-theme components to the three user-facing pages. The backend logic does not change.

**Implementation instructions:**

1. Read `forward-auth/page.go` fully before editing. Identify where `loginPage`, `enrollPage`,
   `passwordPage`, and `backupCodesPage` template strings are defined.
2. Replace the inline `<style>` blocks in each template with a single
   `<link rel="stylesheet" href="/static/claude-theme.css">`.
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
- `/static/claude-theme.css` is served (verify with `curl -I http://localhost:4181/static/claude-theme.css`).

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
   - `<link>` to `/static/claude-theme.css`
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

## Completion criteria

The implementation is complete when all of the following are true:

1. `go test ./...` in `forward-auth/` reports 0 failures.
2. `go build ./...` produces no errors or warnings.
3. `go vet ./...` is clean.
4. The login page uses the Claude theme and passes Chrome DevTools Lighthouse accessibility check ≥ 90.
5. All new session cookies start with `v4.local.`.
6. The admin panel System pane shows live data.
7. `/_auth/metrics` includes `forwardauth_cert_bound_sessions`.
8. Argon2id hashes are used for all new passwords.
9. Common passwords are rejected at `/_auth/password`.
10. Sessions idle longer than `IDLE_TIMEOUT_MINUTES` are automatically revoked.

---

## Quick reference: file map

| File | Purpose |
|---|---|
| `forward-auth/main.go` | Config, session tokens, handlers, server setup |
| `forward-auth/users.go` | User store, password hashing, TOTP |
| `forward-auth/sessions.go` | Session registry, revocation list |
| `forward-auth/admin.go` | Admin API handlers |
| `forward-auth/adminpage.go` | Admin panel HTML template |
| `forward-auth/page.go` | Login / enroll / password page templates |
| `forward-auth/notify.go` | Webhook notifier |
| `forward-auth/ui/claude-theme.css` | *(create in Step 1)* CSS design system |
| `forward-auth/ui/app.html` | *(create in Step 3)* App shell + settings modal |
| `forward-auth/apppage.go` | *(create in Step 3)* `/auth/app` handler |
| `forward-auth/mtls.go` | *(create in Step 18)* mTLS cert helpers |
| `forward-auth/mysessions.go` | *(create in Step 5)* `/_auth/sessions/mine` handler |
| `forward-auth/pwcheck.go` | *(create in Step 7)* Common-password embed + check |
