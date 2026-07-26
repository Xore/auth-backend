# Auth-Backend — Improvement Guide

This document analyses the current `forward-auth` implementation against 2025–2026 security research
and best practices, lists concrete gaps, and provides implementation guidance for every item.

---

## Table of Contents

1. [What the codebase already does well](#1-what-the-codebase-already-does-well)
2. [Security concerns](#2-security-concerns)
3. [Missing features](#3-missing-features)
4. [Neat additions worth considering](#4-neat-additions-worth-considering)
5. [Implementation guidance](#5-implementation-guidance)
6. [Priority matrix](#6-priority-matrix)

---

## 1. What the codebase already does well

| Area | Implementation |
|---|---|
| Password storage | bcrypt (solid; see §2.1 for upgrade path) |
| Brute-force protection | Per-IP + per-username throttle with exponential backoff |
| TOTP | Per-user secret, replay protection, backup codes (bcrypt-hashed) |
| Passkeys | WebAuthn via `go-webauthn/webauthn` |
| Session tokens | HMAC-SHA-256 signed, v2 layout, per-user generation revocation |
| Cookie hygiene | HttpOnly, Secure, SameSite=Lax, host-scoped device cookie |
| CSRF | HMAC-signed form token + timing window |
| Open-redirect protection | `safeRedirect` validates scheme + domain |
| Bot traps | Honeypot field + minimum dwell time |
| Audit logging | JSON structured log + in-memory ring, webhook alerts |
| Prometheus metrics | Token-gated `/metrics` endpoint |
| Docker secrets | `_FILE` suffix env-var pattern |
| Trusted-proxy IP resolution | Validates `X-Forwarded-For` chain, CF-Connecting-IP preference |
| Graceful shutdown | SIGTERM → 10 s drain |

---

## 2. Security concerns

### 2.1 Password hashing: bcrypt → Argon2id

**Issue.** bcrypt is still acceptable but Argon2id is the NIST SP 800-63B Rev 4 (2024) recommended
algorithm for new systems. bcrypt's 72-byte password truncation is also a known footgun.

**Risk level:** Medium

**Fix.** Migrate `hashPassword` / `checkPassword` in `users.go`:

```go
// go.mod: golang.org/x/crypto v0.23+ includes argon2
import "golang.org/x/crypto/argon2"

const argon2Time    = 3
const argon2Memory  = 64 * 1024  // 64 MB
const argon2Threads = 4
const argon2KeyLen  = 32

func hashPassword(pw string) (string, error) {
    salt := make([]byte, 16)
    _, _ = rand.Read(salt)
    hash := argon2.IDKey([]byte(pw), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
    encoded := fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
        argon2Memory, argon2Time, argon2Threads,
        base64.RawStdEncoding.EncodeToString(salt),
        base64.RawStdEncoding.EncodeToString(hash))
    return encoded, nil
}

func checkPassword(pw, stored string) bool {
    if strings.HasPrefix(stored, "$2a$") || strings.HasPrefix(stored, "$2b$") {
        // Transparent upgrade path: still accept existing bcrypt hashes
        return bcrypt.CompareHashAndPassword([]byte(stored), []byte(pw)) == nil
    }
    // parse argon2id PHC string and verify
    // ... (use a small PHC parser or alexedwards/argon2id library)
}
```

On successful bcrypt login, re-hash with Argon2id and persist. This upgrades all users transparently
without forcing a password reset.

### 2.2 Password strength enforcement

**Issue.** The only policy is `len >= 10`. There is no check against common passwords
(NIST 800-63B §5.1.1 mandates checking against a known-bad list).

**Risk level:** Medium

**Fix.**
- Embed a top-100k password list (≈ 700 KB compressed) and reject exact matches at `/_auth/password`.
- Optionally compute zxcvbn score and require score ≥ 3.
- Go library: `github.com/nbutton23/zxcvbn-go` or a static embedded wordlist.

```go
// In s.password handler, before hashPassword:
if isCommonPassword(newPW) {
    s.renderPassword(w, cl.has("c"), "That password is too common — choose a different one.")
    return
}
```

### 2.3 Throttle state is in-memory only

**Issue.** The `throttle` map lives in the process. A container restart (OOM, deploy, crash) resets
all lockout counters. An attacker can exhaust attempts, wait for a restart, and continue.

**Risk level:** Medium–High in high-availability deployments.

**Fix.** Persist throttle state to the same JSON data directory used for sessions:

```go
// Flush throttle map to /data/throttle.json on SIGTERM and reload on start.
// Alternatively: write on every lockout trigger (low write frequency).
func (t *throttle) persist(path string) error { ... }
func (t *throttle) load(path string) error { ... }
```

Alternatively, if you introduce Redis (see §3.3), store counters there with TTL.

### 2.4 TOTP: no rate limiting on the TOTP field separately

**Issue.** The per-IP throttle fires after `MAX_ATTEMPTS` total failures across password + TOTP.
An attacker who already has the correct password can try TOTP codes more aggressively if they
spread retries across IPs (e.g. rotating proxies).

**Risk level:** Low (TOTP space is 10⁶, window is 30 s, but still worth closing).

**Fix.** Track per-user TOTP failure counter separately, lock the user's TOTP attempts for 60 s
after 3 consecutive wrong codes:

```go
type user struct {
    // ...
    TOTPFailStreak int
    TOTPLockUntil  time.Time
}
```

### 2.5 Session cookie SameSite=Lax allows GET-based CSRF on sub-actions

**Issue.** `SameSite=Lax` sends the cookie on top-level navigations (link clicks, redirects).
The `/_auth/logout` handler is GET-only and has no CSRF token, so a cross-site link can force
logout (low-severity CSRF).

**Risk level:** Low (logout-only impact).

**Fix.** Accept logout via POST with a CSRF token, or use `SameSite=Strict` for the session cookie
(confirm this doesn't break the Traefik redirect flow — it should be fine since the forwardAuth
redirect is a top-level navigation).

### 2.6 Content-Security-Policy uses `unsafe-inline` for scripts

**Issue.** The CSP in `secHeaders()` allows `script-src 'unsafe-inline'`, weakening XSS protection
for the admin panel and login page.

**Risk level:** Low (server-rendered HTML, no external input reflected into scripts, but defense-in-depth matters).

**Fix.** Generate a per-request nonce and use `script-src 'nonce-<value>'`:

```go
func secHeaders(w http.ResponseWriter) (nonce string) {
    b := make([]byte, 16)
    _, _ = rand.Read(b)
    nonce = base64.StdEncoding.EncodeToString(b)
    // ...
    h.Set("Content-Security-Policy",
        fmt.Sprintf("default-src 'none'; style-src 'unsafe-inline'; img-src data:; "+
            "script-src 'nonce-%s'; connect-src 'self'; form-action 'self'; "+
            "base-uri 'none'; frame-ancestors 'none'", nonce))
    return nonce
}
// Pass nonce into page templates.
```

### 2.7 Backup codes: 8-code set never regenerated unless re-enrolling

**Issue.** A user who uses several backup codes has no self-service way to generate a fresh set
short of re-enrolling TOTP entirely. If backup codes are captured by an attacker (clipboard,
screenshot), there is no revocation path.

**Fix.** Add a `/_auth/backup-codes` endpoint (session-gated, POST + CSRF token) that regenerates
the backup code set and voids the old ones, similar to how `/_auth/password` works for passwords.

### 2.8 No absolute session lifetime — idle sessions live forever until TTL

**Issue.** `SESSION_TTL_HOURS` sets the cookie `MaxAge` at issuance. A session opened once and
left open is valid for up to 12 hours regardless of inactivity. NIST 800-63B (Rev 4) recommends
≤ 30-minute idle timeout for AAL2 contexts, plus an absolute bound.

**Risk level:** Low for personal homelab, higher for shared deployments.

**Fix.** Store `last_active` in the session registry (already tracked via `reg.touch`) and reject
sessions idle for longer than `IDLE_TIMEOUT_MINUTES` (default: 60):

```go
// In sessionRegistry.touch, record time.
// In server.session, after reg.touch, check idle:
if time.Since(reg.lastActive(cl.sid)) > s.cfg.idleTimeout {
    _ = s.reg.revoke(cl.sid)
    return sessionClaims{}, nil, false
}
```

---

## 3. Missing features

### 3.1 Email-based account recovery

**Current state.** Recovery is purely admin-mediated (see `docs/CREDENTIAL-RECOVERY.md`). There is
no self-service flow for lost TOTP or password.

**Implementation.**

```
 POST /_auth/recover          — submit username → server emails a time-limited HMAC token
 GET  /_auth/recover?token=…  — validates token, shows reset form
 POST /_auth/recover?token=…  — sets new password, voids token, revokes all sessions
```

Token format (same HMAC machinery already present):
```go
func (c config) issueRecovery(user string) string {
    exp := strconv.FormatInt(time.Now().Add(15*time.Minute).Unix(), 10)
    body := "rec|" + exp + "|" + user
    return body + "|" + c.mac(body)
}
```

Email transport: simple SMTP via `net/smtp` or a relay env-var (`SMTP_URL=smtp://user:pass@host:587`).
Rate-limit recovery requests to 3 per hour per IP to prevent address enumeration via timing.

### 3.2 Per-user session list & remote logout

**Current state.** The admin panel shows active sessions globally. Users cannot see or revoke their
own sessions from a self-service page.

**Implementation.** Add `/_auth/sessions` (session-gated, GET + POST for per-session revoke).
The session registry already stores `sid → {username, ip, ua, lastSeen}`. Filtering by username
is a one-liner:

```go
// sessions.go – add:
func (r *sessionRegistry) forUser(username string) []sessionEntry { ... }
```

Then render a table of sessions with a revoke button for each.

### 3.3 Redis-backed throttle + session registry (multi-replica support)

**Current state.** All state (throttle, session registry) is in-process memory + JSON files.
This works for single-instance deployments but blocks horizontal scaling.

**Implementation.** Abstract the throttle and session registry behind an interface:

```go
type ThrottleBackend interface {
    Locked(ip string) (bool, time.Duration)
    Fail(ip string) bool
    Reset(ip string)
}

type SessionBackend interface {
    Touch(sid, user, ip, ua string)
    IsRevoked(sid string) bool
    Revoke(sid string) error
    // ...
}
```

Provide two implementations: `MemoryThrottle` (current) and `RedisThrottle` (selected when
`REDIS_URL` is set). The Redis implementation uses `INCR + EXPIRE` for counters and a
`SADD` set for revoked SIDs with a TTL matching `SESSION_TTL_HOURS`.

### 3.4 OIDC / OAuth2 upstream identity provider

**Current state.** All users are local (JSON file). There is no way to delegate authentication
to an upstream IdP (Google Workspace, Authentik, Keycloak, Entra ID).

**Implementation.** Add an optional OIDC flow:

```
GET  /_auth/oidc/login    — redirect to IdP authorization endpoint
GET  /_auth/oidc/callback — exchange code, extract sub/email, issue local session
```

Use `golang.org/x/oauth2` + `github.com/coreos/go-oidc/v3`. The existing local user store can act
as an allowlist: only provision sessions for IdP users whose email matches a record in `users.json`
(or an `OIDC_ALLOWED_DOMAINS` env-var for whole-domain allows).

### 3.5 Structured `/_auth/admin/api/sessions` endpoint

**Current state.** The admin panel exposes users and audit logs via JSON API, but the session
registry is only visible in the HTML panel.

**Implementation.** Add:

```
GET  /_auth/admin/api/sessions          — list all active sessions
DELETE /_auth/admin/api/sessions/{sid}  — revoke specific session
DELETE /_auth/admin/api/sessions        — revoke all sessions for a user (?user=…)
```

This enables programmatic session management from external scripts (useful for incident response).

### 3.6 Webhook payload enrichment

**Current state.** `notify.go` sends a minimal JSON payload: `{event, user, ip, host, detail}`.
There is no request ID, no severity level, and no machine-readable event type mapping.

**Enhancement.**

```go
type webhookPayload struct {
    RequestID string    `json:"request_id"`
    Event     string    `json:"event"`
    Severity  string    `json:"severity"`  // "info"|"warn"|"critical"
    User      string    `json:"user"`
    IP        string    `json:"ip"`
    Host      string    `json:"host"`
    Detail    string    `json:"detail"`
    Timestamp time.Time `json:"timestamp"`
}
```

Severity mapping: `login_ok` → info, `locked_out` / `bad_backup_code` → warn,
`backup_code_used` → critical.

---

## 4. Neat additions worth considering

### 4.1 Risk-Based Authentication (RBA)

RBA computes a risk score at login time based on signals like:
- Unknown IP subnet (not seen in last N logins)
- Unusual user-agent
- Login time anomaly
- Country change (if GeoIP is available)

When risk is elevated, step up to TOTP even if the device is trusted. Research (Wiefling et al., 2022)
shows RBA is perceived as more usable than mandatory 2FA while closing most of the same threat surface.

```go
func (s *server) riskScore(r *http.Request, u *User, ip string) int {
    score := 0
    if !u.knownSubnet(ip) { score += 40 }
    if !u.knownUA(r.UserAgent()) { score += 20 }
    if isUnusualHour(u, time.Now()) { score += 10 }
    return score
}
// In login handler: if riskScore > 50 && trusted_device → demand TOTP anyway
```

### 4.2 Passkey-only (passwordless) mode

Passkeys are already implemented for MFA. A small addition (`PASSWORDLESS=true`) would disable
the password field entirely and route login straight to the WebAuthn flow. This aligns with the
2026 industry push (Apple, Google, Microsoft) toward passkey-first authentication.

```go
// In renderLogin:
if s.cfg.passwordless {
    // render passkey-only button, skip password form
}
```

### 4.3 HIBP (Have I Been Pwned) password check

On password change, submit the first 5 hex chars of SHA-1(password) to the HIBP k-anonymity API
and warn the user if the suffix appears in the response. This is purely advisory (don't block on
API failure):

```go
func hibpPwned(pw string) (int, error) {
    h := sha1.Sum([]byte(pw))
    prefix := strings.ToUpper(hex.EncodeToString(h[:2]) + hex.EncodeToString(h[2:3])[:1])
    // GET https://api.pwnedpasswords.com/range/{prefix}
    // count matches in response
}
```

### 4.4 Signed audit log (tamper evidence)

The current audit log is a plain JSON file. An attacker with write access to the data directory
could scrub entries. Sign each log line with an HMAC chain (each entry includes the hash of the
previous entry) so deletion or modification of any line breaks the chain:

```go
type auditEntry struct {
    Seq   int    `json:"seq"`
    Prev  string `json:"prev"` // HMAC of previous line
    // ... event fields
    MAC   string `json:"mac"`  // HMAC(seq|prev|event|...)
}
```

### 4.5 Automatic HTTPS redirect for the auth host

If `forward-auth` is ever exposed on a non-TLS port (dev/testing), add an HTTP→HTTPS redirect
listener on a second port (`REDIRECT_PORT`, default off) rather than relying solely on Traefik.

### 4.6 Slack / Ntfy / Gotify webhook templates

The current notifier sends a single JSON blob. Adding provider-specific templates
(Slack `attachments`, ntfy priority headers, Gotify Markdown) requires only a few extra lines in
`notify.go` and a `WEBHOOK_PROVIDER=slack|ntfy|gotify|raw` env-var.

---

## 5. Implementation guidance

### 5.1 How to add a new handler

1. Write the handler method on `*server` in a new `<feature>.go` file.
2. Register the route in `main()` inside `main.go`.
3. Gate it behind `s.session()` for authenticated-only access.
4. Add a CSRF check (`s.cfg.checkForm(...)`) for any state-mutating POST.
5. Call `s.audit("event_name", ...)` and `s.ntf.send(...)` for significant events.
6. Add config fields to `config` struct + `loadConfig()` + `validate()` in `main.go`.

### 5.2 How to add a new env-var

```go
// In config struct:
myFeature bool

// In loadConfig:
myFeature: getenv("MY_FEATURE", "false") == "true",

// In validate (if required):
if c.myFeature && c.dependencyMissing {
    problems = append(problems, "MY_FEATURE requires DEPENDENCY")
}

// Document in .env.example:
# MY_FEATURE=false   # enable experimental XYZ
```

### 5.3 Adding a new user field

All user fields live in `users.go` → `type User struct`. The JSON file is the source of truth.

1. Add the field to `User` with a `json:"field_name,omitempty"` tag.
2. Mutate via `users.mutate(username, func(u *User) bool { ... })` — this takes the write lock,
   modifies in place, and atomically persists (write to `.tmp` then `os.Rename`).
3. Read via `users.get(username)` — returns a deep copy, safe to read without a lock.

### 5.4 Testing

The existing `main_test.go` uses `httptest.NewRecorder`. Follow the same pattern:

```go
func TestMyFeature(t *testing.T) {
    srv := testServer(t)  // helper that sets up a server with temp users.json
    w := httptest.NewRecorder()
    r := httptest.NewRequest(http.MethodPost, "/_auth/my-endpoint", strings.NewReader("ft="+srv.cfg.issueForm()))
    r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    srv.myHandler(w, r)
    if w.Code != http.StatusOK {
        t.Fatalf("expected 200, got %d", w.Code)
    }
}
```

### 5.5 Building & running locally

```bash
cd forward-auth
go build ./...
go test ./...

# Or via Docker:
docker compose up --build forward-auth
```

---

## 6. Priority matrix

| # | Item | Impact | Effort | Priority |
|---|---|---|---|---|
| 2.2 | Common-password check | High | Low | 🔴 Do first |
| 2.8 | Idle session timeout | Medium | Low | 🔴 Do first |
| 2.1 | Argon2id migration | Medium | Low | 🔴 Do first |
| 3.1 | Email recovery flow | High | Medium | 🟠 High |
| 2.3 | Persist throttle state | Medium | Low | 🟠 High |
| 3.2 | Self-service session list | Medium | Low | 🟠 High |
| 2.7 | Backup code regeneration | Medium | Low | 🟠 High |
| 2.6 | CSP nonce (no unsafe-inline) | Low | Low | 🟡 Medium |
| 3.6 | Webhook enrichment | Low | Low | 🟡 Medium |
| 4.6 | Ntfy/Slack/Gotify templates | Low | Low | 🟡 Medium |
| 4.3 | HIBP pwned-password check | Medium | Low | 🟡 Medium |
| 4.1 | Risk-Based Authentication | High | High | 🟡 Medium |
| 3.4 | OIDC upstream IdP | High | High | 🟢 Future |
| 3.3 | Redis backend | Medium | High | 🟢 Future |
| 4.2 | Passwordless passkey mode | Medium | Medium | 🟢 Future |
| 4.4 | Signed audit log chain | Low | Medium | 🟢 Future |

---

## References

- NIST SP 800-63B Revision 4 (2024) — Digital Identity Guidelines
- OWASP ASVS v4.0 — Authentication Verification Requirements (V2)
- Wiefling et al. (2022) — *Pump Up Password Security: Evaluating Risk-Based Authentication*
- Gilsenan et al. (2023) — *Security and Privacy of TOTP 2FA App Backup Mechanisms* (USENIX Sec '23)
- OAuth 2.0 Security Best Current Practice (RFC 9700, 2025)
- Security Boulevard (2026) — *User Authentication Best Practices for B2B SaaS*
