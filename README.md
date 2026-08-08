# auth-backend — hardened Traefik forward-auth SSO

A single sign-on portal at your `AUTH_HOST` (e.g. `auth.xore.rocks`) that
protects any number of services behind a Traefik reverse proxy. Attach the
`forward-auth` middleware to a router and unauthenticated requests get
bounced to a styled login page; one login issues a **PASETO v4.local**
session cookie scoped to `COOKIE_DOMAIN`, so it works across every
subdomain (SSO).

Users, TOTP secrets, passkeys, backup codes and login history live in a
small JSON store with multi-user support and an admin UI — no database
required. Optionally, throttle and session state move to Redis for
multi-replica deployments.

## How it works

```mermaid
flowchart LR
    U[User's browser] --> T[Traefik]
    T -->|forwardAuth middleware| V[auth-portal<br/>/_auth/verify]
    V -->|200 + X-Auth-User| T
    V -->|302 to login| T
    T -->|200: request proceeds| S[Protected service]
    U -->|login at AUTH_HOST| P[auth-portal<br/>/_auth/login]
    P --> C[(users.json<br/>Argon2id, TOTP,<br/>passkeys)]
    P --> R[(Redis<br/>optional)]
    P -->|PASETO v4.local cookie<br/>scoped to COOKIE_DOMAIN| U
```

- `/_auth/verify` returns **200** (with `X-Auth-User`/`X-Auth-Role`
  identity hints) for a valid session, **302** to the login page otherwise.
  These headers are useful for display and legacy upstreams but are not an
  authorization credential unless the upstream is provably reachable only
  through the trusted proxy path.
- Protected applications that make authorization decisions should use
  `POST /_auth/introspect` instead of trusting request headers. Introspection
  requires a separate service bearer token and the browser session cookie,
  then returns the current immutable subject, username, role and generation
  after rechecking revocation, account status and allowed hosts.
- Sessions are stateless PASETO tokens (user, generation, session id,
  flags, expiry). A per-user **generation counter** invalidates every
  session and trusted-device cookie on password change, admin reset or
  "log out everywhere"; a server-side **session registry** allows revoking
  individual sessions and enforces idle timeouts.
- If auth-portal is down, Traefik surfaces a 5xx — protected services
  **fail closed, never open**.

## Sign-in flow

```mermaid
sequenceDiagram
    participant B as Browser
    participant T as Traefik
    participant A as auth-portal
    participant S as User store
    B->>T: GET admin.example.com
    T->>A: forwardAuth /_auth/verify
    A-->>T: 302 (no valid session)
    T-->>B: redirect to AUTH_HOST/_auth/login
    B->>A: POST username + password
    A->>A: throttle check (per-IP + per-user),<br/>form token, honeypot, dwell time
    A->>S: verify Argon2id hash (bcrypt auto-upgrade)
    alt TOTP enrolled and device not trusted
        A-->>B: TOTP challenge (5-min pending cookie)
        B->>A: POST TOTP / backup code
        A->>S: verify code (replay-protected, persisted)
    else passkey sign-in
        B->>A: WebAuthn assertion
    end
    A->>A: risk score (subnet / UA / hour)<br/>over 50 demands TOTP anyway
    A-->>B: PASETO session cookie + 302 to original URL
    B->>T: GET admin.example.com (cookie)
    T->>A: /_auth/verify → 200
    T->>B: protected content
```

## Features

**Identity & second factors**
- Multi-user store (`users.json`, atomic writes): Argon2id password hashes
  with transparent bcrypt upgrade, per-user roles (`admin`/`user`)
- TOTP with session-gated enrollment, QR setup and replay protection
  (persisted across restarts); one-time backup codes
- WebAuthn/passkeys: register, delete and passwordless sign-in;
  `PASSWORDLESS=true` disables the password path entirely
- Password policy: 15+ characters (72-byte cap), NCSC top-100k breach-list
  rejection on every change
- Optional per-user **Email** field for self-service recovery (see below)
- Per-user allowed-hosts lists — a session only authorizes the
  `X-Forwarded-Host`s the user may access
- Optional `SSO_URL` "Continue with SSO" button delegating to an external
  IdP

**Sessions & devices**
- PASETO v4.local cookies (`HttpOnly`, `Secure`, `SameSite=Lax`), key
  rotation via `PASETO_KEY_PREVIOUS` with transparent re-issue
- Server-side session registry: live session list, per-session revocation,
  durable revocations across restarts
- Idle-timeout enforcement (`IDLE_TIMEOUT_MINUTES`); absolute TTL
  (`SESSION_TTL_HOURS`)
- Trusted devices (`TRUST_DEVICE_DAYS`) skip the TOTP challenge —
  overridden by risk-based authentication
- **Risk-based authentication**: unseen /24 (IPv4) or /64 (IPv6) subnet,
  user-agent or hour-of-day scores the login; above threshold the second
  factor is demanded even on trusted devices
- "My sessions" / trusted-device self-service pages

**Admin**
- Admin app shell (`/auth/app`) backed by a CSRF-protected JSON API:
  create users (temporary password + forced change), disable/enable,
  delete, reset password/TOTP/passkeys, set role, hosts and email,
  lockout unlock, session revocation
- Emergency **"Revoke all sessions"** action (System tab): force every
  user, on every device, to re-authenticate immediately — for incident
  response, distinct from a single user's "log out everywhere" and from
  a `PASETO_KEY` rotation (an infrastructure change with its own deploy
  cycle)
- Live audit log (ring buffer + optional JSONL file), active-session and
  lockout views, system info pane
- Webhook alerts (`raw`, `slack`, `ntfy`, `gotify`) with severity mapping
- Bearer-token-gated Prometheus metrics

**Abuse resistance**
- Per-IP **and** per-username throttling with exponential backoff
  (15 min → 30 min → 1 h … capped 24 h), persisted across restarts
- Signed one-time form tokens with minimum dwell time, `website` honeypot
- Constant-time credential comparisons; dummy-hash verification for
  unknown users; identical "Invalid credentials" for every failure mode
- Recovery endpoint answers identically whether or not an account exists
  or is reachable by mail (no enumeration)
- Security headers + nonce-based CSP on every page; body-size limits;
  real client IP only honored from `TRUSTED_PROXIES`

**Email recovery** (`/_auth/recover`, enabled by `SMTP_URL`)
- 15-minute, single-use HMAC reset tokens bound to a fingerprint of the
  current password hash — validation and consumption are atomic under the
  store lock, so exactly one concurrent reset succeeds
- Mail goes to the user's validated **Email** field; accounts created
  before that field existed keep working if their username is an email
  address
- Bounded per-IP rate limiter (3/hour) with TTL pruning
- Transport is always encrypted: STARTTLS for `smtp://`, TLS 1.2+ for
  `smtps://`; plaintext only via the explicit `SMTP_ALLOW_INSECURE=true`
  development opt-in
- A successful reset bumps both generations — every session and trusted
  device dies

**Magic-link sign-in** (`/_auth/magic`, enabled by `MAGIC_LINK=true` + `SMTP_URL`)
- 15-minute, single-use HMAC sign-in tokens. The fingerprint covers a
  per-user counter (single use), the session generation, and the password
  hash — so a password change, an admin disable or "log out everywhere", or
  a passkey/TOTP reset invalidates every outstanding link without those code
  paths needing to know magic links exist
- Validation and consumption are atomic under the store lock: exactly one
  concurrent redemption succeeds
- Replaces the **password factor only** — users with TOTP enrolled still
  complete the second factor, and `REQUIRE_TOTP=true` still forces
  enrollment before the session is usable
- Same anti-enumeration contract as recovery: the response is byte-identical
  whether the account exists, is disabled, or has no recovery address
- Bounded per-IP rate limiter (3/hour), shared design with recovery

## Deployment architecture

```mermaid
flowchart TD
    subgraph VPS
        T[Traefik<br/>:80/:443] -->|proxy network| A[auth-portal<br/>:4181]
        T -->|forwardAuth| A
        A --> V1[/data volume<br/>users.json<br/>throttle.json<br/>revoked-sessions.json/]
        A -. optional .-> R[(Redis)]
        A -. recovery mail .-> M[SMTP relay]
        A -. alerts .-> W[Webhook<br/>Slack/ntfy/Gotify]
    end
    T --> S1[service A]
    T --> S2[service B]
    T --> S3[...]
```

## Prerequisites

This is the auth layer only — it needs a reverse proxy and network to sit
behind. [Xore/cgnat](https://github.com/Xore/cgnat) provides a compatible
Traefik + WireGuard tunnel setup. Any other Traefik setup with a shared
Docker network works too.

## Layout

```
.
├── docker-compose.yml        # standalone stack: auth-portal + credential-reset tool
├── .env.example
├── docs/                     # guides (admin UI, credential recovery, hardening, …)
└── forward-auth/             # Go source, compiled via its own Dockerfile
```

## Deploy

```bash
cp .env.example .env
openssl rand -hex 32   # -> COOKIE_SECRET and PASETO_KEY in .env
# set AUTH_PASSWORD (bootstrap admin); optionally SMTP_URL for recovery

docker compose up -d --build auth-portal
```

Then wire it into your reverse proxy (Traefik shown; adapt for others):

- **router** `auth-portal` → ``Host(`<AUTH_HOST>`)`` → service
  `auth-portal` (**no** `forward-auth` middleware on this router — that
  would loop the login page)
- **service** `auth-portal` → `http://auth-portal:4181`
- **middleware** `forward-auth` →
  `forwardAuth: http://auth-portal:4181/_auth/verify`
- **middleware** `rate-limit-auth` → tight per-IP limit on the login
  router itself

Then protect any other router by adding `forward-auth` to its middleware
list:

```yaml
    my-admin-panel:
      rule: "Host(`admin.example.com`)"
      service: my-admin-panel
      tls: { options: modern }
      middlewares: [security-headers, forward-auth]   # ← login required
```

Add a proxied DNS record for `AUTH_HOST` (and each protected subdomain).

The initial admin is bootstrapped from `AUTH_USERNAME`/`AUTH_PASSWORD`
only while the user store is empty; afterwards manage users in the admin
UI at `https://<AUTH_HOST>/auth/app`.

Administrators can edit login-page branding and stage supported application
settings from **Administration → Configuration**. Branding applies
immediately. Runtime, infrastructure and signing-key changes are persisted in
`admin-settings.json` beside `users.json` and apply after a restart. Sensitive
values are never returned to the browser; Docker `_FILE` secrets remain
externally managed and read-only. Cookie and PASETO rotation actions generate a
new key and retain the active key as the previous key for the transition.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `VERSION` | `dev` | Compile-time identifier shown in Administration → System; set `production` on production deployments |
| `AUTH_HOST` | *(required)* | Hostname the login page lives at |
| `COOKIE_DOMAIN` | *(empty)* | Cookie scope — SSO across every subdomain |
| `COOKIE_NAME` | `xore_sso` | Session cookie name |
| `COOKIE_SECRET` | *(required)* | HMAC key for form/recovery tokens, `openssl rand -hex 32` |
| `COOKIE_SECRET_PREVIOUS` | *(empty)* | Previous key during rotation |
| `PASETO_KEY` | *(required)* | PASETO v4.local session key — exactly 64 hex chars |
| `PASETO_KEY_PREVIOUS` | *(empty)* | Former PASETO key(s), comma-separated, during rotation |
| `AUTH_USERNAME` | *(required)* | Bootstrap-only initial admin username |
| `AUTH_PASSWORD` | *(required)* | Bootstrap-only initial admin password — ignored once `users.json` is non-empty |
| `TOTP_SECRET` | *(empty)* | Optional bootstrap TOTP secret for the initial admin |
| `TOTP_ISSUER` | `AUTH_HOST` | Issuer name shown in authenticator apps |
| `REQUIRE_TOTP` | `true` | Force accounts without TOTP through enrollment |
| `PASSWORDLESS` | `false` | Passkey-only mode: password login and email recovery are disabled |
| `MAGIC_LINK` | `false` | Email magic-link sign-in at `/_auth/magic`; requires `SMTP_URL` (startup fails without it) |
| `TRUST_DEVICE_DAYS` | `0` | Days a device skips re-challenging TOTP (0 = always challenge) |
| `TRUSTED_PROXIES` | loopback + RFC1918 | Comma-separated proxy CIDRs trusted to set client-IP headers |
| `SESSION_TTL_HOURS` | `12` | Absolute session lifetime |
| `IDLE_TIMEOUT_MINUTES` | `60` | Revoke sessions with no activity for this long; 0 disables |
| `MAX_ATTEMPTS` | `5` | Failed logins before lockout |
| `LOCKOUT_MINUTES` | `15` | Base lockout duration (doubles each further burst, capped at 24h) |
| `MIN_DWELL_SECONDS` | `2` | Reject logins submitted faster than a human |
| `FORM_TTL_MINUTES` | `15` | Login form token lifetime |
| `COOKIE_SECURE` | `true` | Require HTTPS for the session cookie |
| `MAX_BODY_KB` | `64` | Max request body size |
| `LISTEN_ADDR` | `:4181` | Listen address |
| `USERS_FILE` | `/data/users.json` | User store location |
| `AUDIT_LOG` | *(empty)* | Optional JSONL audit log file; entries are HMAC-chained for tamper evidence |
| `AUDIT_RING` | `500` | In-memory audit ring size for the admin UI |
| `WEBHOOK_URL` | *(empty)* | Optional alert webhook — must be `https://` |
| `WEBHOOK_PROVIDER` | `raw` | Webhook payload format: `raw`, `slack`, `ntfy` or `gotify` |
| `METRICS_TOKEN` | *(empty)* | Bearer token gating `/_auth/metrics`; blank disables |
| `AUTH_INTROSPECTION_TOKEN` | *(empty)* | Service bearer token gating `POST /_auth/introspect`; at least 32 bytes, blank disables |
| `SSO_URL` | *(empty)* | External IdP URL — adds a "Continue with SSO" button |
| `SMTP_URL` | *(empty)* | `smtps://user:pass@host:465` or `smtp://[user:pass@]host:587` — enables email recovery |
| `SMTP_FROM` | `forward-auth@<AUTH_HOST>` | Sender address for recovery mail |
| `SMTP_ALLOW_INSECURE` | `false` | **Dev only**: permit `smtp://` without STARTTLS |
| `REDIS_PASSWORD` | *(required by Compose)* | Password for the bundled private Redis service; generate 64 safe hex characters with `openssl rand -hex 32` |
| `REDIS_URL` | bundled Redis | `redis://[:password@]host:6379/0` — override to use an external Redis throttle + session backend. Use `rediss://` (TLS) unless the connection stays on a network you already trust the way the bundled compose stack's private Docker network is; plain `redis://` to a remote host sends the password, session data and client IPs in cleartext |
| `ORG_ID` | *(empty)* | Organization label on the admin System pane |
| `AUTH_RESET_CONFIRM` | *(empty)* | Confirmation flag for the `auth-credentials-reset` maintenance profile |

All variables also support a `_FILE` suffix for Docker secrets
(e.g. `COOKIE_SECRET_FILE=/run/secrets/cookie_secret`).

## Backends: memory vs Redis

Outside the bundled Compose stack, without `REDIS_URL`, throttle and session state live in memory and persist
to JSON files (`throttle.json`, `revoked-sessions.json`) next to
`USERS_FILE`. With `REDIS_URL` set, both move to Redis (atomic Lua
transitions, startup connectivity check) so multiple replicas share
lockouts, sessions and revocations.

On Linux production hosts, enable Redis background persistence safely once:

```bash
printf 'vm.overcommit_memory = 1\n' >/etc/sysctl.d/99-redis-overcommit.conf
sysctl --system
```

**Fail-closed policy:** when a security backend cannot be reached, the
portal does not degrade to "allow". Login/TOTP/passkey endpoints answer a
controlled **503**, and sessions whose revocation or idle state cannot be
verified are rejected. Admin conveniences (session lists, metrics) simply
show nothing.

## Endpoints

| Path | Purpose |
|---|---|
| `/_auth/verify` | forwardAuth check (Traefik only) — 200 or 302 |
| `POST /_auth/introspect` | Live session/identity lookup for protected backends; requires `AUTH_INTROSPECTION_TOKEN` |
| `/_auth/login` | login page + POST handler |
| `/_auth/totp` | second-factor step (TOTP / backup code) |
| `/_auth/logout` | revoke + clear the session |
| `/_auth/health` | unauthenticated health probe (checks store writability) |
| `/_auth/enroll` | session-gated TOTP enrollment and backup codes |
| `/_auth/password` | self-service password change |
| `/_auth/passkeys` | register and remove WebAuthn/passkeys |
| `/_auth/recover` | email-based self-service password reset (needs `SMTP_URL`) |
| `/_auth/magic` | email magic-link sign-in (needs `MAGIC_LINK=true` + `SMTP_URL`) |
| `/_auth/resend` | request another magic link (same handler as `POST /_auth/magic`) |
| `/_auth/sessions/mine` | the user's own active sessions |
| `/_auth/sessions/trusted` | the user's trusted devices |
| `/auth/app` | settings + admin app shell |
| `/_auth/admin/api/*` | admin JSON API (session + CSRF gated) |
| `/_auth/metrics` | Prometheus metrics; requires `METRICS_TOKEN` |

## Credential recovery

Locked out, need to reset a user, or want a full wipe? See
[docs/CREDENTIAL-RECOVERY.md](docs/CREDENTIAL-RECOVERY.md).

Self-service email recovery (`/_auth/recover`) is enabled by `SMTP_URL`
and covered above. The recovery address model: each user has an optional,
separately validated **Email** field (set from the admin panel); usernames
stay opaque identifiers. Accounts created before the field existed keep
working if their username is itself an email address.

## Hardening

| Threat | Defence |
|---|---|
| Password guessing | per-IP **and** per-user lockout after `MAX_ATTEMPTS`, exponential backoff capped at 24h, durable across restarts |
| Credential spraying | pair with a Traefik rate-limit middleware on the login router (8 req / 10s per IP is a reasonable start) |
| Timing attacks / enumeration | constant-time compares, dummy-hash burn for unknown users, one generic failure message, identical recovery responses |
| CSRF | signed form token on every public POST; per-session CSRF token on the admin API |
| Bots | form-token dwell time, `website` honeypot |
| Stolen/forged cookie | PASETO v4.local authenticated encryption + expiry; generation counters kill all sessions on password/admin reset |
| Session theft | `HttpOnly` + `Secure` + `SameSite=Lax`, short TTL, idle timeout, per-session revocation |
| Open redirect | post-login redirect must be `https://…<COOKIE_DOMAIN>` |
| Weak single factor | TOTP + backup codes, passkeys, `REQUIRE_TOTP`, risk-based step-up |
| Token replay (TOTP) | each 30 s step accepted once; last-step persisted |
| Recovery token reuse | password-hash fingerprint re-checked under the store lock — atomic single use |
| Backend outage | fail closed: 503 on auth endpoints, unverifiable sessions rejected, startup connectivity checks |
| SMTP downgrade | STARTTLS required for `smtp://`, TLS 1.2+ for `smtps://`, explicit dev-only plaintext opt-in |
| Forensics | HMAC-chained (tamper-evident) JSON audit log + ring buffer, admin audit view, webhook alerts, token-gated Prometheus metrics |

Real client IP is read from `CF-Connecting-IP` (Cloudflare) →
`X-Forwarded-For` (only trusted if the peer is in `TRUSTED_PROXIES`).

## Development

```bash
cd forward-auth
go test ./... -race -shuffle=on -count=1          # unit tests (miniredis)
REDIS_TEST_URL=redis://127.0.0.1:6379/15 \
  go test ./... -race -count=1 -run '^TestRedisIntegration'   # real Redis
go vet ./... && golangci-lint run ./... && govulncheck ./...
```

CI runs gofmt/`go mod tidy` verification, vet, race-enabled tests with a
coverage floor, a real-Redis integration job, golangci-lint, govulncheck,
CodeQL, secret scanning and workflow linting (actionlint + zizmor).

## Documentation

- [docs/README.md](docs/README.md) — documentation index
- [docs/CREDENTIAL-RECOVERY.md](docs/CREDENTIAL-RECOVERY.md) — break-glass recovery runbook
- [docs/THEME-GUIDE.md](docs/THEME-GUIDE.md) — shared-theme integration
- [docs/BACKLOG.md](docs/BACKLOG.md) — deliberately deferred work

## Related

- [Xore/theme](https://github.com/Xore/theme) — reusable design tokens,
  components, examples, and adoption guidance
- [Xore/cgnat](https://github.com/Xore/cgnat) — WireGuard/CGNAT tunnel and Traefik reverse-proxy setup this typically runs behind
- [Xore/www](https://github.com/Xore/www) — personal homepage (does not use this)
