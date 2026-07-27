# auth-backend — hardened Traefik forward-auth SSO

A single login at your `AUTH_HOST` (e.g. `auth.xore.rocks`) that protects any
number of services behind a Traefik reverse proxy. Attach the `forward-auth`
middleware to a router and unauthenticated requests get bounced to a styled
login page; one login sets an HMAC-signed cookie scoped to `COOKIE_DOMAIN`,
so it works across every subdomain (SSO).

```
request ─▶ Traefik ─(forwardAuth)▶ auth-portal /_auth/verify
                                      ├─ valid cookie → 200 → request proceeds
                                      └─ no cookie   → 302 → https://<AUTH_HOST>/_auth/login
login ─▶ sets <COOKIE_DOMAIN> cookie ─▶ back to the original URL
```

## Prerequisites

This is the auth layer only — it needs a reverse proxy and network to sit
behind. [Xore/cgnat](https://github.com/Xore/cgnat) provides a compatible
Traefik + WireGuard tunnel setup (see its `vps/docker-compose.yml`, which has
a commented-out `auth-portal` service block ready to uncomment once this is
deployed). Any other Traefik setup with a shared Docker network works too.

## Layout

```
.
├── docker-compose.yml        # standalone stack: auth-portal + credential-reset tool
├── .env.example
├── docs/CREDENTIAL-RECOVERY.md
└── forward-auth/              # Go source, compiled via its own Dockerfile
```

## Deploy

```bash
cp .env.example .env
openssl rand -hex 32   # -> COOKIE_SECRET in .env
# set AUTH_PASSWORD; optionally TOTP_SECRET

docker compose up -d --build auth-portal
```

Then wire it into your reverse proxy (Traefik shown; adapt for others):

- **router** `auth-portal` → `Host(`<AUTH_HOST>`)` → service `auth-portal`
  (**no** `forward-auth` middleware on this router — that would loop the login page)
- **service** `auth-portal` → `http://auth-portal:4181`
- **middleware** `forward-auth` → `forwardAuth: http://auth-portal:4181/_auth/verify`
- **middleware** `rate-limit-auth` → tight per-IP limit on the login router itself

Then protect any other router by adding `forward-auth` to its middleware list:

```yaml
    my-admin-panel:
      rule: "Host(`admin.example.com`)"
      service: my-admin-panel
      tls: { options: modern }
      middlewares: [security-headers, forward-auth]   # ← login required
```

Add a proxied DNS record for `AUTH_HOST` (and each protected subdomain).

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `AUTH_HOST` | *(required)* | Hostname the login page lives at |
| `COOKIE_DOMAIN` | `.xore.rocks` | Cookie scope — SSO across every subdomain |
| `COOKIE_NAME` | `xore_sso` | Session cookie name |
| `COOKIE_SECRET` | *(required)* | HMAC signing key, `openssl rand -hex 32`. Keep stable across restarts/replicas |
| `COOKIE_SECRET_PREVIOUS` | *(empty)* | Previous key during rotation — remove once old sessions expire |
| `AUTH_USERNAME` | *(required)* | Bootstrap-only initial admin username |
| `AUTH_PASSWORD` | *(required)* | Bootstrap-only initial admin password — ignored once `users.json` is non-empty |
| `TOTP_SECRET` | *(empty)* | Optional bootstrap TOTP secret for the initial admin |
| `TOTP_ISSUER` | `auth.xore.rocks` | Issuer name shown in authenticator apps |
| `REQUIRE_TOTP` | `true` | Force accounts without TOTP through enrollment |
| `TRUST_DEVICE_DAYS` | `0` | Days a device skips re-challenging TOTP (0 = always challenge) |
| `TRUSTED_PROXIES` | *(empty)* | Comma-separated proxy CIDRs trusted to set client-IP headers |
| `SESSION_TTL_HOURS` | `12` | Session lifetime |
| `MAX_ATTEMPTS` | `5` | Failed logins before lockout |
| `LOCKOUT_MINUTES` | `15` | Base lockout duration (doubles each further burst, capped at 24h) |
| `MIN_DWELL_SECONDS` | `2` | Reject logins submitted faster than a human |
| `FORM_TTL_MINUTES` | `15` | Login form token lifetime |
| `COOKIE_SECURE` | `true` | Require HTTPS for the session cookie |
| `MAX_BODY_KB` | `64` | Max request body size |
| `WEBHOOK_URL` | *(empty)* | Optional alert webhook |
| `WEBHOOK_PROVIDER` | `raw` | Webhook payload format: `raw`, `slack`, `ntfy` or `gotify` |
| `METRICS_TOKEN` | *(empty)* | Bearer token gating `/_auth/metrics`; leave blank to disable |
| `AUTH_RESET_CONFIRM` | *(empty)* | Confirmation flag for the `auth-credentials-reset` maintenance profile |

## Hardening

| Threat | Defence |
|---|---|
| Password guessing | per-IP lockout after `MAX_ATTEMPTS`, exponential backoff (15m → 30m → 1h …, capped 24h) |
| Credential spraying | pair with a Traefik rate-limit middleware on the login router (8 req / 10s per IP is a reasonable start) |
| Timing attacks | constant-time username + password compare |
| CSRF | signed form token required on every POST |
| Bots (instant submit) | form token carries a timestamp — submits faster than `MIN_DWELL_SECONDS` are rejected |
| Bots (form fillers) | hidden `website` honeypot field — any value = rejected |
| Stolen/forged cookie | HMAC-SHA256 signature + expiry, verified constant-time |
| Session theft | `HttpOnly` + `Secure` + `SameSite=Lax`, short TTL |
| Open redirect | post-login redirect must be `https://…<COOKIE_DOMAIN>` |
| User enumeration | one generic "Invalid credentials" for every failure mode |
| Weak single factor | per-user TOTP, backup codes, and WebAuthn/passkeys; `REQUIRE_TOTP=true` enforces enrollment |
| Session compromise | server-side session registry, per-session revocation, password-change revocation, optional trusted-device lifetime |
| Forensics | JSON audit log, admin audit view, optional webhook, token-gated Prometheus metrics |

Real client IP is read from `CF-Connecting-IP` (Cloudflare) → `X-Forwarded-For`
(only trusted if the peer is in `TRUSTED_PROXIES`).

## Enroll 2FA and passkeys

`TOTP_SECRET` only bootstraps the first admin on an empty user store. Normally,
log in and use `/_auth/enroll` to scan a newly generated per-user TOTP secret,
or `/_auth/passkeys` to register a passkey.

## Endpoints

| Path | Purpose |
|---|---|
| `/_auth/verify` | forwardAuth check (Traefik only) — 200 or 302 |
| `/_auth/login` | login page + POST handler |
| `/_auth/logout` | clear the session |
| `/_auth/health` | unauthenticated health probe |
| `/_auth/enroll` | session-gated TOTP enrollment and backup codes |
| `/_auth/password` | self-service password change |
| `/_auth/passkeys` | register and remove WebAuthn/passkeys |
| `/_auth/admin` | admin-only users, sessions, and audit interface |
| `/_auth/metrics` | Prometheus metrics; requires `METRICS_TOKEN` |

## Credential recovery

Locked out, need to reset a user, or want a full wipe? See
[docs/CREDENTIAL-RECOVERY.md](docs/CREDENTIAL-RECOVERY.md).

> **Fail-closed:** if auth-portal is down, `forward-auth` returns 5xx and
> protected services stay locked — never open. Keep the stack running.

## Related

- [Xore/cgnat](https://github.com/Xore/cgnat) — WireGuard/CGNAT tunnel and Traefik reverse-proxy setup this typically runs behind
- [Xore/www](https://github.com/Xore/www) — personal homepage (does not use this)
