# Shipping the audit log to a SIEM

`AUDIT_LOG` (unset by default) points auth-backend at a JSONL file — one
line per auth event, written as it happens. #69 asked whether this project
needs new plumbing (a second webhook target, a dedicated event-stream
endpoint) to feed a SIEM, or whether the file that already exists is enough.
It's enough: every auth event this service ever records — not just the
subset that also triggers a webhook alert — goes through this one file, in a
stable, already-documented schema. What follows is how to point a log
shipper at it, not a new feature.

## Enable it

```bash
AUDIT_LOG=/state/audit.jsonl
```

Mount `/state` on a persistent volume (the bundled `docker-compose.yml`
already does this for `USERS_FILE` and friends). The file grows forever —
rotate it externally (`logrotate`, or your shipper's own rotation) the same
way you would any other append-only service log; auth-backend itself never
truncates or deletes it.

## Record shape

One JSON object per line:

```json
{"time":"2026-08-08T12:34:56.789Z","event":"login_fail:bad_credentials","ip":"203.0.113.7","user":"alice","ua":"Mozilla/5.0 ...","host":"admin.example.com","seq":142,"prev":"a1b2c3...","mac":"d4e5f6..."}
```

| Field | Always present | Meaning |
|---|---|---|
| `time` | yes | RFC3339Nano, UTC |
| `event` | yes | see below |
| `ip` | yes | client IP (post `TRUSTED_PROXIES` resolution) |
| `user` | no | omitted when the event has no associated username (e.g. `locked_out` on an IP-only lockout) |
| `ua` | no | `User-Agent` header, when the event came from a browser request |
| `host` | no | the `X-Forwarded-Host`/`Host` the request was for |
| `seq`, `prev`, `mac` | only when `COOKIE_SECRET` signs the chain (always, in practice — `COOKIE_SECRET` is required) | tamper-evidence chain; see below |

## Tamper evidence, and what it means for ingestion

Every line is HMAC-chained: `mac` covers `seq`, `prev` (the previous line's
own `mac`), and every other field, keyed by `COOKIE_SECRET`. Deleting or
editing any line — including one your SIEM already ingested and auth-backend
has since rotated past — breaks the chain from that point forward, and
auth-backend's own `resumeChain` logic (checked on every restart) reports
this loudly rather than silently starting a new chain. This means:

- Your SIEM can independently verify integrity if you give it read access to
  `COOKIE_SECRET` (and `COOKIE_SECRET_PREVIOUS`, across a rotation) — the
  same `auditMAC` computation this service uses is a straightforward
  HMAC-SHA256 over netstring-encoded fields, portable to any language.
- If you don't want to share that secret with the SIEM, ingest the file
  as-is: the *content* is still fully structured and useful for detection
  rules, you just lose independent tamper verification on the SIEM side —
  auth-backend itself still verifies the chain on every restart regardless.

## Example: Filebeat

```yaml
filebeat.inputs:
  - type: filestream
    id: auth-backend-audit
    paths:
      - /state/audit.jsonl
    parsers:
      - ndjson:
          target: ""
          add_error_key: true
```

Any JSON-codec log shipper works the same way (Vector, Logstash, Fluent Bit)
— there's nothing auth-backend-specific here beyond "it's one JSON object
per line."

## Event types

Every event `s.audit()` ever writes, grouped by area. `admin_<action>` events
carry the target (username, IP, or session ID) after a colon, e.g.
`admin_disable:alice`; `admin_revoke_all` (#66) is the one admin action with
no single target, since it applies to every user at once.

**Login**
`login_ok`, `login_fail:bad_credentials`, `login_fail:disabled_user`,
`login_fail:bad_request`, `login_fail:honeypot`, `login_fail:bad_form_token`,
`locked_out`, `rba_totp_required` (risk-based step-up demanded a fresh
challenge despite a trusted device), `host_totp_required` (#67 — same, but
because the target host is in the user's `RequireTOTPHosts` policy)

**TOTP / backup codes**
`enroll_ok`, `backup_code_used`, `backup_codes_regenerated`

**Passkeys**
`passkey_login_ok`, `passkey_login_fail:*`, `passkey_login_clone_warning`
(a credential's signature counter went backwards — possible cloned
authenticator), `passkey_registered`, `passkey_register_fail`,
`passkey_deleted`

**Password / recovery / magic link**
`pw_change_ok`, `pw_change_fail`, `recover_ok`, `recover_ratelimit`,
`magic_ok`, `magic_ratelimit`

**Session / access**
`logout`, `idle_timeout`, `forbidden_host` (a valid session tried a host
outside its `AllowedHosts`), `introspection_forbidden_host`

**Admin API** (all prefixed `admin_`)
`create_user`, `disable`, `enable`, `delete`, `reset_password`,
`reset_totp`, `logout_user`, `revoke_all` (#66), `set_role`, `set_hosts`,
`set_require_totp_hosts` (#67), `set_email`, `set_display_name`,
`set_description`, `rename_user`, `set_permissions`, `reset_passkeys`,
`unlock`, `revoke_session`, `settings_updated`

**Derived alerts** (also fired as webhooks, per `WEBHOOK_URL` — written here
too, not webhook-only, so a SIEM that only ingests this file still sees them)
`credential_stuffing_suspected` (#68) — this is the one event class this
audit trail carries that isn't itself a single request's outcome; it's a
sliding-window aggregate the whole file's own `ip`/`user`/`host` fields
don't fully capture (see the `detail` text embedded in the corresponding
webhook payload — not currently duplicated into the audit line itself,
since `authEvent` has no free-text field for it — only the fact that the
alert fired, when, and from which IP triggered it, is in the audit log; the
failure-count/distinct-user detail lives in the webhook payload only)

This list is accurate as of the events `s.audit()` calls existing in this
codebase at the time of writing; the authoritative source is
`grep -rn 's\.audit("' forward-auth/*.go` — worth re-running rather than
trusting this list blindly if you're building detection rules against a
future version of this project.
