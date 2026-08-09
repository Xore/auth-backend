# Login theme page/state matrix (#100)

Every page/state this theme is responsible for, cross-checked against the
**real** APIARY realm export (`apiary-realm.json`, read live from the
`hp-keycloak` container's `/opt/keycloak/data/import/apiary-realm.json` on
2026-08-09 — not assumed/guessed), not just Keycloak's generic template
list. Re-derive the realm-facts columns from a fresh export whenever realm
config changes; re-derive the template list from
`themes/apiary/keycloak.lock`'s pinned `git_tag` whenever that changes.

Legend: **Covered** = styled and verified against inherited markup.
**Partial** = shell-level coverage only (renders correctly via the general
`.pf-v5-c-login*` rules from #104/#98, not individually audited).
**Gap** = known missing/unverified. **N/A** = not enabled in the real realm
right now — explicitly out of scope per this matrix, not silently
untested.

## Realm facts this matrix is built from

| Setting | Value |
|---|---|
| `registrationAllowed` | `false` |
| `resetPasswordAllowed` | `true` |
| `rememberMe` | `false` |
| `verifyEmail` | `true` |
| `loginWithEmailAllowed` | `true` |
| `bruteForceProtected` | `true` |
| `otpPolicyType` | `totp` |
| `identityProviders` | none configured |
| `browserFlow` / `resetCredentialsFlow` / `registrationFlow` | all unset — realm uses Keycloak's **built-in default flows**, no custom flow overrides exist |
| Default required actions | `CONFIGURE_TOTP` (default-on), `VERIFY_EMAIL` (default-on) |
| Available (opt-in) required actions | `UPDATE_PASSWORD`, `UPDATE_PROFILE`, `webauthn-register`, `webauthn-register-passwordless` |
| Recovery/backup codes | not enabled (no `recovery-codes` feature flag on the container; matches this repo's existing pre-merge-checklist note that the pinned runtime has no recovery-code required-action factory) |

Because there's no custom flow override, the actual login step-up a real
user hits is Keycloak's shipped default **browser** flow: username/password
→ conditional OTP subflow (mandatory here, since `CONFIGURE_TOTP` is a
default action and every account ends up with a TOTP credential). WebAuthn
is reachable only via self-service enrollment (opt-in required actions,
account console), not as an automatic alternative in the default challenge
step, since the realm never added a WebAuthn executor to a custom flow.

## Matrix

| Page / template | Reachable how | Status | Historical state mapped to |
|---|---|---|---|
| `login-username.ftl` / `login.ftl` | Always — first step of every browser-flow login | Covered | username step |
| `login-password.ftl` | Always — after username, since no custom identity-first-only flow removes it | Covered | "signing in as" credential step |
| `login-otp.ftl` | Always for any account that has completed `CONFIGURE_TOTP` (default action → effectively all accounts) | Partial | follow-on OTP presentation (historical `verify.html`) |
| `login-config-totp.ftl` | First login for every account (`CONFIGURE_TOTP` is default-on) — one of the most-hit pages in the whole realm | Covered — styled, and now exercised end-to-end by `test/specs/login.spec.ts` (#102) against a real disposable realm | follow-on OTP presentation |
| `login-reset-password.ftl` | "Forgot your password?" link — `resetPasswordAllowed=true` | Covered by shell rules | recovery link + compact server error |
| `login-update-password.ftl` | `UPDATE_PASSWORD` required action, opt-in / admin-triggered | Partial | password step (reused layout) |
| `webauthn-register.ftl` | `webauthn-register` required action, opt-in (self-service) | Gap — WebAuthn status/error tiles not styled | passkey alternative |
| `webauthn-authenticate.ftl` | Only for accounts that have already self-registered a WebAuthn credential | Gap | passkey alternative on credential step |
| `webauthn-error.ftl` | WebAuthn ceremony failure | Gap | compact server error |
| `select-authenticator.ftl` | Only for an account with more than one usable credential type registered (e.g. both TOTP and WebAuthn) | Gap | not in historical baseline — new state, needs explicit design |
| `login-recovery-authn-code-*.ftl` | **N/A** — recovery-codes feature not enabled on this realm/runtime | N/A | — |
| `register.ftl` / `register-commons.ftl` | **N/A** — `registrationAllowed=false` | N/A | — |
| `social-providers.ftl` | **N/A** — no identity providers configured | N/A | SSO-first branch + divider (dormant, CSS already present from the historical `{{if .SSOEnabled}}` mapping but currently unreachable) |
| `link-idp-action.ftl` | **N/A** — no identity providers configured | N/A | — |
| `terms.ftl` | **N/A** — Terms and Conditions required action not enabled | N/A | — |
| `login-oauth-grant.ftl` (consent) | Depends on per-client consent settings — not yet cross-checked against every client in the realm export | Needs verification | — |
| `login-oauth2-device-verify-user-code.ftl` | Depends on whether any client has device flow enabled — not yet cross-checked | Needs verification | — |
| `oid4vc-credential-offer.ftl` | No evidence any client uses OID4VC | Needs verification, likely N/A | — |
| Base-inherited `login-verify-email.ftl` (not in keycloak.v2's own override list, falls through to `base`) | `VERIFY_EMAIL` required action, default-on — hit on every new account | Gap — not fetched/audited this pass, inherits `base` markup only | — |
| Base-inherited `error.ftl` | Any unhandled auth error | Partial — shell renders, not individually audited | compact server error |
| Base-inherited `info.ftl` | E.g. "email sent" confirmations after reset-password | Partial | compact server error / confirmation state |
| Base-inherited `logout-confirm.ftl` | Standard logout | Partial | — |
| `delete-account-confirm.ftl` / `delete-credential.ftl` | Account console self-service, not the login flow proper | Not in scope for this pass | — |
| `user-profile-commons.ftl` (update profile) | `UPDATE_PROFILE` required action, opt-in | Gap | — |

## What's actually done vs. still open

**Done this pass**: the matrix itself (this file), confirmed against the
real realm export rather than assumed; the shell/branding work from #104
and #98 covers every row via the general `.pf-v5-c-login*`/`#kc-*` rules
(nothing renders as an unstyled raw PatternFly island, since those are
upstream `keycloak.v2` classes this theme's CSS already targets globally).

**Still open** (tracked here so they're not silently untested, per this
issue's own acceptance criterion):

- Individual audit + narrow CSS for `login-config-totp.ftl` (QR/secret
  display) and the WebAuthn pages — these are real, frequently-hit pages
  (TOTP setup is mandatory for every account) that have not been
  individually exercised against a live realm, only covered by the
  general shell rules.
- `select-authenticator.ftl` has no historical-baseline equivalent at all
  and needs an explicit design decision, not just shell inheritance.
- Consent/device-code/OID4VC applicability depends on per-client settings
  not yet cross-checked client-by-client.
- Accessibility acceptance criteria (200% zoom, RTL, live-region
  announcements, reduced motion beyond the existing `prefers-reduced-
  motion` rule) not yet verified against a running instance.
- The interaction-layer requirements (focus transitions, loading/
  submitting states, no-JS behavior per state) are #103's scope, not
  reachable until that lands.

This matrix should be re-verified against a live realm export whenever
realm config changes, and whenever `themes/apiary/keycloak.lock`'s pinned
Keycloak version changes (its own upgrade-sequence docs cover re-deriving
the template list).
