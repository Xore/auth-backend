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
| `webauthn-register.ftl` | `webauthn-register` and `webauthn-register-passwordless` required actions, both opt-in (self-service) — **Keycloak 26.7.1 has no separate `webauthn-register-passwordless.ftl`; both required actions render this one template** (confirmed against the pinned release's theme source tree, not guessed — the older two-template assumption in this row no longer applies) | Covered — verified live via a real CDP virtual-authenticator registration ceremony (#106/#107); renders correctly via the general shell rules, no bespoke CSS needed | passkey alternative |
| `webauthn-authenticate.ftl` | Only for accounts that have already self-registered a WebAuthn credential | Covered — verified live via a real ceremony (successful and, separately, failed); shell rules plus the new select-auth-container styling (shared with `select-authenticator.ftl` below) cover it fully | passkey alternative on credential step |
| `webauthn-error.ftl` | WebAuthn ceremony failure | Covered — verified live by deliberately failing a real ceremony (no matching credential on the authenticator); renders correctly via shell rules (danger alert, themed secondary retry link) | compact server error |
| `select-authenticator.ftl` | Reachable via "Try another way" once an account has 2+ *applicable* ALTERNATIVE credentials in the browser flow's 2FA subflow. **The real APIARY realm has never enabled this** — Keycloak's built-in `browser` flow ships a WebAuthn Authenticator execution here but it imports `DISABLED`; only OTP Form is active, so this page is not reachable in production today (verified against a live realm-facts check, not assumed). Verified live in this repo's own disposable test realm by deliberately flipping that execution to `ALTERNATIVE` (test/global-setup.ts) — a test-only change, not a recommendation to change the production realm, which remains a separate decision for whoever owns realm config (Xore/APIARY) | Covered (styled) — was a genuine Gap: keycloak.v2 ships this as a plain white PatternFly data-list with no dark-theme awareness at all (barely-legible muted-on-white text). Now matches this theme's list/row idiom | not in historical baseline — new state, explicit design added (dark card list, matches `.dropdown__item`/`.card__row`), not just shell inheritance |
| `login-recovery-authn-code-*.ftl` | **N/A** — recovery-codes feature not enabled on this realm/runtime | N/A | — |
| `register.ftl` / `register-commons.ftl` | **N/A** — `registrationAllowed=false` | N/A | — |
| `social-providers.ftl` | **N/A** — no identity providers configured | N/A | SSO-first branch + divider (dormant, CSS already present from the historical `{{if .SSOEnabled}}` mapping but currently unreachable) |
| `link-idp-action.ftl` | **N/A** — no identity providers configured | N/A | — |
| `terms.ftl` | **N/A** — Terms and Conditions required action not enabled | N/A | — |
| `login-oauth-grant.ftl` (consent) | Cross-checked against every client in the real realm export: **none set `consentRequired: true`** — N/A in production today, confirmed not assumed. Styled anyway (a test-only `theme-test-consent-client` fixture exercises it) since any future client could enable it | Covered (styled) — was a real Gap: `#kc-page-title` wraps this template's own `<p>`, and the vendored `xore-theme.css`'s generic `p { color: var(--text-secondary) }` rule beat the inherited title color; separately the "No" secondary button rendered with keycloak.v2's stock blue PatternFly outline (a `pf-m-secondary` bug shared with every secondary button on the whole theme — see below) | — |
| `login-oauth2-device-verify-user-code.ftl` | Cross-checked: **no client has `oauth2.device.authorization.grant.enabled`** — N/A in production today, confirmed not assumed. Verified live anyway via a test-only device-flow client | Covered — renders correctly via the general shell rules already, no bespoke CSS needed | — |
| `oid4vc-credential-offer.ftl` | Cross-checked: every real client uses `protocol: openid-connect`, none use `oid4vc` — confirmed N/A, not just assumed | N/A, confirmed | — |
| Base-inherited `login-verify-email.ftl` (not in keycloak.v2's own override list, falls through to `base`) | `VERIFY_EMAIL` required action, default-on — hit on every new account | Covered — verified live end-to-end. The fixture realm previously had no reachable SMTP server, so `RequiredActionVerifyEmail` threw before this template ever rendered, falling back to the generic `error.ftl` "Failed to send email" page instead of its own "check your email" content — fixed by adding a mailhog sink to `test/docker-compose.test.yml` + realm `smtpServer` config. Renders correctly via shell rules once actually reachable | — |
| Base-inherited `error.ftl` | Any unhandled auth error | Partial — shell renders, not individually audited | compact server error |
| Base-inherited `info.ftl` | E.g. "email sent" confirmations after reset-password | Partial | compact server error / confirmation state |
| Base-inherited `logout-confirm.ftl` | Standard logout | Partial | — |
| `delete-account-confirm.ftl` / `delete-credential.ftl` | Account console self-service, not the login flow proper | Not in scope for this pass | — |
| `user-profile-commons.ftl` (update profile) | `UPDATE_PROFILE` required action, opt-in | Gap | — |

## What's actually done vs. still open

**Done this pass (#106)**: every row above is now individually
audited/verified against a live disposable Keycloak instance (not just
covered by shell inheritance and left unverified) --

- WebAuthn register/authenticate/error and `select-authenticator.ftl`:
  exercised via real CDP virtual-authenticator ceremonies (register,
  successful authenticate, and a deliberately-failed authenticate), not
  simulated. `select-authenticator.ftl` needed real CSS (was unstyled
  white-on-white); the WebAuthn pages needed none.
- `login-verify-email.ftl`: was silently broken in the test fixture (no
  reachable SMTP meant it never rendered its own content, only the
  generic error fallback) -- fixed and now verified rendering correctly.
- Consent and device-code: confirmed **not reachable by any real client in
  the production realm today** (cross-checked every client's
  `consentRequired`/device-flow attributes in the real realm export, not
  assumed) -- styled and verified anyway via test-only fixture clients,
  since either could be enabled by a future client. Consent had two real
  bugs (title color, unstyled secondary button); device-code needed no
  changes.
- `oid4vc-credential-offer.ftl`: confirmed N/A (every real client uses
  `openid-connect`, none use `oid4vc`) -- not just assumed.
- `pf-m-secondary` (kcButtonSecondaryClass) was unstyled realm-wide --
  found via the consent screen's "No" button, also affects WebAuthn's
  "Cancel" AIA button, "Try another way", and "Switch organization".
  Fixed in `login.css` for every page at once.

**Still open**, now #107's scope specifically (not re-litigated here):

- RTL, 200% zoom, forced-colors, and CSP-specific assertions -- not yet
  verified against a running instance.
- Reduced-motion is still only asserted structurally (the static CSS rule
  exists), not simulated/verified in the browser.
- Whether to enable `select-authenticator.ftl`'s trigger condition (a
  WebAuthn ALTERNATIVE execution) in the *production* realm remains a
  separate decision for whoever owns realm config (Xore/APIARY) -- this
  pass only proves the page renders correctly once reached, via a
  test-fixture-only flow change (`test/global-setup.ts`).

This matrix should be re-verified against a live realm export whenever
realm config changes, and whenever `themes/apiary/keycloak.lock`'s pinned
Keycloak version changes (its own upgrade-sequence docs cover re-deriving
the template list).
