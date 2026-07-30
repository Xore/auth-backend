# Deferred work

This file contains only work that was explicitly deferred rather than
implemented or rejected.

## Upstream OIDC identity provider

Status: deferred by owner on 2026-07-28.

The existing `SSO_URL` support is a redirect entry point, not a complete OIDC
relying-party implementation. A future implementation would need discovery,
authorization-code flow with PKCE, state and nonce validation, account mapping,
and lifecycle tests.

## Deliberately closed items

These are not backlog tasks:

- mTLS client-certificate session binding was skipped by owner decision.
- Online HIBP password lookup was rejected in favor of the embedded offline
  common-password list.
- `SameSite=Lax` was retained as an accepted risk because state-changing routes
  require POST plus a form token or CSRF header.
- Email magic-link sign-in (`/_auth/magic`, `/_auth/resend`) was deferred on
  2026-07-28 and implemented on 2026-07-30 behind `MAGIC_LINK`. It preserves the
  anti-enumeration response, single-use tokens, 15-minute expiry, and the 3/hour
  per-IP limiter that the deferral required. See "Magic-link sign-in" in the
  README and `docs/CREDENTIAL-RECOVERY.md` for the invalidation contract.
