# Deferred work

This file contains only work that was explicitly deferred rather than
implemented or rejected.

## Upstream OIDC identity provider

Status: deferred by owner on 2026-07-28.

The existing `SSO_URL` support is a redirect entry point, not a complete OIDC
relying-party implementation. A future implementation would need discovery,
authorization-code flow with PKCE, state and nonce validation, account mapping,
and lifecycle tests.

## Email magic-link or one-time-code sign-in

Status: deferred by owner on 2026-07-28.

Credential-recovery email exists, but email-based passwordless sign-in and its
resend endpoint do not. Any future implementation must preserve
anti-enumeration responses, single-use tokens, short expirations, and strict
rate limits.

## Deliberately closed items

These are not backlog tasks:

- mTLS client-certificate session binding was skipped by owner decision.
- Online HIBP password lookup was rejected in favor of the embedded offline
  common-password list.
- `SameSite=Lax` was retained as an accepted risk because state-changing routes
  require POST plus a form token or CSRF header.
