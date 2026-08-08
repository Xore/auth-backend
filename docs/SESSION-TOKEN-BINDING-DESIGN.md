# Session token binding — design decision

> **Status**: Decided (direction), not implemented. This is #70's own
> "research/design, not a ready-to-build ticket" ask, answered — a real
> implementation is real follow-up work, scoped below, not attempted here.
> Deliberately not attempted as a rushed partial feature: the client-side
> half (key generation, persistence across page loads, proof signing) has
> enough real edge cases that shipping it half-thought-through would be
> worse than not shipping it at all.
> **Tracking**: [#70](https://github.com/Xore/auth-backend/issues/70)

## Why this exists

The PASETO v4.local session cookie (`token.go`) is a pure bearer credential:
`HttpOnly`/`Secure`/`SameSite=Lax` and a short TTL/idle-timeout meaningfully
reduce the exposure window, but nothing stops the token itself from being
replayed from anywhere if it's ever exfiltrated by some means other than the
dominant vector those flags already close (XSS reading `document.cookie` —
`HttpOnly` blocks exactly that). Keycloak's own answer to this class of
problem is DPoP (RFC 9449): bind a token to a client-held keypair so a
stolen token alone is unusable without also stealing the private key.

**Decision: pursue the stronger direction** — a DPoP-inspired
proof-of-possession mechanism, not the lighter IP-prefix/UA-hash binding
alternative that was also on the table. The lighter option was rejected
because it only raises the bar against an attacker on a different
network/browser; a proof-of-possession key raises it against replay from
*anywhere*, which is the property actually worth having given `HttpOnly`
already covers the common case.

This is **not** the already-rejected mTLS approach (`docs/BACKLOG.md`:
"mTLS client-certificate session binding was skipped by owner decision").
DPoP-style binding needs no client certificate infrastructure at all — just
a browser-generated WebCrypto keypair. Nothing here reopens that decision.

## What DPoP actually is, adapted to this project

Real DPoP (RFC 9449) is specified for `Authorization: Bearer` usage: a
client generates a keypair, includes a `DPoP` proof header (a signed JWT
covering the HTTP method, URL, and a timestamp/nonce) on every request, and
the server checks the proof's public key thumbprint against the one bound to
the token at issuance. This project doesn't have that shape — the session
credential is a cookie the browser attaches automatically, not a
header the client code constructs per-request — so the adaptation is:

1. **At login**, after credentials (and TOTP/passkey, if required) succeed
   but before the session cookie is issued, the browser generates (or reuses
   — see persistence below) a non-extractable ECDSA P-256 keypair via
   `crypto.subtle.generateKey`, computes a JWK thumbprint of the public key,
   and sends that thumbprint alongside the final login step.
2. **The server embeds the thumbprint** in the PASETO session claims as a
   new `cnf` (confirmation) field — same name RFC 7800 uses for this exact
   concept in JWT-land, no reason to invent a different one.
3. **On every state-changing request** (i.e. everywhere the existing
   per-session CSRF token is already required — `checkSessionCSRF` in
   `token.go` — this rides the same enforcement point, not a new one), the
   client additionally computes and sends a proof: a signature over
   `method + path + a short-lived timestamp`, using the private key from
   step 1.
4. **The server verifies** the proof's signature against the `cnf`
   thumbprint bound in the session claims. A session whose cookie was
   replayed on a different device (no access to the original private key)
   fails this check even though the cookie itself is valid PASETO.

## Key persistence across page loads

The hard part isn't the crypto — WebCrypto's non-extractable keys already
exist for exactly this ("generate a key JS can use but never read out in
plaintext"). It's that a non-extractable `CryptoKey` object doesn't survive
a page reload as a JS variable; it has to be persisted as a `CryptoKey`
*reference* in IndexedDB (which *can* store non-extractable keys — this is
explicitly supported, not a workaround), keyed per `(origin, session)` so a
new login gets a fresh key and an old one doesn't leak forward. Every
existing browser tab/device ends up with its *own* keypair and its own
`cnf` binding — which is correct: two devices sharing one login should each
get their own proof-of-possession key, not a shared secret that itself
becomes something to protect.

## Degrade path — what happens when the proof is missing or invalid

Three cases, each needing an explicit answer before implementation, not
left implicit:

- **Proof present and valid**: request proceeds normally.
- **Proof missing entirely**: during a rollout window, treat as
  backward-compatible (this session predates the feature, or the browser
  doesn't support the WebCrypto calls used) — degrade to today's
  bearer-only behavior, not a hard reject. This is a real availability
  tradeoff: strict enforcement from day one would break every session
  issued before an upgrade, and any client environment where IndexedDB is
  unavailable (some privacy-hardened browser configurations block it
  entirely). A future `SESSION_BINDING_REQUIRED=true` could tighten this
  once a deployment is confident every real client supports it — not
  attempted here, this is scoping the next decision, not making it.
- **Proof present but invalid** (wrong signature, thumbprint mismatch):
  always a hard reject, unlike the missing case — a *present-but-wrong*
  proof is exactly the replay-from-a-different-device signal this feature
  exists to catch, not an environment-compatibility question.

## What this does and doesn't close

Closes: a session cookie exfiltrated by some means other than
`HttpOnly`-blocked XSS-cookie-read (a misconfigured proxy that logs
headers including `Cookie`, a browser extension with broad permissions, a
backup/log file that captured request headers) is not usable from a
different device — the attacker would also need the private key, which
never leaves the original browser's key store.

Does not close: an attacker with code execution *inside the same browser
context* the legitimate session is in (the WebCrypto key is reachable to
any JS running on that origin, same as the cookie already is) — this was
never in scope; that's a full compromise of the client, not a token-theft
scenario.

## Explicitly out of scope for this design

- Non-browser API clients (the `AUTH_INTROSPECTION_TOKEN`-gated
  `/_auth/introspect` path is a separate, already-bearer-token-based trust
  boundary between the auth portal and protected backends — not the
  browser session this document is about, and not affected by any of this).
- Any change to `PASETO_KEY`/`PASETO_KEY_PREVIOUS` rotation — orthogonal.
- Mobile app / non-browser clients that can't run WebCrypto the way a
  browser does — would need their own binding mechanism if ever built,
  not designed here.

## Suggested first implementation step, when this is picked up

A minimal end-to-end slice, gated behind a new config flag defaulting off
(matching this codebase's own "opt-in hardening controls" convention
throughout — #62's `PERMANENT_LOCKOUT_AFTER_CYCLES`, #63's
`PASSWORD_HISTORY_COUNT`, #68's `STUFFING_ALERT_MIN_FAILURES`, all default
disabled):

1. `cnf` claim plumbing in `token.go`'s `sessionPayload` (empty/absent when
   the feature is off or the client didn't supply a thumbprint — same
   "backward compatible by construction" pattern `PASETO_KEY_PREVIOUS`
   already uses for a different kind of transition).
2. The IndexedDB key-persistence helper as its own reviewable client-side
   module, with its own tests independent of the login flow — this is the
   piece with the most real edge cases (multiple tabs racing to generate
   the first key for a fresh login, IndexedDB unavailable, a user clearing
   site data mid-session).
3. Proof generation/verification wired into the existing CSRF-token
   enforcement point, not a parallel mechanism — reuse `checkSessionCSRF`'s
   call sites rather than adding a second header check scattered across
   every mutating handler.
4. Land 1-3 behind the flag, default off, before writing the "missing proof
   during rollout" backward-compatibility path — that path only matters
   once real sessions exist that predate the feature, which can't happen
   before the feature itself ships.
