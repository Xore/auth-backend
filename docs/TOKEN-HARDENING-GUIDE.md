# Token & HMAC Hardening Guide

This document audits the current `forward-auth` token machinery in detail,
maps every weakness to concrete academic or standards references, and provides
a step-by-step implementation roadmap to a hardened token stack.

---

## Table of Contents

1. [Current token machinery — audit](#1-current-token-machinery--audit)
2. [Weakness catalogue](#2-weakness-catalogue)
3. [Hardening options — comparison](#3-hardening-options--comparison)
4. [Recommendation](#4-recommendation)
5. [Implementation path A — HKDF key separation (lowest friction)](#5-implementation-path-a--hkdf-key-separation-lowest-friction)
6. [Implementation path B — PASETO v4.local (highest assurance)](#6-implementation-path-b--paseto-v4local-highest-assurance)
7. [Key rotation guidance](#7-key-rotation-guidance)
8. [Checklist](#8-checklist)
9. [References](#9-references)

---

## 1. Current token machinery — audit

### What exists today

All tokens share **one HMAC-SHA-256 key** (`COOKIE_SECRET`) and a **pipe-delimited plaintext body**:

| Token type | Format | MAC covers |
|---|---|---|
| Session cookie | `v2\|exp\|user\|gen\|sid\|flags\|mac` | All 6 fields joined with `\|` |
| Device trust | `dev\|exp\|user\|gen\|mac` | Fields 0–3 |
| CSRF | `mac("csrf\|" + sid)` | Just `csrf\|sid` |
| Form timing | `issued\|nonce\|mac` | `issued\|nonce` |

`mac()` = `HMAC-SHA-256(secret, body)` → `base64url(raw)`

`validMAC()` checks the current secret first, then any `COOKIE_SECRET_PREVIOUS` values
using `subtle.ConstantTimeCompare`. Key rollover is supported.

### What is done well ✅

- `subtle.ConstantTimeCompare` — no timing oracle on MAC verification.
- Secret length enforced ≥ 32 bytes at startup.
- `COOKIE_SECRET_PREVIOUS` supports zero-downtime key rotation.
- Per-session `sid` + per-user `gen` — revocation is immediate without a deny-list lookup.
- Form token includes a random 8-byte nonce — prevents precomputed replay.
- Device cookie is host-only (no `Domain=`) — cannot be forwarded to subdomains.

---

## 2. Weakness catalogue

### 2.1 Single key for all token purposes (Key Separation Violation)

**Finding.** The same `COOKIE_SECRET` is fed into HMAC for session tokens, device cookies,
CSRF tokens, and form tokens. If any one context is broken or misused, it could weaken
the others.

**Standard.** NIST SP 800-108r1 (KDF Using Pseudorandom Functions, 2022) §4 and
Trail of Bits key derivation best practices (2025) both mandate **deriving separate keys
per purpose** from a single master secret via HKDF or similar.

**Impact.** An attacker who can observe many session MACs and has a partial key-recovery
path (e.g. length-extension against a naive hash — not HMAC — or a related-key attack)
gets no cross-domain oracle. Low probability, but zero cost to fix.

### 2.2 HMAC-SHA-256 provides integrity only — payload is in plaintext

**Finding.** Session cookies contain `username`, `gen`, `sid`, `flags` in cleartext.
Anyone who can read the cookie (shared device, logging middleware that logs cookies,
accidental `Set-Cookie` header in a log aggregator) can learn the username and session
generation of every active session.

**Standard.** PASETO v4.local (XChaCha20-Poly1305 + BLAKE2b) provides
**Authenticated Encryption with Associated Data (AEAD)** — the payload is both
confidential and integrity-protected with a single primitive. PASETO v4 specification
mandates XChaCha20-Poly1305 for local (symmetric) tokens and Ed25519 for public tokens.

### 2.3 Pipe-delimiter format: no canonical serialisation

**Finding.** The token body is `strings.Join(parts, "|")`. A value that contains `|`
in any field (e.g. a username with a pipe) would silently corrupt parsing. The parser
uses `strings.Split(tok, "|")` and checks `len(parts) != 7` — any field injection that
keeps the part count at 7 is a parsing confusion risk.

**Mitigation.** Usernames are validated to not contain `|` today, but this is an
implicit constraint with no enforcement at the store level.

**Standard.** Structured serialisation formats (JSON + AEAD, PASETO, Branca) eliminate
delimiter-injection entirely.

### 2.4 HMAC-SHA-256: no resistance to length-extension attacks when used naively

**Finding.** `HMAC(key, msg)` is not vulnerable to length-extension (unlike raw `SHA-256(key || msg)`).
The current implementation correctly uses the `crypto/hmac` package so **this is not a bug**.
However, SHA-256 under HMAC has a 128-bit security level against collision and a
256-bit PRF security level — adequate today but worth noting that BLAKE2b or SHA-3
offer the same security with no length-extension risk even in non-HMAC mode, giving
implementation flexibility.

### 2.5 Token version is unauthenticated in device and form tokens

**Finding.** Session tokens carry a `v2` prefix that is included in the MAC body.
Device tokens start with `dev` and form tokens have no version prefix — they are not
forward-versioned. If a new token format were introduced, old tokens of the other type
could not be distinguished without full parse attempts.

**Impact.** Low for current code. Becomes a design constraint when adding new token types.

### 2.6 No implicit assertion / binding to request context

**Finding.** The session cookie MAC does not bind to any request-level value
(e.g. `User-Agent`, `IP prefix`, `TLS session resumption ID`). A stolen cookie is
valid from any IP.

**Standard.** PASETO v4 supports **implicit assertions** — additional data that is
MAC'd but not included in the token body. This can be used to bind a token to a
channel property (e.g. hashed IP prefix) without storing it in the cookie.

**Trade-off.** Mobile clients and Cloudflare-proxied traffic may change IP mid-session.
Use a coarse binding (e.g. `/24` subnet) if enabling this.

---

## 3. Hardening options — comparison

| Property | Current (HMAC-SHA-256) | Path A: HKDF + HMAC-SHA-256 | Path B: PASETO v4.local |
|---|---|---|---|
| Key separation | ❌ Single key | ✅ Derived per purpose | ✅ Derived internally |
| Payload confidentiality | ❌ Plaintext | ❌ Plaintext | ✅ Encrypted (XChaCha20) |
| Auth algorithm | HMAC-SHA-256 | HMAC-SHA-256 | BLAKE2b (Poly1305-based) |
| Timing-safe verify | ✅ | ✅ | ✅ (library) |
| Format injection risk | Low (validated) | Low | None (binary AEAD) |
| Implicit assertions | ❌ | Manual | ✅ Native |
| Go library needed | stdlib only | stdlib only | `zntr.io/paseto/v4` or `github.com/o1ecc8b9/paseto` |
| Migration effort | — | Low (≈ 50 lines) | Medium (new dep, token version bump) |
| Cookie size change | — | None | +32 bytes (nonce + tag) |
| Breaking change | — | No (same token body structure) | Yes (must rotate all sessions) |

---

## 4. Recommendation

**Implement Path A immediately** (HKDF key separation) — it is a non-breaking,
low-risk fix that closes weakness 2.1 with ~50 lines of code changes.

**Plan Path B (PASETO v4.local)** for the next major version that already requires
a session rotation (e.g. after the Argon2id password-hash migration triggers a
forced re-login). PASETO eliminates weaknesses 2.2, 2.3, 2.5 and 2.6 in one step.

---

## 5. Implementation path A — HKDF key separation (lowest friction)

### 5.1 How HKDF works

HKDF (RFC 5869) is a two-step KDF:

```
PRK  = HKDF-Extract(salt, IKM)       // IKM = COOKIE_SECRET, salt = nil (optional)
OKM  = HKDF-Expand(PRK, info, L)     // info = purpose label, L = key length
```

Each derived key is cryptographically independent even though they share the same root.
NIST SP 800-108r1 and RFC 9709 (CMS Key Derivation, Jan 2025) both standardise this pattern.

### 5.2 Code change — `main.go`

Add a `derivedKeys` struct to `config` and populate it in `loadConfig`:

```go
import "golang.org/x/crypto/hkdf"

type derivedKeys struct {
    session []byte // HKDF info = "forward-auth session v1"
    device  []byte // HKDF info = "forward-auth device v1"
    csrf    []byte // HKDF info = "forward-auth csrf v1"
    form    []byte // HKDF info = "forward-auth form v1"
}

func deriveKeys(master []byte) derivedKeys {
    derive := func(info string) []byte {
        r := hkdf.New(sha256.New, master, nil, []byte(info))
        k := make([]byte, 32)
        if _, err := io.ReadFull(r, k); err != nil {
            panic("hkdf derive: " + err.Error())
        }
        return k
    }
    return derivedKeys{
        session: derive("forward-auth session v1"),
        device:  derive("forward-auth device v1"),
        csrf:    derive("forward-auth csrf v1"),
        form:    derive("forward-auth form v1"),
    }
}
```

Add `keys derivedKeys` to `config` and call `deriveKeys(secret)` in `loadConfig`:

```go
// In loadConfig, after secret is resolved:
keys: deriveKeys(secret),
```

### 5.3 Thread all MAC calls through purpose-specific keys

Replace the single `c.mac(msg)` with purpose-aware helpers:

```go
func (c config) macSession(msg string) string  { return macWith(c.keys.session, msg) }
func (c config) macDevice(msg string) string   { return macWith(c.keys.device, msg) }
func (c config) macCSRF(msg string) string     { return macWith(c.keys.csrf, msg) }
func (c config) macForm(msg string) string     { return macWith(c.keys.form, msg) }
```

Update callers:

| Current call | Replace with |
|---|---|
| `c.mac(body)` in `issueSession` | `c.macSession(body)` |
| `c.validMAC(body, parts[6])` in `parseSession` | `validMACWith(c.keys.session, body, parts[6])` |
| `c.mac(body)` in `issueDevice` | `c.macDevice(body)` |
| `c.validMAC(body, parts[4])` in `validDevice` | `validMACWith(c.keys.device, body, parts[4])` |
| `c.mac("csrf\|" + sid)` in `csrfToken` | `c.macCSRF("csrf\|" + sid)` |
| `c.mac(body)` in `issueForm` | `c.macForm(body)` |
| `c.validMAC(body, parts[2])` in `checkForm` | `validMACWith(c.keys.form, body, parts[2])` |

Add `validMACWith` that only checks one key (no cross-purpose fallback):

```go
func validMACWith(key []byte, msg, got string) bool {
    return subtle.ConstantTimeCompare(
        []byte(got),
        []byte(macWith(key, msg)),
    ) == 1
}
```

Key rotation for old tokens: derive old keys from each `oldSecrets` entry and check those
in `parseSession` / `validDevice` if the current key fails:

```go
func (c config) validSessionMAC(body, got string) bool {
    if validMACWith(c.keys.session, body, got) {
        return true
    }
    for _, old := range c.oldSecrets {
        if validMACWith(deriveKeys(old).session, body, got) {
            return true
        }
    }
    return false
}
```

### 5.4 Test coverage

```go
func TestKeyIsolation(t *testing.T) {
    cfg := config{secret: []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")}
    cfg.keys = deriveKeys(cfg.secret)

    // A session MAC must not verify as a form MAC and vice versa
    body := "v2|9999999999|alice|1|deadbeef|"
    sessionMAC := cfg.macSession(body)
    if cfg.macForm(body) == sessionMAC {
        t.Fatal("session and form keys must be distinct")
    }
    if validMACWith(cfg.keys.form, body, sessionMAC) {
        t.Fatal("session MAC must not verify under form key")
    }
}
```

### 5.5 Deployment — zero downtime

1. Deploy the new binary. Existing cookies carry MACs derived from the old undivided key.
2. In `validSessionMAC`, fall back to `macWith(c.secret, body)` (the old global key) for
   one rotation window (e.g. `SESSION_TTL_HOURS`, default 12 h).
3. After the window passes, remove the fallback. All active sessions will have been
   re-issued with new purpose-scoped MACs via the `setCookie` call on each verify.

```go
// Temporary fallback (remove after one SESSION_TTL_HOURS window):
func (c config) validSessionMAC(body, got string) bool {
    if validMACWith(c.keys.session, body, got) {
        return true
    }
    // Legacy: tokens issued before key-separation migration
    if subtle.ConstantTimeCompare([]byte(got), []byte(macWith(c.secret, body))) == 1 {
        return true
    }
    for _, old := range c.oldSecrets {
        if validMACWith(deriveKeys(old).session, body, got) {
            return true
        }
    }
    return false
}
```

---

## 6. Implementation path B — PASETO v4.local (highest assurance)

### 6.1 What PASETO v4.local provides

PASETO v4.local uses:
- **XChaCha20** stream cipher (192-bit nonce — safe for random nonce generation)
- **BLAKE2b** as the MAC (Encrypt-then-MAC)
- **Key-splitting via BLAKE2b** (`paseto-encryption-key` / `paseto-auth-key-for-aead`)
- **Implicit assertions** — additional authenticated data not included in the token

This eliminates plaintext payload (weakness 2.2), delimiter injection (2.3),
and adds native implicit assertion support (2.6). The algorithm is fixed by the
version prefix `v4.local.` — there is no `alg` field an attacker can manipulate.

### 6.2 Go library

```
go get zntr.io/paseto/v4
```

`zntr.io/paseto` implements v3 (NIST-compliant HKDF-HMAC-SHA384 / AES-CTR / HMAC-SHA384)
and v4 (BLAKE2b / XChaCha20 / Ed25519). The v4 `Encrypt` / `Decrypt` functions are
the entry points for symmetric (local) tokens.

### 6.3 Session token — new format

```go
import pasetov4 "zntr.io/paseto/v4"

// sessionPayload is JSON-marshalled inside the encrypted PASETO token.
type sessionPayload struct {
    Subject  string `json:"sub"`           // username
    Expiry   int64  `json:"exp"`           // Unix timestamp
    Gen      int    `json:"gen"`           // user generation
    SID      string `json:"sid"`           // per-session ID
    Flags    string `json:"flags,omitempty"`
    IssuedAt int64  `json:"iat"`
}

func (c config) issueSessionPASETO(cl sessionClaims) (string, error) {
    pl, _ := json.Marshal(sessionPayload{
        Subject:  cl.user,
        Expiry:   cl.exp,
        Gen:      cl.gen,
        SID:      cl.sid,
        Flags:    cl.flags,
        IssuedAt: time.Now().Unix(),
    })
    // implicit assertion = "forward-auth session" (not in token, verified on decrypt)
    tok, err := pasetov4.Encrypt(rand.Reader, c.pasetoKey, pl, []byte("forward-auth session"), nil)
    return tok, err
}

func (c config) parseSessionPASETO(tok string) (sessionClaims, bool) {
    plain, err := pasetov4.Decrypt(c.pasetoKey, tok, []byte("forward-auth session"), nil)
    if err != nil {
        return sessionClaims{}, false
    }
    var pl sessionPayload
    if json.Unmarshal(plain, &pl) != nil {
        return sessionClaims{}, false
    }
    if time.Now().Unix() >= pl.Expiry {
        return sessionClaims{}, false
    }
    return sessionClaims{
        user: pl.Subject, exp: pl.Expiry,
        gen: pl.Gen, sid: pl.SID, flags: pl.Flags,
    }, true
}
```

### 6.4 Key setup

```go
// config struct: add
pasetoKey pasetov4.LocalKey  // 32-byte symmetric key for v4.local

// In loadConfig, derive the PASETO key from the master secret via HKDF:
import pasetov4 "zntr.io/paseto/v4"

func derivePASETOKey(master []byte) pasetov4.LocalKey {
    r := hkdf.New(sha256.New, master, nil, []byte("forward-auth paseto-local v1"))
    var k pasetov4.LocalKey
    if _, err := io.ReadFull(r, k[:]); err != nil {
        panic("paseto key derive: " + err.Error())
    }
    return k
}
```

### 6.5 Migration strategy

PASETO v4 tokens look like `v4.local.<base64>` and are not valid pipe-delimited tokens.
The parser can distinguish them by the `v4.local.` prefix:

```go
func (c config) parseSession(tok string) (sessionClaims, bool) {
    if strings.HasPrefix(tok, "v4.local.") {
        return c.parseSessionPASETO(tok)
    }
    return c.parseSessionLegacy(tok)  // existing pipe-delimited parser
}
```

This allows a gradual rollout:
1. Deploy new binary — both formats accepted.
2. New sessions issued as PASETO v4.
3. Old pipe-delimited sessions expire within `SESSION_TTL_HOURS`.
4. Remove legacy parser after one TTL window.

### 6.6 Cookie size impact

| Format | Example size |
|---|---|
| Current pipe-delimited | ~140 bytes |
| PASETO v4.local | ~200 bytes (+60 bytes: nonce 24 B + tag 32 B + b64 overhead) |

Well within the 4096-byte cookie limit.

### 6.7 Implicit assertion binding to request (optional)

To bind a session token to the user's IP `/24` subnet (prevents cookie theft across
network segments):

```go
func subnetAssertion(ip string) []byte {
    parsed := net.ParseIP(ip)
    if parsed == nil {
        return []byte("forward-auth session")
    }
    // mask to /24 for IPv4, /48 for IPv6
    masked := parsed.Mask(net.CIDRMask(24, 32))
    return []byte("forward-auth session " + masked.String())
}

// In issueSessionPASETO and parseSessionPASETO:
assertion := subnetAssertion(clientIP)
tok, err := pasetov4.Encrypt(rand.Reader, c.pasetoKey, pl, assertion, nil)
```

⚠️ **Warning**: Only enable this if your users have stable IPs. Cloudflare, mobile
clients, and VPNs will cause frequent session expiry. Consider making this
opt-in via `BIND_SESSION_SUBNET=true`.

---

## 7. Key rotation guidance

### Rotation procedure (applies to both paths)

1. Generate a new 32-byte secret: `openssl rand -hex 32`
2. Set `COOKIE_SECRET=<new>` and `COOKIE_SECRET_PREVIOUS=<old>` in your environment.
3. Deploy. Old tokens (signed with the previous key) continue to be accepted via
   `oldSecrets` fallback. New tokens are issued with the new key.
4. Wait one full `SESSION_TTL_HOURS` window.
5. Remove `COOKIE_SECRET_PREVIOUS` at next deploy. All old-key tokens have expired.

### Emergency rotation (key compromise suspected)

1. Set `COOKIE_SECRET=<new>` and **do not** set `COOKIE_SECRET_PREVIOUS`.
2. Deploy immediately. All existing sessions are instantly invalidated —
   users must re-login. This is the correct response to a key compromise.

### Rotation frequency recommendation

NIST SP 800-57 Part 1 Rev 5 recommends cryptoperiods based on usage volume.
For a homelab / small-team deployment:
- Routine rotation: every 90 days.
- After any suspected exposure: immediately.
- After any admin account compromise: immediately + bump all user `Gen` fields
  via admin API (`DELETE /_auth/admin/api/action` with `regen_sessions`).

---

## 8. Checklist

### Path A (HKDF key separation)

- [ ] Add `derivedKeys` struct to `config`
- [ ] Call `deriveKeys(secret)` in `loadConfig`
- [ ] Replace `c.mac()` / `c.validMAC()` with purpose-scoped helpers
- [ ] Derive old keys from `oldSecrets` in fallback paths
- [ ] Add `TestKeyIsolation` unit test
- [ ] Add temporary legacy fallback (remove after one TTL window)
- [ ] Update `.env.example` — no new env-vars required

### Path B (PASETO v4.local, after Path A)

- [ ] `go get zntr.io/paseto/v4`
- [ ] Add `derivePASETOKey` using HKDF
- [ ] Implement `issueSessionPASETO` / `parseSessionPASETO`
- [ ] Add `v4.local.` prefix detection in `parseSession`
- [ ] Port device token to PASETO v4 (or keep as HMAC with key separation from Path A)
- [ ] Add integration test: issue PASETO token, parse it, verify claims
- [ ] Remove legacy parser after one TTL window post-deploy
- [ ] Update `main.go` header comment

---

## 9. References

| # | Source |
|---|---|
| 1 | NIST SP 800-108r1 (2022) — *Recommendation for Key Derivation Using Pseudorandom Functions* |
| 2 | NIST SP 800-57 Part 1 Rev 5 (2020) — *Recommendation for Key Management* |
| 3 | RFC 5869 (2010) — *HMAC-based Extract-and-Expand Key Derivation Function (HKDF)* |
| 4 | RFC 9709 (Jan 2025) — *Encryption Key Derivation in CMS Using HKDF with SHA-256* |
| 5 | Trail of Bits (Jan 2025) — *Best Practices for Key Derivation* |
| 6 | PASETO Specification v4 — `paseto-standard/paseto-spec`, Rationale-V3-V4.md |
| 7 | Paragon Initiative Enterprises (2021) — *PASETO is a Secure Alternative to JOSE/JWT* |
| 8 | `zntr.io/paseto` — v3/v4 Go PASETO implementation (XChaCha20 + BLAKE2b) |
| 9 | `golang.org/x/crypto/hkdf` — Go standard HKDF implementation |
| 10 | Synclovis (2025) — *Beyond JWT: Why PASETO and Branca Are the Future of Secure Tokens* |
