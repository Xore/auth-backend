# Token & HMAC Hardening Guide

> **Archived:** The PASETO migration and token-hardening implementation are
> complete. This document remains as historical design and migration context.

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
7. [PASETO v4.local — best practices in depth](#7-paseto-v4local--best-practices-in-depth)
8. [Key rotation guidance](#8-key-rotation-guidance)
9. [Checklist](#9-checklist)
10. [References](#10-references)

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

**Standard.** PASETO v4.local (XChaCha20 + BLAKE2b, Encrypt-then-MAC) provides
**Authenticated Encryption with Associated Data (AEAD)** — the payload is both
confidential and integrity-protected with a single primitive. The algorithm is fixed
by the `v4.local.` version prefix; there is no `alg` field an attacker can manipulate.

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
offer the same security with no length-extension risk even in non-HMAC mode.

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
| Auth algorithm | HMAC-SHA-256 | HMAC-SHA-256 | BLAKE2b (Encrypt-then-MAC) |
| Timing-safe verify | ✅ | ✅ | ✅ (library) |
| Format injection risk | Low (validated) | Low | None (binary AEAD) |
| Implicit assertions | ❌ | Manual | ✅ Native |
| Go library needed | stdlib only | stdlib only | `zntr.io/paseto/v4` |
| Migration effort | — | Low (≈ 50 lines) | Medium (new dep, token version bump) |
| Cookie size change | — | None | +~60 bytes (nonce + tag + b64) |
| Breaking change | — | No | No (dual-parser migration) |

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
- **XChaCha20** stream cipher (192-bit nonce — safe for random nonce generation at scale)
- **BLAKE2b** as the MAC (Encrypt-then-MAC via internal key splitting)
- **Key-splitting via BLAKE2b** (`paseto-encryption-key` / `paseto-auth-key-for-aead`)
- **Implicit assertions** — additional authenticated data not included in the token body

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
    Subject  string `json:"sub"`            // username
    Expiry   int64  `json:"exp"`            // Unix timestamp
    Gen      int    `json:"gen"`            // user generation
    SID      string `json:"sid"`            // per-session ID
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
| PASETO v4.local | ~200 bytes (+60 bytes: nonce 32 B + tag 32 B + b64 overhead) |

Well within the 4096-byte cookie limit.

### 6.7 Implicit assertion binding to request (optional)

```go
func subnetAssertion(ip string) []byte {
    parsed := net.ParseIP(ip)
    if parsed == nil {
        return []byte("forward-auth session")
    }
    masked := parsed.Mask(net.CIDRMask(24, 32))
    return []byte("forward-auth session " + masked.String())
}
```

⚠️ **Warning**: Only enable this if your users have stable IPs. Cloudflare, mobile
clients, and VPNs will cause frequent session expiry. Make it opt-in via `BIND_SESSION_SUBNET=true`.

---

## 7. PASETO v4.local — best practices in depth

This section covers every non-obvious decision when implementing PASETO v4.local correctly,
drawn directly from the official PASETO specification and security research.

---

### 7.1 Algorithm internals — what actually happens inside Encrypt

Understanding the internals guards against misuse and helps audit library behaviour.

The PASETO v4.local Encrypt operation (from the official spec):

```
1. Assert key length == 32 bytes.
2. Set header h = "v4.local."  (trailing dot is part of the header)
3. Generate n = 32 random bytes from OS CSPRNG.
4. Split key into Ek (encryption key, 32 B) and Ak (auth key, 32 B)
   using keyed BLAKE2b:

   tmp = BLAKE2b(msg = "paseto-encryption-key" || n, key = k, outlen = 56)
   Ek  = tmp[0:32]
   n2  = tmp[32:56]   ← 24-byte counter nonce for XChaCha20

   Ak  = BLAKE2b(msg = "paseto-auth-key-for-aead" || n, key = k, outlen = 32)

5. c = XChaCha20(message = plaintext, nonce = n2, key = Ek)

6. preAuth = PAE(h, n, c, footer, implicit_assertion)
   PAE = Pre-Authentication Encoding: length-prefixed concatenation
         that prevents delimiter confusion between fields.

7. t = BLAKE2b(message = preAuth, key = Ak, outlen = 32)

8. token = h || base64url(n || c || t)
           optionally: || "." || base64url(footer)
```

**Key insight**: The 32-byte random `n` is never reused as the XChaCha20 nonce directly.
Instead it feeds a BLAKE2b key-derivation step that produces both `Ek` and the actual
24-byte XChaCha20 nonce `n2`. This means:

- Even if the OS CSPRNG produces a repeated nonce `n` (astronomically unlikely), the
  derived `n2` will differ because `Ek` and `n2` are domain-separated by the label
  `"paseto-encryption-key"`.
- The full 32-byte `n` is included in `preAuth` and is therefore covered by the MAC `t`,
  so nonce commitment is implicit.

---

### 7.2 Pre-Authentication Encoding (PAE) — why it matters

PAE is a length-prefixed encoding applied before the BLAKE2b MAC:

```
PAE(pieces...) =
    LE64(len(pieces))
    || for each piece p:
         LE64(len(p)) || p
```

where `LE64(x)` is the 64-bit little-endian encoding of `x`.

**Why this prevents attacks**: Without PAE, an adversary who controls the footer could
shift bytes from the footer into the ciphertext field (or vice versa) and produce a
valid MAC over a rearranged input. PAE makes field boundaries unambiguous.

**Implementation checklist**:
- Never attempt to manually re-implement PAE; always use the library's `Encrypt`/`Decrypt`.
- Verify your library version actually implements PAE correctly — check its test vectors
  against the official PASETO test vectors at `paseto-standard/paseto-spec/test-vectors/v4.json`.

---

### 7.3 Claims — what to include and validate

PASETO payloads are JSON. The spec (Implementation Guide §02-Validators) recommends
validating these **registered claims** before trusting any payload value:

| Claim | Type | Meaning | Validate |
|---|---|---|---|
| `sub` | string | Subject (username) | Must not be empty; must match known user |
| `exp` | RFC3339 or Unix int | Expiry time | `now < exp` — reject if expired |
| `iat` | RFC3339 or Unix int | Issued-at time | `now >= iat` — reject tokens from the future |
| `nbf` | RFC3339 or Unix int | Not-before time | `now >= nbf` — reject premature tokens |
| `iss` | string | Issuer | Must equal `"forward-auth"` or your `AUTH_HOST` |
| `jti` | string | Token ID (= `sid`) | Use for per-session revocation lookup |

**Validation must be fail-closed**: if any claim is missing or unparseable, reject the token.

```go
type sessionPayload struct {
    // Registered PASETO/JWT claims
    Issuer    string `json:"iss"`
    Subject   string `json:"sub"`
    IssuedAt  int64  `json:"iat"`
    NotBefore int64  `json:"nbf"`
    Expiry    int64  `json:"exp"`
    TokenID   string `json:"jti"`  // = sid

    // Application claims
    Gen   int    `json:"gen"`
    Flags string `json:"flags,omitempty"`
}

func (c config) parseSessionPASETO(tok string) (sessionClaims, bool) {
    plain, err := pasetov4.Decrypt(c.pasetoKey, tok, []byte("forward-auth session"), nil)
    if err != nil {
        return sessionClaims{}, false  // MAC failure or wrong key — never log the token
    }
    var pl sessionPayload
    if err := json.Unmarshal(plain, &pl); err != nil {
        return sessionClaims{}, false
    }
    now := time.Now().Unix()

    // Fail-closed claim validation:
    if pl.Subject == ""                          { return sessionClaims{}, false }
    if pl.TokenID == ""                          { return sessionClaims{}, false }
    if pl.Issuer != c.authHost                   { return sessionClaims{}, false }
    if now >= pl.Expiry                          { return sessionClaims{}, false }
    if pl.IssuedAt > 0 && now < pl.IssuedAt     { return sessionClaims{}, false }  // future token
    if pl.NotBefore > 0 && now < pl.NotBefore   { return sessionClaims{}, false }

    return sessionClaims{
        user:  pl.Subject,
        exp:   pl.Expiry,
        gen:   pl.Gen,
        sid:   pl.TokenID,
        flags: pl.Flags,
    }, true
}
```

**Clock skew**: Add a ±30 s tolerance to `iat` and `nbf` checks only — never to `exp`.
Expired tokens must always be rejected immediately.

---

### 7.4 Footer — key-ID for zero-downtime rotation

The PASETO footer is base64url-encoded metadata appended after the token body,
separated by a dot: `v4.local.<payload>.<footer>`. The footer is **authenticated**
(included in PAE/BLAKE2b) but **not encrypted** — it is readable without the key.

Use the footer to carry a **key-ID (kid)** so the verifier knows which key to try first
without attempting decryption with every possible key:

```go
type pasetoFooter struct {
    KeyID string `json:"kid"`
}

func (c config) issueSessionPASETO(cl sessionClaims) (string, error) {
    pl, _ := json.Marshal(sessionPayload{ /* ... */ })
    footer, _ := json.Marshal(pasetoFooter{KeyID: c.pasetoKeyID})

    tok, err := pasetov4.Encrypt(rand.Reader, c.pasetoKey, pl,
        []byte("forward-auth session"), // implicit assertion
        footer,                         // authenticated, unencrypted footer
    )
    return tok, err
}

func (c config) parseSessionPASETO(tok string) (sessionClaims, bool) {
    // 1. Peek at the footer (base64url-decode the last dot-segment) to get kid.
    // 2. Select the matching key (current or previous).
    // 3. Decrypt with that key and the fixed implicit assertion.
    key, assertion := c.keyForToken(tok)
    plain, err := pasetov4.Decrypt(key, tok, assertion, nil /* footer already consumed */)
    // ...
}
```

**kid format**: Use the first 8 hex characters of `SHA-256(key)` — this is a fingerprint,
not a secret. Log it at startup so you can correlate tokens to key versions.

```go
func keyFingerprint(k []byte) string {
    sum := sha256.Sum256(k)
    return hex.EncodeToString(sum[:4])
}
```

---

### 7.5 Implicit assertions — correct usage

Implicit assertions are authenticated (included in the BLAKE2b MAC) but **not stored in
the token** — both issuer and verifier must agree on the same assertion bytes out-of-band.

**Correct uses** for `forward-auth`:

| Assertion value | Binds token to | Risk of session breaks |
|---|---|---|
| `"forward-auth session"` (static label) | Token purpose only | None |
| `"forward-auth session " + /24-subnet` | Network location | High (mobile, VPN, Cloudflare) |
| `"forward-auth session " + authHost` | Auth domain | None (stable) |

**Rules**:
1. The implicit assertion **must be identical** at `Encrypt` and `Decrypt` time. A mismatch
   causes a BLAKE2b MAC failure and the token is rejected — this is intentional.
2. Never include user-controlled data in the implicit assertion without sanitisation.
3. An empty assertion (`nil` or `[]byte{}`) is valid and common — it means no binding.
4. **Do not** include the implicit assertion in the token footer. Its value is a
   shared secret between issuer and verifier — that is the point.

---

### 7.6 Nonce handling — what you must and must not do

The PASETO v4.local spec generates a fresh 32-byte random nonce `n` per encryption.

**DO**:
- Always pass `rand.Reader` (Go's `crypto/rand`) as the source. Never seed with time or
  a deterministic PRNG.
- Let the library generate `n` — do not pass a nonce externally (the `zntr.io/paseto`
  API does not expose external nonces, which is correct by design).
- Verify that the library you use generates `n` from the OS CSPRNG (check the source).

**DO NOT**:
- Reuse a nonce under any circumstances. With XChaCha20, nonce reuse leaks the XOR of
  two plaintexts and breaks confidentiality completely (stream cipher vulnerability).
- Use a counter nonce with XChaCha20. The spec's random 32-byte nonce gives 2^256 nonce
  space, making collision probability negligible even at very high issuance rates.
- Cache or pre-generate nonces. Generate them at issuance time, use once.

---

### 7.7 Key lifecycle and storage

**Key material**:
- Derive the PASETO key from `COOKIE_SECRET` via HKDF (as in §6.4). Never store a
  separate raw PASETO key in the environment — this creates two secrets to manage.
- The derived key is deterministic: the same `COOKIE_SECRET` always produces the same
  PASETO key. Key rotation is therefore handled entirely through `COOKIE_SECRET` rotation.

**Key length**: Must be exactly 32 bytes. The `pasetov4.LocalKey` type is `[32]byte` —
the library enforces this at compile time.

**Storage rules**:
- Store `COOKIE_SECRET` in Docker secrets (`_FILE` env-var pattern already implemented)
  or a secrets manager (Vault, Infisical, AWS Secrets Manager).
- **Never** log the key, its hex encoding, or any token that could allow key recovery.
  Log only the key fingerprint (first 4 bytes of `SHA-256(key)`).
- Zero the key from memory after use where possible. In Go, this means avoiding string
  conversions of key material (strings are immutable and GC'd non-deterministically).

**Key rotation with PASETO**:

Because PASETO tokens carry a `kid` in the footer (§7.4), rotation is clean:

```
1. Generate new COOKIE_SECRET.
2. Set COOKIE_SECRET=<new>, COOKIE_SECRET_PREVIOUS=<old>.
3. Deploy. New tokens: new key + new kid. Old tokens: verified with old key via kid lookup.
4. Wait SESSION_TTL_HOURS. All old tokens expired.
5. Remove COOKIE_SECRET_PREVIOUS.
```

---

### 7.8 What to never log

| Data | Why |
|---|---|
| Full token value | Allows session hijacking if logs are leaked |
| Decrypted payload | Exposes username, session ID, flags |
| Key bytes or hex | Allows token forgery |
| Decryption errors with token content | Could enable oracle attacks |

**Safe to log**: `kid` (key fingerprint), `jti` (session ID — already pseudonymous),
event type, IP, timestamp.

```go
// BAD — never do this:
s.log.Error("token parse failed", "token", tok)

// GOOD:
s.log.Warn("token parse failed", "kid", extractKID(tok), "ip", ip)
```

---

### 7.9 Test vectors — verify your implementation

The PASETO project publishes official test vectors at:
`https://github.com/paseto-standard/test-vectors/blob/master/v4.json`

Run these as part of your CI suite to catch any library regression:

```go
func TestPASETOv4Vectors(t *testing.T) {
    // Load v4.json from testdata/
    type vector struct {
        Name        string `json:"name"`
        Key         string `json:"key"`         // hex
        Nonce       string `json:"nonce"`        // hex — used only in test mode
        Token       string `json:"token"`
        Payload     string `json:"payload"`      // expected plaintext (JSON)
        Footer      string `json:"footer"`
        Assertion   string `json:"implicit-assertion"`
        ExpectFail  bool   `json:"expect-fail"`
    }
    // For each vector: decrypt and compare plaintext, or expect failure.
    // This guarantees your library's PAE and BLAKE2b match the spec.
}
```

---

### 7.10 Common pitfalls — mistakes to avoid

| Pitfall | Consequence | Fix |
|---|---|---|
| Using `v4.public` when you want confidentiality | Payload is signed but **visible in plaintext** | Use `v4.local` for session cookies |
| Passing the footer as the implicit assertion | Footer is public; assertion should be a shared secret | Keep them separate |
| Not validating `iss` claim | A token issued by a different service is accepted | Always validate `iss == authHost` |
| Accepting tokens with `exp` in the past | Expired sessions remain valid | Always check `now < exp`, no grace period |
| Logging `err.Error()` on decrypt failure with token content | Oracle for timing/content attacks | Log only kid + ip |
| Treating PASETO as a drop-in for JWT | Claim names and semantics differ slightly | Use registered PASETO claim names (`sub`, `exp`, `iat`, `jti`, `iss`) |
| Generating the PASETO key outside HKDF | Two secrets to manage; rotation breaks | Always derive from `COOKIE_SECRET` |
| Storing raw PASETO tokens in server-side logs (access logs) | Session hijack via log access | Strip `Cookie:` headers in Traefik access logs |

---

### 7.11 Integration test pattern (Go)

```go
func TestRoundTrip(t *testing.T) {
    cfg := testConfig(t)

    original := sessionClaims{
        user:  "alice",
        gen:   3,
        sid:   "abcdef123456",
        flags: "",
        exp:   time.Now().Add(time.Hour).Unix(),
    }

    tok, err := cfg.issueSessionPASETO(original)
    if err != nil {
        t.Fatalf("issue: %v", err)
    }
    if !strings.HasPrefix(tok, "v4.local.") {
        t.Fatalf("expected v4.local. prefix, got: %s", tok[:20])
    }

    parsed, ok := cfg.parseSessionPASETO(tok)
    if !ok {
        t.Fatal("parseSessionPASETO returned false")
    }
    if parsed.user != original.user || parsed.sid != original.sid || parsed.gen != original.gen {
        t.Fatalf("claims mismatch: got %+v, want %+v", parsed, original)
    }
}

func TestTamperedTokenRejected(t *testing.T) {
    cfg := testConfig(t)
    cl := sessionClaims{user: "bob", gen: 1, sid: "xyz", exp: time.Now().Add(time.Hour).Unix()}

    tok, _ := cfg.issueSessionPASETO(cl)
    // Flip a byte in the ciphertext portion
    b := []byte(tok)
    b[len(b)-5] ^= 0xFF
    _, ok := cfg.parseSessionPASETO(string(b))
    if ok {
        t.Fatal("tampered token must be rejected")
    }
}

func TestExpiredTokenRejected(t *testing.T) {
    cfg := testConfig(t)
    cl := sessionClaims{user: "carol", gen: 1, sid: "abc", exp: time.Now().Add(-time.Second).Unix()}
    tok, _ := cfg.issueSessionPASETO(cl)
    _, ok := cfg.parseSessionPASETO(tok)
    if ok {
        t.Fatal("expired token must be rejected")
    }
}

func TestWrongImplicitAssertionRejected(t *testing.T) {
    cfg := testConfig(t)
    cl := sessionClaims{user: "dave", gen: 1, sid: "def", exp: time.Now().Add(time.Hour).Unix()}

    // Issue with correct assertion
    pl, _ := json.Marshal(sessionPayloadFrom(cl, cfg.authHost))
    tok, _ := pasetov4.Encrypt(rand.Reader, cfg.pasetoKey, pl, []byte("forward-auth session"), nil)

    // Attempt to parse with wrong assertion — must fail
    _, err := pasetov4.Decrypt(cfg.pasetoKey, tok, []byte("wrong assertion"), nil)
    if err == nil {
        t.Fatal("wrong implicit assertion must cause MAC failure")
    }
}
```

---

## 8. Key rotation guidance

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
  via admin API (`/_auth/admin/api/action` with `regen_sessions`).

---

## 9. Checklist

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
- [ ] Add `derivePASETOKey` using HKDF (§6.4)
- [ ] Implement `issueSessionPASETO` / `parseSessionPASETO` with full claim validation (§7.3)
- [ ] Add `kid` to footer (§7.4)
- [ ] Set implicit assertion to `"forward-auth session"` (§7.5)
- [ ] Add `v4.local.` prefix detection in `parseSession` for dual-parser migration (§6.5)
- [ ] Port device token to PASETO v4 (or keep as HMAC with key separation from Path A)
- [ ] Run official PASETO v4 test vectors (§7.9)
- [ ] Add round-trip, tamper, expiry, and wrong-assertion tests (§7.11)
- [ ] Strip `Cookie:` from Traefik access logs (§7.8)
- [ ] Remove legacy parser after one TTL window post-deploy
- [ ] Update `main.go` header comment

---

## 10. References

| # | Source |
|---|---|
| 1 | NIST SP 800-108r1 (2022) — *Recommendation for Key Derivation Using Pseudorandom Functions* |
| 2 | NIST SP 800-57 Part 1 Rev 5 (2020) — *Recommendation for Key Management* |
| 3 | RFC 5869 (2010) — *HMAC-based Extract-and-Expand Key Derivation Function (HKDF)* |
| 4 | RFC 9709 (Jan 2025) — *Encryption Key Derivation in CMS Using HKDF with SHA-256* |
| 5 | Trail of Bits (Jan 2025) — *Best Practices for Key Derivation* |
| 6 | PASETO Specification v4 — `paseto-standard/paseto-spec/docs/01-Protocol-Versions/Version4.md` |
| 7 | PASETO Implementation Guide — `paseto-standard/paseto-spec/docs/02-Implementation-Guide/02-Validators.md` |
| 8 | PASETO Rationale v3/v4 — `paseto-standard/paseto-spec/docs/Rationale-V3-V4.md` |
| 9 | Paragon Initiative Enterprises (2021) — *PASETO is a Secure Alternative to JOSE/JWT* |
| 10 | `zntr.io/paseto` — v3/v4 Go PASETO implementation (XChaCha20 + BLAKE2b) |
| 11 | `golang.org/x/crypto/hkdf` — Go standard HKDF implementation |
| 12 | Synclovis (2025) — *Beyond JWT: Why PASETO and Branca Are the Future of Secure Tokens* |
| 13 | PASETO Test Vectors — `paseto-standard/test-vectors/v4.json` |
| 14 | IETF PASETO Draft RFC — `draft-paragon-paseto-rfc-01` |
