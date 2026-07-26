# mTLS Session Binding — Defending Against Session Hijacking with PASETO v4.local

This guide extends the token hardening work in [TOKEN-HARDENING-GUIDE.md](./TOKEN-HARDENING-GUIDE.md)
with a concrete implementation path for **mutual TLS (mTLS) session binding** — the strongest
available defence against stolen session cookies in a Go + Traefik deployment.

---

## Table of Contents

1. [Why session cookies alone are insufficient](#1-why-session-cookies-alone-are-insufficient)
2. [The attack model](#2-the-attack-model)
3. [How mTLS session binding works](#3-how-mtls-session-binding-works)
4. [Standards basis](#4-standards-basis)
5. [Architecture in this deployment](#5-architecture-in-this-deployment)
6. [Implementation — Phase 1: cert fingerprint in PASETO implicit assertion](#6-implementation--phase-1-cert-fingerprint-in-paseto-implicit-assertion)
7. [Implementation — Phase 2: mTLS between Traefik and auth-portal](#7-implementation--phase-2-mtls-between-traefik-and-auth-portal)
8. [Implementation — Phase 3: client cert header forwarding](#8-implementation--phase-3-client-cert-header-forwarding)
9. [Implementation — Phase 4: bind session to cert thumbprint](#9-implementation--phase-4-bind-session-to-cert-thumbprint)
10. [Key rotation and cert lifecycle](#10-key-rotation-and-cert-lifecycle)
11. [Traefik configuration](#11-traefik-configuration)
12. [Docker Compose changes](#12-docker-compose-changes)
13. [Threat model re-evaluation](#13-threat-model-re-evaluation)
14. [Deployment checklist](#14-deployment-checklist)
15. [References](#15-references)

---

## 1. Why session cookies alone are insufficient

The current `forward-auth` issues an HMAC-SHA-256 signed cookie (`xore_sso`) that is:

- `HttpOnly` — not readable by JavaScript
- `Secure` — only sent over TLS
- `SameSite=Lax` — blocked on cross-site POST requests
- HMAC-signed with a 32-byte secret

This is strong, but the cookie is still a **bearer token**: anyone who obtains a copy of the
cookie value — via XSS, an access log leak, a compromised CDN edge node, or a stolen laptop
session — can replay it from any IP until it expires.

The HMAC signature proves the token was *issued by this server*. It does not prove
that the *presenter* is the same client that originally authenticated.

---

## 2. The attack model

| Attack vector | Mitigated by current stack? | Mitigated by mTLS binding? |
|---|---|---|
| XSS cookie theft | Partially (`HttpOnly`) | ✅ Stolen cookie invalid without client cert |
| Network interception (HTTP) | ✅ HTTPS only | ✅ |
| Access log / proxy log leak | ❌ Cookie value visible | ✅ |
| Compromised intermediate proxy | ❌ Cookie forwarded | ✅ Cert not presentable by proxy |
| Stolen session from shared device | ❌ | ✅ Cert tied to device key |
| SSRF replay within the same network | ❌ | ✅ Server cert ≠ client cert |
| Token export from memory | ❌ | ✅ Private key never leaves client keystore |

The binding guarantee: a session token is only valid when presented alongside the
**exact client certificate** that was present when the session was created.

---

## 3. How mTLS session binding works

In standard TLS, only the **server** presents a certificate. In **mutual TLS (mTLS)**,
the **client** also presents a certificate during the TLS handshake.

The server extracts the client certificate's **public key fingerprint** (SHA-256 of the
SubjectPublicKeyInfo, i.e. the `cnf.x5t#S256` claim from RFC 8705) and binds it into the
session token at issuance time. On every subsequent request, the server re-derives the
fingerprint from the presented certificate and checks it matches the one stored in the token.

With PASETO v4.local, this binding can be expressed two ways (we use both):

1. **Implicit assertion** — the cert fingerprint is part of the BLAKE2b MAC input but not
   stored in the token body. A token issued with cert A cannot be decrypted using cert B's
   fingerprint as the assertion. Zero extra bytes in the cookie.

2. **`cnf` claim in payload** — the fingerprint is stored in the encrypted payload as a
   `cnf.x5t#S256` field (per RFC 8705 §3). The verifier checks it against the presented cert
   on every `/_auth/verify` call.

Using both is defence-in-depth: the implicit assertion prevents decryption on wrong cert,
the `cnf` claim provides an auditable, logged binding check even if the assertion ever drifts.

---

## 4. Standards basis

| Standard | Relevance |
|---|---|
| **RFC 8705** (2020) — *OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens* | Defines `cnf.x5t#S256` fingerprint binding; the `x5t#S256` thumbprint algorithm |
| **IETF draft-mw-oauth-tls-session-bound-tokens-07** (June 2026) — *TLS-Session-Bound Access Tokens for OAuth 2.0* | Extends RFC 8705 to bind tokens to a specific TLS session via RFC 5705 Exporter values; directly motivated by multi-hop replay risk in autonomous agent architectures |
| **RFC 5705** — *Keying Material Exporters for TLS* | Defines `tls.ExportKeyingMaterial()` — used to derive a per-connection binding value |
| **PASETO v4 spec** — `paseto-standard/paseto-spec` | Implicit assertions: additional authenticated data bound into BLAKE2b MAC but absent from token body |
| **NIST SP 800-63B Rev 4** (July 2025) | AAL3 requires cryptographic authenticator with hardware-protected key — mTLS client certs stored in OS keystore satisfy this |

---

## 5. Architecture in this deployment

```
Browser/CLI client
  │  (presents client cert during TLS handshake)
  ▼
Traefik (TLS termination + mTLS)
  │  X-Forwarded-Client-Cert: <base64 DER cert>   (or SSL_CLIENT_CERT header)
  ▼
auth-portal:4181   ←── forwardAuth checks here
  │  extracts cert, computes x5t#S256 thumbprint
  │  binds thumbprint into PASETO v4.local token (implicit assertion + cnf claim)
  ▼
Protected services
  │  every request hits /_auth/verify
  │  Traefik forwards current client cert
  │  auth-portal re-checks thumbprint matches session's cnf claim
  ▼
  200 OK (or 302 → login)
```

### What if a client has no cert?

Non-cert clients (browsers without a cert installed) fall through to the standard
password + TOTP flow. The `cnf` binding is **opt-in per session**: sessions issued
without a client cert carry no `cnf` claim and are verified by HMAC/PASETO only
(existing behaviour). Sessions issued with a cert carry a `cnf` claim and require
the cert on every subsequent request.

Enable cert-required mode per-route by setting `REQUIRE_CLIENT_CERT=true`.

---

## 6. Implementation — Phase 1: cert fingerprint in PASETO implicit assertion

This is the minimal, zero-new-dependency change. It extends the PASETO migration from
`TOKEN-HARDENING-GUIDE.md §6` with cert-aware implicit assertions.

### 6.1 Fingerprint helper

Add `mtls.go` in `forward-auth/`:

```go
// mtls.go — client certificate thumbprint extraction for session binding.
package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"net/http"
)

// certThumbprint returns the RFC 8705 §3.1 x5t#S256 thumbprint:
// base64url( SHA-256( SubjectPublicKeyInfo(cert) ) ).
// Returns "" if no client cert is present.
func certThumbprint(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// clientCert extracts the peer certificate from a request.
// Traefik can pass it via the X-Forwarded-Tls-Client-Cert header (base64 DER)
// or it may be present directly in r.TLS.PeerCertificates when auth-portal
// itself terminates mTLS (Phase 2).
func clientCert(r *http.Request) *x509.Certificate {
	// Direct mTLS (Phase 2): cert is in the TLS state.
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		return r.TLS.PeerCertificates[0]
	}
	// Header forwarding from Traefik (Phase 3).
	// Traefik sets X-Forwarded-Tls-Client-Cert as a URL-encoded PEM block.
	if hdr := r.Header.Get("X-Forwarded-Tls-Client-Cert"); hdr != "" {
		if cert, err := parseCertHeader(hdr); err == nil {
			return cert
		}
	}
	return nil
}

// parseCertHeader decodes a URL-encoded base64 DER certificate as forwarded
// by Traefik's passTLSClientCert middleware.
func parseCertHeader(encoded string) (*x509.Certificate, error) {
	// Traefik URL-encodes the PEM block; strip the PEM armor and decode DER.
	import_url_unescape := func(s string) string {
		out, _ := url.QueryUnescape(s)
		return out
	}
	pem := import_url_unescape(encoded)
	// Strip PEM header/footer if present.
	pem = strings.TrimPrefix(pem, "-----BEGIN CERTIFICATE-----")
	pem = strings.TrimSuffix(strings.TrimSpace(pem), "-----END CERTIFICATE-----")
	pem = strings.TrimSpace(pem)
	der, err := base64.StdEncoding.DecodeString(pem)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// pasetoAssertion builds the PASETO v4.local implicit assertion for a session.
// Format: "forward-auth session v1 <thumbprint>" (or without thumbprint if none).
// Both issuer and verifier MUST use the identical assertion bytes.
func pasetoAssertion(thumbprint string) []byte {
	base := "forward-auth session v1"
	if thumbprint == "" {
		return []byte(base)
	}
	return []byte(base + " " + thumbprint)
}
```

> **Note**: the `parseCertHeader` function needs `"net/url"` and `"strings"` imports
> in the file header.

### 6.2 Extend sessionPayload with cnf claim

In the PASETO session payload struct (from `TOKEN-HARDENING-GUIDE.md §6.3`):

```go
type sessionPayload struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	IssuedAt  int64  `json:"iat"`
	NotBefore int64  `json:"nbf,omitempty"`
	Expiry    int64  `json:"exp"`
	TokenID   string `json:"jti"`
	Gen       int    `json:"gen"`
	Flags     string `json:"flags,omitempty"`

	// RFC 8705 §3.1 — certificate-bound confirmation claim.
	// Present only when the session was issued with a client cert.
	// Value: base64url( SHA-256( SubjectPublicKeyInfo ) )
	CertThumbprint string `json:"cnf_x5t,omitempty"`
}
```

### 6.3 Issue session with cert binding

```go
func (c config) issueSessionPASETO(cl sessionClaims, thumbprint string) (string, error) {
	pl, _ := json.Marshal(sessionPayload{
		Issuer:         c.authHost,
		Subject:        cl.user,
		IssuedAt:       time.Now().Unix(),
		Expiry:         cl.exp,
		TokenID:        cl.sid,
		Gen:            cl.gen,
		Flags:          cl.flags,
		CertThumbprint: thumbprint, // empty string → omitted from JSON
	})
	// The implicit assertion embeds the thumbprint into the BLAKE2b MAC.
	// A token issued with cert A cannot be verified using cert B's assertion.
	assertion := pasetoAssertion(thumbprint)
	return pasetov4.Encrypt(rand.Reader, c.pasetoKey, pl, assertion, nil)
}
```

### 6.4 Verify session with cert binding

```go
func (c config) parseSessionPASETO(tok string, thumbprint string) (sessionClaims, bool) {
	assertion := pasetoAssertion(thumbprint)
	plain, err := pasetov4.Decrypt(c.pasetoKey, tok, assertion, nil)
	if err != nil {
		// MAC failure — wrong key, tampered token, OR wrong cert (assertion mismatch).
		// Do NOT log the token value here; log only the thumbprint for correlation.
		return sessionClaims{}, false
	}
	var pl sessionPayload
	if json.Unmarshal(plain, &pl) != nil {
		return sessionClaims{}, false
	}
	now := time.Now().Unix()
	if pl.Subject == "" || pl.TokenID == "" {
		return sessionClaims{}, false
	}
	if pl.Issuer != c.authHost {
		return sessionClaims{}, false
	}
	if now >= pl.Expiry {
		return sessionClaims{}, false
	}
	if pl.IssuedAt > 0 && now < pl.IssuedAt-30 { // 30s clock skew tolerance on iat only
		return sessionClaims{}, false
	}

	// Double-check: if token carries a cnf claim, the presented thumbprint must match.
	// This is redundant with the implicit assertion but provides an auditable log path.
	if pl.CertThumbprint != "" {
		if thumbprint == "" {
			// Token requires a cert but none was presented.
			return sessionClaims{}, false
		}
		if subtle.ConstantTimeCompare([]byte(pl.CertThumbprint), []byte(thumbprint)) != 1 {
			// Cert mismatch — possible stolen token replay.
			return sessionClaims{}, false
		}
	}

	return sessionClaims{
		user: pl.Subject, exp: pl.Expiry,
		gen: pl.Gen, sid: pl.TokenID, flags: pl.Flags,
	}, true
}
```

### 6.5 Thread thumbprint through the request pipeline

Update `server.session()` in `main.go`:

```go
func (s *server) session(r *http.Request) (sessionClaims, *User, bool) {
	c, err := r.Cookie(s.cfg.cookieName)
	if err != nil {
		return sessionClaims{}, nil, false
	}

	// Extract client cert thumbprint (may be "" if no mTLS).
	thumb := certThumbprint(clientCert(r))

	var cl sessionClaims
	var ok bool
	if strings.HasPrefix(c.Value, "v4.local.") {
		cl, ok = s.cfg.parseSessionPASETO(c.Value, thumb)
	} else {
		// Legacy HMAC pipe-delimited token (pre-PASETO migration).
		// No cert binding on legacy tokens — this is acceptable during migration.
		cl, ok = s.cfg.parseSession(c.Value)
	}

	if !ok || s.reg.isRevoked(cl.sid) {
		return sessionClaims{}, nil, false
	}
	u := s.users.get(cl.user)
	if u == nil || u.Disabled || u.Gen != cl.gen {
		return sessionClaims{}, nil, false
	}
	return cl, u, true
}
```

Update `server.login()` to pass the thumbprint when issuing the session:

```go
// In s.login, replace s.setCookie(w, cl) with:
thumb := certThumbprint(clientCert(r))
s.setCookiePASETO(w, cl, thumb)

// New helper:
func (s *server) setCookiePASETO(w http.ResponseWriter, cl sessionClaims, thumb string) {
	tok, err := s.cfg.issueSessionPASETO(cl, thumb)
	if err != nil {
		s.log.Error("issue PASETO session", "error", err)
		http.Error(w, "session issuance failed", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     s.cfg.cookieName,
		Value:    tok,
		Path:     "/",
		Domain:   s.cfg.cookieDom,
		HttpOnly: true,
		Secure:   s.cfg.secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(time.Until(time.Unix(cl.exp, 0)).Seconds()),
	})
}
```

---

## 7. Implementation — Phase 2: mTLS between Traefik and auth-portal

If `auth-portal` itself terminates TLS (running behind Traefik on an internal TLS listener),
Go's `net/http` server can be configured to require client certificates.

```go
// In main(), replace srv := &http.Server{...} with:

tlsCfg := &tls.Config{
	// Request a client certificate; do NOT set RequireAnyClientCert here —
	// we want to allow cert-less sessions too (see §5).
	ClientAuth: tls.RequestClientCert,

	// Accept self-signed certs from clients — we verify by thumbprint, not CA chain.
	// For CA-issued certs, use tls.RequireAndVerifyClientCert and set ClientCAs.
	ClientCAs: nil,

	MinVersion: tls.VersionTLS13,
}

srv := &http.Server{
	Addr:              cfg.listen,
	Handler:           mux,
	TLSConfig:         tlsCfg,
	ReadHeaderTimeout: 5 * time.Second,
	ReadTimeout:       15 * time.Second,
	WriteTimeout:      30 * time.Second,
	IdleTimeout:       60 * time.Second,
	MaxHeaderBytes:    1 << 20,
}

// Start with TLS:
if err := srv.ListenAndServeTLS(cfg.tlsCertFile, cfg.tlsKeyFile); err != nil && err != http.ErrServerClosed {
	log.Error("server stopped", "error", err)
	os.Exit(1)
}
```

Add `tlsCertFile` and `tlsKeyFile` to `config` and `loadConfig`:

```go
// In config struct:
tlsCertFile string
tlsKeyFile  string
mtlsEnabled bool

// In loadConfig:
tlsCertFile: getenv("TLS_CERT_FILE", ""),
tlsKeyFile:  getenv("TLS_KEY_FILE", ""),
mtlsEnabled: getenv("MTLS_ENABLED", "false") == "true",
```

> **Homelab note**: For the Traefik + WireGuard setup in `Xore/cgnat`, the internal
> Docker network is already trusted and encrypted at the network layer. Phase 2 adds
> defence-in-depth for the auth-portal ↔ Traefik leg. Use a self-signed CA for this
> internal cert — see §12 for the `docker-compose.yml` changes.

---

## 8. Implementation — Phase 3: client cert header forwarding

When Traefik terminates TLS (the common case), it can forward the client cert to
`auth-portal` via a header. This requires the `passTLSClientCert` Traefik middleware.

### 8.1 Traefik middleware definition

```yaml
# In your Traefik static or dynamic config:
http:
  middlewares:
    pass-client-cert:
      passTLSClientCert:
        pem: true           # Forward the full PEM-encoded cert
        info:
          subject:
            commonName: true
          sans: true
```

### 8.2 Attach to the auth router

```yaml
routers:
  auth-portal:
    rule: "Host(`auth.xore.rocks`)"
    service: auth-portal
    tls:
      options: modern
    middlewares:
      - security-headers
      - pass-client-cert   # ← forwards client cert as X-Forwarded-Tls-Client-Cert
      # DO NOT add forward-auth here — that would loop
```

### 8.3 Trust the header only from Traefik

`clientCert()` in `mtls.go` already reads `X-Forwarded-Tls-Client-Cert`. The existing
`TRUSTED_PROXIES` mechanism in `main.go` ensures this header is only honoured when the
request comes from a trusted Traefik instance. **Never trust this header from untrusted peers.**

Verify: the `clientIP()` function already validates `X-Forwarded-For` against `trustedNets`.
Add the same guard before accepting the cert header:

```go
func clientCertFromHeader(r *http.Request, trustedNets []*net.IPNet) *x509.Certificate {
	// Only accept the cert header when the direct peer is a trusted proxy.
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	peer := net.ParseIP(host)
	trusted := false
	for _, n := range trustedNets {
		if peer != nil && n.Contains(peer) {
			trusted = true
			break
		}
	}
	if !trusted {
		return nil
	}
	hdr := r.Header.Get("X-Forwarded-Tls-Client-Cert")
	if hdr == "" {
		return nil
	}
	cert, err := parseCertHeader(hdr)
	if err != nil {
		return nil
	}
	return cert
}
```

Update `clientCert()` to call this instead:

```go
func (s *server) clientCert(r *http.Request) *x509.Certificate {
	// Phase 2: direct mTLS
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		return r.TLS.PeerCertificates[0]
	}
	// Phase 3: header from trusted Traefik
	return clientCertFromHeader(r, s.cfg.trustedNets)
}
```

---

## 9. Implementation — Phase 4: bind session to cert thumbprint

This phase adds the **server-side enforcement** — sessions that were issued with a cert
fingerprint are rejected when presented without the matching cert.

This is already handled by `parseSessionPASETO` in §6.4. The only additional piece is
**logging** the binding check for audit purposes:

```go
// In server.session(), after parseSessionPASETO:
if cl.certThumbprint != "" { // expose certThumbprint on sessionClaims if needed
	s.log.Debug("cert-bound session verified",
		"sid", cl.sid,
		"user", cl.user,
		"thumb", thumb[:8], // log only first 8 chars — enough for correlation
	)
}
```

Extend `sessionClaims` to carry the thumbprint for downstream use:

```go
type sessionClaims struct {
	user           string
	gen            int
	sid            string
	flags          string
	exp            int64
	certThumbprint string // "" = unbound session; non-empty = cert-bound
}
```

Add a Prometheus metric for cert-bound vs unbound sessions (in `metrics` handler):

```go
_, _ = fmt.Fprintf(w,
	"# TYPE forwardauth_cert_bound_sessions gauge\nforwardauth_cert_bound_sessions %d\n",
	s.reg.certBoundCount())
```

Extend `sessionInfo` in `sessions.go`:

```go
type sessionInfo struct {
	SID       string    `json:"sid"`
	User      string    `json:"user"`
	IP        string    `json:"ip"`
	UA        string    `json:"ua"`
	Created   time.Time `json:"created"`
	LastSeen  time.Time `json:"last_seen"`
	CertBound bool      `json:"cert_bound"` // true = mTLS session
}
```

Update `reg.touch()` to accept the cert-bound flag:

```go
func (sr *sessionRegistry) touch(sid, user, ip, ua string, certBound bool) {
	// ... existing logic ...
	sr.m[sid] = &sessionInfo{
		SID: sid, User: user, IP: ip, UA: ua,
		Created: now, LastSeen: now, CertBound: certBound,
	}
}
```

---

## 10. Key rotation and cert lifecycle

### Session key rotation
The PASETO implicit assertion includes the cert thumbprint, meaning **key rotation
(`COOKIE_SECRET` change) does not affect cert binding** — it is derived from the cert's
public key, not from `COOKIE_SECRET`. Follow the standard rotation procedure from
`TOKEN-HARDENING-GUIDE.md §8`.

### Client cert lifecycle

| Event | Action |
|---|---|
| Client cert expires | User re-authenticates; new session issued with new cert thumbprint |
| Client cert revoked | Revoke the session via `/_auth/admin` (`reg.revoke(sid)`) |
| Client rotates cert (key stays same) | Thumbprint unchanged (it's the *public key* hash, not the cert serial) |
| Client rotates keypair | New thumbprint → session rejected → re-login required |

### CA-signed vs self-signed client certs

For the homelab case, **self-signed client certs per device** are the pragmatic choice:

```bash
# Generate a per-device client cert (no CA needed)
openssl req -x509 -newkey ed25519 -keyout client.key -out client.crt \
  -days 730 -nodes -subj "/CN=device-laptop-$(hostname)"

# Install in browser (PKCS12 format):
openssl pkcs12 -export -in client.crt -inkey client.key -out client.p12
```

The server verifies by thumbprint (`SHA-256(SubjectPublicKeyInfo)`), not by CA chain,
so `ClientCAs: nil` with `ClientAuth: tls.RequestClientCert` is the correct Go TLS config.

For team deployments, issue client certs from an internal CA (e.g. `step-ca` or
`cfssl`) and set `ClientAuth: tls.RequireAndVerifyClientCert` with a `ClientCAs` pool.

---

## 11. Traefik configuration

### 11.1 Enable mTLS on the entry point

```yaml
# traefik.yml (static config)
entryPoints:
  websecure:
    address: ":443"
    http:
      tls:
        options: modern
    # Optional: request client certs at the entry-point level.
    # Use this only if ALL services require mTLS. Otherwise, handle per-router.
    # transport:
    #   respondingTimeouts:
    #     readTimeout: 30s
```

### 11.2 Per-router TLS options with client cert

```yaml
# dynamic/tls.yml
tls:
  options:
    modern:
      minVersion: VersionTLS13
      sniStrict: true
    mtls-required:
      minVersion: VersionTLS13
      sniStrict: true
      clientAuth:
        clientAuthType: RequireAndVerifyClientCert
        caFiles:
          - /certs/client-ca.crt   # your internal CA
```

Attach `mtls-required` to admin-only routers that must enforce cert presence:

```yaml
routers:
  auth-portal-admin:
    rule: "Host(`auth.xore.rocks`) && PathPrefix(`/_auth/admin`)"
    service: auth-portal
    tls:
      options: mtls-required   # ← admin panel always requires client cert
    middlewares:
      - security-headers
      - pass-client-cert
```

---

## 12. Docker Compose changes

```yaml
# In docker-compose.yml, auth-portal service:
services:
  auth-portal:
    build:
      context: ./forward-auth
    environment:
      - MTLS_ENABLED=false          # Set true to enable Phase 2 direct mTLS
      - TLS_CERT_FILE=/certs/server.crt
      - TLS_KEY_FILE=/certs/server.key
    volumes:
      - ./certs:/certs:ro            # Mount cert directory
      - auth-data:/data
    # ... rest unchanged

  # Helper: generate self-signed internal cert for auth-portal ↔ Traefik mTLS
  cert-init:
    image: alpine/openssl
    profiles: ["setup"]
    volumes:
      - ./certs:/out
    command: >
      req -x509 -newkey ed25519
      -keyout /out/server.key -out /out/server.crt
      -days 3650 -nodes
      -subj "/CN=auth-portal.internal"
```

Generate client certs for devices:

```bash
# One-time setup per device
mkdir -p certs/clients
openssl req -x509 -newkey ed25519 \
  -keyout certs/clients/laptop.key \
  -out certs/clients/laptop.crt \
  -days 730 -nodes \
  -subj "/CN=xore-laptop"

# Export for browser import
openssl pkcs12 -export \
  -in certs/clients/laptop.crt \
  -inkey certs/clients/laptop.key \
  -out certs/clients/laptop.p12 \
  -name "Xore SSO - laptop"
```

---

## 13. Threat model re-evaluation

After implementing all four phases:

| Threat | Before | After |
|---|---|---|
| Cookie theft via XSS | `HttpOnly` reduces risk | Token useless without matching client private key |
| Cookie from access log | ❌ Replay possible | ✅ Replay fails (implicit assertion mismatch) |
| MITM between browser and Traefik | TLS prevents passive read | mTLS adds mutual authentication |
| Compromised Traefik forwarding stolen cookie to another service | ❌ | ✅ `cnf` claim verified at auth-portal |
| Cert-less session replayed with a cert | N/A | ✅ Bound sessions reject no-cert presenters |
| Cert-bound session replayed with a different cert | N/A | ✅ Thumbprint mismatch → reject |
| Cookie replay after cert rotation | N/A | ✅ New thumbprint → automatic session invalidation |

**What mTLS does NOT protect against:**

- An attacker who has stolen both the cookie AND the client private key (full device compromise).
  Mitigate with hardware-backed keys (OS keychain, YubiKey PIV slot).
- Server-side session store compromise. Mitigate with the PASETO encryption (payload confidential)
  and per-session revocation already in `sessions.go`.

---

## 14. Deployment checklist

### Phase 1 — PASETO cert binding (no infra change)
- [ ] Add `mtls.go` with `certThumbprint`, `clientCert`, `pasetoAssertion`
- [ ] Extend `sessionPayload` with `CertThumbprint string \`json:"cnf_x5t,omitempty"\``
- [ ] Update `issueSessionPASETO` to accept and embed thumbprint
- [ ] Update `parseSessionPASETO` to verify thumbprint via implicit assertion + cnf claim
- [ ] Update `server.session()` to extract cert and pass thumbprint
- [ ] Update `server.login()` to call `setCookiePASETO(w, cl, thumb)` 
- [ ] Extend `sessionClaims` with `certThumbprint` field
- [ ] Add `CertBound bool` to `sessionInfo` in `sessions.go`
- [ ] Update `reg.touch()` signature
- [ ] Add `TestCertBoundSessionRejectedWithWrongCert` unit test
- [ ] Add `TestCertBoundSessionRejectedWithNoCert` unit test
- [ ] Add `TestUnboundSessionStillAccepted` unit test (backward compat)

### Phase 2 — Direct mTLS on auth-portal (optional, defence-in-depth)
- [ ] Add `MTLS_ENABLED`, `TLS_CERT_FILE`, `TLS_KEY_FILE` env-vars to `config`
- [ ] Conditionally call `srv.ListenAndServeTLS()` when `MTLS_ENABLED=true`
- [ ] Generate internal server cert for auth-portal

### Phase 3 — Traefik passTLSClientCert forwarding
- [ ] Add `pass-client-cert` middleware to Traefik dynamic config
- [ ] Attach to `auth-portal` router
- [ ] Update `clientCert()` to call `clientCertFromHeader()` with trust guard
- [ ] Test: verify Traefik sets `X-Forwarded-Tls-Client-Cert` header correctly

### Phase 4 — Enforcement and observability
- [ ] Add cert-bound session count to Prometheus metrics
- [ ] Add `cert_bound` field to admin panel session list
- [ ] Log thumbprint (first 8 chars) on binding verification
- [ ] Set `REQUIRE_CLIENT_CERT=true` for routes where mandatory enforcement is desired

---

## 15. References

| # | Source |
|---|---|
| 1 | RFC 8705 (2020) — *OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens* |
| 2 | IETF draft-mw-oauth-tls-session-bound-tokens-07 (June 2026) — *TLS-Session-Bound Access Tokens for OAuth 2.0* |
| 3 | RFC 5705 (2010) — *Keying Material Exporters for Transport Layer Security (TLS)* |
| 4 | PASETO v4 Specification — `paseto-standard/paseto-spec/docs/01-Protocol-Versions/Version4.md` |
| 5 | Go `crypto/tls` package — `tls.Config.ClientAuth`, `tls.ConnectionState.PeerCertificates` |
| 6 | Traefik `passTLSClientCert` middleware documentation |
| 7 | NIST SP 800-63B Rev 4 (July 2025) — AAL3 hardware-backed authenticator requirements |
| 8 | TOKEN-HARDENING-GUIDE.md (this repo) — PASETO v4.local migration path |
| 9 | IMPROVEMENT-GUIDE.md (this repo) — priority matrix and security gap analysis |
| 10 | Go blog — *Mutual TLS: Authenticating Connections with Client Certificates* (2021) |
