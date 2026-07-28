// forward-auth — a hardened single-sign-on gate for Traefik's forwardAuth
// middleware. One login at auth.<domain> protects every service you attach the
// `forward-auth` middleware to, via an HMAC-signed cookie scoped to the whole
// parent domain (SSO across all subdomains).
//
// Endpoints (all under /_auth so they never clash with a protected app):
//
//	GET  /_auth/verify        — Traefik calls this; 2xx = allow, 302 = go log in
//	GET  /_auth/login         — the login page (served on auth.<domain>)
//	POST /_auth/login         — validate credentials (+ per-user TOTP), set cookie
//	GET  /_auth/logout        — clear the cookie
//	GET  /_auth/health        — unauthenticated health probe
//	GET  /_auth/enroll        — session-gated TOTP enrollment (QR + confirm)
//	GET  /_auth/password      — self-service password change
//	GET  /auth/app            — app shell: settings + admin UI (session-gated)
//	GET  /_auth/admin         — legacy route, redirects to /auth/app
//	GET  /_auth/admin/api/*   — admin JSON API (CSRF-protected)
//	GET  /_auth/metrics       — Prometheus metrics (METRICS_TOKEN-gated)
//
// Users live in a JSON file (USERS_FILE, default /data/users.json) with
// bcrypt password hashes, per-user TOTP secrets, backup codes, roles and
// per-user host allowlists. On first start with an empty store, an admin
// user is bootstrapped from AUTH_USERNAME / AUTH_PASSWORD / TOTP_SECRET so
// existing deployments upgrade in place. TOTP enrollment happens in-session
// at /_auth/enroll — the old public FIRST_RUN setup page is gone.
//
// Hardening: bcrypt password hashes, per-IP brute-force lockout with
// exponential backoff, TOTP replay protection, constant-time compares,
// session revocation (per-user generation + per-session ID), trusted-proxy
// client IP validation, signed CSRF+timing token, hidden bot-trap field,
// minimum form dwell time, open-redirect protection, generic errors (no user
// enumeration), Secure/HttpOnly/SameSite cookies, JSON audit logging and
// optional webhook alerts.
package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"golang.org/x/crypto/hkdf"
	pasetov4 "zntr.io/paseto/v4"
)

type config struct {
	listen          string
	authHost        string
	cookieName      string
	cookieDom       string
	secret          []byte
	oldSecrets      [][]byte
	username        string // bootstrap only
	password        string // bootstrap only (plaintext or bcrypt hash)
	totpSecret      string // bootstrap only
	totpIssuer      string
	usersFile       string
	requireTOTP     bool
	trustDevDays    int
	ttl             time.Duration
	idleTimeout     time.Duration
	maxAttempts     int
	lockout         time.Duration
	minDwell        time.Duration
	formTTL         time.Duration
	secure          bool
	auditLog        string
	ringCap         int
	webhookURL      string
	webhookProvider string
	metricsToken    string
	trustedNets     []*net.IPNet
	maxBodyBytes    int64
	orgID           string
	ssoURL          string
	pasetoKey       pasetov4.LocalKey // XChaCha20 + BLAKE2b key for PASETO v4.local session tokens
	pasetoKeySet    bool              // true when PASETO_KEY was set explicitly
	oldPasetoKeys   []pasetov4.LocalKey
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// getenvFile supports docker secrets: FOO_FILE=/run/secrets/foo takes
// precedence over FOO.
func getenvFile(k, def string) string {
	if p := os.Getenv(k + "_FILE"); p != "" {
		if raw, err := os.ReadFile(p); err == nil {
			return strings.TrimSpace(string(raw))
		}
	}
	return getenv(k, def)
}

func requireEnv(k string) string {
	v := os.Getenv(k)
	if v == "" {
		log.Fatalf("required env var %s is not set", k)
	}
	return v
}

func requireEnvFile(k string) string {
	v := getenvFile(k, "")
	if v == "" {
		log.Fatalf("required env var %s is not set", k)
	}
	return v
}

func atoi(s string, def int) int {
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return def
}

// Default trusted proxies: loopback + RFC1918 + ULA, i.e. the docker network
// Traefik connects from. Forwarded-for headers are only honored from these.
const defaultTrustedProxies = "127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7,::1/128"

func parseCIDRs(s string, logger *slog.Logger) []*net.IPNet {
	var nets []*net.IPNet
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(part); err == nil {
			nets = append(nets, n)
		} else {
			logger.Warn("ignoring invalid TRUSTED_PROXIES entry", "entry", part)
		}
	}
	return nets
}

func loadConfig(logger *slog.Logger) config {
	secret := []byte(getenvFile("COOKIE_SECRET", ""))
	if len(secret) == 0 {
		secret = make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			panic("crypto/rand failed: " + err.Error())
		}
		logger.Warn("COOKIE_SECRET not set — generated a random key; sessions drop on restart and won't match across replicas")
	}
	authHost := getenv("AUTH_HOST", "")
	if authHost == "" {
		log.Fatal("AUTH_HOST must be set")
	}
	var oldSecrets [][]byte
	for _, old := range strings.Split(getenvFile("COOKIE_SECRET_PREVIOUS", ""), ",") {
		if old = strings.TrimSpace(old); old != "" {
			oldSecrets = append(oldSecrets, []byte(old))
		}
	}
	if len(oldSecrets) > 0 {
		// Session cookies are PASETO now — old cookie secrets only cover the
		// remaining HMAC tokens (device trust, form, pending). Session-key
		// rotation goes through PASETO_KEY_PREVIOUS.
		logger.Info("COOKIE_SECRET_PREVIOUS is set — covers only legacy HMAC device/form tokens, not sessions")
	}
	// PASETO_KEY must be exactly 64 hex chars (32 bytes) and is required.
	// When unset, a key is still derived from COOKIE_SECRET so the config
	// object is usable, but validate() rejects the deployment — silent
	// derivation was only allowed during the migration window.
	var pasetoKey pasetov4.LocalKey
	pasetoKeySet := false
	if hex64 := getenvFile("PASETO_KEY", ""); hex64 != "" {
		decoded, err := hex.DecodeString(hex64)
		if err != nil || len(decoded) != 32 {
			log.Fatal("PASETO_KEY must be exactly 64 hex chars (32 bytes)")
		}
		copy(pasetoKey[:], decoded)
		pasetoKeySet = true
	} else {
		k, err := deriveKey(secret, "paseto-v4-local")
		if err != nil {
			log.Fatalf("derive PASETO key: %v", err)
		}
		pasetoKey = pasetov4.LocalKey(k)
		logger.Warn("PASETO_KEY not set — derived from COOKIE_SECRET for now; set it explicitly, derived keys are rejected at startup")
	}
	var oldPasetoKeys []pasetov4.LocalKey
	for _, old := range strings.Split(getenvFile("PASETO_KEY_PREVIOUS", ""), ",") {
		if old = strings.TrimSpace(old); old != "" {
			decoded, err := hex.DecodeString(old)
			if err != nil || len(decoded) != 32 {
				log.Fatal("each PASETO_KEY_PREVIOUS value must be exactly 64 hex chars (32 bytes)")
			}
			var k pasetov4.LocalKey
			copy(k[:], decoded)
			oldPasetoKeys = append(oldPasetoKeys, k)
		}
	}
	return config{
		listen:          getenv("LISTEN_ADDR", ":4181"),
		authHost:        authHost,
		cookieName:      getenv("COOKIE_NAME", "xore_sso"),
		cookieDom:       getenv("COOKIE_DOMAIN", ""),
		secret:          secret,
		oldSecrets:      oldSecrets,
		username:        requireEnv("AUTH_USERNAME"),
		password:        requireEnvFile("AUTH_PASSWORD"),
		totpSecret:      normalizeB32(getenvFile("TOTP_SECRET", "")),
		totpIssuer:      getenv("TOTP_ISSUER", authHost),
		usersFile:       getenv("USERS_FILE", "/data/users.json"),
		requireTOTP:     getenv("REQUIRE_TOTP", "true") != "false",
		trustDevDays:    atoi(os.Getenv("TRUST_DEVICE_DAYS"), 0),
		ttl:             time.Duration(atoi(os.Getenv("SESSION_TTL_HOURS"), 12)) * time.Hour,
		idleTimeout:     time.Duration(atoi(os.Getenv("IDLE_TIMEOUT_MINUTES"), 60)) * time.Minute,
		maxAttempts:     atoi(os.Getenv("MAX_ATTEMPTS"), 5),
		lockout:         time.Duration(atoi(os.Getenv("LOCKOUT_MINUTES"), 15)) * time.Minute,
		minDwell:        time.Duration(atoi(os.Getenv("MIN_DWELL_SECONDS"), 2)) * time.Second,
		formTTL:         time.Duration(atoi(os.Getenv("FORM_TTL_MINUTES"), 15)) * time.Minute,
		secure:          getenv("COOKIE_SECURE", "true") != "false",
		auditLog:        getenv("AUDIT_LOG", ""),
		ringCap:         atoi(os.Getenv("AUDIT_RING"), 500),
		webhookURL:      getenv("WEBHOOK_URL", ""),
		webhookProvider: getenv("WEBHOOK_PROVIDER", "raw"),
		metricsToken:    getenvFile("METRICS_TOKEN", ""),
		trustedNets:     parseCIDRs(getenv("TRUSTED_PROXIES", defaultTrustedProxies), logger),
		maxBodyBytes:    int64(atoi(os.Getenv("MAX_BODY_KB"), 64)) * 1024,
		orgID:           getenv("ORG_ID", ""),
		ssoURL:          getenv("SSO_URL", ""),
		pasetoKey:       pasetoKey,
		pasetoKeySet:    pasetoKeySet,
		oldPasetoKeys:   oldPasetoKeys,
	}
}

// deriveKey stretches secret into a purpose-labelled 32-byte key with
// HKDF-SHA-256 (RFC 5869; salt nil, info = label).
func deriveKey(secret []byte, label string) ([32]byte, error) {
	var key [32]byte
	r := hkdf.New(sha256.New, secret, nil, []byte(label))
	if _, err := io.ReadFull(r, key[:]); err != nil {
		return [32]byte{}, err
	}
	return key, nil
}

func (c config) validate() error {
	var problems []string
	if c.authHost == "" || normalizeHost(c.authHost) != strings.ToLower(c.authHost) {
		problems = append(problems, "AUTH_HOST must be a hostname without a scheme or port")
	}
	if len(c.secret) < 32 {
		problems = append(problems, "COOKIE_SECRET must be at least 32 bytes")
	}
	for _, old := range c.oldSecrets {
		if len(old) < 32 {
			problems = append(problems, "each COOKIE_SECRET_PREVIOUS value must be at least 32 bytes")
		}
	}
	if string(c.secret) == "CHANGE_ME_openssl_rand_hex_32" {
		problems = append(problems, "COOKIE_SECRET still uses the public placeholder")
	}
	if c.password == "change-me-auth" {
		problems = append(problems, "AUTH_PASSWORD still uses the public placeholder")
	}
	if c.ttl <= 0 {
		problems = append(problems, "SESSION_TTL_HOURS must be positive")
	}
	if c.maxAttempts < 1 {
		problems = append(problems, "MAX_ATTEMPTS must be positive")
	}
	if c.lockout <= 0 {
		problems = append(problems, "LOCKOUT_MINUTES must be positive")
	}
	if c.minDwell < 0 || c.formTTL <= c.minDwell {
		problems = append(problems, "form TTL must exceed non-negative dwell time")
	}
	if c.ringCap < 1 || c.ringCap > 100000 {
		problems = append(problems, "AUDIT_RING must be between 1 and 100000")
	}
	if c.maxBodyBytes < 1024 || c.maxBodyBytes > 10<<20 {
		problems = append(problems, "MAX_BODY_KB must be between 1 and 10240")
	}
	if len(c.trustedNets) == 0 {
		problems = append(problems, "TRUSTED_PROXIES must contain at least one valid CIDR")
	}
	switch c.webhookProvider {
	case "", "raw", "slack", "ntfy", "gotify":
	default:
		problems = append(problems, "WEBHOOK_PROVIDER must be raw, slack, ntfy or gotify")
	}
	if !c.pasetoKeySet {
		problems = append(problems, "PASETO_KEY must be set explicitly (64 hex chars) — silent derivation is no longer supported")
	}
	if len(problems) == 0 {
		return nil
	}
	return errors.New(strings.Join(problems, "; "))
}

func (c config) mac(msg string) string {
	return macWith(c.secret, msg)
}

func macWith(secret []byte, msg string) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(msg))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (c config) validMAC(msg, got string) bool {
	if subtle.ConstantTimeCompare([]byte(got), []byte(c.mac(msg))) == 1 {
		return true
	}
	for _, secret := range c.oldSecrets {
		if subtle.ConstantTimeCompare([]byte(got), []byte(macWith(secret, msg))) == 1 {
			return true
		}
	}
	return false
}

// --- session tokens ---------------------------------------------------------
//
// Session cookies are PASETO v4.local (XChaCha20 + BLAKE2b AEAD) — see the
// PASETO section below. The legacy pipe-delimited HMAC format was removed
// after the migration window (roadmap Step 17).
//   gen   — user's session generation; bumping it invalidates all tokens
//   sid   — random per-session id, for the registry and single-session revoke
//   flags — "c" must change password, "p" must enroll TOTP (may combine)

type sessionClaims struct {
	user  string
	gen   int
	sid   string
	flags string
	exp   int64
}

func (cl sessionClaims) has(flag string) bool { return strings.Contains(cl.flags, flag) }

func newSID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// csrfToken derives a per-session CSRF token for the admin API — no expiry
// of its own, it dies with the session.
func (c config) csrfToken(sid string) string { return c.mac("csrf|" + sid) }

// --- PASETO v4.local session tokens -------------------------------------------
//
// The only session format: claims are JSON, encrypted and authenticated with
// XChaCha20 + BLAKE2b. Key rotation happens via PASETO_KEY_PREVIOUS; tokens
// verified with an old key are transparently re-issued under the current one.

// pasetoAssertion is the implicit assertion for session tokens — MAC'd but
// not stored in the token. Step 19 will additionally bind it to the client
// certificate thumbprint.
func pasetoAssertion() []byte { return []byte("forward-auth session v1") }

// sessionPayload is the JSON claims set inside the encrypted token.
type sessionPayload struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	IssuedAt  int64  `json:"iat"`
	NotBefore int64  `json:"nbf,omitempty"`
	Expiry    int64  `json:"exp"`
	TokenID   string `json:"jti"`
	Gen       int    `json:"gen"`
	Flags     string `json:"flags,omitempty"`
}

func (c config) issueSessionPASETO(cl sessionClaims) (string, error) {
	pl, err := json.Marshal(sessionPayload{
		Issuer:   c.authHost,
		Subject:  cl.user,
		IssuedAt: time.Now().Unix(),
		Expiry:   cl.exp,
		TokenID:  cl.sid,
		Gen:      cl.gen,
		Flags:    cl.flags,
	})
	if err != nil {
		return "", err
	}
	key := c.pasetoKey
	return pasetov4.Encrypt(rand.Reader, &key, pl, nil, pasetoAssertion())
}

// parseSessionPASETO decrypts and validates fail-closed: issuer, expiry,
// future-issued guard (30 s clock skew), non-empty subject and token ID.
// The current key is tried first, then each PASETO_KEY_PREVIOUS key in
// order; usedOldKey reports which path succeeded.
func (c config) parseSessionPASETO(tok string) (sessionClaims, bool, bool) {
	// The library panics on truncated payloads (zntr.io/paseto v1.4.0
	// local.go slices the nonce without a length check) — pre-validate the
	// shape so a malformed cookie is a clean reject, not a panic.
	payload := strings.TrimPrefix(tok, "v4.local.")
	if i := strings.Index(payload, "."); i >= 0 { // strip optional footer
		payload = payload[:i]
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil || len(raw) < 64 { // 32-byte nonce + 32-byte MAC minimum
		return sessionClaims{}, false, false
	}
	key := c.pasetoKey
	plain, err := pasetov4.Decrypt(&key, tok, nil, pasetoAssertion())
	usedOldKey := false
	if err != nil {
		for i := range c.oldPasetoKeys {
			key = c.oldPasetoKeys[i]
			if plain, err = pasetov4.Decrypt(&key, tok, nil, pasetoAssertion()); err == nil {
				usedOldKey = true
				break
			}
		}
		if err != nil {
			return sessionClaims{}, false, false
		}
	}
	var pl sessionPayload
	if err := json.Unmarshal(plain, &pl); err != nil {
		return sessionClaims{}, false, false
	}
	now := time.Now().Unix()
	if pl.Issuer != c.authHost || pl.Subject == "" || pl.TokenID == "" {
		return sessionClaims{}, false, false
	}
	if now >= pl.Expiry {
		return sessionClaims{}, false, false
	}
	if pl.IssuedAt > now+30 {
		return sessionClaims{}, false, false
	}
	return sessionClaims{
		user:  pl.Subject,
		gen:   pl.Gen,
		sid:   pl.TokenID,
		flags: pl.Flags,
		exp:   pl.Expiry,
	}, true, usedOldKey
}

// --- device trust ("remember this device" skips TOTP) -----------------------

func (c config) issueDevice(user string, gen int) string {
	exp := strconv.FormatInt(time.Now().Add(time.Duration(c.trustDevDays)*24*time.Hour).Unix(), 10)
	body := "dev|" + exp + "|" + user + "|" + strconv.Itoa(gen)
	return body + "|" + c.mac(body)
}

func (c config) validDevice(tok, user string, gen int) bool {
	parts := strings.Split(tok, "|")
	if len(parts) != 5 || parts[0] != "dev" || parts[2] != user || parts[3] != strconv.Itoa(gen) {
		return false
	}
	body := strings.Join(parts[:4], "|")
	if !c.validMAC(body, parts[4]) {
		return false
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	return err == nil && time.Now().Unix() < exp
}

// --- pending (post-password, pre-TOTP) tokens --------------------------------
//
// After a correct password for a TOTP-enrolled user the server sets a
// short-lived pending cookie; only /_auth/totp accepts it. The cookie proves
// "password OK a moment ago" and carries the remember-device choice.

const pendingTTL = 5 * time.Minute

func (c config) issuePending(user string, remember bool) string {
	exp := strconv.FormatInt(time.Now().Add(pendingTTL).Unix(), 10)
	rem := "0"
	if remember {
		rem = "1"
	}
	body := "pend|" + exp + "|" + user + "|" + rem
	return body + "|" + c.mac(body)
}

func (c config) parsePending(tok string) (user string, remember bool, ok bool) {
	parts := strings.Split(tok, "|")
	if len(parts) != 5 || parts[0] != "pend" {
		return "", false, false
	}
	body := strings.Join(parts[:4], "|")
	if !c.validMAC(body, parts[4]) {
		return "", false, false
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || time.Now().Unix() >= exp {
		return "", false, false
	}
	return parts[2], parts[3] == "1", true
}

// --- form (CSRF + timing) tokens --------------------------------------------

func (c config) issueForm() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	body := strconv.FormatInt(time.Now().Unix(), 10) + "|" + hex.EncodeToString(b)
	return body + "|" + c.mac(body)
}

func (c config) checkForm(tok string) bool {
	parts := strings.SplitN(tok, "|", 3)
	if len(parts) != 3 {
		return false
	}
	body := parts[0] + "|" + parts[1]
	if !c.validMAC(body, parts[2]) {
		return false
	}
	issued, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return false
	}
	age := time.Since(time.Unix(issued, 0))
	return age >= c.minDwell && age <= c.formTTL
}

// totpURI returns the otpauth:// URI for QR enrollment. Deliberately minimal:
// only secret + issuer. algorithm/digits/period are the spec defaults anyway,
// and some strict parsers (1Password among them) reject URIs over extra or
// unexpected parameters — the fewer moving parts, the more apps scan it.
func (c config) totpURI(user, secret string) string {
	return fmt.Sprintf(
		"otpauth://totp/%s:%s?secret=%s&issuer=%s",
		url.PathEscape(c.totpIssuer),
		url.PathEscape(user),
		secret, // normalized base32 — never percent-encoded
		url.QueryEscape(c.totpIssuer),
	)
}

// --- brute-force throttle ---------------------------------------------------

type entry struct {
	fails     int
	lockUntil time.Time
}

type throttle struct {
	mu   sync.Mutex
	m    map[string]*entry
	cfg  config
	path string
}

func newThrottle(cfg config) *throttle { return &throttle{m: map[string]*entry{}, cfg: cfg} }

// throttleEntryJSON is the on-disk shape of an entry (entry's fields are
// unexported, so encoding/json can't see them directly).
type throttleEntryJSON struct {
	Fails     int       `json:"fails"`
	LockUntil time.Time `json:"lock_until"`
}

// load reads persisted throttle state from path (missing file is not an
// error) and remembers the path for future persists.
func (t *throttle) load(path string) error {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		t.mu.Lock()
		t.path = path
		t.mu.Unlock()
		return nil
	}
	if err != nil {
		return err
	}
	var m map[string]throttleEntryJSON
	if err := json.Unmarshal(raw, &m); err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.path = path
	for k, v := range m {
		t.m[k] = &entry{fails: v.Fails, lockUntil: v.LockUntil}
	}
	t.pruneLocked(time.Now())
	return nil
}

// persist writes the throttle map to path atomically (temp file + rename).
func (t *throttle) persist(path string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.persistLocked(path)
}

// persistLocked persists with the caller holding t.mu. Expired entries are
// pruned first — no point writing lockouts that have already cleared.
func (t *throttle) persistLocked(path string) error {
	t.pruneLocked(time.Now())
	out := make(map[string]throttleEntryJSON, len(t.m))
	for k, v := range t.m {
		out[k] = throttleEntryJSON{Fails: v.fails, LockUntil: v.lockUntil}
	}
	raw, err := json.Marshal(out)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".throttle-*.tmp")
	if err != nil {
		return err
	}
	name := f.Name()
	defer func() { _ = os.Remove(name) }() // no-op once renamed on the success path
	if err = f.Chmod(0o600); err == nil {
		_, err = f.Write(append(raw, '\n'))
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, path)
}

func (t *throttle) locked(ip string) (bool, time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.m[ip]
	if e == nil {
		return false, 0
	}
	if e.lockUntil.IsZero() {
		// counting entry, no lock yet — keep it, the fails must accumulate
		return false, 0
	}
	if d := time.Until(e.lockUntil); d > 0 {
		return true, d
	}
	if time.Since(e.lockUntil) > t.cfg.lockout {
		delete(t.m, ip)
	}
	return false, 0
}

func (t *throttle) fail(ip string) (lockedNow bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.m[ip]
	if e == nil {
		e = &entry{}
		t.m[ip] = e
	}
	e.fails++
	if len(t.m) > 8192 {
		t.pruneLocked(time.Now())
	}
	if e.fails >= t.cfg.maxAttempts {
		mult := time.Duration(1) << uint(min(e.fails-t.cfg.maxAttempts, 10))
		d := t.cfg.lockout * mult
		if d > 24*time.Hour {
			d = 24 * time.Hour
		}
		e.lockUntil = time.Now().Add(d)
		if t.path != "" {
			_ = t.persistLocked(t.path) // durable lockout; best-effort
		}
		return true
	}
	return false
}

func (t *throttle) pruneLocked(now time.Time) {
	for key, e := range t.m {
		if e.lockUntil.IsZero() {
			continue // counting entry — no lock timestamp to expire
		}
		if !e.lockUntil.After(now) && now.Sub(e.lockUntil) > t.cfg.lockout {
			delete(t.m, key)
		}
	}
	for key := range t.m {
		if len(t.m) <= 4096 {
			break
		}
		delete(t.m, key)
	}
}

func (t *throttle) reset(ip string) {
	t.mu.Lock()
	delete(t.m, ip)
	t.mu.Unlock()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// --- server -----------------------------------------------------------------

type server struct {
	cfg        config
	log        *slog.Logger
	tr         *throttle
	aud        *auditor
	users      *userStore
	reg        *sessionRegistry
	ntf        *notifier
	wa         *webauthn.WebAuthn
	ceremonies *ceremonyStore
	startedAt  time.Time
}

// clientIP returns the real client address. Forwarded headers are only
// honored when the direct peer is a trusted proxy — otherwise anyone who can
// reach the container directly could spoof a fresh IP per request and walk
// straight past the lockout.
func (s *server) clientIP(r *http.Request) string {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	peer := net.ParseIP(host)
	trusted := false
	for _, n := range s.cfg.trustedNets {
		if peer != nil && n.Contains(peer) {
			trusted = true
			break
		}
	}
	if trusted {
		if ip := r.Header.Get("CF-Connecting-IP"); ip != "" {
			if parsed := net.ParseIP(strings.TrimSpace(ip)); parsed != nil {
				return parsed.String()
			}
		}
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			for i := len(parts) - 1; i >= 0; i-- {
				candidate := net.ParseIP(strings.TrimSpace(parts[i]))
				if candidate == nil {
					continue
				}
				isTrusted := false
				for _, n := range s.cfg.trustedNets {
					if n.Contains(candidate) {
						isTrusted = true
						break
					}
				}
				if !isTrusted {
					return candidate.String()
				}
			}
		}
	}
	return host
}

func normalizeHost(raw string) string {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if h, _, err := net.SplitHostPort(raw); err == nil {
		raw = h
	}
	raw = strings.Trim(raw, "[]")
	return strings.TrimSuffix(raw, ".")
}

func (c config) safeRedirect(raw string) string {
	fallback := "https://" + c.authHost + "/_auth/ok"
	if raw == "" {
		return fallback
	}

	// Some clients/browsers may treat backslashes as path separators.
	raw = strings.ReplaceAll(raw, "\\", "/")

	u, err := url.Parse(raw)
	if err != nil {
		return fallback
	}

	// Allow local relative redirects only when they are absolute-path references.
	if u.Scheme == "" && u.Host == "" {
		if strings.HasPrefix(u.Path, "/") {
			return u.EscapedPath() + "?" + strings.TrimPrefix(u.RawQuery, "?")
		}
		return fallback
	}

	// For absolute URLs, require HTTPS and no userinfo.
	if u.Scheme != "https" || u.User != nil {
		return fallback
	}

	host := normalizeHost(u.Hostname())
	if host == "" {
		return fallback
	}

	dom := strings.TrimPrefix(c.cookieDom, ".")
	if dom == "" {
		dom = normalizeHost(c.authHost)
	}
	if host != dom && !strings.HasSuffix(host, "."+dom) {
		return fallback
	}

	// Rebuild canonical redirect from validated components.
	out := "https://" + host + u.EscapedPath()
	if u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	if u.Fragment != "" {
		out += "#" + u.Fragment
	}
	return out
}

func nonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}

func secHeaders(w http.ResponseWriter, n string) {
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy",
		"default-src 'none'; style-src 'self' 'unsafe-inline'; script-src 'nonce-"+n+"'; img-src data:; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
}

func (s *server) setCookie(w http.ResponseWriter, cl sessionClaims) {
	tok, err := s.cfg.issueSessionPASETO(cl)
	if err != nil {
		panic("paseto encrypt: " + err.Error())
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

func (s *server) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: s.cfg.cookieName, Value: "", Path: "/", Domain: s.cfg.cookieDom,
		HttpOnly: true, Secure: s.cfg.secure, SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
}

func (s *server) setDeviceCookie(w http.ResponseWriter, user string) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cfg.cookieName + "_dev",
		Value:    s.cfg.issueDevice(user, s.users.get(user).DeviceGen),
		Path:     "/_auth",
		Domain:   "", // host-only: device trust doesn't need to cross subdomains
		HttpOnly: true,
		Secure:   s.cfg.secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   s.cfg.trustDevDays * 24 * 3600,
	})
}

func (s *server) setPendingCookie(w http.ResponseWriter, user string, remember bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cfg.cookieName + "_pend",
		Value:    s.cfg.issuePending(user, remember),
		Path:     "/_auth",
		Domain:   "", // host-only: the 2FA step never leaves the auth host
		HttpOnly: true,
		Secure:   s.cfg.secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(pendingTTL.Seconds()),
	})
}

func (s *server) clearPendingCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: s.cfg.cookieName + "_pend", Value: "", Path: "/_auth", Domain: "",
		HttpOnly: true, Secure: s.cfg.secure, SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
}

func (s *server) trustedDevice(r *http.Request, user string) bool {
	if s.cfg.trustDevDays <= 0 {
		return false
	}
	c, err := r.Cookie(s.cfg.cookieName + "_dev")
	u := s.users.get(user)
	return err == nil && u != nil && s.cfg.validDevice(c.Value, user, u.DeviceGen)
}

// session returns the validated claims and user for a request, checking
// signature, expiry, single-session revocation, user existence, disabled
// flag and generation. Tokens verified with a previous PASETO key are
// transparently re-issued under the current key.
func (s *server) session(w http.ResponseWriter, r *http.Request) (sessionClaims, *User, bool) {
	c, err := r.Cookie(s.cfg.cookieName)
	if err != nil {
		return sessionClaims{}, nil, false
	}
	cl, ok, usedOldKey := s.cfg.parseSessionPASETO(c.Value)
	if !ok || s.reg.isRevoked(cl.sid) {
		return sessionClaims{}, nil, false
	}
	if usedOldKey {
		// transparent key rotation: re-issue under the current key
		s.setCookie(w, cl)
		s.log.Info("paseto_token_rotated", "user", cl.user)
	}
	u := s.users.get(cl.user)
	if u == nil || u.Disabled || u.Gen != cl.gen {
		return sessionClaims{}, nil, false
	}
	if s.cfg.idleTimeout > 0 {
		if last := s.reg.lastActive(cl.sid); !last.IsZero() &&
			time.Since(last) > s.cfg.idleTimeout {
			_ = s.reg.revoke(cl.sid)
			s.audit("idle_timeout", s.clientIP(r), cl.user, r)
			return sessionClaims{}, nil, false
		}
	}
	return cl, u, true
}

// flagsFor computes the pending-action flags for a user at login time.
func (s *server) flagsFor(u *User) string {
	f := ""
	if u.MustChange {
		f += "c"
	}
	if s.cfg.requireTOTP && u.TOTPSecret == "" {
		f += "p"
	}
	return f
}

// pendingRedirect returns the URL a flagged session must visit first, or "".
func pendingRedirect(cl sessionClaims, authHost string) string {
	switch {
	case cl.has("c"):
		return "https://" + authHost + "/_auth/password"
	case cl.has("p"):
		return "https://" + authHost + "/_auth/enroll"
	}
	return ""
}

// --- handlers ---------------------------------------------------------------

func (s *server) verify(w http.ResponseWriter, r *http.Request) {
	n := nonce()
	secHeaders(w, n)
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cl, u, ok := s.session(w, r)
	if ok {
		if rd := pendingRedirect(cl, s.cfg.authHost); rd != "" {
			http.Redirect(w, r, rd, http.StatusFound)
			return
		}
		host := r.Header.Get("X-Forwarded-Host")
		if normalizeHost(host) == "" {
			http.Error(w, "missing forwarded host", http.StatusBadRequest)
			return
		}
		if !u.hostAllowed(host) {
			s.audit("forbidden_host", s.clientIP(r), u.Username, r)
			secHeaders(w, n)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusForbidden)
			s.renderForbidden(w, normalizeHost(host), n)
			return
		}
		s.reg.touch(cl.sid, u.Username, s.clientIP(r), r.UserAgent())
		w.Header().Set("X-Auth-User", u.Username)
		w.Header().Set("X-Auth-Role", u.Role)
		w.WriteHeader(http.StatusOK)
		return
	}
	proto := firstNonEmpty(r.Header.Get("X-Forwarded-Proto"), "https")
	host := r.Header.Get("X-Forwarded-Host")
	uri := r.Header.Get("X-Forwarded-Uri")
	orig := proto + "://" + host + uri
	rd := s.cfg.safeRedirect(orig)
	login := "https://" + s.cfg.authHost + "/_auth/login?rd=" + url.QueryEscape(rd)
	http.Redirect(w, r, login, http.StatusFound)
}

func (s *server) login(w http.ResponseWriter, r *http.Request) {
	n := nonce()
	secHeaders(w, n)
	rd := s.cfg.safeRedirect(r.URL.Query().Get("rd"))
	ip := s.clientIP(r)

	if r.Method == http.MethodGet {
		if cl, _, ok := s.session(w, r); ok {
			if p := pendingRedirect(cl, s.cfg.authHost); p != "" {
				http.Redirect(w, r, p, http.StatusFound)
				return
			}
			http.Redirect(w, r, rd, http.StatusFound)
			return
		}
		s.renderLogin(w, rd, "", n)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.maxBodyBytes)

	if locked, d := s.tr.locked(ip); locked {
		s.audit("locked_out", ip, "", r)
		s.renderLogin(w, rd, "Too many attempts. Try again in "+d.Round(time.Second).String()+".", n)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.fail(w, r, ip, rd, "bad_request", n)
		return
	}
	rd = s.cfg.safeRedirect(r.PostForm.Get("rd"))

	if r.PostForm.Get("website") != "" {
		s.fail(w, r, ip, rd, "honeypot", n)
		return
	}
	if !s.cfg.checkForm(r.PostForm.Get("ft")) {
		s.fail(w, r, ip, rd, "bad_form_token", n)
		return
	}

	username := r.PostForm.Get("username")
	if locked, d := s.tr.locked("user:" + strings.ToLower(username)); locked {
		s.audit("locked_out", ip, "", r)
		s.renderLogin(w, rd, "Too many attempts. Try again in "+d.Round(time.Second).String()+".", n)
		return
	}
	if !s.users.checkPassword(username, r.PostForm.Get("password")) {
		s.fail(w, r, ip, rd, "bad_credentials", n)
		return
	}
	u := s.users.get(username)
	if u.Disabled {
		s.fail(w, r, ip, rd, "disabled_user", n)
		return
	}
	if u.TOTPSecret != "" && !s.trustedDevice(r, username) {
		// password OK — the second factor happens on the verify page,
		// gated by a short-lived pending cookie
		s.setPendingCookie(w, username, r.PostForm.Get("remember") == "1")
		s.renderVerify(w, rd, "", n)
		return
	}
	s.finishLogin(w, r, u, ip, rd, r.PostForm.Get("remember") == "1")
}

// finishLogin completes a successful authentication: clears the throttles,
// records the login, issues the session cookie and redirects. remember
// controls the trusted-device cookie (only meaningful for TOTP users).
func (s *server) finishLogin(w http.ResponseWriter, r *http.Request, u *User, ip, rd string, remember bool) {
	if remember && s.cfg.trustDevDays > 0 && u.TOTPSecret != "" {
		s.setDeviceCookie(w, u.Username)
	}
	s.tr.reset(ip)
	s.tr.reset("user:" + strings.ToLower(u.Username))
	prevIP := u.LastIP
	if err := s.users.mutate(u.Username, func(u *User) bool {
		u.LastLogin = time.Now().UTC()
		u.LastIP = ip
		return true
	}); err != nil {
		s.log.Error("persist last login", "user", u.Username, "error", err)
		http.Error(w, "authentication storage unavailable", http.StatusServiceUnavailable)
		return
	}
	if prevIP != "" && prevIP != ip {
		s.ntf.send("login_new_ip", u.Username, ip, s.cfg.authHost, "previous ip "+prevIP)
	}

	cl := sessionClaims{
		user:  u.Username,
		gen:   u.Gen,
		sid:   newSID(),
		flags: s.flagsFor(u),
		exp:   time.Now().Add(s.cfg.ttl).Unix(),
	}
	s.setCookie(w, cl)
	s.reg.touch(cl.sid, u.Username, ip, r.UserAgent())
	s.audit("login_ok", ip, u.Username, r)
	if p := pendingRedirect(cl, s.cfg.authHost); p != "" {
		http.Redirect(w, r, p, http.StatusFound)
		return
	}
	http.Redirect(w, r, rd, http.StatusFound)
}

func (s *server) fail(w http.ResponseWriter, r *http.Request, ip, rd, reason, nonce string) {
	username := strings.ToLower(strings.TrimSpace(r.PostForm.Get("username")))
	locked := s.tr.fail(ip)
	if username != "" && s.tr.fail("user:"+username) {
		locked = true
	}
	if locked {
		s.ntf.send("locked_out", r.PostForm.Get("username"), ip, s.cfg.authHost, reason)
	}
	s.audit("login_fail:"+reason, ip, r.PostForm.Get("username"), r)
	s.renderLogin(w, rd, "Invalid credentials.", nonce)
}

// totp is the second step of the two-step login: a valid pending cookie
// (set after a correct password) plus a TOTP or backup code completes the
// sign-in. Anything else redirects back to the login page.
func (s *server) totp(w http.ResponseWriter, r *http.Request) {
	n := nonce()
	secHeaders(w, n)
	loginURL := "https://" + s.cfg.authHost + "/_auth/login"
	if r.Method != http.MethodPost {
		http.Redirect(w, r, loginURL, http.StatusSeeOther)
		return
	}
	user, remember, ok := "", false, false
	if c, err := r.Cookie(s.cfg.cookieName + "_pend"); err == nil {
		user, remember, ok = s.cfg.parsePending(c.Value)
	}
	if !ok {
		http.Redirect(w, r, loginURL, http.StatusSeeOther)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.maxBodyBytes)
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, loginURL, http.StatusSeeOther)
		return
	}
	rd := s.cfg.safeRedirect(r.PostForm.Get("rd"))
	ip := s.clientIP(r)
	u := s.users.get(user)
	if u == nil || u.Disabled || u.TOTPSecret == "" {
		s.clearPendingCookie(w)
		http.Redirect(w, r, loginURL, http.StatusSeeOther)
		return
	}
	if locked, d := s.tr.locked(ip); locked {
		s.audit("locked_out", ip, user, r)
		s.renderVerify(w, rd, "Too many attempts. Try again in "+d.Round(time.Second).String()+".", n)
		return
	}
	if locked, d := s.tr.locked("user:" + strings.ToLower(user)); locked {
		s.audit("locked_out", ip, user, r)
		s.renderVerify(w, rd, "Too many attempts. Try again in "+d.Round(time.Second).String()+".", n)
		return
	}

	code := strings.TrimSpace(r.PostForm.Get("code"))
	switch {
	case len(code) >= 8 && strings.Contains(code, "-"):
		if !s.users.checkBackupCode(user, code) {
			s.totpFail(w, r, ip, user, rd, "bad_backup_code", n)
			return
		}
		s.audit("backup_code_used", ip, user, r)
		s.ntf.send("backup_code_used", user, ip, s.cfg.authHost,
			fmt.Sprintf("%d backup codes remain", len(s.users.get(user).BackupCodes)))
	default:
		if !s.users.checkTOTP(user, code) {
			s.totpFail(w, r, ip, user, rd, "bad_totp", n)
			return
		}
	}

	s.clearPendingCookie(w)
	s.finishLogin(w, r, u, ip, rd, remember)
}

// totpFail is s.fail for the 2FA step: throttle, audit, re-render the
// verify page with a generic error.
func (s *server) totpFail(w http.ResponseWriter, r *http.Request, ip, user, rd, reason, nonce string) {
	locked := s.tr.fail(ip)
	if user != "" && s.tr.fail("user:"+strings.ToLower(user)) {
		locked = true
	}
	if locked {
		s.ntf.send("locked_out", user, ip, s.cfg.authHost, reason)
	}
	s.audit("login_fail:"+reason, ip, user, r)
	s.renderVerify(w, rd, "Invalid code.", nonce)
}

func (s *server) logout(w http.ResponseWriter, r *http.Request) {
	secHeaders(w, nonce())
	if c, err := r.Cookie(s.cfg.cookieName); err == nil {
		if cl, ok, _ := s.cfg.parseSessionPASETO(c.Value); ok {
			if err := s.reg.revoke(cl.sid); err != nil {
				s.log.Error("persist logout revocation", "error", err)
			}
			s.audit("logout", s.clientIP(r), cl.user, r)
		}
	}
	s.clearCookie(w)
	http.Redirect(w, r, "https://"+s.cfg.authHost+"/_auth/login", http.StatusFound)
}

// enroll serves per-user TOTP enrollment: generates a pending secret, shows
// the QR, and commits only once the user proves their app generates valid
// codes. Session-gated — unlike the old FIRST_RUN page, never public.
func (s *server) enroll(w http.ResponseWriter, r *http.Request) {
	n := nonce()
	secHeaders(w, n)
	cl, u, ok := s.session(w, r)
	if !ok {
		http.Redirect(w, r, "https://"+s.cfg.authHost+"/_auth/login", http.StatusFound)
		return
	}
	if cl.has("c") {
		// password change comes first
		http.Redirect(w, r, "https://"+s.cfg.authHost+"/_auth/password", http.StatusFound)
		return
	}
	if u.TOTPSecret != "" {
		http.Redirect(w, r, "https://"+s.cfg.authHost+"/_auth/ok", http.StatusFound)
		return
	}

	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, s.cfg.maxBodyBytes)
		if err := r.ParseForm(); err != nil || !s.cfg.checkForm(r.PostForm.Get("ft")) {
			s.renderEnroll(w, u, "Session expired — try again.", n)
			return
		}
		pending := u.PendingTOTP
		okCode, _ := totpValidStep(pending, r.PostForm.Get("totp"))
		if pending == "" || !okCode {
			s.renderEnroll(w, u, "That code didn't match — scan again and retry.", n)
			return
		}
		plain, hashed := newBackupCodes(8)
		if err := s.users.mutate(u.Username, func(u *User) bool {
			u.TOTPSecret = u.PendingTOTP
			u.PendingTOTP = ""
			u.BackupCodes = hashed
			u.DeviceGen++
			return true
		}); err != nil {
			s.log.Error("persist TOTP enrollment", "user", u.Username, "error", err)
			http.Error(w, "authentication storage unavailable", http.StatusServiceUnavailable)
			return
		}
		ip := s.clientIP(r)
		s.audit("enroll_ok", ip, u.Username, r)
		s.ntf.send("enroll_ok", u.Username, ip, s.cfg.authHost, "TOTP enrolled")
		// reissue the session without the pending flag
		fresh := s.users.get(u.Username)
		cl2 := sessionClaims{user: u.Username, gen: fresh.Gen, sid: cl.sid, flags: s.flagsFor(fresh), exp: cl.exp}
		s.setCookie(w, cl2)
		s.renderBackupCodes(w, plain, n)
		return
	}

	if u.PendingTOTP == "" {
		if err := s.users.mutate(u.Username, func(u *User) bool {
			u.PendingTOTP = newTOTPSecret()
			return true
		}); err != nil {
			http.Error(w, "authentication storage unavailable", http.StatusServiceUnavailable)
			return
		}
		u = s.users.get(u.Username)
	}
	s.renderEnroll(w, u, "", n)
}

// handleBackupCodes lets a signed-in user regenerate their one-time
// recovery codes. Old codes are replaced and the device generation is
// bumped, invalidating every trusted-device cookie.
func (s *server) handleBackupCodes(w http.ResponseWriter, r *http.Request) {
	n := nonce()
	secHeaders(w, n)
	cl, u, ok := s.session(w, r)
	if !ok {
		http.Redirect(w, r, "https://"+s.cfg.authHost+"/_auth/login", http.StatusFound)
		return
	}
	if p := pendingRedirect(cl, s.cfg.authHost); p != "" {
		http.Redirect(w, r, p, http.StatusFound)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.maxBodyBytes)
	if err := r.ParseForm(); err != nil || !s.cfg.checkForm(r.PostForm.Get("ft")) {
		http.Error(w, "session expired — try again", http.StatusForbidden)
		return
	}
	plain, hashed := newBackupCodes(8)
	if err := s.users.mutate(u.Username, func(u *User) bool {
		u.BackupCodes = hashed
		u.DeviceGen++
		return true
	}); err != nil {
		s.log.Error("persist backup code regeneration", "user", u.Username, "error", err)
		http.Error(w, "authentication storage unavailable", http.StatusServiceUnavailable)
		return
	}
	s.audit("backup_codes_regenerated", s.clientIP(r), u.Username, r)
	s.renderBackupCodes(w, plain, n)
}

// password serves self-service password change; forced first when the
// session carries the must-change flag (temp passwords from user creation
// or admin resets).
func (s *server) password(w http.ResponseWriter, r *http.Request) {
	n := nonce()
	secHeaders(w, n)
	cl, u, ok := s.session(w, r)
	if !ok {
		http.Redirect(w, r, "https://"+s.cfg.authHost+"/_auth/login", http.StatusFound)
		return
	}
	if r.Method == http.MethodGet {
		s.renderPassword(w, cl.has("c"), "", n)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.maxBodyBytes)
	if err := r.ParseForm(); err != nil || !s.cfg.checkForm(r.PostForm.Get("ft")) {
		s.renderPassword(w, cl.has("c"), "Session expired — try again.", n)
		return
	}
	if !s.users.checkPassword(u.Username, r.PostForm.Get("current")) {
		s.audit("pw_change_fail", s.clientIP(r), u.Username, r)
		s.renderPassword(w, cl.has("c"), "Current password is wrong.", n)
		return
	}
	newPW := r.PostForm.Get("new1")
	if len(newPW) < 10 {
		s.renderPassword(w, cl.has("c"), "New password must be at least 10 characters.", n)
		return
	}
	if newPW != r.PostForm.Get("new2") {
		s.renderPassword(w, cl.has("c"), "Passwords don't match.", n)
		return
	}
	if isCommonPassword(newPW) {
		s.renderPassword(w, cl.has("c"), "That password appears in breach lists — choose a unique one.", n)
		return
	}
	hash, err := hashPassword(newPW)
	if err != nil {
		s.renderPassword(w, cl.has("c"), "Internal error — try again.", n)
		return
	}
	// bump the generation: a password change invalidates every other session
	if err := s.users.mutate(u.Username, func(u *User) bool {
		u.Hash = hash
		u.MustChange = false
		u.Gen++
		u.DeviceGen++
		return true
	}); err != nil {
		s.log.Error("persist password change", "user", u.Username, "error", err)
		http.Error(w, "authentication storage unavailable", http.StatusServiceUnavailable)
		return
	}
	ip := s.clientIP(r)
	s.audit("pw_change_ok", ip, u.Username, r)
	s.ntf.send("pw_change", u.Username, ip, s.cfg.authHost, "password changed")
	fresh := s.users.get(u.Username)
	cl2 := sessionClaims{user: u.Username, gen: fresh.Gen, sid: cl.sid, flags: s.flagsFor(fresh), exp: cl.exp}
	s.setCookie(w, cl2)
	if p := pendingRedirect(cl2, s.cfg.authHost); p != "" {
		http.Redirect(w, r, p, http.StatusFound)
		return
	}
	http.Redirect(w, r, "https://"+s.cfg.authHost+"/_auth/ok", http.StatusFound)
}

func (s *server) audit(event, ip, user string, r *http.Request) {
	host := firstNonEmpty(r.Header.Get("X-Forwarded-Host"), r.Host)
	s.log.Info("auth", "event", event, "ip", ip, "user", user, "ua", r.UserAgent(), "host", host)
	s.aud.record(authEvent{
		Time: time.Now().UTC(), Event: event, IP: ip, User: user,
		UA: r.UserAgent(), Host: host,
	})
}

// metrics exposes Prometheus text-format counters, gated by METRICS_TOKEN
// via "Authorization: Bearer <token>".
func (s *server) metrics(w http.ResponseWriter, r *http.Request) {
	if s.cfg.metricsToken == "" {
		http.NotFound(w, r)
		return
	}
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if subtle.ConstantTimeCompare([]byte(got), []byte(s.cfg.metricsToken)) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	snap := s.aud.snapshot(0)
	locked := s.tr.snapshot()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_, _ = fmt.Fprintf(w, "# TYPE forwardauth_attempts_total counter\nforwardauth_attempts_total %d\n", snap.Total)
	_, _ = fmt.Fprintf(w, "# TYPE forwardauth_success_total counter\nforwardauth_success_total %d\n", snap.Success)
	_, _ = fmt.Fprintf(w, "# TYPE forwardauth_failed_total counter\nforwardauth_failed_total %d\n", snap.Failed)
	_, _ = fmt.Fprintf(w, "# TYPE forwardauth_locked_ips gauge\nforwardauth_locked_ips %d\n", len(locked))
	_, _ = fmt.Fprintf(w, "# TYPE forwardauth_users gauge\nforwardauth_users %d\n", s.users.count())
	_, _ = fmt.Fprintf(w, "# TYPE forwardauth_sessions_active gauge\nforwardauth_sessions_active %d\n", s.reg.active())
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-healthcheck":
			addr := getenv("LISTEN_ADDR", ":4181")
			if strings.HasPrefix(addr, ":") {
				addr = "127.0.0.1" + addr
			}
			c := http.Client{Timeout: 3 * time.Second}
			if resp, err := c.Get("http://" + addr + "/_auth/health"); err != nil || resp.StatusCode != 200 {
				os.Exit(1)
			}
			os.Exit(0)
		case "-hash":
			if len(os.Args) < 3 {
				fmt.Fprintln(os.Stderr, "usage: forward-auth -hash <password>")
				os.Exit(2)
			}
			h, err := hashPassword(os.Args[2])
			if err != nil {
				fmt.Fprintln(os.Stderr, "error:", err)
				os.Exit(1)
			}
			fmt.Println(h)
			os.Exit(0)
		}
	}

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg := loadConfig(log)
	if err := cfg.validate(); err != nil {
		log.Error("invalid configuration", "error", err)
		os.Exit(2)
	}
	aud := newAuditor(cfg.auditLog, cfg.ringCap)

	users := newUserStore(cfg.usersFile)
	if err := users.load(); err != nil {
		log.Error("cannot read user store — refusing to start with a possibly corrupt file",
			"path", cfg.usersFile, "error", err)
		os.Exit(1)
	}
	if created, err := users.bootstrap(cfg.username, cfg.password, cfg.totpSecret); err != nil {
		log.Error("bootstrap failed", "error", err)
		os.Exit(1)
	} else if created {
		log.Info("bootstrapped admin user from environment", "user", cfg.username,
			"totp_enrolled", cfg.totpSecret != "", "store", cfg.usersFile)
	}
	if os.Getenv("FIRST_RUN") != "" {
		log.Warn("FIRST_RUN is deprecated and ignored — TOTP enrollment now happens per-user at /_auth/enroll after login")
	}

	s := &server{
		cfg: cfg, log: log, tr: newThrottle(cfg), aud: aud,
		users: users,
		reg:   newSessionRegistry(cfg.ttl, filepath.Join(filepath.Dir(cfg.usersFile), "revoked-sessions.json")),
		ntf:   newNotifier(cfg.webhookURL, cfg.webhookProvider, log),

		startedAt: time.Now(),
	}
	if err := s.reg.load(); err != nil {
		log.Error("cannot load session revocations", "error", err)
		os.Exit(1)
	}
	throttlePath := filepath.Join(filepath.Dir(cfg.usersFile), "throttle.json")
	if err := s.tr.load(throttlePath); err != nil {
		// losing lockout state on a corrupt file beats refusing to start
		log.Error("cannot load throttle state — starting fresh", "path", throttlePath, "error", err)
	}
	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: cfg.totpIssuer,
		RPID:          cfg.authHost,
		RPOrigins:     []string{"https://" + cfg.authHost},
	})
	if err != nil {
		log.Error("initialize passkeys", "error", err)
		os.Exit(2)
	}
	s.wa = wa
	s.ceremonies = newCeremonyStore()

	mux := http.NewServeMux()
	mux.HandleFunc("/_auth/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := users.writable(); err != nil {
			http.Error(w, "storage unavailable", http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, "ok")
	})
	mux.HandleFunc("/_auth/verify", s.verify)
	mux.HandleFunc("/_auth/login", s.login)
	mux.HandleFunc("/_auth/totp", s.totp)
	mux.HandleFunc("/_auth/logout", s.logout)
	mux.HandleFunc("/_auth/enroll", s.enroll)
	mux.HandleFunc("/_auth/password", s.password)
	mux.HandleFunc("/_auth/backup-codes", s.handleBackupCodes)
	mux.HandleFunc("/_auth/passkeys", s.passkeyPage)
	mux.HandleFunc("/_auth/passkeys/register/begin", s.passkeyRegisterBegin)
	mux.HandleFunc("/_auth/passkeys/register/finish", s.passkeyRegisterFinish)
	mux.HandleFunc("/_auth/passkeys/delete", s.passkeyDelete)
	mux.HandleFunc("/_auth/passkeys/login/begin", s.passkeyLoginBegin)
	mux.HandleFunc("/_auth/passkeys/login/finish", s.passkeyLoginFinish)
	mux.HandleFunc("/_auth/metrics", s.metrics)
	mux.HandleFunc("/_auth/ok", func(w http.ResponseWriter, r *http.Request) {
		n := nonce()
		secHeaders(w, n)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(strings.ReplaceAll(okPage, "{{NONCE}}", n)))
	})
	mux.HandleFunc("/_auth/admin", func(w http.ResponseWriter, r *http.Request) {
		// the standalone admin panel is gone — the app shell hosts all admin UI
		http.Redirect(w, r, "/auth/app", http.StatusFound)
	})
	mux.HandleFunc("/_auth/admin/api/state", s.adminState)
	mux.HandleFunc("/_auth/admin/api/user", s.adminCreateUser)
	mux.HandleFunc("/_auth/admin/api/action", s.adminAction)
	mux.HandleFunc("/_auth/admin/api/system", s.handleAdminSystem)
	mux.HandleFunc("POST /_auth/admin/api/sessions/{sid}/revoke", s.adminRevokeSession)
	mux.HandleFunc("/_auth/sessions/mine", s.handleMySessions)
	mux.HandleFunc("/_auth/sessions/trusted", s.handleTrustedDevices)
	mux.HandleFunc("/_auth/admin/audit", s.adminAudit) // legacy JSON endpoint
	mux.HandleFunc("/_auth/setup", func(w http.ResponseWriter, r *http.Request) {
		// the old public FIRST_RUN page; enrollment is session-gated now
		http.Redirect(w, r, "https://"+cfg.authHost+"/_auth/enroll", http.StatusFound)
	})
	if cfg.ssoURL != "" {
		mux.HandleFunc("/_auth/sso", func(w http.ResponseWriter, r *http.Request) {
			rd := r.URL.Query().Get("rd")
			sep := "?"
			if strings.Contains(cfg.ssoURL, "?") {
				sep = "&"
			}
			http.Redirect(w, r, cfg.ssoURL+sep+"rd="+url.QueryEscape(rd), http.StatusFound)
		})
	}
	mux.HandleFunc("/auth/app", s.renderApp)
	mux.Handle("/static/", staticHandler())
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/_auth/login", http.StatusFound)
	})

	sum := sha256.Sum256(cfg.secret)
	log.Info("forward-auth starting",
		"listen", cfg.listen, "auth_host", cfg.authHost,
		"cookie_domain", cfg.cookieDom, "users", users.count(),
		"require_totp", cfg.requireTOTP, "trust_device_days", cfg.trustDevDays,
		"secret_fp", hex.EncodeToString(sum[:4]),
		"audit_log", cfg.auditLog, "audit_ring", cfg.ringCap,
		"webhook", cfg.webhookURL != "", "metrics", cfg.metricsToken != "")

	srv := &http.Server{
		Addr: cfg.listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second,
		IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 20,
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-quit
		log.Info("shutting down")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Error("shutdown", "error", err)
		}
		if err := s.tr.persist(throttlePath); err != nil {
			log.Error("persist throttle state", "error", err)
		}
		if aud.file != nil {
			if err := aud.file.Close(); err != nil {
				log.Error("audit log close", "error", err)
			}
		}
	}()

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Error("server stopped", "error", err)
		os.Exit(1)
	}
}
