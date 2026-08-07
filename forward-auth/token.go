package main

// token.go — issuance and parsing of every token the portal signs:
// HMAC helpers (MAC, device, pending, form, CSRF) and the PASETO
// v4.local session tokens with key-rotation support.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	pasetov4 "zntr.io/paseto/v4"
)

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

// checkSessionCSRF verifies tok against the per-session CSRF token
// (csrfToken(sid)) in constant time. Session-gated, state-changing
// endpoints (enroll, handleBackupCodes, password) use this instead of
// checkForm: checkForm's "ft" token only proves dwell-time/anti-bot — it is
// valid for any session (or none), so it does not stop a form submitted
// under an attacker's session from acting on the victim's. Binding the
// token to sid the same way the admin API's X-Csrf header already does
// closes that gap.
func (c config) checkSessionCSRF(tok, sid string) bool {
	return subtle.ConstantTimeCompare([]byte(tok), []byte(c.csrfToken(sid))) == 1
}

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
