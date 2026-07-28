package main

// recover.go — email-based self-service password recovery.
//
// Flow: POST /_auth/recover with a username → if the account exists and has
// a recovery address (its validated Email field, or an email-shaped username
// from before the field existed), a 15-minute HMAC reset link is mailed.
// The response is identical either way — no user enumeration and no signal
// about whether an account is reachable by mail. The link opens a password
// form; submitting it resets the password and kills every session.
//
// The reset token embeds a fingerprint of the current password hash. The
// fingerprint is re-checked under the user-store lock as part of the reset
// mutation, so validation and consumption are atomic: exactly one concurrent
// reset per token can succeed, and the token dies the moment the password
// changes.
//
// Recovery requires SMTP_URL; without it the route 404s. SMTP transport is
// always encrypted (STARTTLS for smtp://, TLS 1.2+ for smtps://) unless
// SMTP_ALLOW_INSECURE explicitly opts in to plaintext for local development.

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const recoveryTokenTTL = 15 * time.Minute

// --- rate limiter (3 requests per IP per hour) -------------------------------

// rateLimiterMaxKeys bounds the key space so a spray of source IPs cannot
// grow the map without limit.
const rateLimiterMaxKeys = 10000

// rateLimiter is a bounded per-key sliding-window limiter. Keys whose
// timestamps have all expired are pruned; when the map is full the key with
// the oldest activity is evicted. now is replaceable so tests can drive the
// clock instead of sleeping.
type rateLimiter struct {
	mu      sync.Mutex
	m       map[string][]time.Time
	max     int
	window  time.Duration
	maxKeys int
	now     func() time.Time
}

func (rl *rateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if rl.m == nil {
		rl.m = map[string][]time.Time{}
	}
	now := time.Now()
	if rl.now != nil {
		now = rl.now()
	}
	var recent []time.Time
	for _, t := range rl.m[key] {
		if now.Sub(t) < rl.window {
			recent = append(recent, t)
		}
	}
	allowed := len(recent) < rl.max
	if allowed {
		recent = append(recent, now)
	}
	if len(recent) == 0 {
		delete(rl.m, key) // fully expired: free the key instead of leaking it
	} else {
		rl.m[key] = recent
	}
	rl.pruneLocked(now)
	return allowed
}

// pruneLocked enforces the key bound: first drop keys whose newest timestamp
// has aged out of the window, then — if still over capacity — evict the
// least-recently-active keys. Callers must hold rl.mu.
func (rl *rateLimiter) pruneLocked(now time.Time) {
	maxKeys := rl.maxKeys
	if maxKeys <= 0 {
		maxKeys = rateLimiterMaxKeys
	}
	if len(rl.m) <= maxKeys {
		return
	}
	for k, ts := range rl.m {
		if len(ts) == 0 || now.Sub(ts[len(ts)-1]) >= rl.window {
			delete(rl.m, k)
		}
	}
	for len(rl.m) > maxKeys {
		oldest, oldestAt := "", now
		for k, ts := range rl.m {
			if ts[len(ts)-1].Before(oldestAt) || oldest == "" {
				oldest, oldestAt = k, ts[len(ts)-1]
			}
		}
		delete(rl.m, oldest)
	}
}

// --- recovery tokens ----------------------------------------------------------

// recoveryFP fingerprints the current password hash. After a successful
// reset the hash changes and every outstanding token becomes invalid.
func (c config) recoveryFP(u *User) string {
	return c.mac("recfp|" + u.Username + "|" + u.Hash)[:16]
}

func (c config) issueRecoveryToken(u *User) string {
	exp := strconv.FormatInt(time.Now().Add(recoveryTokenTTL).Unix(), 10)
	body := "rec|" + exp + "|" + u.Username + "|" + c.recoveryFP(u)
	return body + "|" + c.mac(body)
}

// parseRecoveryToken validates format, signature and expiry only — no
// account state. It returns the username and the embedded password-hash
// fingerprint so callers can re-verify account state under the store lock.
func (c config) parseRecoveryToken(tok string) (username, fp string, ok bool) {
	parts := strings.Split(tok, "|")
	if len(parts) != 5 || parts[0] != "rec" {
		return "", "", false
	}
	body := strings.Join(parts[:4], "|")
	if !c.validMAC(body, parts[4]) {
		return "", "", false
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || time.Now().Unix() >= exp {
		return "", "", false
	}
	return parts[2], parts[3], true
}

// checkRecoveryToken validates signature, expiry, account state and the
// hash fingerprint (single-use). Returns the username on success. It is a
// read-only check for rendering pages; the actual reset re-verifies the
// fingerprint under the store lock (see recoverReset).
func (s *server) checkRecoveryToken(tok string) (string, bool) {
	username, fp, ok := s.cfg.parseRecoveryToken(tok)
	if !ok {
		return "", false
	}
	u := s.users.get(username)
	if u == nil || u.Disabled || fp != s.cfg.recoveryFP(u) {
		return "", false
	}
	return u.Username, true
}

// --- SMTP ----------------------------------------------------------------------

// sendMailFunc is the mail sender (a variable so tests can stub it).
var sendMailFunc = smtpSend

// smtpSend delivers a plain-text message. SMTP_URL schemes:
//
//	smtps://user:pass@host[:465]  — implicit TLS, TLS 1.2 minimum
//	smtp://[user:pass@]host[:587] — STARTTLS required, TLS 1.2 minimum
//
// Credentials and reset links are never sent over plaintext: smtp:// without
// a STARTTLS offer fails unless allowInsecure (SMTP_ALLOW_INSECURE) is set —
// an explicit development-only opt-in.
func smtpSend(rawURL, from, to, subject, body string, allowInsecure bool) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	if u.Scheme != "smtp" && u.Scheme != "smtps" {
		return fmt.Errorf("unsupported SMTP scheme %q (want smtp or smtps)", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("SMTP URL has no host")
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "smtps" {
			port = "465"
		} else {
			port = "587"
		}
	}
	addr := net.JoinHostPort(host, port)

	var auth smtp.Auth
	if u.User != nil {
		pw, _ := u.User.Password()
		auth = smtp.PlainAuth("", u.User.Username(), pw, host)
	}
	msg := "From: " + from + "\r\n" +
		"To: " + to + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n\r\n" + body

	tlsCfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	var c *smtp.Client
	if u.Scheme == "smtps" {
		conn, err := tls.Dial("tcp", addr, tlsCfg)
		if err != nil {
			return err
		}
		if c, err = smtp.NewClient(conn, host); err != nil {
			return err
		}
	} else {
		if c, err = smtp.Dial(addr); err != nil {
			return err
		}
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(tlsCfg); err != nil {
				_ = c.Close()
				return fmt.Errorf("STARTTLS failed: %w", err)
			}
		} else if !allowInsecure {
			_ = c.Close()
			return errors.New("SMTP server does not offer STARTTLS — refusing to send credentials and reset links in plaintext (set SMTP_ALLOW_INSECURE=true for local development only)")
		}
	}
	defer func() { _ = c.Close() }()
	tlsState, tlsActive := c.TLSConnectionState()
	if tlsActive && tlsState.Version < tls.VersionTLS12 {
		return fmt.Errorf("SMTP TLS version too old: %s", tls.VersionName(tlsState.Version))
	}
	if auth != nil {
		if !tlsActive && !allowInsecure {
			return errors.New("refusing SMTP authentication over an unencrypted connection")
		}
		if err := c.Auth(auth); err != nil {
			return err
		}
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	if err := c.Rcpt(to); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte(msg)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// --- handlers ------------------------------------------------------------------

func (s *server) recoverEnabled() bool { return s.cfg.smtpURL != "" && !s.cfg.passwordless }

// recover handles both the request form (username → email) and, when a
// valid token is present, the reset form and the reset itself.
func (s *server) recover(w http.ResponseWriter, r *http.Request) {
	n := nonce()
	secHeaders(w, n)
	if !s.recoverEnabled() {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		tok := r.URL.Query().Get("token")
		if tok == "" {
			s.renderRecoverRequest(w, "", false, n)
			return
		}
		if _, ok := s.checkRecoveryToken(tok); !ok {
			s.renderRecoverRequest(w, "That reset link is invalid or has expired — request a new one below.", false, n)
			return
		}
		s.renderRecoverReset(w, tok, "", n)

	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, s.cfg.maxBodyBytes)
		if err := r.ParseForm(); err != nil {
			s.renderRecoverRequest(w, "Bad request.", false, n)
			return
		}
		if r.PostForm.Get("token") != "" {
			s.recoverReset(w, r, n)
			return
		}
		s.recoverRequest(w, r, n)

	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// recoverRequest takes the username and mails a reset link when possible.
// The response is always the same generic notice — whether the account
// exists, is disabled, or has no recovery address must not be observable.
func (s *server) recoverRequest(w http.ResponseWriter, r *http.Request, n string) {
	if !s.cfg.checkForm(r.PostForm.Get("ft")) {
		s.renderRecoverRequest(w, "Session expired — try again.", false, n)
		return
	}
	ip := s.clientIP(r)
	if !s.recoverLimit.allow(ip) {
		s.audit("recover_ratelimit", ip, "", r)
		s.renderRecoverRequest(w, "Too many requests — try again later.", false, n)
		return
	}
	username := strings.TrimSpace(r.PostForm.Get("username"))
	if r.PostForm.Get("website") == "" && username != "" { // honeypot: pretend success
		if u := s.users.get(username); u != nil && !u.Disabled {
			if to := u.recoveryEmail(); to != "" {
				link := "https://" + s.cfg.authHost + "/_auth/recover?token=" +
					url.QueryEscape(s.cfg.issueRecoveryToken(u))
				body := fmt.Sprintf(
					"A password reset was requested for %s at %s.\n\n%s\n\n"+
						"The link is valid for 15 minutes and works exactly once.\n"+
						"If you did not request this, ignore this email.",
					u.Username, s.cfg.authHost, link)
				if err := sendMailFunc(s.cfg.smtpURL, s.cfg.smtpFrom, to,
					"Password reset — "+s.cfg.authHost, body, s.cfg.smtpAllowInsecure); err != nil {
					s.log.Error("recovery email failed", "user", username, "error", err)
				} else {
					s.audit("recover_request", ip, username, r)
				}
			}
		}
	}
	s.renderRecoverRequest(w, "", true, n)
}

// recoverReset performs the password change for a valid token. Token
// consumption is atomic with the password mutation: the token's
// password-hash fingerprint is re-checked under the user-store lock, so
// exactly one concurrent reset per token can succeed.
func (s *server) recoverReset(w http.ResponseWriter, r *http.Request, n string) {
	tok := r.PostForm.Get("token")
	username, fp, ok := s.cfg.parseRecoveryToken(tok)
	if !ok {
		s.renderRecoverRequest(w, "That reset link is invalid or has expired — request a new one below.", false, n)
		return
	}
	newPW := r.PostForm.Get("new1")
	if err := validatePassword(newPW); err != nil {
		s.renderRecoverReset(w, tok, "New password "+err.Error()+".", n)
		return
	}
	switch {
	case newPW != r.PostForm.Get("new2"):
		s.renderRecoverReset(w, tok, "Passwords don't match.", n)
		return
	case isCommonPassword(newPW):
		s.renderRecoverReset(w, tok, "That password appears in breach lists — choose a unique one.", n)
		return
	}
	hash, err := hashPassword(newPW)
	if err != nil {
		s.renderRecoverReset(w, tok, "Internal error — try again.", n)
		return
	}
	// Consume under the store lock: re-verify the fingerprint against the
	// live record and apply the new hash in the same critical section.
	// Bumping the generations invalidates every session and device cookie.
	applied, err := s.users.mutateIf(username, func(u *User) bool {
		if u.Disabled || fp != s.cfg.recoveryFP(u) {
			return false
		}
		u.Hash = hash
		u.MustChange = false
		u.Gen++
		u.DeviceGen++
		return true
	})
	if errors.Is(err, errNoSuchUser) {
		applied = false
	} else if err != nil {
		s.log.Error("persist password recovery", "user", username, "error", err)
		http.Error(w, "authentication storage unavailable", http.StatusServiceUnavailable)
		return
	}
	if !applied {
		s.renderRecoverRequest(w, "That reset link is invalid or has expired — request a new one below.", false, n)
		return
	}
	ip := s.clientIP(r)
	s.audit("recover_ok", ip, username, r)
	s.ntf.send("recover_ok", username, ip, s.cfg.authHost, "password reset via email")
	http.Redirect(w, r, "https://"+s.cfg.authHost+"/_auth/login", http.StatusFound)
}
