package main

// recover.go — email-based self-service password recovery.
//
// Flow: POST /_auth/recover with a username → if the account exists and its
// username is an email address, a 15-minute HMAC reset link is mailed (the
// response is identical either way — no user enumeration). The link opens a
// password form; submitting it resets the password and kills every session.
//
// The reset token embeds a fingerprint of the current password hash, so it
// dies the moment the password changes — tokens are single-use by
// construction. Recovery requires SMTP_URL; without it the route 404s.

import (
	"crypto/tls"
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

type rateLimiter struct {
	mu     sync.Mutex
	m      map[string][]time.Time
	max    int
	window time.Duration
}

func (rl *rateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if rl.m == nil {
		rl.m = map[string][]time.Time{}
	}
	now := time.Now()
	var recent []time.Time
	for _, t := range rl.m[key] {
		if now.Sub(t) < rl.window {
			recent = append(recent, t)
		}
	}
	if len(recent) >= rl.max {
		rl.m[key] = recent
		return false
	}
	rl.m[key] = append(recent, now)
	return true
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

// checkRecoveryToken validates signature, expiry, account state and the
// hash fingerprint (single-use). Returns the username on success.
func (s *server) checkRecoveryToken(tok string) (string, bool) {
	parts := strings.Split(tok, "|")
	if len(parts) != 5 || parts[0] != "rec" {
		return "", false
	}
	body := strings.Join(parts[:4], "|")
	if !s.cfg.validMAC(body, parts[4]) {
		return "", false
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || time.Now().Unix() >= exp {
		return "", false
	}
	u := s.users.get(parts[2])
	if u == nil || u.Disabled {
		return "", false
	}
	if parts[3] != s.cfg.recoveryFP(u) {
		return "", false
	}
	return u.Username, true
}

// --- SMTP ----------------------------------------------------------------------

// sendMailFunc is the mail sender (a variable so tests can stub it).
var sendMailFunc = smtpSend

// smtpSend delivers a plain-text message. SMTP_URL schemes:
//
//	smtps://user:pass@host[:465]  — implicit TLS
//	smtp://[user:pass@]host[:587] — plain, upgraded via STARTTLS when offered
func smtpSend(rawURL, from, to, subject, body string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	host := u.Hostname()
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

	var c *smtp.Client
	if u.Scheme == "smtps" {
		conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
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
			if err := c.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
				return err
			}
		}
	}
	defer func() { _ = c.Close() }()
	if auth != nil {
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

func (s *server) recoverEnabled() bool { return s.cfg.smtpURL != "" }

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
// The response is always the same generic notice.
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
		if u := s.users.get(username); u != nil && !u.Disabled && strings.Contains(u.Username, "@") {
			link := "https://" + s.cfg.authHost + "/_auth/recover?token=" +
				url.QueryEscape(s.cfg.issueRecoveryToken(u))
			body := fmt.Sprintf(
				"A password reset was requested for %s at %s.\n\n%s\n\n"+
					"The link is valid for 15 minutes and works exactly once.\n"+
					"If you did not request this, ignore this email.",
				u.Username, s.cfg.authHost, link)
			if err := sendMailFunc(s.cfg.smtpURL, s.cfg.smtpFrom, u.Username,
				"Password reset — "+s.cfg.authHost, body); err != nil {
				s.log.Error("recovery email failed", "user", username, "error", err)
			} else {
				s.audit("recover_request", ip, username, r)
			}
		}
	}
	s.renderRecoverRequest(w, "", true, n)
}

// recoverReset performs the password change for a valid token.
func (s *server) recoverReset(w http.ResponseWriter, r *http.Request, n string) {
	tok := r.PostForm.Get("token")
	user, ok := s.checkRecoveryToken(tok)
	if !ok {
		s.renderRecoverRequest(w, "That reset link is invalid or has expired — request a new one below.", false, n)
		return
	}
	newPW := r.PostForm.Get("new1")
	switch {
	case len(newPW) < 10:
		s.renderRecoverReset(w, tok, "New password must be at least 10 characters.", n)
		return
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
	// bump the generation: a reset invalidates every session and device
	if err := s.users.mutate(user, func(u *User) bool {
		u.Hash = hash
		u.MustChange = false
		u.Gen++
		u.DeviceGen++
		return true
	}); err != nil {
		s.log.Error("persist password recovery", "user", user, "error", err)
		http.Error(w, "authentication storage unavailable", http.StatusServiceUnavailable)
		return
	}
	ip := s.clientIP(r)
	s.audit("recover_ok", ip, user, r)
	s.ntf.send("recover_ok", user, ip, s.cfg.authHost, "password reset via email")
	http.Redirect(w, r, "https://"+s.cfg.authHost+"/_auth/login", http.StatusFound)
}
