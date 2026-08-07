package main

// magic.go — email magic-link sign-in (passwordless email login; roadmap
// Step 21 extra, deferred from the Step 5b deviation notes).
//
// Enabled with MAGIC_LINK=true plus SMTP_URL. POST /_auth/magic (or
// /_auth/resend) with a username mails a 15-minute sign-in link when the
// account exists and has a recovery address (its Email field, or an
// email-shaped username) — the response is identical either way, so the
// endpoint cannot be used for enumeration. The link logs the user in.
//
// Single-use works like the recovery tokens: the token embeds a fingerprint
// of the user's MagicSeq counter, and consumption increments that counter
// under the user-store lock — exactly one concurrent use succeeds. The
// fingerprint also covers the session generation and password hash, so every
// existing credential-revocation path invalidates outstanding links (see
// magicFP).
//
// A magic link replaces the password factor only: users with TOTP enrolled
// continue to the second-factor page before a session is issued.

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const magicTokenTTL = 15 * time.Minute

// magicFP fingerprints the state that must invalidate an outstanding link:
// the single-use counter, the session generation, and the password hash.
// MagicSeq gives single use — after a successful sign-in the counter moves
// on and every outstanding link dies. Gen and Hash piggyback on the
// revocation actions the rest of the codebase already performs, so a
// password reset, an admin disable/logout-everywhere, or a passkey reset
// kills outstanding links without any of those call sites having to know
// magic links exist. This mirrors recoveryFP, which binds to Hash for the
// same reason; binding to MagicSeq alone would leave a harvested link valid
// for its full TTL across every credential revocation.
func (c config) magicFP(u *User) string {
	return c.mac("magfp|" + u.Username + "|" + strconv.Itoa(u.MagicSeq) +
		"|" + strconv.Itoa(u.Gen) + "|" + u.Hash)[:16]
}

func (c config) issueMagicToken(u *User) string {
	exp := strconv.FormatInt(time.Now().Add(magicTokenTTL).Unix(), 10)
	body := "mag|" + exp + "|" + u.Username + "|" + c.magicFP(u)
	return body + "|" + c.mac(body)
}

// parseMagicToken validates format, signature and expiry only — account
// state is re-checked under the store lock at consumption.
func (c config) parseMagicToken(tok string) (username, fp string, ok bool) {
	parts := strings.Split(tok, "|")
	if len(parts) != 5 || parts[0] != "mag" {
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

func (s *server) magicEnabled() bool { return s.cfg.magicLink && s.cfg.smtpURL != "" }

// magic serves the request form (GET), consumes a link (GET with token)
// and mails links (POST).
func (s *server) magic(w http.ResponseWriter, r *http.Request) {
	n := nonce()
	secHeaders(w, n)
	if !s.magicEnabled() {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		if tok := r.URL.Query().Get("token"); tok != "" {
			s.magicConsume(w, r, tok, n)
			return
		}
		s.renderMagicRequest(w, "", false, s.cfg.safeRedirect(r.URL.Query().Get("rd")), n)
	case http.MethodPost:
		s.magicSend(w, r, n)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// resend is the explicit "send another link" endpoint from the Step 5b
// deviation notes — same behaviour as POST /_auth/magic.
func (s *server) resend(w http.ResponseWriter, r *http.Request) {
	n := nonce()
	secHeaders(w, n)
	if !s.magicEnabled() {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.magicSend(w, r, n)
}

// magicSend mails a sign-in link when possible. The response is always the
// same generic notice — whether the account exists, is disabled, or has no
// recovery address must not be observable.
func (s *server) magicSend(w http.ResponseWriter, r *http.Request, n string) {
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.maxBodyBytes)
	if err := r.ParseForm(); err != nil || !s.cfg.checkForm(r.PostForm.Get("ft")) {
		s.renderMagicRequest(w, "Session expired — try again.", false, "", n)
		return
	}
	rd := s.cfg.safeRedirect(r.PostForm.Get("rd"))
	ip := s.clientIP(r)
	if !s.magicLimit.allow(ip) {
		s.audit("magic_ratelimit", ip, "", r)
		s.renderMagicRequest(w, "Too many requests — try again later.", false, rd, n)
		return
	}
	username := strings.TrimSpace(r.PostForm.Get("username"))
	if r.PostForm.Get("website") == "" && username != "" { // honeypot: pretend success
		if u := s.users.get(username); u != nil && !u.Disabled {
			if to := u.recoveryEmail(); to != "" {
				link := "https://" + s.cfg.authHost + "/_auth/magic?token=" +
					url.QueryEscape(s.cfg.issueMagicToken(u)) + "&rd=" + url.QueryEscape(rd)
				body := fmt.Sprintf(
					"A sign-in link was requested for %s at %s.\n\n%s\n\n"+
						"The link is valid for 15 minutes and works exactly once.\n"+
						"If you did not request this, ignore this email.",
					sanitizeMailBody(u.Username), s.cfg.authHost, link)
				s.dispatchMail(r, "magic_request", ip, username, to,
					"Sign in — "+s.cfg.authHost, body, "magic-link email failed")
			}
		}
	}
	s.renderMagicRequest(w, "", true, rd, n)
}

// magicConsume redeems a link: the MagicSeq fingerprint is re-checked and
// incremented under the store lock, so exactly one concurrent use succeeds.
// TOTP users continue to the second factor; everyone else is signed in.
func (s *server) magicConsume(w http.ResponseWriter, r *http.Request, tok, n string) {
	const invalid = "That sign-in link is invalid or has expired — request a new one below."
	rd := s.cfg.safeRedirect(r.URL.Query().Get("rd"))
	username, fp, ok := s.cfg.parseMagicToken(tok)
	if !ok {
		s.renderMagicRequest(w, invalid, false, rd, n)
		return
	}
	applied, err := s.users.mutateIf(username, func(u *User) bool {
		if u.Disabled || fp != s.cfg.magicFP(u) {
			return false
		}
		u.MagicSeq++
		return true
	})
	if errors.Is(err, errNoSuchUser) {
		applied = false
	} else if err != nil {
		s.log.Error("persist magic-link sign-in", "user", sanitizeLogField(username), "error", err)
		http.Error(w, "authentication storage unavailable", http.StatusServiceUnavailable)
		return
	}
	if !applied {
		s.renderMagicRequest(w, invalid, false, rd, n)
		return
	}
	ip := s.clientIP(r)
	u := s.users.get(username)
	if u == nil {
		// deleted between the mutation and this lookup — treat as invalid
		s.renderMagicRequest(w, invalid, false, rd, n)
		return
	}
	s.audit("magic_ok", ip, username, r)
	if u.TOTPSecret != "" {
		// second factor still required — same pending-cookie flow as a password
		s.setPendingCookie(w, username, false)
		s.renderVerify(w, rd, "", n)
		return
	}
	s.finishLogin(w, r, u, ip, rd, false)
}
