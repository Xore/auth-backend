package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// --- server -----------------------------------------------------------------

type server struct {
	cfg          config
	settings     *settingsStore
	log          *slog.Logger
	tr           ThrottleBackend
	aud          *auditor
	users        *userStore
	reg          SessionBackend
	ntf          *notifier
	wa           *webauthn.WebAuthn
	ceremonies   *ceremonyStore
	startedAt    time.Time
	recoverLimit rateLimiter
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
	fallback := "https://" + c.authHost + "/auth/app"
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

// sanitizeLogField neutralizes user-controlled values before they enter log
// output: control characters (CR, LF, …) are stripped so an attacker cannot
// forge log lines, and the value is capped to bound log volume.
func sanitizeLogField(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	const maxLogField = 256
	if len(s) > maxLogField {
		s = s[:maxLogField] + "…"
	}
	return s
}

func secHeaders(w http.ResponseWriter, n string) {
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy",
		"default-src 'none'; style-src 'self' 'nonce-"+n+"'; script-src 'nonce-"+n+"'; img-src data:; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
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
	if !ok {
		return sessionClaims{}, nil, false
	}
	revoked, err := s.reg.isRevoked(cl.sid)
	if err != nil {
		// fail closed: revocation state unverifiable → do not accept
		s.log.Warn("session revocation check failed — rejecting session", "error", err)
		return sessionClaims{}, nil, false
	}
	if revoked {
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
		last, err := s.reg.lastActive(cl.sid)
		if err != nil {
			// fail closed: idle state unverifiable → do not accept
			s.log.Warn("session idle check failed — rejecting session", "error", err)
			return sessionClaims{}, nil, false
		}
		if !last.IsZero() && time.Since(last) > s.cfg.idleTimeout {
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

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// settingsRedirect retires standalone account/admin pages without breaking

// awaitShutdown blocks until SIGINT/SIGTERM, then gracefully stops srv,
// persists throttle state (for the in-memory backend) and closes the audit
// log file.
func (s *server) awaitShutdown(srv *http.Server, throttlePath string) {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	s.log.Info("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		s.log.Error("shutdown", "error", err)
	}
	if th, ok := s.tr.(*throttle); ok {
		if err := th.persist(throttlePath); err != nil {
			s.log.Error("persist throttle state", "error", err)
		}
	}
	if s.aud.file != nil {
		if err := s.aud.file.Close(); err != nil {
			s.log.Error("audit log close", "error", err)
		}
	}
}
