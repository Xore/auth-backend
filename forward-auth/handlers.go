package main

import (
	"crypto/subtle"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// --- risk-based authentication (roadmap Step 24) ------------------------------
//
// riskScore measures how unusual a successful password authentication is for
// this user, based on their persisted login history:
//
//	unseen /24 (IPv4) or /64 (IPv6) subnet → 40
//	unseen user-agent                      → 30
//	unseen hour-of-day (needs ≥5 samples)  → 20
//
// Above 50, device trust is overridden and TOTP is demanded anyway.

func subnetMask(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	if v4 := parsed.To4(); v4 != nil {
		return v4.Mask(net.CIDRMask(24, 32)).String()
	}
	return parsed.Mask(net.CIDRMask(64, 128)).String()
}

func riskScore(u *User, ip, ua string, now time.Time) int {
	if len(u.History) == 0 {
		return 0 // no baseline yet — first logins can't be anomalous
	}
	sub := subnetMask(ip)
	subnetSeen, uaSeen := false, false
	hours := map[int]bool{}
	for _, h := range u.History {
		if subnetMask(h.IP) == sub {
			subnetSeen = true
		}
		if h.UA == ua {
			uaSeen = true
		}
		hours[h.Time.Hour()] = true
	}
	score := 0
	if !subnetSeen {
		score += 40
	}
	if !uaSeen {
		score += 30
	}
	if len(u.History) >= 5 && !hours[now.Hour()] {
		score += 20
	}
	return score
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
		if err := s.reg.touch(cl.sid, u.Username, s.clientIP(r), r.UserAgent()); err != nil {
			// the session itself was verified above; losing the activity
			// record only makes later idle checks fail closed
			s.log.Warn("session touch failed", "error", err)
		}
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
			// rd comes from safeRedirect(): HTTPS-only, restricted to the
			// cookie domain, constant fallback — never attacker-controlled.
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
	if s.cfg.passwordless {
		// passkey-only mode: the password path is disabled entirely
		s.renderLogin(w, rd, "Password sign-in is disabled on this server — use your passkey.", n)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.maxBodyBytes)

	if locked, d, err := s.tr.locked(ip); err != nil {
		s.log.Warn("throttle check failed — failing closed", "error", err)
		http.Error(w, "authentication storage unavailable", http.StatusServiceUnavailable)
		return
	} else if locked {
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
	if locked, d, err := s.tr.locked("user:" + strings.ToLower(username)); err != nil {
		s.log.Warn("throttle check failed — failing closed", "error", err)
		http.Error(w, "authentication storage unavailable", http.StatusServiceUnavailable)
		return
	} else if locked {
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
	trusted := s.trustedDevice(r, username)
	if trusted && u.TOTPSecret != "" && riskScore(u, ip, r.UserAgent(), time.Now()) > 50 {
		// anomalous sign-in: device trust alone is not enough — demand the
		// second factor anyway
		s.audit("rba_totp_required", ip, username, r)
		trusted = false
	}
	if u.TOTPSecret != "" && !trusted {
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
		u.History = append(u.History, loginRecord{Time: time.Now().UTC(), IP: ip, UA: r.UserAgent()})
		if len(u.History) > 25 {
			u.History = u.History[len(u.History)-25:]
		}
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
	if err := s.reg.touch(cl.sid, u.Username, ip, r.UserAgent()); err != nil {
		s.log.Warn("session touch failed", "error", err)
	}
	s.audit("login_ok", ip, u.Username, r)
	if p := pendingRedirect(cl, s.cfg.authHost); p != "" {
		http.Redirect(w, r, p, http.StatusFound)
		return
	}
	http.Redirect(w, r, rd, http.StatusFound)
}

func (s *server) fail(w http.ResponseWriter, r *http.Request, ip, rd, reason, nonce string) {
	username := strings.ToLower(strings.TrimSpace(r.PostForm.Get("username")))
	locked, err := s.tr.fail(ip)
	if err == nil && username != "" {
		userLocked, uErr := s.tr.fail("user:" + username)
		if uErr != nil {
			err = uErr
		} else if userLocked {
			locked = true
		}
	}
	if err != nil {
		// throttle state could not be recorded — fail closed with a
		// controlled 503 rather than letting attempts through unthrottled
		s.log.Warn("throttle record failed — failing closed", "error", err)
		http.Error(w, "authentication storage unavailable", http.StatusServiceUnavailable)
		return
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
	if locked, d, err := s.tr.locked(ip); err != nil {
		s.log.Warn("throttle check failed — failing closed", "error", err)
		http.Error(w, "authentication storage unavailable", http.StatusServiceUnavailable)
		return
	} else if locked {
		s.audit("locked_out", ip, user, r)
		s.renderVerify(w, rd, "Too many attempts. Try again in "+d.Round(time.Second).String()+".", n)
		return
	}
	if locked, d, err := s.tr.locked("user:" + strings.ToLower(user)); err != nil {
		s.log.Warn("throttle check failed — failing closed", "error", err)
		http.Error(w, "authentication storage unavailable", http.StatusServiceUnavailable)
		return
	} else if locked {
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
	locked, err := s.tr.fail(ip)
	if err == nil && user != "" {
		userLocked, uErr := s.tr.fail("user:" + strings.ToLower(user))
		if uErr != nil {
			err = uErr
		} else if userLocked {
			locked = true
		}
	}
	if err != nil {
		s.log.Warn("throttle record failed — failing closed", "error", err)
		http.Error(w, "authentication storage unavailable", http.StatusServiceUnavailable)
		return
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
		http.Redirect(w, r, "https://"+s.cfg.authHost+"/auth/app", http.StatusFound)
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
	if err := validatePassword(newPW); err != nil {
		s.renderPassword(w, cl.has("c"), "New password "+err.Error()+".", n)
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
	http.Redirect(w, r, "https://"+s.cfg.authHost+"/auth/app", http.StatusFound)
}

func (s *server) audit(event, ip, user string, r *http.Request) {
	host := firstNonEmpty(r.Header.Get("X-Forwarded-Host"), r.Host)
	s.log.Info("auth", "event", sanitizeLogField(event), "ip", sanitizeLogField(ip), "user", sanitizeLogField(user), "ua", sanitizeLogField(r.UserAgent()), "host", sanitizeLogField(host))
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

func settingsRedirect(pane string) http.HandlerFunc {
	target := "/auth/app"
	if pane != "" {
		target += "?pane=" + url.QueryEscape(pane)
	}
	return func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target, http.StatusFound)
	}
}
