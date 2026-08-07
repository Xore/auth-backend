package main

// csrf_test.go — session-bound CSRF protection for logout and the
// session-gated forms (enroll, backup codes, password change). See #36
// and #51: the pre-auth "ft" token (issueForm/checkForm) only proves
// dwell-time/anti-bot, not which session it was issued to, so it does not
// stop a token or link from being replayed under a different session.

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func newCSRFTestServer(t *testing.T) (*server, *userStore, sessionClaims, *http.Cookie) {
	t.Helper()
	c := testConfig(t)
	st := newUserStore(t.TempDir() + "/users.json")
	if _, err := st.bootstrap("admin", "a-long-test-password", ""); err != nil {
		t.Fatal(err)
	}
	s := &server{
		cfg: c, users: st, reg: newSessionRegistry(time.Hour), tr: newThrottle(c),
		aud: newAuditor("", 10), log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		ntf: newNotifier("", "raw", slog.Default()),
	}
	u := st.get("admin")
	cl := sessionClaims{user: u.Username, gen: u.Gen, sid: "victim-sid", exp: time.Now().Add(time.Minute).Unix()}
	cookie := &http.Cookie{Name: c.cookieName, Value: mustIssuePASETO(t, c, cl)}
	return s, st, cl, cookie
}

// A cross-site GET to /_auth/logout (the only way a third party can reach
// it, per SameSite=Lax) must not revoke the session or clear the cookie
// unless it carries the session's own CSRF token — otherwise any page can
// force a visitor's session closed just by linking here.
func TestLogoutRequiresCSRFToken(t *testing.T) {
	s, _, cl, cookie := newCSRFTestServer(t)
	if err := s.reg.touch(cl.sid, cl.user, "192.0.2.1", "ua"); err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest("GET", "http://auth/_auth/logout", nil)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	s.logout(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("expected a redirect either way, got %d", w.Code)
	}
	if set := w.Result().Cookies(); len(set) > 0 {
		t.Fatalf("cookie was cleared without a valid csrf token: %+v", set)
	}
	revoked, err := s.reg.isRevoked(cl.sid)
	if err != nil {
		t.Fatal(err)
	}
	if revoked {
		t.Fatal("session was revoked by a request with no csrf token")
	}
}

// The legitimate case: the token a page would actually render for this
// session (csrfToken(sid)) must still work.
func TestLogoutWithValidCSRFToken(t *testing.T) {
	s, _, cl, cookie := newCSRFTestServer(t)
	if err := s.reg.touch(cl.sid, cl.user, "192.0.2.1", "ua"); err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest("GET", "http://auth/_auth/logout?csrf="+url.QueryEscape(s.cfg.csrfToken(cl.sid)), nil)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	s.logout(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("expected redirect, got %d", w.Code)
	}
	cleared := false
	for _, c := range w.Result().Cookies() {
		if c.Name == s.cfg.cookieName && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("cookie was not cleared despite a valid csrf token")
	}
	revoked, err := s.reg.isRevoked(cl.sid)
	if err != nil {
		t.Fatal(err)
	}
	if !revoked {
		t.Fatal("session was not revoked despite a valid csrf token")
	}
}

// A validly-signed "ft" minted for one session must not authorize a
// mutation submitted under a different session — this is the exact gap
// checkForm (session-independent) had and checkSessionCSRF closes.
func TestPasswordChangeRejectsTokenFromAnotherSession(t *testing.T) {
	s, _, _, cookie := newCSRFTestServer(t)
	attackerToken := s.cfg.csrfToken("attacker-sid") // validly signed, wrong session

	f := url.Values{}
	f.Set("ft", attackerToken)
	f.Set("current", "a-long-test-password")
	f.Set("new1", "a-brand-new-long-password")
	f.Set("new2", "a-brand-new-long-password")
	r := httptest.NewRequest("POST", "http://auth/_auth/password", strings.NewReader(f.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	s.password(w, r)

	if !strings.Contains(w.Body.String(), "Session expired") {
		t.Fatalf("a csrf token from a different session was accepted: %d %s", w.Code, w.Body.String())
	}
}
