package main

// admin_test.go — admin API coverage for the user Email field: create with
// email, set_email action, normalization and validation.

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAdminUserEmailEndpoints(t *testing.T) {
	c := testConfig(t)
	st := newUserStore(filepath.Join(t.TempDir(), "users.json"))
	if _, err := st.bootstrap("admin", "a-long-test-password", ""); err != nil {
		t.Fatal(err)
	}
	s := &server{cfg: c, users: st, reg: newSessionRegistry(time.Hour), tr: newThrottle(c),
		aud: newAuditor("", 10), log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		ntf: newNotifier("", "raw", slog.Default())}

	do := func(body string, h http.HandlerFunc) *httptest.ResponseRecorder {
		u := st.get("admin")
		cl := sessionClaims{user: "admin", gen: u.Gen, sid: "adminsid", exp: time.Now().Add(time.Hour).Unix()}
		r := httptest.NewRequest("POST", "http://auth/_auth/admin/api", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.AddCookie(&http.Cookie{Name: c.cookieName, Value: mustIssuePASETO(t, c, cl)})
		r.Header.Set("X-Csrf", c.csrfToken(cl.sid))
		w := httptest.NewRecorder()
		h(w, r)
		return w
	}

	// create with a valid email → normalized (domain lowercased) and stored
	if w := do(`{"username":"bob","role":"user","email":"Bob@Example.ORG"}`, s.adminCreateUser); w.Code != http.StatusOK {
		t.Fatalf("create with email: %d %s", w.Code, w.Body.String())
	}
	if got := st.get("bob").Email; got != "Bob@example.org" {
		t.Fatalf("email = %q, want domain-normalized Bob@example.org", got)
	}
	// create with an invalid email → 400, no user
	if w := do(`{"username":"bad","role":"user","email":"nope"}`, s.adminCreateUser); w.Code != http.StatusBadRequest {
		t.Fatalf("create with bad email: %d, want 400", w.Code)
	}
	if st.get("bad") != nil {
		t.Fatal("user created despite invalid email")
	}
	// set_email updates, normalizes, and clears
	if w := do(`{"action":"set_email","username":"bob","email":"New@Example.com"}`, s.adminAction); w.Code != http.StatusOK {
		t.Fatalf("set_email: %d", w.Code)
	}
	if got := st.get("bob").Email; got != "New@example.com" {
		t.Fatalf("email = %q, want New@example.com", got)
	}
	if w := do(`{"action":"set_email","username":"bob","email":"@@"}`, s.adminAction); w.Code != http.StatusBadRequest {
		t.Fatalf("set_email invalid: %d, want 400", w.Code)
	}
	if w := do(`{"action":"set_email","username":"bob","email":""}`, s.adminAction); w.Code != http.StatusOK {
		t.Fatalf("set_email clear: %d", w.Code)
	}
	if got := st.get("bob").Email; got != "" {
		t.Fatalf("email not cleared: %q", got)
	}
}
