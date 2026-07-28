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

func TestAdminSecurityActionsMutateAndInvalidate(t *testing.T) {
	c := testConfig(t)
	st := newUserStore(filepath.Join(t.TempDir(), "users.json"))
	if _, err := st.bootstrap("admin", "a-long-test-password", ""); err != nil {
		t.Fatal(err)
	}
	initialHash, err := hashPassword("target-original-password")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.create(&User{
		Username: "target", Hash: initialHash, Role: roleUser,
		TOTPSecret: "JBSWY3DPEHPK3PXP", PendingTOTP: "PENDING",
		BackupCodes: []string{"one", "two"}, Gen: 4, DeviceGen: 7, Created: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := &server{
		cfg: c, users: st, reg: newSessionRegistry(time.Hour), tr: newThrottle(c),
		aud: newAuditor("", 20), log: logger, ntf: newNotifier("", "raw", logger),
	}
	do := func(action string) *httptest.ResponseRecorder {
		admin := st.get("admin")
		cl := sessionClaims{user: "admin", gen: admin.Gen, sid: "adminsid", exp: time.Now().Add(time.Hour).Unix()}
		body := `{"action":"` + action + `","username":"target"}`
		r := httptest.NewRequest(http.MethodPost, "http://auth/_auth/admin/api/action", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.AddCookie(&http.Cookie{Name: c.cookieName, Value: mustIssuePASETO(t, c, cl)})
		r.Header.Set("X-Csrf", c.csrfToken(cl.sid))
		w := httptest.NewRecorder()
		s.adminAction(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", action, w.Code, w.Body.String())
		}
		return w
	}

	w := do("reset_password")
	afterPassword := st.get("target")
	if !afterPassword.MustChange || afterPassword.Hash == initialHash ||
		afterPassword.Gen != 5 || afterPassword.DeviceGen != 8 {
		t.Fatalf("reset_password did not replace credentials and invalidate sessions: %#v", afterPassword)
	}
	if !strings.Contains(w.Body.String(), "temp_password") {
		t.Fatalf("reset_password did not return the one-time password: %s", w.Body.String())
	}

	do("reset_totp")
	afterTOTP := st.get("target")
	if afterTOTP.TOTPSecret != "" || afterTOTP.PendingTOTP != "" || len(afterTOTP.BackupCodes) != 0 ||
		afterTOTP.Gen != 6 || afterTOTP.DeviceGen != 9 {
		t.Fatalf("reset_totp did not clear 2FA and invalidate sessions: %#v", afterTOTP)
	}

	do("logout_user")
	afterLogout := st.get("target")
	if afterLogout.Gen != 7 || afterLogout.DeviceGen != 10 {
		t.Fatalf("logout_user did not invalidate sessions and devices: %#v", afterLogout)
	}

	do("disable")
	afterDisable := st.get("target")
	if !afterDisable.Disabled || afterDisable.Gen != 8 || afterDisable.DeviceGen != 11 {
		t.Fatalf("disable did not block user and invalidate sessions: %#v", afterDisable)
	}
}
