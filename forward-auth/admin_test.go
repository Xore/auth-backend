package main

// admin_test.go — admin API coverage for the user Email field: create with
// email, set_email action, normalization and validation.

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
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

// #66: revoke_all must bump every user's Gen/DeviceGen in one action,
// including users the request itself doesn't name (unlike every other
// action here, which targets req.Username) -- the whole point is a
// single admin click force-logs-out everyone, not just one account.
func TestAdminRevokeAllSessions(t *testing.T) {
	c := testConfig(t)
	st := newUserStore(filepath.Join(t.TempDir(), "users.json"))
	if _, err := st.bootstrap("admin", "a-long-test-password", ""); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"alice", "bob"} {
		hash, err := hashPassword(name + "-original-password")
		if err != nil {
			t.Fatal(err)
		}
		if err := st.create(&User{Username: name, Hash: hash, Role: roleUser, Gen: 1, DeviceGen: 2, Created: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := &server{
		cfg: c, users: st, reg: newSessionRegistry(time.Hour), tr: newThrottle(c),
		aud: newAuditor("", 20), log: logger, ntf: newNotifier("", "raw", logger),
	}

	admin := st.get("admin")
	cl := sessionClaims{user: "admin", gen: admin.Gen, sid: "adminsid", exp: time.Now().Add(time.Hour).Unix()}
	r := httptest.NewRequest(http.MethodPost, "http://auth/_auth/admin/api/action", strings.NewReader(`{"action":"revoke_all"}`))
	r.Header.Set("Content-Type", "application/json")
	r.AddCookie(&http.Cookie{Name: c.cookieName, Value: mustIssuePASETO(t, c, cl)})
	r.Header.Set("X-Csrf", c.csrfToken(cl.sid))
	w := httptest.NewRecorder()
	s.adminAction(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("revoke_all: %d %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"changed":"3"`) {
		t.Fatalf("revoke_all response missing changed count for all 3 users: %s", w.Body.String())
	}

	if got := st.get("admin"); got.Gen != admin.Gen+1 || got.DeviceGen != admin.DeviceGen+1 {
		t.Fatalf("admin not bumped: Gen=%d DeviceGen=%d", got.Gen, got.DeviceGen)
	}
	if got := st.get("alice"); got.Gen != 2 || got.DeviceGen != 3 {
		t.Fatalf("alice not bumped: Gen=%d DeviceGen=%d", got.Gen, got.DeviceGen)
	}
	if got := st.get("bob"); got.Gen != 2 || got.DeviceGen != 3 {
		t.Fatalf("bob not bumped: Gen=%d DeviceGen=%d", got.Gen, got.DeviceGen)
	}

	// revoke_all unconditionally bumps every user on every call (unlike a
	// hypothetical idempotent action) -- calling it twice in a row must
	// genuinely revoke sessions twice, including the caller's own,
	// mid-request. This exercises that the handler re-reads the caller's
	// own fresh Gen for its own response rather than relying on a stale
	// value from before the sweep.
	w2 := httptest.NewRecorder()
	cl2 := sessionClaims{user: "admin", gen: st.get("admin").Gen, sid: "adminsid2", exp: time.Now().Add(time.Hour).Unix()}
	r2 := httptest.NewRequest(http.MethodPost, "http://auth/_auth/admin/api/action", strings.NewReader(`{"action":"revoke_all"}`))
	r2.Header.Set("Content-Type", "application/json")
	r2.AddCookie(&http.Cookie{Name: c.cookieName, Value: mustIssuePASETO(t, c, cl2)})
	r2.Header.Set("X-Csrf", c.csrfToken(cl2.sid))
	s.adminAction(w2, r2)
	if w2.Code != http.StatusOK {
		t.Fatalf("second revoke_all: %d %s", w2.Code, w2.Body.String())
	}
	if !strings.Contains(w2.Body.String(), `"changed":"3"`) {
		t.Fatalf("second revoke_all should still bump all 3 users: %s", w2.Body.String())
	}
}

// mutateAdminGuarded/deleteAdminGuarded must refuse to act on the sole
// enabled admin (#43). Exercised directly against userStore rather than
// through adminAction: the HTTP handler's separate "cannot act on yourself"
// check means a single actor can never legitimately reach the
// last-admin-via-a-different-target case in a purely sequential request —
// this guard exists specifically for the concurrent case (see the test
// below), but its refusal behavior in isolation is worth pinning directly.
func TestMutateAdminGuardedRefusesSoleAdmin(t *testing.T) {
	st := newUserStore(filepath.Join(t.TempDir(), "users.json"))
	if _, err := st.bootstrap("solo", "a-long-test-password", ""); err != nil {
		t.Fatal(err)
	}
	err := st.mutateAdminGuarded("solo", func(u *User, otherAdmins int) error {
		if u.Role == roleAdmin && !u.Disabled && otherAdmins == 0 {
			return errLastAdmin
		}
		u.Disabled = true
		return nil
	})
	if !errors.Is(err, errLastAdmin) {
		t.Fatalf("err = %v, want errLastAdmin", err)
	}
	if st.get("solo").Disabled {
		t.Fatal("sole admin was disabled despite the guard refusing")
	}
}

func TestDeleteAdminGuardedRefusesSoleAdmin(t *testing.T) {
	st := newUserStore(filepath.Join(t.TempDir(), "users.json"))
	if _, err := st.bootstrap("solo", "a-long-test-password", ""); err != nil {
		t.Fatal(err)
	}
	if err := st.deleteAdminGuarded("solo"); !errors.Is(err, errLastAdmin) {
		t.Fatalf("err = %v, want errLastAdmin", err)
	}
	if st.get("solo") == nil {
		t.Fatal("sole admin was deleted despite the guard refusing")
	}
}

// The actual bug: two enabled admins, each disabling the OTHER
// concurrently. The old code computed adminCount() and the target's state
// as two separate, independently-locked reads before its mutation — so
// both requests could each see "the other admin is still enabled" and both
// proceed, leaving zero enabled admins. mutateAdminGuarded computes
// otherAdmins under the same lock hold as the mutation itself, so whichever
// request's mutation actually lands first is reflected in the other's
// count — never both.
func TestMutateAdminGuardedConcurrentMutualDisableLeavesOneAdmin(t *testing.T) {
	st := newUserStore(filepath.Join(t.TempDir(), "users.json"))
	if _, err := st.bootstrap("a", "a-long-test-password", ""); err != nil {
		t.Fatal(err)
	}
	if err := st.create(&User{Username: "b", Hash: st.get("a").Hash, Role: roleAdmin, Gen: 1, DeviceGen: 1, Created: time.Now()}); err != nil {
		t.Fatal(err)
	}

	disable := func(name string) error {
		return st.mutateAdminGuarded(name, func(u *User, otherAdmins int) error {
			if u.Role == roleAdmin && !u.Disabled && otherAdmins == 0 {
				return errLastAdmin
			}
			u.Disabled = true
			return nil
		})
	}

	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Add(2)
	go func() { defer wg.Done(); <-start; _ = disable("a") }()
	go func() { defer wg.Done(); <-start; _ = disable("b") }()
	close(start)
	wg.Wait()

	enabled := 0
	for _, name := range []string{"a", "b"} {
		if !st.get(name).Disabled {
			enabled++
		}
	}
	if enabled == 0 {
		t.Fatal("both admins were disabled concurrently — zero enabled admins remain")
	}
}

// End-to-end version of the same race, through the actual HTTP handler and
// two distinct admin sessions, each acting on the other.
func TestAdminActionConcurrentMutualDisableLeavesOneAdmin(t *testing.T) {
	c := testConfig(t)
	st := newUserStore(filepath.Join(t.TempDir(), "users.json"))
	if _, err := st.bootstrap("a", "a-long-test-password", ""); err != nil {
		t.Fatal(err)
	}
	if err := st.create(&User{Username: "b", Hash: st.get("a").Hash, Role: roleAdmin, Gen: 1, DeviceGen: 1, Created: time.Now()}); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := &server{
		cfg: c, users: st, reg: newSessionRegistry(time.Hour), tr: newThrottle(c),
		aud: newAuditor("", 20), log: logger, ntf: newNotifier("", "raw", logger),
	}

	disableOther := func(actor, target string) {
		u := st.get(actor)
		cl := sessionClaims{user: actor, gen: u.Gen, sid: actor + "-sid", exp: time.Now().Add(time.Hour).Unix()}
		body := `{"action":"disable","username":"` + target + `"}`
		r := httptest.NewRequest(http.MethodPost, "http://auth/_auth/admin/api/action", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.AddCookie(&http.Cookie{Name: c.cookieName, Value: mustIssuePASETO(t, c, cl)})
		r.Header.Set("X-Csrf", c.csrfToken(cl.sid))
		s.adminAction(httptest.NewRecorder(), r)
	}

	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Add(2)
	go func() { defer wg.Done(); <-start; disableOther("a", "b") }()
	go func() { defer wg.Done(); <-start; disableOther("b", "a") }()
	close(start)
	wg.Wait()

	enabled := 0
	for _, name := range []string{"a", "b"} {
		if !st.get(name).Disabled {
			enabled++
		}
	}
	if enabled == 0 {
		t.Fatal("both admins were disabled concurrently via adminAction — zero enabled admins remain")
	}
}
