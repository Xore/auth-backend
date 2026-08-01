package main

// identity_test.go — coverage for the admin-editable identity fields
// (display name, description), username rename, and per-user permission
// grants added for auth-backend#21 (redirected from
// Xore/honeypot-stack#156 parts 2/3).

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

func newIdentityTestServer(t *testing.T) (*server, *userStore, config) {
	t.Helper()
	c := testConfig(t)
	st := newUserStore(filepath.Join(t.TempDir(), "users.json"))
	if _, err := st.bootstrap("admin", "a-long-test-password", ""); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := &server{
		cfg: c, users: st, reg: newSessionRegistry(time.Hour), tr: newThrottle(c),
		aud: newAuditor("", 50), log: logger, ntf: newNotifier("", "raw", logger),
	}
	return s, st, c
}

func adminAdminAction(t *testing.T, s *server, c config, actorUsername, body string) *httptest.ResponseRecorder {
	t.Helper()
	actor := s.users.get(actorUsername)
	cl := sessionClaims{user: actorUsername, gen: actor.Gen, sid: "sid-" + actorUsername, exp: time.Now().Add(time.Hour).Unix()}
	r := httptest.NewRequest(http.MethodPost, "http://auth/_auth/admin/api/action", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.AddCookie(&http.Cookie{Name: c.cookieName, Value: mustIssuePASETO(t, c, cl)})
	r.Header.Set("X-Csrf", c.csrfToken(cl.sid))
	w := httptest.NewRecorder()
	s.adminAction(w, r)
	return w
}

// --- display name / description ---------------------------------------------

func TestAdminSetDisplayNameAndDescription(t *testing.T) {
	s, st, c := newIdentityTestServer(t)
	if err := st.create(&User{Username: "target", Hash: "x", Role: roleUser, Gen: 1, Created: time.Now()}); err != nil {
		t.Fatal(err)
	}

	if w := adminAdminAction(t, s, c, "admin", `{"action":"set_display_name","username":"target","display_name":"  Target User  "}`); w.Code != http.StatusOK {
		t.Fatalf("set_display_name: %d %s", w.Code, w.Body.String())
	}
	if got := st.get("target").DisplayName; got != "Target User" {
		t.Fatalf("display name = %q, want trimmed \"Target User\"", got)
	}

	if w := adminAdminAction(t, s, c, "admin", `{"action":"set_description","username":"target","description":"Second analyst account"}`); w.Code != http.StatusOK {
		t.Fatalf("set_description: %d %s", w.Code, w.Body.String())
	}
	if got := st.get("target").Description; got != "Second analyst account" {
		t.Fatalf("description = %q", got)
	}

	// Over-length values are rejected and leave the stored value untouched.
	tooLong := strings.Repeat("a", maxDisplayNameLen+1)
	if w := adminAdminAction(t, s, c, "admin", `{"action":"set_display_name","username":"target","display_name":"`+tooLong+`"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("over-length display name: %d, want 400", w.Code)
	}
	if got := st.get("target").DisplayName; got != "Target User" {
		t.Fatalf("rejected display name changed stored value: %q", got)
	}

	// Clearing restores the introspection fallback to username.
	if w := adminAdminAction(t, s, c, "admin", `{"action":"set_display_name","username":"target","display_name":""}`); w.Code != http.StatusOK {
		t.Fatalf("clear display name: %d", w.Code)
	}
	if got := st.get("target").DisplayName; got != "" {
		t.Fatalf("display name not cleared: %q", got)
	}
}

func TestIntrospectionDisplayNameFallsBackToUsername(t *testing.T) {
	if got := firstNonEmpty("", "target"); got != "target" {
		t.Fatalf("firstNonEmpty fallback = %q, want %q", got, "target")
	}
	if got := firstNonEmpty("Target User", "target"); got != "Target User" {
		t.Fatalf("firstNonEmpty preference = %q, want %q", got, "Target User")
	}
}

// --- username rename ----------------------------------------------------------

func TestUserStoreRenamePreservesIdentityAndInvalidatesSessions(t *testing.T) {
	st := newUserStore(filepath.Join(t.TempDir(), "users.json"))
	created := time.Now().Add(-time.Hour).Truncate(time.Second)
	if err := st.create(&User{
		Username: "old-name", Hash: "x", Role: roleUser, Gen: 3, DeviceGen: 5,
		Created: created, Email: "old@example.com",
	}); err != nil {
		t.Fatal(err)
	}
	before := st.get("old-name")

	if err := st.rename("old-name", "new-name"); err != nil {
		t.Fatalf("rename: %v", err)
	}

	if st.get("old-name") != nil {
		t.Fatal("old username still resolves after rename")
	}
	after := st.get("new-name")
	if after == nil {
		t.Fatal("new username does not resolve after rename")
	}
	if after.Subject != before.Subject {
		t.Fatalf("rename changed the immutable subject: %q -> %q", before.Subject, after.Subject)
	}
	if !after.Created.Equal(before.Created) || after.Email != before.Email {
		t.Fatalf("rename lost other fields: %+v", after)
	}
	if after.Gen != before.Gen+1 || after.DeviceGen != before.DeviceGen+1 {
		t.Fatalf("rename did not force re-login: gen %d->%d, device_gen %d->%d", before.Gen, after.Gen, before.DeviceGen, after.DeviceGen)
	}

	// A session token issued for the old username can never resolve again --
	// the store has no entry under that key any more, exactly like a
	// disabled/deleted account today.
	if u := st.get("old-name"); u != nil {
		t.Fatal("old username must never resolve, simulating a stale session cookie")
	}
}

func TestUserStoreRenamePreservesTOTPReplayState(t *testing.T) {
	st := newUserStore(filepath.Join(t.TempDir(), "users.json"))
	if err := st.create(&User{Username: "old-name", Hash: "x", Role: roleUser, Gen: 1, Created: time.Now()}); err != nil {
		t.Fatal(err)
	}
	st.mu.Lock()
	st.lastStep["old-name"] = 12345
	st.mu.Unlock()

	if err := st.rename("old-name", "new-name"); err != nil {
		t.Fatalf("rename: %v", err)
	}

	st.mu.Lock()
	_, oldPresent := st.lastStep["old-name"]
	newStep, newPresent := st.lastStep["new-name"]
	st.mu.Unlock()
	if oldPresent {
		t.Fatal("TOTP replay state left behind under the old username")
	}
	if !newPresent || newStep != 12345 {
		t.Fatalf("TOTP replay state did not move to the new username: present=%v step=%d", newPresent, newStep)
	}
}

func TestUserStoreRenameRejectsTakenOrInvalidNames(t *testing.T) {
	st := newUserStore(filepath.Join(t.TempDir(), "users.json"))
	if err := st.create(&User{Username: "alice", Hash: "x", Role: roleUser, Gen: 1, Created: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := st.create(&User{Username: "bob", Hash: "x", Role: roleUser, Gen: 1, Created: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := st.rename("alice", "bob"); err == nil {
		t.Fatal("rename onto a taken username must fail")
	}
	if err := st.rename("alice", "not valid!"); err == nil {
		t.Fatal("rename to an invalid username must fail")
	}
	if err := st.rename("nobody", "someone"); err == nil {
		t.Fatal("rename of a missing user must fail")
	}
	// Nothing above should have mutated alice.
	if a := st.get("alice"); a == nil || a.Gen != 1 {
		t.Fatalf("a rejected rename mutated the user: %+v", a)
	}
}

func TestAdminRenameUserEndpoint(t *testing.T) {
	s, st, c := newIdentityTestServer(t)
	if err := st.create(&User{Username: "target", Hash: "x", Role: roleUser, Gen: 1, Created: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if w := adminAdminAction(t, s, c, "admin", `{"action":"rename_user","username":"target","new_username":"retitled"}`); w.Code != http.StatusOK {
		t.Fatalf("rename_user: %d %s", w.Code, w.Body.String())
	}
	if st.get("target") != nil {
		t.Fatal("old username still present after admin rename")
	}
	if st.get("retitled") == nil {
		t.Fatal("new username missing after admin rename")
	}
	events := s.aud.snapshot(10).Recent
	found := false
	for _, e := range events {
		if strings.Contains(e.Event, "admin_rename_user") && strings.Contains(e.Event, "before=\"target\"") && strings.Contains(e.Event, "after=\"retitled\"") {
			found = true
		}
	}
	if !found {
		t.Fatalf("audit log missing rename before/after detail: %+v", events)
	}
}

// --- permission grants ---------------------------------------------------------

func TestAdminSetPermissionsRoundTripAndIsolation(t *testing.T) {
	s, st, c := newIdentityTestServer(t)
	if err := st.create(&User{Username: "alice", Hash: "x", Role: roleUser, Gen: 1, Created: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := st.create(&User{Username: "bob", Hash: "x", Role: roleUser, Gen: 1, Created: time.Now()}); err != nil {
		t.Fatal(err)
	}

	if w := adminAdminAction(t, s, c, "admin", `{"action":"set_permissions","username":"alice","host":"dashboard.example.com","permissions":["pages:sandbox:view","actions:export"]}`); w.Code != http.StatusOK {
		t.Fatalf("set_permissions: %d %s", w.Code, w.Body.String())
	}

	alice := st.get("alice")
	got := alice.Permissions["dashboard.example.com"]
	if len(got) != 2 || got[0] != "actions:export" || got[1] != "pages:sandbox:view" {
		t.Fatalf("permissions not stored/sorted as expected: %v", got)
	}

	// Isolation: bob and other hosts are untouched.
	bob := st.get("bob")
	if len(bob.Permissions) != 0 {
		t.Fatalf("permission grant leaked to another user: %+v", bob.Permissions)
	}
	if len(alice.Permissions["other.example.com"]) != 0 {
		t.Fatalf("permission grant leaked to another host: %+v", alice.Permissions)
	}

	// Clearing (empty list) removes the host entry entirely -- deny by
	// default, not "grant nothing but keep the key".
	if w := adminAdminAction(t, s, c, "admin", `{"action":"set_permissions","username":"alice","host":"dashboard.example.com","permissions":[]}`); w.Code != http.StatusOK {
		t.Fatalf("clear permissions: %d %s", w.Code, w.Body.String())
	}
	if alice := st.get("alice"); len(alice.Permissions) != 0 {
		t.Fatalf("cleared host key left behind: %+v", alice.Permissions)
	}
}

func TestAdminSetPermissionsValidation(t *testing.T) {
	s, st, c := newIdentityTestServer(t)
	if err := st.create(&User{Username: "alice", Hash: "x", Role: roleUser, Gen: 1, Created: time.Now()}); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		body string
	}{
		{"missing host", `{"action":"set_permissions","username":"alice","permissions":["a"]}`},
		{"bad permission chars", `{"action":"set_permissions","username":"alice","host":"dashboard.example.com","permissions":["not a valid key!"]}`},
		{"too many permissions", `{"action":"set_permissions","username":"alice","host":"dashboard.example.com","permissions":["p1","p2","p3","p4","p5","p6","p7","p8","p9","p10","p11","p12","p13","p14","p15","p16","p17"]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if w := adminAdminAction(t, s, c, "admin", tc.body); w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400, body = %s", w.Code, w.Body.String())
			}
		})
	}
	if got := st.get("alice").Permissions; len(got) != 0 {
		t.Fatalf("rejected requests changed stored permissions: %+v", got)
	}
}

func TestIntrospectionReturnsOnlyRequestedHostPermissions(t *testing.T) {
	s, st, c := newIdentityTestServer(t)
	if err := st.create(&User{
		Username: "alice", Hash: "x", Role: roleUser, Gen: 1, Created: time.Now(),
		Permissions: map[string][]string{
			"dashboard.example.com": {"pages:sandbox:view"},
			"other.example.com":     {"pages:secret:view"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	c.introspectToken = "test-introspect-token-1234567890ab"
	s.cfg = c

	alice := st.get("alice")
	cl := sessionClaims{user: "alice", gen: alice.Gen, sid: "sid-alice", exp: time.Now().Add(time.Hour).Unix()}
	body := `{"target_host":"dashboard.example.com"}`
	r := httptest.NewRequest(http.MethodPost, "http://auth/_auth/introspect", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+c.introspectToken)
	r.AddCookie(&http.Cookie{Name: c.cookieName, Value: mustIssuePASETO(t, c, cl)})
	w := httptest.NewRecorder()
	s.introspect(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("introspect: %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "pages:secret:view") {
		t.Fatalf("introspection leaked another host's permissions: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "pages:sandbox:view") {
		t.Fatalf("introspection missing the requested host's permissions: %s", w.Body.String())
	}
}

// --- authorization matrix -------------------------------------------------------

func TestNewAdminActionsRejectNonAdminAndNoSession(t *testing.T) {
	s, st, c := newIdentityTestServer(t)
	if err := st.create(&User{Username: "target", Hash: "x", Role: roleUser, Gen: 1, Created: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := st.create(&User{Username: "plain-user", Hash: "x", Role: roleUser, Gen: 1, Created: time.Now()}); err != nil {
		t.Fatal(err)
	}

	bodies := []string{
		`{"action":"set_display_name","username":"target","display_name":"X"}`,
		`{"action":"set_description","username":"target","description":"X"}`,
		`{"action":"rename_user","username":"target","new_username":"retitled"}`,
		`{"action":"set_permissions","username":"target","host":"dashboard.example.com","permissions":["a"]}`,
	}
	for _, body := range bodies {
		// Non-admin session: rejected.
		if w := adminAdminAction(t, s, c, "plain-user", body); w.Code != http.StatusForbidden {
			t.Fatalf("non-admin %s: status = %d, want 403", body, w.Code)
		}
		// No session at all: rejected (redirect to login).
		r := httptest.NewRequest(http.MethodPost, "http://auth/_auth/admin/api/action", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.adminAction(w, r)
		if w.Code == http.StatusOK {
			t.Fatalf("unauthenticated %s: status = %d, want a redirect/error, not 200", body, w.Code)
		}
	}
	if got := st.get("target"); got.DisplayName != "" || got.Description != "" || len(got.Permissions) != 0 {
		t.Fatalf("rejected requests mutated the target user: %+v", got)
	}
	if st.get("retitled") != nil {
		t.Fatal("rejected rename_user request still renamed the user")
	}
}
