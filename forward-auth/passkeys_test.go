package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

func newPasskeyTestServer(t *testing.T) (*server, *userStore) {
	t.Helper()
	c := testConfig(t)
	st := newUserStore(filepath.Join(t.TempDir(), "users.json"))
	if _, err := st.bootstrap("alice", "a-long-test-password", ""); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "test", RPID: "auth.example.com", RPOrigins: []string{"https://auth.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	s := &server{
		cfg: c, users: st, reg: newSessionRegistry(time.Hour), tr: newThrottle(c),
		aud: newAuditor("", 10), log: logger, ntf: newNotifier("", "raw", logger),
		wa: wa, ceremonies: newCeremonyStore(),
	}
	return s, st
}

// go-webauthn silently discards a clone-warning signal into
// cred.Authenticator.CloneWarning instead of returning an error from
// FinishLogin (see #39) — the caller must check it explicitly. This drives
// that check directly with a hand-built credential rather than a full
// simulated WebAuthn ceremony, which needs no real assertion signing to
// exercise.
func TestRejectClonedPasskey(t *testing.T) {
	s, _ := newPasskeyTestServer(t)
	cred := &webauthn.Credential{Authenticator: webauthn.Authenticator{CloneWarning: true}}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "http://auth/_auth/passkeys/login/finish", nil)
	rejected := s.rejectClonedPasskey(w, r, "203.0.113.7", "alice", "alice", cred)

	if !rejected {
		t.Fatal("expected rejection for a clone-warning credential")
	}
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (jsonErr)", w.Code, http.StatusBadRequest)
	}
	if strings.Contains(w.Body.String(), "redirect") {
		t.Fatalf("response looks like a successful login: %s", w.Body.String())
	}
	locked, _, err := s.tr.locked("user:alice")
	_ = locked // a single attempt won't lock; just confirm no error reading the counter
	if err != nil {
		t.Fatal(err)
	}
	snap := s.aud.snapshot(10)
	found := false
	for _, e := range snap.Recent {
		if e.Event == "passkey_login_clone_warning" {
			found = true
		}
	}
	if !found {
		t.Fatal("clone-warning login did not produce a distinct audit event")
	}
}

// A credential without the clone-warning flag must pass through unaffected.
func TestRejectClonedPasskeyAllowsCleanCredential(t *testing.T) {
	s, _ := newPasskeyTestServer(t)
	cred := &webauthn.Credential{}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "http://auth/_auth/passkeys/login/finish", nil)
	if s.rejectClonedPasskey(w, r, "203.0.113.7", "alice", "alice", cred) {
		t.Fatal("a credential with no clone warning was rejected")
	}
	if w.Body.Len() != 0 {
		t.Fatalf("rejectClonedPasskey wrote a response for a clean credential: %s", w.Body.String())
	}
}

// Registration must request user verification — without it, an
// authenticator with no PIN/biometric configured can register with mere
// possession, and PASSWORDLESS mode makes a passkey the sole factor (#40).
func TestPasskeyRegisterRequiresUserVerification(t *testing.T) {
	s, st := newPasskeyTestServer(t)
	u := st.get("alice")
	cl := sessionClaims{user: "alice", gen: u.Gen, sid: "sid", exp: time.Now().Add(time.Hour).Unix()}

	body := strings.NewReader(`{"name":"laptop"}`)
	r := httptest.NewRequest(http.MethodPost, "http://auth/_auth/passkeys/register/begin", body)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Csrf", s.cfg.csrfToken(cl.sid))
	r.AddCookie(&http.Cookie{Name: s.cfg.cookieName, Value: mustIssuePASETO(t, s.cfg, cl)})
	w := httptest.NewRecorder()
	s.passkeyRegisterBegin(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	assertUserVerificationRequired(t, w.Body.Bytes())
}

// Login (assertion) must equally request user verification.
func TestPasskeyLoginRequiresUserVerification(t *testing.T) {
	s, st := newPasskeyTestServer(t)
	if err := st.mutate("alice", func(u *User) bool {
		u.Passkeys = []Passkey{{Name: "laptop", Credential: webauthn.Credential{ID: []byte{1, 2, 3}}}}
		return true
	}); err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest(http.MethodPost, "http://auth/_auth/passkeys/login/begin", strings.NewReader(`{"username":"alice"}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.passkeyLoginBegin(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	assertUserVerificationRequired(t, w.Body.Bytes())
}

func assertUserVerificationRequired(t *testing.T, body []byte) {
	t.Helper()
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatal(err)
	}
	options, ok := raw["options"]
	if !ok {
		t.Fatalf("response has no options field: %s", body)
	}
	var opts struct {
		PublicKey struct {
			AuthenticatorSelection struct {
				UserVerification string `json:"userVerification"`
			} `json:"authenticatorSelection"`
			UserVerification string `json:"userVerification"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(options, &opts); err != nil {
		t.Fatal(err)
	}
	got := opts.PublicKey.AuthenticatorSelection.UserVerification
	if got == "" {
		got = opts.PublicKey.UserVerification
	}
	if got != "required" {
		t.Fatalf("userVerification = %q, want %q — options: %s", got, "required", options)
	}
}

// PASSWORDLESS=true must not be allowed to start unless an enabled admin
// already has a registered passkey (#38): password login and recovery are
// both disabled in that mode, and passkey enrollment itself requires a
// session, so reaching this state with no admin passkey locks out every
// administrator permanently.
func TestHasEnabledAdminWithPasskey(t *testing.T) {
	st := newUserStore(filepath.Join(t.TempDir(), "users.json"))
	if _, err := st.bootstrap("admin", "a-long-test-password", ""); err != nil {
		t.Fatal(err)
	}
	if st.hasEnabledAdminWithPasskey() {
		t.Fatal("fresh bootstrap admin has no passkey yet")
	}
	if err := st.mutate("admin", func(u *User) bool {
		u.Passkeys = []Passkey{{Name: "key", Credential: webauthn.Credential{ID: []byte{1}}}}
		return true
	}); err != nil {
		t.Fatal(err)
	}
	if !st.hasEnabledAdminWithPasskey() {
		t.Fatal("admin now has a passkey but hasEnabledAdminWithPasskey said no")
	}
	if err := st.mutate("admin", func(u *User) bool { u.Disabled = true; return true }); err != nil {
		t.Fatal(err)
	}
	if st.hasEnabledAdminWithPasskey() {
		t.Fatal("a disabled admin's passkey must not count")
	}
	if err := st.mutate("admin", func(u *User) bool { u.Disabled = false; u.Role = "user"; return true }); err != nil {
		t.Fatal(err)
	}
	if st.hasEnabledAdminWithPasskey() {
		t.Fatal("a non-admin's passkey must not count")
	}
}

func TestPasskeyListReturnsOnlyDisplayMetadata(t *testing.T) {
	c := testConfig(t)
	st := newUserStore(filepath.Join(t.TempDir(), "users.json"))
	if _, err := st.bootstrap("alice", "a-long-test-password", ""); err != nil {
		t.Fatal(err)
	}
	created := time.Date(2026, 7, 28, 10, 30, 0, 0, time.UTC)
	if err := st.mutate("alice", func(u *User) bool {
		u.Passkeys = []Passkey{{
			Name: "Laptop",
			Credential: webauthn.Credential{
				ID:        []byte{0xde, 0xad, 0xbe, 0xef},
				PublicKey: []byte("must-not-be-returned"),
			},
			Created: created,
		}}
		return true
	}); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := &server{
		cfg: c, users: st, reg: newSessionRegistry(time.Hour), tr: newThrottle(c),
		aud: newAuditor("", 10), log: logger, ntf: newNotifier("", "raw", logger),
	}
	u := st.get("alice")
	claims := sessionClaims{user: "alice", gen: u.Gen, sid: "sid", exp: time.Now().Add(time.Hour).Unix()}

	request := httptest.NewRequest(http.MethodGet, "http://auth/_auth/passkeys/list", nil)
	request.AddCookie(&http.Cookie{Name: c.cookieName, Value: mustIssuePASETO(t, c, claims)})
	response := httptest.NewRecorder()
	s.passkeyList(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "must-not-be-returned") ||
		strings.Contains(response.Body.String(), "publicKey") {
		t.Fatalf("response leaked credential material: %s", response.Body.String())
	}
	var got []struct {
		ID      string    `json:"id"`
		Name    string    `json:"name"`
		Created time.Time `json:"created"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "deadbeef" || got[0].Name != "Laptop" || !got[0].Created.Equal(created) {
		t.Fatalf("unexpected passkey list: %#v", got)
	}
}

func TestPasskeyListRequiresSessionAndGET(t *testing.T) {
	c := testConfig(t)
	st := newUserStore(filepath.Join(t.TempDir(), "users.json"))
	if _, err := st.bootstrap("alice", "a-long-test-password", ""); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := &server{
		cfg: c, users: st, reg: newSessionRegistry(time.Hour), tr: newThrottle(c),
		aud: newAuditor("", 10), log: logger, ntf: newNotifier("", "raw", logger),
	}

	response := httptest.NewRecorder()
	s.passkeyList(response, httptest.NewRequest(http.MethodGet, "http://auth/_auth/passkeys/list", nil))
	if response.Code != http.StatusForbidden {
		t.Fatalf("unauthenticated status = %d, want %d", response.Code, http.StatusForbidden)
	}

	response = httptest.NewRecorder()
	s.passkeyList(response, httptest.NewRequest(http.MethodPost, "http://auth/_auth/passkeys/list", nil))
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d, want %d", response.Code, http.StatusMethodNotAllowed)
	}
}
