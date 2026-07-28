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
