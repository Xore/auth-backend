package main

// recover_test.go — regression tests for the recovery identity model
// (optional validated Email field, back-compat with email-shaped usernames)
// and for atomic single-use recovery tokens.

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNormalizeEmail(t *testing.T) {
	for in, want := range map[string]string{
		"Alice@Example.COM": "Alice@example.com", // domain lowercased, local part verbatim
		"  bob@x.org  ":     "bob@x.org",
		"":                  "",
	} {
		got, err := normalizeEmail(in)
		if err != nil || got != want {
			t.Errorf("normalizeEmail(%q) = %q, %v — want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{
		"not-an-email",
		"Bob <bob@x.com>", // display names rejected
		"a b@c.com",
		"@x.com",
		"a@",
		strings.Repeat("a", 250) + "@x.com",
	} {
		if got, err := normalizeEmail(bad); err == nil {
			t.Errorf("normalizeEmail(%q) = %q, want error", bad, got)
		}
	}
}

func TestRecoveryEmailModel(t *testing.T) {
	// the dedicated field wins
	if got := (&User{Username: "bob", Email: "bob@example.org"}).recoveryEmail(); got != "bob@example.org" {
		t.Fatalf("Email field ignored: %q", got)
	}
	// back-compat: an email-shaped username is its own recovery address,
	// normalized for sending without the username itself changing
	legacy := &User{Username: "Alice@Example.COM"}
	if got := legacy.recoveryEmail(); got != "Alice@example.com" {
		t.Fatalf("email-shaped username not recovered: %q", got)
	}
	if legacy.Username != "Alice@Example.COM" {
		t.Fatal("username rewritten by normalization")
	}
	// a plain username with no Email field is not reachable
	if got := (&User{Username: "carol"}).recoveryEmail(); got != "" {
		t.Fatalf("unexpected recovery address: %q", got)
	}
}

// The Email field persists across store save/load; files written before the
// field existed load unchanged.
func TestUserEmailPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	st := newUserStore(path)
	h, err := hashPassword("a-long-test-password")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.create(&User{Username: "bob", Hash: h, Role: roleUser, Email: "bob@example.org", Gen: 1, Created: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := st.create(&User{Username: "legacy@example.com", Hash: h, Role: roleUser, Gen: 1, Created: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	loaded := newUserStore(path)
	if err := loaded.load(); err != nil {
		t.Fatal(err)
	}
	if got := loaded.get("bob").Email; got != "bob@example.org" {
		t.Fatalf("Email not persisted: %q", got)
	}
	if got := loaded.get("legacy@example.com").Email; got != "" {
		t.Fatalf("legacy user gained an Email: %q", got)
	}
	if got := loaded.get("legacy@example.com").recoveryEmail(); got != "legacy@example.com" {
		t.Fatalf("legacy email username unreachable: %q", got)
	}
}

func newRecoverTestServer(t *testing.T, c config, st *userStore) *server {
	t.Helper()
	return &server{cfg: c, users: st, reg: newSessionRegistry(time.Hour), tr: newThrottle(c),
		aud: newAuditor("", 10), log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		ntf: newNotifier("", "raw", slog.Default()), recoverLimit: rateLimiter{max: 3, window: time.Hour}}
}

func recoverPostForm(s *server, f url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "http://auth/_auth/recover", strings.NewReader(f.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.recover(w, r)
	return w
}

// Recovery mail goes to the validated Email field; accounts with no
// recovery address get the identical generic response (no enumeration).
func TestRecoverRequestUsesEmailField(t *testing.T) {
	c := testConfig(t)
	c.smtpURL = "smtp://mail.example.com"
	path := filepath.Join(t.TempDir(), "users.json")
	st := newUserStore(path)
	h, err := hashPassword("a-long-test-password")
	if err != nil {
		t.Fatal(err)
	}
	mk := func(name, email string) {
		if err := st.create(&User{Username: name, Hash: h, Role: roleUser, Email: email, Gen: 1, DeviceGen: 1, Created: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
	}
	mk("bob", "bob@example.org")
	mk("carol", "")
	s := newRecoverTestServer(t, c, st)

	var sentTo string
	old := sendMailFunc
	sendMailFunc = func(_, _, to, _, _ string, _ bool) error { sentTo = to; return nil }
	t.Cleanup(func() { sendMailFunc = old })

	post := func(username string) *httptest.ResponseRecorder {
		f := url.Values{}
		f.Set("ft", c.issueForm())
		f.Set("username", username)
		return recoverPostForm(s, f)
	}

	w := post("bob")
	if sentTo != "bob@example.org" {
		t.Fatalf("recovery mail went to %q, want the Email field", sentTo)
	}
	if !strings.Contains(w.Body.String(), "reset email is on its way") {
		t.Fatal("generic notice missing for emailable account")
	}

	sentTo = ""
	w = post("carol")
	if sentTo != "" {
		t.Fatalf("mail sent for account without recovery address: %q", sentTo)
	}
	if !strings.Contains(w.Body.String(), "reset email is on its way") {
		t.Fatal("response differs between emailable and unemailable accounts — enumeration signal")
	}

	sentTo = ""
	w = post("ghost")
	if sentTo != "" {
		t.Fatal("mail sent for unknown account")
	}
	if !strings.Contains(w.Body.String(), "reset email is on its way") {
		t.Fatal("response differs for unknown accounts — enumeration signal")
	}
}

// Two (or N) concurrent resets with the same token: exactly one succeeds —
// the fingerprint is re-checked under the store lock, so the loser sees the
// "invalid or expired" page. Deterministic regardless of scheduling.
func TestRecoverConcurrentResetSingleUse(t *testing.T) {
	c := testConfig(t)
	c.smtpURL = "smtp://mail.example.com"
	path := filepath.Join(t.TempDir(), "users.json")
	st := newUserStore(path)
	if _, err := st.bootstrap("alice@example.com", "a-long-test-password", ""); err != nil {
		t.Fatal(err)
	}
	s := newRecoverTestServer(t, c, st)

	u := st.get("alice@example.com")
	tok := c.issueRecoveryToken(u)
	genBefore, devGenBefore := u.Gen, u.DeviceGen

	const racers = 8
	var wg sync.WaitGroup
	codes := make([]int, racers)
	bodies := make([]string, racers)
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			f := url.Values{}
			f.Set("token", tok)
			pw := fmt.Sprintf("unique-recovery-pw-%d", i)
			f.Set("new1", pw)
			f.Set("new2", pw)
			w := recoverPostForm(s, f)
			codes[i] = w.Code
			bodies[i] = w.Body.String()
		}(i)
	}
	close(start)
	wg.Wait()

	wins := 0
	winnerPW := ""
	for i := range racers {
		switch {
		case codes[i] == http.StatusFound:
			wins++
			winnerPW = fmt.Sprintf("unique-recovery-pw-%d", i)
		case codes[i] == http.StatusOK && strings.Contains(bodies[i], "invalid or has expired"):
			// the expected loser outcome
		default:
			t.Fatalf("racer %d: unexpected outcome %d", i, codes[i])
		}
	}
	if wins != 1 {
		t.Fatalf("%d concurrent resets succeeded with one token, want exactly 1", wins)
	}
	if !st.checkPassword("alice@example.com", winnerPW) {
		t.Fatal("winner's password not in effect")
	}
	got := st.get("alice@example.com")
	if got.Gen != genBefore+1 || got.DeviceGen != devGenBefore+1 {
		t.Fatalf("generations = %d/%d, want exactly one bump (%d/%d)",
			got.Gen, got.DeviceGen, genBefore+1, devGenBefore+1)
	}
	if _, ok := s.checkRecoveryToken(tok); ok {
		t.Fatal("token still valid after the winning reset")
	}
}
