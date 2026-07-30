package main

// magic_test.go — regression tests for magic-link sign-in, focused on the
// invalidation contract: an outstanding link must die when the account's
// credentials are revoked, not merely when the link itself is consumed.

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

func newMagicTestServer(t *testing.T, c config, st *userStore) *server {
	t.Helper()
	return &server{cfg: c, users: st, reg: newSessionRegistry(time.Hour), tr: newThrottle(c),
		aud: newAuditor("", 10), log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		ntf: newNotifier("", "raw", slog.Default()), magicLimit: rateLimiter{max: 3, window: time.Hour}}
}

func newMagicTestStore(t *testing.T) *userStore {
	t.Helper()
	st := newUserStore(filepath.Join(t.TempDir(), "users.json"))
	if _, err := st.bootstrap("alice@example.com", "a-long-test-password", ""); err != nil {
		t.Fatal(err)
	}
	return st
}

func magicConfig(t *testing.T) config {
	t.Helper()
	c := testConfig(t)
	c.magicLink = true
	c.smtpURL = "smtp://mail.example.com"
	return c
}

// consumeMagic redeems a token and reports whether the link was accepted.
// The rejection path re-renders the request form with the "invalid or has
// expired" notice; acceptance redirects or renders the second-factor page.
func consumeMagic(s *server, tok string) bool {
	r := httptest.NewRequest("GET", "http://auth/_auth/magic?token="+url.QueryEscape(tok), nil)
	w := httptest.NewRecorder()
	s.magic(w, r)
	return !strings.Contains(w.Body.String(), "invalid or has expired")
}

// A password change must invalidate every outstanding magic link. The
// fingerprint covers the password hash, so the reset alone is enough — no
// call site has to know magic links exist.
func TestMagicLinkDiesOnPasswordChange(t *testing.T) {
	c := magicConfig(t)
	st := newMagicTestStore(t)
	s := newMagicTestServer(t, c, st)

	tok := c.issueMagicToken(st.get("alice@example.com"))

	newHash, err := hashPassword("a-different-long-password")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.mutate("alice@example.com", func(u *User) bool {
		u.Hash = newHash
		u.Gen++
		return true
	}); err != nil {
		t.Fatal(err)
	}

	if consumeMagic(s, tok) {
		t.Fatal("magic link still valid after password change — revocation does not reach outstanding links")
	}
}

// Admin "log out everywhere" bumps Gen without touching the password. That
// must also kill outstanding links.
func TestMagicLinkDiesOnGenerationBump(t *testing.T) {
	c := magicConfig(t)
	st := newMagicTestStore(t)
	s := newMagicTestServer(t, c, st)

	tok := c.issueMagicToken(st.get("alice@example.com"))

	if err := st.mutate("alice@example.com", func(u *User) bool {
		u.Gen++
		u.DeviceGen++
		return true
	}); err != nil {
		t.Fatal(err)
	}

	if consumeMagic(s, tok) {
		t.Fatal("magic link survived a session-generation bump")
	}
}

// A disabled account cannot redeem an outstanding link.
func TestMagicLinkDiesOnDisable(t *testing.T) {
	c := magicConfig(t)
	st := newMagicTestStore(t)
	s := newMagicTestServer(t, c, st)

	tok := c.issueMagicToken(st.get("alice@example.com"))

	if err := st.mutate("alice@example.com", func(u *User) bool {
		u.Disabled = true
		return true
	}); err != nil {
		t.Fatal(err)
	}

	if consumeMagic(s, tok) {
		t.Fatal("disabled account redeemed a magic link")
	}
}

// Baseline: an untouched link works, and works exactly once — consumption
// increments MagicSeq, which the fingerprint also covers.
func TestMagicLinkSingleUse(t *testing.T) {
	c := magicConfig(t)
	st := newMagicTestStore(t)
	s := newMagicTestServer(t, c, st)

	tok := c.issueMagicToken(st.get("alice@example.com"))

	if !consumeMagic(s, tok) {
		t.Fatal("freshly issued magic link was rejected")
	}
	if consumeMagic(s, tok) {
		t.Fatal("magic link redeemed twice — not single-use")
	}
}

// N concurrent redemptions of the same token: exactly one succeeds. The
// fingerprint is re-checked and MagicSeq incremented under the store lock.
func TestMagicLinkConcurrentSingleUse(t *testing.T) {
	c := magicConfig(t)
	st := newMagicTestStore(t)
	s := newMagicTestServer(t, c, st)

	tok := c.issueMagicToken(st.get("alice@example.com"))

	const racers = 8
	var wg sync.WaitGroup
	accepted := make([]bool, racers)
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			accepted[i] = consumeMagic(s, tok)
		}(i)
	}
	close(start)
	wg.Wait()

	wins := 0
	for _, ok := range accepted {
		if ok {
			wins++
		}
	}
	if wins != 1 {
		t.Fatalf("concurrent redemptions accepted %d times, want exactly 1", wins)
	}
}

// The endpoint must not reveal whether an account exists. The CSP nonce and
// the anti-replay form token are freshly random on every render, so they are
// masked out before comparing — everything else must match byte for byte.
var magicNonceRE = regexp.MustCompile(`nonce="[0-9a-f]+"`)

func maskPerRequest(body string) string {
	body = magicNonceRE.ReplaceAllString(body, `nonce="X"`)
	return regexp.MustCompile(`name="ft" value="[^"]*"`).ReplaceAllString(body, `name="ft" value="X"`)
}

func TestMagicRequestNoEnumeration(t *testing.T) {
	c := magicConfig(t)
	st := newMagicTestStore(t)
	s := newMagicTestServer(t, c, st)
	// headroom: this test issues several requests from one IP and is not
	// exercising the limiter.
	s.magicLimit = rateLimiter{max: 100, window: time.Hour}

	post := func(username string) string {
		f := url.Values{}
		f.Set("username", username)
		f.Set("ft", c.issueForm())
		r := httptest.NewRequest("POST", "http://auth/_auth/magic", strings.NewReader(f.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		s.magic(w, r)
		return maskPerRequest(w.Body.String())
	}

	// Known account, unknown account, and a known account with no recovery
	// address on file must all produce the identical page.
	if err := st.mutate("alice@example.com", func(u *User) bool { u.Disabled = true; return true }); err != nil {
		t.Fatal(err)
	}
	disabled := post("alice@example.com")
	if err := st.mutate("alice@example.com", func(u *User) bool { u.Disabled = false; return true }); err != nil {
		t.Fatal(err)
	}

	known, unknown := post("alice@example.com"), post("nobody@example.com")
	if known != unknown {
		t.Fatal("response differs for unknown accounts — enumeration signal")
	}
	if known != disabled {
		t.Fatal("response differs for disabled accounts — enumeration signal")
	}
}

// With MAGIC_LINK unset the routes must not exist at all.
func TestMagicDisabledReturns404(t *testing.T) {
	c := testConfig(t)
	c.magicLink = false
	st := newMagicTestStore(t)
	s := newMagicTestServer(t, c, st)

	r := httptest.NewRequest("GET", "http://auth/_auth/magic", nil)
	w := httptest.NewRecorder()
	s.magic(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("disabled magic endpoint returned %d, want 404", w.Code)
	}
}
