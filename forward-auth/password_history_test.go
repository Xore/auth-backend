package main

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPasswordWasUsedBeforeChecksCurrentAndHistory(t *testing.T) {
	currentHash, err := hashPassword("current-password-value")
	if err != nil {
		t.Fatal(err)
	}
	oldHash1, err := hashPassword("old-password-value-one")
	if err != nil {
		t.Fatal(err)
	}
	oldHash2, err := hashPassword("old-password-value-two")
	if err != nil {
		t.Fatal(err)
	}
	u := &User{Hash: currentHash, PasswordHistory: []string{oldHash1, oldHash2}}

	for _, pw := range []string{"current-password-value", "old-password-value-one", "old-password-value-two"} {
		if !passwordWasUsedBefore(pw, u) {
			t.Errorf("passwordWasUsedBefore(%q) = false, want true", pw)
		}
	}
	if passwordWasUsedBefore("a-genuinely-new-password", u) {
		t.Error("passwordWasUsedBefore reported a never-used password as reused")
	}
}

func TestRecordPasswordHistoryPrependsAndTrims(t *testing.T) {
	u := &User{}
	for i, h := range []string{"h1", "h2", "h3", "h4"} {
		recordPasswordHistory(u, h, 3)
		if u.PasswordHistory[0] != h {
			t.Fatalf("step %d: newest entry = %q, want %q (%v)", i, u.PasswordHistory[0], h, u.PasswordHistory)
		}
	}
	if len(u.PasswordHistory) != 3 {
		t.Fatalf("history not capped: %v", u.PasswordHistory)
	}
	if got := u.PasswordHistory; got[0] != "h4" || got[1] != "h3" || got[2] != "h2" {
		t.Fatalf("history not newest-first / oldest dropped: %v", got)
	}
}

func TestRecordPasswordHistoryZeroKeepClears(t *testing.T) {
	u := &User{PasswordHistory: []string{"h1", "h2"}}
	recordPasswordHistory(u, "h3", 0)
	if u.PasswordHistory != nil {
		t.Fatalf("keep<=0 should clear history, got %v", u.PasswordHistory)
	}
}

// TestPasswordChangeRejectsReuse is the end-to-end point of #63: a
// self-service change back to a recently-retired password must be
// rejected, with a message that doesn't read like the unrelated
// "current password wrong" or "breach list" failures.
func TestPasswordChangeRejectsReuse(t *testing.T) {
	c := testConfig(t)
	c.passwordHistory = 2
	path := filepath.Join(t.TempDir(), "users.json")
	st := newUserStore(path)
	if _, err := st.bootstrap("admin", "a-long-test-password", ""); err != nil {
		t.Fatal(err)
	}
	s := &server{cfg: c, users: st, reg: newSessionRegistry(time.Hour), tr: newThrottle(c), aud: newAuditor("", 10), log: slog.New(slog.NewTextHandler(io.Discard, nil)), ntf: newNotifier("", "raw", slog.Default())}

	change := func(current, new1, new2 string) *httptest.ResponseRecorder {
		u := st.get("admin")
		cl := sessionClaims{user: u.Username, gen: u.Gen, sid: "sid", exp: time.Now().Add(time.Minute).Unix()}
		sess := &http.Cookie{Name: c.cookieName, Value: mustIssuePASETO(t, c, cl)}
		f := url.Values{}
		f.Set("ft", s.cfg.csrfToken("sid"))
		f.Set("current", current)
		f.Set("new1", new1)
		f.Set("new2", new2)
		r := httptest.NewRequest("POST", "http://auth/_auth/password", strings.NewReader(f.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(sess)
		w := httptest.NewRecorder()
		s.password(w, r)
		return w
	}

	// First change: bootstrap password -> "first-new-password-value" succeeds.
	if w := change("a-long-test-password", "first-new-password-value", "first-new-password-value"); w.Code != http.StatusFound {
		t.Fatalf("first change: %d %s", w.Code, w.Body.String())
	}
	if got := st.get("admin").PasswordHistory; len(got) != 1 {
		t.Fatalf("history after first change = %v, want 1 entry (the bootstrap hash)", got)
	}

	// Second change: attempting to go right back to the bootstrap password
	// (now retired into history) must be rejected, not silently accepted.
	w := change("first-new-password-value", "a-long-test-password", "a-long-test-password")
	if w.Code != http.StatusOK {
		t.Fatalf("reused password change status = %d, want 200 (re-rendered form with an error)", w.Code)
	}
	if !strings.Contains(w.Body.String(), "matches a recent password") {
		t.Fatalf("reused password rejection missing expected message: %s", w.Body.String())
	}
	if !st.checkPassword("admin", "first-new-password-value") {
		t.Fatal("password was changed despite the reuse rejection")
	}

	// A genuinely new password succeeds.
	if w := change("first-new-password-value", "second-new-password-value", "second-new-password-value"); w.Code != http.StatusFound {
		t.Fatalf("genuinely new password rejected: %d %s", w.Code, w.Body.String())
	}
	if got := st.get("admin").PasswordHistory; len(got) != 2 {
		t.Fatalf("history after second change = %v, want 2 entries", got)
	}
}

// #63 is opt-in: testConfig (used by every other test in this package)
// leaves passwordHistory at its zero value, and every one of those
// existing tests already passes without ever tripping a reuse rejection
// -- this pins that zero-value contract directly rather than relying on
// it only being implied elsewhere.
func TestPasswordHistoryZeroValueIsDisabled(t *testing.T) {
	if got := testConfig(t).passwordHistory; got != 0 {
		t.Fatalf("testConfig().passwordHistory = %d, want 0 (existing deployments that never set PASSWORD_HISTORY_COUNT must see no behavior change)", got)
	}
}
