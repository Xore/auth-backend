package main

import (
	"encoding/base32"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func testConfig(t *testing.T) config {
	t.Helper()
	_, n, _ := netParseCIDR("127.0.0.0/8")
	return config{authHost: "auth.example.com", cookieDom: ".example.com", cookieName: "auth", secret: []byte("01234567890123456789012345678901"), secure: true, ttl: time.Hour, maxAttempts: 3, lockout: time.Minute, minDwell: 0, formTTL: time.Minute, ringCap: 10, trustedNets: []*net.IPNet{n}, maxBodyBytes: 65536}
}

// Alias keeps the test setup readable without hiding production behavior.
func netParseCIDR(s string) (net.IP, *net.IPNet, error) { return net.ParseCIDR(s) }

func TestSafeRedirect(t *testing.T) {
	c := testConfig(t)
	for _, tc := range []struct {
		in      string
		allowed bool
	}{
		{"https://grafana.example.com/path?q=1", true},
		{"https://example.com/", true},
		{"https://example.com.evil.test/", false},
		{"http://grafana.example.com/", false},
		{"//evil.test/", false},
	} {
		got := c.safeRedirect(tc.in)
		if tc.allowed && got != tc.in {
			t.Fatalf("safeRedirect(%q) = %q", tc.in, got)
		}
		if !tc.allowed && got == tc.in {
			t.Fatalf("unsafe redirect accepted: %q", got)
		}
	}
	c.cookieDom = ""
	if got := c.safeRedirect("https://evil.test/"); strings.Contains(got, "evil.test") {
		t.Fatalf("empty cookie domain allowed open redirect: %s", got)
	}
}

func TestHostAllowedFailsClosedAndSupportsIPv6(t *testing.T) {
	u := &User{AllowedHosts: []string{"*.example.com", "[2001:db8::1]"}}
	for _, host := range []string{"a.example.com", "A.EXAMPLE.COM:443", "[2001:db8::1]:443"} {
		if !u.hostAllowed(host) {
			t.Errorf("expected %q allowed", host)
		}
	}
	for _, host := range []string{"", "example.com", "example.com.evil.test"} {
		if u.hostAllowed(host) {
			t.Errorf("expected %q denied", host)
		}
	}
}

func TestSessionAndDeviceTokens(t *testing.T) {
	c := testConfig(t)
	cl := sessionClaims{user: "alice", gen: 2, sid: "sid", exp: time.Now().Add(time.Minute).Unix()}
	tok := c.issueSession(cl)
	if got, ok := c.parseSession(tok); !ok || got.user != "alice" {
		t.Fatal("valid session rejected")
	}
	if _, ok := c.parseSession(tok + "x"); ok {
		t.Fatal("tampered session accepted")
	}
	c.trustDevDays = 7
	dev := c.issueDevice("alice", 3)
	if !c.validDevice(dev, "alice", 3) {
		t.Fatal("valid device rejected")
	}
	if c.validDevice(dev, "alice", 4) {
		t.Fatal("device survived generation change")
	}
}

func TestStoreCopiesAndPersistsPasskeyID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	st := newUserStore(path)
	if _, err := st.bootstrap("admin", "a-long-test-password", ""); err != nil {
		t.Fatal(err)
	}
	u := st.get("admin")
	if len(u.PasskeyUserID) != 32 {
		t.Fatalf("unexpected WebAuthn ID length %d", len(u.PasskeyUserID))
	}
	u.Role = roleUser
	if st.get("admin").Role != roleAdmin {
		t.Fatal("get returned mutable store pointer")
	}
	loaded := newUserStore(path)
	if err := loaded.load(); err != nil {
		t.Fatal(err)
	}
	if string(loaded.get("admin").PasskeyUserID) != string(st.get("admin").PasskeyUserID) {
		t.Fatal("WebAuthn ID was not stable")
	}
}

func TestThrottleBoundsAndExpires(t *testing.T) {
	c := testConfig(t)
	tr := newThrottle(c)
	for i := 0; i < 9000; i++ {
		tr.fail(fmt.Sprintf("192.0.2.%d", i))
	}
	tr.mu.Lock()
	size := len(tr.m)
	tr.mu.Unlock()
	if size > 8192 {
		t.Fatalf("throttle map unbounded: %d", size)
	}
	tr.mu.Lock()
	tr.m["expired"] = &entry{fails: 5, lockUntil: time.Now().Add(-2 * time.Minute)}
	tr.mu.Unlock()
	if locked, _ := tr.locked("expired"); locked {
		t.Fatal("expired lock remains active")
	}
}

func TestAuditSnapshotClampsNegative(t *testing.T) {
	a := newAuditor("", 10)
	a.record(authEvent{Event: "login_ok"})
	if got := a.snapshot(-1); len(got.Recent) != 0 {
		t.Fatal("negative snapshot was not clamped")
	}
}

func TestVerifyReturnsConfiguredIdentityHeaders(t *testing.T) {
	c := testConfig(t)
	path := filepath.Join(t.TempDir(), "users.json")
	st := newUserStore(path)
	if _, err := st.bootstrap("admin", "a-long-test-password", ""); err != nil {
		t.Fatal(err)
	}
	u := st.get("admin")
	s := &server{cfg: c, users: st, reg: newSessionRegistry(time.Hour), tr: newThrottle(c), aud: newAuditor("", 10), log: slog.New(slog.NewTextHandler(io.Discard, nil)), ntf: newNotifier("", slog.Default())}
	cl := sessionClaims{user: u.Username, gen: u.Gen, sid: "sid", exp: time.Now().Add(time.Minute).Unix()}
	r := httptest.NewRequest("GET", "http://auth/_auth/verify", nil)
	r.Header.Set("X-Forwarded-Host", "app.example.com")
	r.AddCookie(&http.Cookie{Name: c.cookieName, Value: c.issueSession(cl)})
	w := httptest.NewRecorder()
	s.verify(w, r)
	if w.Code != 200 || w.Header().Get("X-Auth-User") != "admin" || w.Header().Get("X-Auth-Role") != "admin" {
		t.Fatalf("unexpected verify response: %d %v", w.Code, w.Header())
	}
}

func TestArgon2idRoundTrip(t *testing.T) {
	h, err := hashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$") {
		t.Fatalf("hash is not argon2id PHC: %s", h)
	}
	ok, err := verifyArgon2id("correct horse battery staple", h)
	if err != nil || !ok {
		t.Fatalf("valid password rejected (ok=%v err=%v)", ok, err)
	}
	if ok, _ := verifyArgon2id("wrong password", h); ok {
		t.Fatal("wrong password accepted")
	}
	if _, err := verifyArgon2id("pw", "not-a-phc-string"); err == nil {
		t.Fatal("garbage hash parsed without error")
	}
	// parameters out of range are rejected before any allocation
	if _, err := verifyArgon2id("pw", "$argon2id$v=19$m=99999999,t=3,p=4$AqEs8VKjYucHBmGSPfqyVQ$A8ilJSZbSUHYrR86d+hLXr4xA8z3DIpvZpaTdICHNLA"); err == nil {
		t.Fatal("out-of-range argon2 parameters accepted")
	}
}

func TestBcryptTransparentUpgrade(t *testing.T) {
	bcryptHash, err := bcrypt.GenerateFromPassword([]byte("a-long-test-password"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "users.json")
	st := newUserStore(path)
	// bootstrap keeps a pre-hashed (bcrypt) password as-is
	if _, err := st.bootstrap("admin", string(bcryptHash), ""); err != nil {
		t.Fatal(err)
	}
	if !looksLikeBcrypt(st.get("admin").Hash) {
		t.Fatal("bootstrap did not keep the bcrypt hash")
	}
	// first login: bcrypt accepted, hash upgraded to argon2id
	if !st.checkPassword("admin", "a-long-test-password") {
		t.Fatal("bcrypt password rejected")
	}
	if got := st.get("admin").Hash; !strings.HasPrefix(got, "$argon2id$") {
		t.Fatalf("hash not upgraded to argon2id: %s", got)
	}
	// second login: goes through the argon2 path
	if !st.checkPassword("admin", "a-long-test-password") {
		t.Fatal("upgraded argon2id password rejected")
	}
	if st.checkPassword("admin", "wrong-password") {
		t.Fatal("wrong password accepted after upgrade")
	}
	// the upgrade was persisted
	loaded := newUserStore(path)
	if err := loaded.load(); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(loaded.get("admin").Hash, "$argon2id$") {
		t.Fatal("upgraded hash not persisted")
	}
	// unknown user still burns time and fails
	if st.checkPassword("nobody", "a-long-test-password") {
		t.Fatal("unknown user accepted")
	}
}

func TestConfigRejectsPlaceholders(t *testing.T) {
	c := testConfig(t)
	c.password = "change-me-auth"
	c.secret = []byte("CHANGE_ME_openssl_rand_hex_32")
	if err := c.validate(); err == nil {
		t.Fatal("placeholder configuration accepted")
	}
}

func TestPendingTokenRoundTrip(t *testing.T) {
	c := testConfig(t)
	tok := c.issuePending("alice", true)
	user, remember, ok := c.parsePending(tok)
	if !ok || user != "alice" || !remember {
		t.Fatal("valid pending token rejected")
	}
	if _, _, ok := c.parsePending(tok + "x"); ok {
		t.Fatal("tampered pending token accepted")
	}
	body := "pend|" + strconv.FormatInt(time.Now().Add(-time.Minute).Unix(), 10) + "|alice|0"
	expired := body + "|" + c.mac(body)
	if _, _, ok := c.parsePending(expired); ok {
		t.Fatal("expired pending token accepted")
	}
}

// TestTwoStepLoginFlow drives the password → pending cookie → TOTP pipeline
// end to end against the real handlers.
func TestTwoStepLoginFlow(t *testing.T) {
	c := testConfig(t)
	path := filepath.Join(t.TempDir(), "users.json")
	st := newUserStore(path)
	if _, err := st.bootstrap("admin", "a-long-test-password", "JBSWY3DPEHPK3PXP"); err != nil {
		t.Fatal(err)
	}
	s := &server{cfg: c, users: st, reg: newSessionRegistry(time.Hour), tr: newThrottle(c), aud: newAuditor("", 10), log: slog.New(slog.NewTextHandler(io.Discard, nil)), ntf: newNotifier("", slog.Default())}

	// Step 1: correct password → verify page + pending cookie, no session yet
	form := url.Values{}
	form.Set("ft", c.issueForm())
	form.Set("username", "admin")
	form.Set("password", "a-long-test-password")
	r := httptest.NewRequest("POST", "http://auth/_auth/login", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.login(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected verify page (200), got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `action="/_auth/totp"`) {
		t.Fatal("verify page not rendered after password")
	}
	var pend *http.Cookie
	for _, ck := range w.Result().Cookies() {
		if ck.Name == c.cookieName+"_pend" {
			pend = ck
		}
		if ck.Name == c.cookieName {
			t.Fatal("session cookie issued before 2FA")
		}
	}
	if pend == nil {
		t.Fatal("no pending cookie issued")
	}

	postCode := func(code string) *httptest.ResponseRecorder {
		f := url.Values{}
		f.Set("code", code)
		r := httptest.NewRequest("POST", "http://auth/_auth/totp", strings.NewReader(f.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(pend)
		w := httptest.NewRecorder()
		s.totp(w, r)
		return w
	}

	// Step 2a: wrong code → generic error re-render, throttle incremented
	if w := postCode("000000"); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Invalid code.") {
		t.Fatalf("wrong code: expected error re-render, got %d", w.Code)
	}

	// Step 2b: correct code → session cookie + redirect, pending cookie cleared
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatal(err)
	}
	w = postCode(hotp(key, time.Now().Unix()/30))
	if w.Code != http.StatusFound {
		t.Fatalf("correct code: expected 302, got %d", w.Code)
	}
	var sess *http.Cookie
	for _, ck := range w.Result().Cookies() {
		if ck.Name == c.cookieName {
			sess = ck
		}
		if ck.Name == c.cookieName+"_pend" && ck.MaxAge != -1 {
			t.Fatal("pending cookie not cleared after 2FA")
		}
	}
	if sess == nil {
		t.Fatal("no session cookie after 2FA")
	}

	// The issued session is accepted
	r = httptest.NewRequest("GET", "http://auth/_auth/verify", nil)
	r.AddCookie(sess)
	if _, _, ok := s.session(r); !ok {
		t.Fatal("session issued after 2FA rejected")
	}

	// A request to /_auth/totp without a pending cookie bounces to login
	r = httptest.NewRequest("POST", "http://auth/_auth/totp", nil)
	w = httptest.NewRecorder()
	s.totp(w, r)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("missing pending cookie: expected 303, got %d", w.Code)
	}
}

func newPasswordTestServer(t *testing.T) (*server, *userStore, *http.Cookie) {
	t.Helper()
	c := testConfig(t)
	path := filepath.Join(t.TempDir(), "users.json")
	st := newUserStore(path)
	if _, err := st.bootstrap("admin", "a-long-test-password", ""); err != nil {
		t.Fatal(err)
	}
	s := &server{cfg: c, users: st, reg: newSessionRegistry(time.Hour), tr: newThrottle(c), aud: newAuditor("", 10), log: slog.New(slog.NewTextHandler(io.Discard, nil)), ntf: newNotifier("", slog.Default())}
	u := st.get("admin")
	cl := sessionClaims{user: u.Username, gen: u.Gen, sid: "sid", exp: time.Now().Add(time.Minute).Unix()}
	return s, st, &http.Cookie{Name: c.cookieName, Value: c.issueSession(cl)}
}

func postPasswordChange(s *server, sess *http.Cookie, new1, new2 string) *httptest.ResponseRecorder {
	f := url.Values{}
	f.Set("ft", s.cfg.issueForm())
	f.Set("current", "a-long-test-password")
	f.Set("new1", new1)
	f.Set("new2", new2)
	r := httptest.NewRequest("POST", "http://auth/_auth/password", strings.NewReader(f.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(sess)
	w := httptest.NewRecorder()
	s.password(w, r)
	return w
}

func TestThrottleLockoutAccumulates(t *testing.T) {
	c := testConfig(t) // maxAttempts 3, lockout 1 minute
	tr := newThrottle(c)
	// regression: locked() must not prune counting entries (zero lockUntil),
	// otherwise the fail counter resets on every attempt and no lockout ever
	// triggers
	for i := 0; i < 2; i++ {
		if locked, _ := tr.locked("192.0.2.1"); locked {
			t.Fatalf("locked after %d fails", i)
		}
		tr.fail("192.0.2.1")
	}
	if !tr.fail("192.0.2.1") {
		t.Fatal("lockout did not trigger at maxAttempts")
	}
	if locked, _ := tr.locked("192.0.2.1"); !locked {
		t.Fatal("ip not locked after maxAttempts")
	}
}

func TestThrottlePersistRoundTrip(t *testing.T) {
	c := testConfig(t)
	path := filepath.Join(t.TempDir(), "throttle.json")
	tr := newThrottle(c)
	if err := tr.load(path); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		tr.fail("192.0.2.9")
	}
	if locked, d := tr.locked("192.0.2.9"); !locked || d <= 0 {
		t.Fatal("ip not locked before persist")
	}
	// simulate a restart: fresh throttle, same file
	tr2 := newThrottle(c)
	if err := tr2.load(path); err != nil {
		t.Fatal(err)
	}
	if locked, d := tr2.locked("192.0.2.9"); !locked || d <= 0 {
		t.Fatal("lockout did not survive the restart")
	}
	// an expired lockout is pruned on persist, not written
	tr.mu.Lock()
	tr.m["192.0.2.10"] = &entry{fails: 5, lockUntil: time.Now().Add(-2 * time.Minute)}
	tr.mu.Unlock()
	if err := tr.persist(path); err != nil {
		t.Fatal(err)
	}
	tr3 := newThrottle(c)
	if err := tr3.load(path); err != nil {
		t.Fatal(err)
	}
	if locked, _ := tr3.locked("192.0.2.10"); locked {
		t.Fatal("expired lockout persisted")
	}
}

func TestIdleSessionExpiry(t *testing.T) {
	c := testConfig(t)
	c.idleTimeout = time.Hour
	path := filepath.Join(t.TempDir(), "users.json")
	st := newUserStore(path)
	if _, err := st.bootstrap("admin", "a-long-test-password", ""); err != nil {
		t.Fatal(err)
	}
	s := &server{cfg: c, users: st, reg: newSessionRegistry(time.Hour), tr: newThrottle(c), aud: newAuditor("", 10), log: slog.New(slog.NewTextHandler(io.Discard, nil)), ntf: newNotifier("", slog.Default())}
	u := st.get("admin")
	mkReq := func(sid string) *http.Request {
		cl := sessionClaims{user: u.Username, gen: u.Gen, sid: sid, exp: time.Now().Add(time.Hour).Unix()}
		r := httptest.NewRequest("GET", "http://auth/_auth/verify", nil)
		r.AddCookie(&http.Cookie{Name: c.cookieName, Value: c.issueSession(cl)})
		return r
	}

	// unknown to the registry (zero LastSeen) → no idle data, allowed
	if _, _, ok := s.session(mkReq("sid-fresh")); !ok {
		t.Fatal("session without registry entry rejected")
	}
	// recently seen → allowed
	s.reg.touch("sid-active", u.Username, "127.0.0.1", "test")
	if _, _, ok := s.session(mkReq("sid-active")); !ok {
		t.Fatal("active session rejected")
	}
	// last seen beyond the idle timeout → rejected and revoked
	s.reg.touch("sid-stale", u.Username, "127.0.0.1", "test")
	s.reg.mu.Lock()
	s.reg.m["sid-stale"].LastSeen = time.Now().Add(-2 * time.Hour)
	s.reg.mu.Unlock()
	if _, _, ok := s.session(mkReq("sid-stale")); ok {
		t.Fatal("idle session accepted")
	}
	if !s.reg.isRevoked("sid-stale") {
		t.Fatal("idle session not revoked")
	}
	// idleTimeout == 0 disables the check entirely
	s.cfg.idleTimeout = 0
	s.reg.touch("sid-old", u.Username, "127.0.0.1", "test")
	s.reg.mu.Lock()
	s.reg.m["sid-old"].LastSeen = time.Now().Add(-720 * time.Hour)
	s.reg.mu.Unlock()
	if _, _, ok := s.session(mkReq("sid-old")); !ok {
		t.Fatal("idle check not disabled by IDLE_TIMEOUT_MINUTES=0")
	}
}

func TestBackupCodeRegeneration(t *testing.T) {
	c := testConfig(t)
	path := filepath.Join(t.TempDir(), "users.json")
	st := newUserStore(path)
	if _, err := st.bootstrap("admin", "a-long-test-password", "JBSWY3DPEHPK3PXP"); err != nil {
		t.Fatal(err)
	}
	s := &server{cfg: c, users: st, reg: newSessionRegistry(time.Hour), tr: newThrottle(c), aud: newAuditor("", 10), log: slog.New(slog.NewTextHandler(io.Discard, nil)), ntf: newNotifier("", slog.Default())}

	// seed an initial set of codes
	oldPlain, oldHashed := newBackupCodes(8)
	if err := st.mutate("admin", func(u *User) bool { u.BackupCodes = oldHashed; return true }); err != nil {
		t.Fatal(err)
	}
	if !st.checkBackupCode("admin", oldPlain[0]) {
		t.Fatal("seeded backup code does not work")
	}
	// restore the consumed code so the old set is complete again
	if err := st.mutate("admin", func(u *User) bool { u.BackupCodes = oldHashed; return true }); err != nil {
		t.Fatal(err)
	}
	u := st.get("admin")
	devGenBefore := u.DeviceGen
	cl := sessionClaims{user: u.Username, gen: u.Gen, sid: "sid", exp: time.Now().Add(time.Minute).Unix()}

	f := url.Values{}
	f.Set("ft", c.issueForm())
	r := httptest.NewRequest("POST", "http://auth/_auth/backup-codes", strings.NewReader(f.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: c.cookieName, Value: c.issueSession(cl)})
	w := httptest.NewRecorder()
	s.handleBackupCodes(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if got := strings.Count(w.Body.String(), "<li>"); got != 8 {
		t.Fatalf("expected 8 new codes, got %d", got)
	}
	fresh := st.get("admin")
	if fresh.DeviceGen != devGenBefore+1 {
		t.Fatal("device generation not bumped")
	}
	if len(fresh.BackupCodes) != 8 {
		t.Fatalf("expected 8 stored code hashes, got %d", len(fresh.BackupCodes))
	}
	for _, code := range oldPlain {
		if st.checkBackupCode("admin", code) {
			t.Fatalf("old backup code %s still valid", code)
		}
	}
	// a bad form token is refused
	r = httptest.NewRequest("POST", "http://auth/_auth/backup-codes", strings.NewReader("ft=garbage"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: c.cookieName, Value: c.issueSession(cl)})
	w = httptest.NewRecorder()
	s.handleBackupCodes(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("bad form token: expected 403, got %d", w.Code)
	}
}

func TestCommonPasswordRejected(t *testing.T) {
	s, st, sess := newPasswordTestServer(t)
	if !isCommonPassword("password123") {
		t.Fatal("password123 missing from embedded breach list")
	}
	w := postPasswordChange(s, sess, "password123", "password123")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "breach lists") {
		t.Fatalf("common password not rejected: %d", w.Code)
	}
	if !st.checkPassword("admin", "a-long-test-password") {
		t.Fatal("password changed despite rejection")
	}
}

func TestUncommonPasswordAccepted(t *testing.T) {
	s, st, sess := newPasswordTestServer(t)
	unique := "zQ7!wR9#mK2$xLp4"
	if isCommonPassword(unique) {
		t.Fatal("unique password flagged as common")
	}
	w := postPasswordChange(s, sess, unique, unique)
	if w.Code != http.StatusFound {
		t.Fatalf("uncommon password rejected: %d", w.Code)
	}
	if !st.checkPassword("admin", unique) {
		t.Fatal("new password not in effect")
	}
}
