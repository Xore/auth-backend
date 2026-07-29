package main

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	pasetov4 "zntr.io/paseto/v4"
)

func testConfig(t *testing.T) config {
	t.Helper()
	_, n, _ := netParseCIDR("127.0.0.0/8")
	k, err := deriveKey([]byte("01234567890123456789012345678901"), "paseto-v4-local")
	if err != nil {
		t.Fatal(err)
	}
	return config{authHost: "auth.example.com", cookieDom: ".example.com", cookieName: "auth", secret: []byte("01234567890123456789012345678901"), pasetoKey: pasetov4.LocalKey(k), secure: true, ttl: time.Hour, maxAttempts: 3, lockout: time.Minute, minDwell: 0, formTTL: time.Minute, ringCap: 10, trustedNets: []*net.IPNet{n}, maxBodyBytes: 65536}
}

// Alias keeps the test setup readable without hiding production behavior.
func netParseCIDR(s string) (net.IP, *net.IPNet, error) { return net.ParseCIDR(s) }

func TestSettingsRedirect(t *testing.T) {
	for _, tc := range []struct {
		name string
		pane string
		want string
	}{
		{name: "default", want: "/auth/app"},
		{name: "specific pane", pane: "passkeys", want: "/auth/app?pane=passkeys"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "http://auth.example.com/_auth/ok", nil)
			settingsRedirect(tc.pane)(w, r)
			if w.Code != http.StatusFound {
				t.Fatalf("status = %d, want %d", w.Code, http.StatusFound)
			}
			if got := w.Header().Get("Location"); got != tc.want {
				t.Fatalf("Location = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestActionDialogsStayInsidePermanentSettingsDialog(t *testing.T) {
	page := string(mustReadUI("app.html"))
	settingsStart := strings.Index(page, `<dialog class="modal modal--permanent"`)
	if settingsStart < 0 {
		t.Fatal("permanent settings dialog is missing")
	}
	settingsEnd := strings.Index(page[settingsStart:], `</dialog>`)
	if settingsEnd < 0 {
		t.Fatal("permanent settings dialog is not closed")
	}
	settingsEnd += settingsStart
	for _, id := range []string{
		`id="flash"`,
		`id="edit-dialog-backdrop"`,
		`id="rotate-dialog-backdrop"`,
		`id="danger-dialog-backdrop"`,
	} {
		at := strings.Index(page, id)
		if at < settingsStart || at > settingsEnd {
			t.Fatalf("%s must remain inside the native settings dialog top layer", id)
		}
	}
}

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

func mustIssuePASETO(t *testing.T, c config, cl sessionClaims) string {
	t.Helper()
	tok, err := c.issueSessionPASETO(cl)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// TestLegacyTokenRejected: the legacy pipe-delimited HMAC format is no
// longer accepted (roadmap Step 17).
func TestLegacyTokenRejected(t *testing.T) {
	c := testConfig(t)
	legacyTok := "v2|9999999999|alice|1|sid|" + c.mac("v2|9999999999|alice|1|sid|")
	if _, ok, _ := c.parseSessionPASETO(legacyTok); ok {
		t.Fatal("legacy HMAC token accepted")
	}
	if _, ok, _ := c.parseSessionPASETO("v4.local.garbage"); ok {
		t.Fatal("garbage PASETO token accepted")
	}
}

func TestSessionAndDeviceTokens(t *testing.T) {
	c := testConfig(t)
	cl := sessionClaims{user: "alice", gen: 2, sid: "sid", exp: time.Now().Add(time.Minute).Unix()}
	tok := mustIssuePASETO(t, c, cl)
	if got, ok, _ := c.parseSessionPASETO(tok); !ok || got.user != "alice" {
		t.Fatal("valid session rejected")
	}
	if _, ok, _ := c.parseSessionPASETO(tok + "x"); ok {
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
	if u.Subject == "" {
		t.Fatal("bootstrap user is missing immutable subject")
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
	if loaded.get("admin").Subject != st.get("admin").Subject {
		t.Fatal("immutable subject was not stable")
	}
}

func TestStoreMigratesLegacyUserToStableSubject(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	if err := os.WriteFile(path, []byte(`{"users":[{"username":"legacy","hash":"x","role":"user","gen":1,"created":"2026-07-29T00:00:00Z"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	store := newUserStore(path)
	if err := store.load(); err != nil {
		t.Fatal(err)
	}
	subject := store.get("legacy").Subject
	if subject == "" {
		t.Fatal("legacy user was not assigned an immutable subject")
	}
	reloaded := newUserStore(path)
	if err := reloaded.load(); err != nil {
		t.Fatal(err)
	}
	if reloaded.get("legacy").Subject != subject {
		t.Fatal("migrated subject did not persist across reload")
	}
}

func TestStoreRejectsInvalidOrDuplicateSubjects(t *testing.T) {
	for _, test := range []struct {
		name string
		body string
	}{
		{
			name: "invalid",
			body: `{"users":[{"subject":"not-a-uuid","username":"first","hash":"x","role":"user","gen":1}]}`,
		},
		{
			name: "duplicate",
			body: `{"users":[
				{"subject":"b65ab0dc-cc07-4b3d-9af0-b482dbb4b096","username":"first","hash":"x","role":"user","gen":1},
				{"subject":"b65ab0dc-cc07-4b3d-9af0-b482dbb4b096","username":"second","hash":"x","role":"user","gen":1}
			]}`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "users.json")
			if err := os.WriteFile(path, []byte(test.body), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := newUserStore(path).load(); err == nil {
				t.Fatal("invalid subject store was accepted")
			}
		})
	}
}

func TestThrottleBoundsAndExpires(t *testing.T) {
	c := testConfig(t)
	tr := newThrottle(c)
	for i := 0; i < 9000; i++ {
		_, _ = tr.fail(fmt.Sprintf("192.0.2.%d", i))
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
	if locked, _, _ := tr.locked("expired"); locked {
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
	s := &server{cfg: c, users: st, reg: newSessionRegistry(time.Hour), tr: newThrottle(c), aud: newAuditor("", 10), log: slog.New(slog.NewTextHandler(io.Discard, nil)), ntf: newNotifier("", "raw", slog.Default())}
	cl := sessionClaims{user: u.Username, gen: u.Gen, sid: "sid", exp: time.Now().Add(time.Minute).Unix()}
	r := httptest.NewRequest("GET", "http://auth/_auth/verify", nil)
	r.Header.Set("X-Forwarded-Host", "app.example.com")
	r.AddCookie(&http.Cookie{Name: c.cookieName, Value: mustIssuePASETO(t, c, cl)})
	w := httptest.NewRecorder()
	s.verify(w, r)
	if w.Code != 200 || w.Header().Get("X-Auth-User") != "admin" || w.Header().Get("X-Auth-Role") != "admin" {
		t.Fatalf("unexpected verify response: %d %v", w.Code, w.Header())
	}
}

func TestIntrospectionReturnsCurrentAuthoritativeIdentity(t *testing.T) {
	c := testConfig(t)
	c.introspectToken = strings.Repeat("i", 32)
	path := filepath.Join(t.TempDir(), "users.json")
	st := newUserStore(path)
	if _, err := st.bootstrap("admin", "a-long-test-password", ""); err != nil {
		t.Fatal(err)
	}
	u := st.get("admin")
	s := &server{cfg: c, users: st, reg: newSessionRegistry(time.Hour), tr: newThrottle(c), aud: newAuditor("", 10), log: slog.New(slog.NewTextHandler(io.Discard, nil)), ntf: newNotifier("", "raw", slog.Default())}
	claims := sessionClaims{user: u.Username, gen: u.Gen, sid: "introspection-session", exp: time.Now().Add(time.Minute).Unix()}
	cookie := &http.Cookie{Name: c.cookieName, Value: mustIssuePASETO(t, c, claims)}

	request := httptest.NewRequest(http.MethodPost, "http://auth/_auth/introspect", strings.NewReader(`{"target_host":"app.example.com"}`))
	request.Header.Set("Authorization", "Bearer "+c.introspectToken)
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	s.introspect(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("introspection status = %d, body = %s", response.Code, response.Body.String())
	}
	var identity introspectionResponse
	if err := json.NewDecoder(response.Body).Decode(&identity); err != nil {
		t.Fatal(err)
	}
	if identity.Subject != u.Subject || identity.Username != u.Username || identity.Role != roleAdmin || identity.Generation != u.Gen {
		t.Fatalf("unexpected identity: %#v", identity)
	}

	if err := st.mutate("admin", func(current *User) bool {
		current.AllowedHosts = []string{"app.example.com"}
		current.Role = roleUser
		return true
	}); err != nil {
		t.Fatal(err)
	}
	request = httptest.NewRequest(http.MethodPost, "http://auth/_auth/introspect", strings.NewReader(`{"target_host":"app.example.com"}`))
	request.Header.Set("Authorization", "Bearer "+c.introspectToken)
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(cookie)
	response = httptest.NewRecorder()
	s.introspect(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("role-change introspection status = %d", response.Code)
	}
	if err := json.NewDecoder(response.Body).Decode(&identity); err != nil {
		t.Fatal(err)
	}
	if identity.Role != roleUser {
		t.Fatalf("stale role returned after mutation: %#v", identity)
	}

	request = httptest.NewRequest(http.MethodPost, "http://auth/_auth/introspect", strings.NewReader(`{"target_host":"other.example.com"}`))
	request.Header.Set("Authorization", "Bearer "+c.introspectToken)
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(cookie)
	response = httptest.NewRecorder()
	s.introspect(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("disallowed target host status = %d, want %d", response.Code, http.StatusForbidden)
	}

	if err := st.mutate("admin", func(current *User) bool {
		current.Disabled = true
		return true
	}); err != nil {
		t.Fatal(err)
	}
	request = httptest.NewRequest(http.MethodPost, "http://auth/_auth/introspect", strings.NewReader(`{"target_host":"app.example.com"}`))
	request.Header.Set("Authorization", "Bearer "+c.introspectToken)
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(cookie)
	response = httptest.NewRecorder()
	s.introspect(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("disabled-account status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
}

func TestIntrospectionRejectsForgedServiceAuthorizationAndInvalidSession(t *testing.T) {
	c := testConfig(t)
	c.introspectToken = strings.Repeat("i", 32)
	st := newUserStore(filepath.Join(t.TempDir(), "users.json"))
	if _, err := st.bootstrap("admin", "a-long-test-password", ""); err != nil {
		t.Fatal(err)
	}
	s := &server{cfg: c, users: st, reg: newSessionRegistry(time.Hour), tr: newThrottle(c), aud: newAuditor("", 10), log: slog.New(slog.NewTextHandler(io.Discard, nil)), ntf: newNotifier("", "raw", slog.Default())}
	for _, test := range []struct {
		name   string
		token  string
		cookie string
		status int
	}{
		{name: "missing service token", status: http.StatusUnauthorized},
		{name: "wrong service token", token: strings.Repeat("x", 32), status: http.StatusUnauthorized},
		{name: "invalid session", token: c.introspectToken, cookie: "forged", status: http.StatusUnauthorized},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "http://auth/_auth/introspect", strings.NewReader(`{"target_host":"app.example.com"}`))
			request.Header.Set("Content-Type", "application/json")
			if test.token != "" {
				request.Header.Set("Authorization", "Bearer "+test.token)
			}
			if test.cookie != "" {
				request.AddCookie(&http.Cookie{Name: c.cookieName, Value: test.cookie})
			}
			response := httptest.NewRecorder()
			s.introspect(response, request)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d", response.Code, test.status)
			}
		})
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

func TestConfigRejectsShortIntrospectionToken(t *testing.T) {
	c := testConfig(t)
	c.introspectToken = "too-short"
	if err := c.validate(); err == nil || !strings.Contains(err.Error(), "AUTH_INTROSPECTION_TOKEN") {
		t.Fatalf("short introspection token was not rejected: %v", err)
	}
}

func TestPASETORoundTrip(t *testing.T) {
	c := testConfig(t)
	original := sessionClaims{user: "alice", gen: 3, sid: "abcdef123456", flags: "c", exp: time.Now().Add(time.Hour).Unix()}
	tok, err := c.issueSessionPASETO(original)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if !strings.HasPrefix(tok, "v4.local.") {
		t.Fatalf("expected v4.local. prefix, got %.20s", tok)
	}
	parsed, ok, _ := c.parseSessionPASETO(tok)
	if !ok {
		t.Fatal("parseSessionPASETO returned false")
	}
	if parsed != original {
		t.Fatalf("claims mismatch: got %+v, want %+v", parsed, original)
	}
}

func TestPASETOTamperedRejected(t *testing.T) {
	c := testConfig(t)
	cl := sessionClaims{user: "bob", gen: 1, sid: "xyz", exp: time.Now().Add(time.Hour).Unix()}
	tok, err := c.issueSessionPASETO(cl)
	if err != nil {
		t.Fatal(err)
	}
	b := []byte(tok)
	b[len(b)-5] ^= 0xFF
	if _, ok, _ := c.parseSessionPASETO(string(b)); ok {
		t.Fatal("tampered token accepted")
	}
}

func TestPASETOExpiredRejected(t *testing.T) {
	c := testConfig(t)
	cl := sessionClaims{user: "carol", gen: 1, sid: "abc", exp: time.Now().Add(-time.Second).Unix()}
	tok, err := c.issueSessionPASETO(cl)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := c.parseSessionPASETO(tok); ok {
		t.Fatal("expired token accepted")
	}
}

func TestPASETOClaimValidation(t *testing.T) {
	c := testConfig(t)
	issue := func(mut func(*sessionPayload)) string {
		pl := sessionPayload{
			Issuer: c.authHost, Subject: "alice", IssuedAt: time.Now().Unix(),
			Expiry: time.Now().Add(time.Hour).Unix(), TokenID: "sid", Gen: 1,
		}
		mut(&pl)
		raw, _ := json.Marshal(pl)
		key := c.pasetoKey
		tok, err := pasetov4.Encrypt(rand.Reader, &key, raw, nil, pasetoAssertion())
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	if _, ok, _ := c.parseSessionPASETO(issue(func(p *sessionPayload) { p.Issuer = "other.host" })); ok {
		t.Fatal("wrong issuer accepted")
	}
	if _, ok, _ := c.parseSessionPASETO(issue(func(p *sessionPayload) { p.Subject = "" })); ok {
		t.Fatal("empty subject accepted")
	}
	if _, ok, _ := c.parseSessionPASETO(issue(func(p *sessionPayload) { p.TokenID = "" })); ok {
		t.Fatal("empty token id accepted")
	}
	if _, ok, _ := c.parseSessionPASETO(issue(func(p *sessionPayload) { p.IssuedAt = time.Now().Add(time.Hour).Unix() })); ok {
		t.Fatal("future-issued token accepted")
	}
}

func TestPASETOKeyRotation(t *testing.T) {
	keyA, _ := deriveKey([]byte("key-material-AAAAAAAAAAAAAAAAAAAAAA"), "paseto-v4-local")
	keyB, _ := deriveKey([]byte("key-material-BBBBBBBBBBBBBBBBBBBBBB"), "paseto-v4-local")

	c := testConfig(t)
	c.pasetoKey = pasetov4.LocalKey(keyA)
	cl := sessionClaims{user: "alice", gen: 1, sid: "sid-rot", exp: time.Now().Add(time.Hour).Unix()}
	tokA, err := c.issueSessionPASETO(cl)
	if err != nil {
		t.Fatal(err)
	}

	// B becomes primary, A moves to PASETO_KEY_PREVIOUS
	c.pasetoKey = pasetov4.LocalKey(keyB)
	c.oldPasetoKeys = []pasetov4.LocalKey{pasetov4.LocalKey(keyA)}
	if _, ok, usedOld := c.parseSessionPASETO(tokA); !ok || !usedOld {
		t.Fatal("old-key token not accepted via PASETO_KEY_PREVIOUS")
	}

	// server.session re-issues the token under the new key
	path := filepath.Join(t.TempDir(), "users.json")
	st := newUserStore(path)
	if _, err := st.bootstrap("alice", "a-long-test-password", ""); err != nil {
		t.Fatal(err)
	}
	s := &server{cfg: c, users: st, reg: newSessionRegistry(time.Hour), tr: newThrottle(c), aud: newAuditor("", 10), log: slog.New(slog.NewTextHandler(io.Discard, nil)), ntf: newNotifier("", "raw", slog.Default())}
	r := httptest.NewRequest("GET", "http://auth/_auth/verify", nil)
	r.AddCookie(&http.Cookie{Name: c.cookieName, Value: tokA})
	w := httptest.NewRecorder()
	if _, _, ok := s.session(w, r); !ok {
		t.Fatal("session rejected for old-key token")
	}
	var newTok string
	for _, ck := range w.Result().Cookies() {
		if ck.Name == c.cookieName {
			newTok = ck.Value
		}
	}
	if newTok == "" {
		t.Fatal("no rotated cookie issued")
	}
	if _, ok, usedOld := c.parseSessionPASETO(newTok); !ok || usedOld {
		t.Fatal("rotated token does not verify under the new primary key")
	}
	// unknown key: rejected
	c.oldPasetoKeys = nil
	if _, ok, _ := c.parseSessionPASETO(tokA); ok {
		t.Fatal("token accepted after its key left the rotation list")
	}
}

func TestPASETOKeyDerivation(t *testing.T) {
	secret := []byte("01234567890123456789012345678901")
	k1, err := deriveKey(secret, "paseto-v4-local")
	if err != nil {
		t.Fatal(err)
	}
	k2, _ := deriveKey(secret, "paseto-v4-local")
	if k1 != k2 {
		t.Fatal("deriveKey is not deterministic")
	}
	k3, _ := deriveKey(secret, "other-label")
	if k1 == k3 {
		t.Fatal("deriveKey ignores the purpose label")
	}
	k4, _ := deriveKey([]byte("different-secret-key-material-32b"), "paseto-v4-local")
	if k1 == k4 {
		t.Fatal("deriveKey ignores the secret")
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
	s := &server{cfg: c, users: st, reg: newSessionRegistry(time.Hour), tr: newThrottle(c), aud: newAuditor("", 10), log: slog.New(slog.NewTextHandler(io.Discard, nil)), ntf: newNotifier("", "raw", slog.Default())}

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
	if _, _, ok := s.session(httptest.NewRecorder(), r); !ok {
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
	s := &server{cfg: c, users: st, reg: newSessionRegistry(time.Hour), tr: newThrottle(c), aud: newAuditor("", 10), log: slog.New(slog.NewTextHandler(io.Discard, nil)), ntf: newNotifier("", "raw", slog.Default())}
	u := st.get("admin")
	cl := sessionClaims{user: u.Username, gen: u.Gen, sid: "sid", exp: time.Now().Add(time.Minute).Unix()}
	return s, st, &http.Cookie{Name: c.cookieName, Value: mustIssuePASETO(t, c, cl)}
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
		if locked, _, _ := tr.locked("192.0.2.1"); locked {
			t.Fatalf("locked after %d fails", i)
		}
		_, _ = tr.fail("192.0.2.1")
	}
	if locked, _ := tr.fail("192.0.2.1"); !locked {
		t.Fatal("lockout did not trigger at maxAttempts")
	}
	if locked, _, _ := tr.locked("192.0.2.1"); !locked {
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
		_, _ = tr.fail("192.0.2.9")
	}
	if locked, d, _ := tr.locked("192.0.2.9"); !locked || d <= 0 {
		t.Fatal("ip not locked before persist")
	}
	// simulate a restart: fresh throttle, same file
	tr2 := newThrottle(c)
	if err := tr2.load(path); err != nil {
		t.Fatal(err)
	}
	if locked, d, _ := tr2.locked("192.0.2.9"); !locked || d <= 0 {
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
	if locked, _, _ := tr3.locked("192.0.2.10"); locked {
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
	s := &server{cfg: c, users: st, reg: newSessionRegistry(time.Hour), tr: newThrottle(c), aud: newAuditor("", 10), log: slog.New(slog.NewTextHandler(io.Discard, nil)), ntf: newNotifier("", "raw", slog.Default())}
	reg := s.reg.(*sessionRegistry)
	u := st.get("admin")
	mkReq := func(sid string) *http.Request {
		cl := sessionClaims{user: u.Username, gen: u.Gen, sid: sid, exp: time.Now().Add(time.Hour).Unix()}
		r := httptest.NewRequest("GET", "http://auth/_auth/verify", nil)
		r.AddCookie(&http.Cookie{Name: c.cookieName, Value: mustIssuePASETO(t, c, cl)})
		return r
	}

	// unknown to the registry (zero LastSeen) → no idle data, allowed
	if _, _, ok := s.session(httptest.NewRecorder(), mkReq("sid-fresh")); !ok {
		t.Fatal("session without registry entry rejected")
	}
	// recently seen → allowed
	_ = reg.touch("sid-active", u.Username, "127.0.0.1", "test")
	if _, _, ok := s.session(httptest.NewRecorder(), mkReq("sid-active")); !ok {
		t.Fatal("active session rejected")
	}
	// last seen beyond the idle timeout → rejected and revoked
	_ = reg.touch("sid-stale", u.Username, "127.0.0.1", "test")
	reg.mu.Lock()
	reg.m["sid-stale"].LastSeen = time.Now().Add(-2 * time.Hour)
	reg.mu.Unlock()
	if _, _, ok := s.session(httptest.NewRecorder(), mkReq("sid-stale")); ok {
		t.Fatal("idle session accepted")
	}
	if revoked, _ := reg.isRevoked("sid-stale"); !revoked {
		t.Fatal("idle session not revoked")
	}
	// idleTimeout == 0 disables the check entirely
	s.cfg.idleTimeout = 0
	_ = reg.touch("sid-old", u.Username, "127.0.0.1", "test")
	reg.mu.Lock()
	reg.m["sid-old"].LastSeen = time.Now().Add(-720 * time.Hour)
	reg.mu.Unlock()
	if _, _, ok := s.session(httptest.NewRecorder(), mkReq("sid-old")); !ok {
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
	s := &server{cfg: c, users: st, reg: newSessionRegistry(time.Hour), tr: newThrottle(c), aud: newAuditor("", 10), log: slog.New(slog.NewTextHandler(io.Discard, nil)), ntf: newNotifier("", "raw", slog.Default())}

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
	r.AddCookie(&http.Cookie{Name: c.cookieName, Value: mustIssuePASETO(t, c, cl)})
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
	r.AddCookie(&http.Cookie{Name: c.cookieName, Value: mustIssuePASETO(t, c, cl)})
	w = httptest.NewRecorder()
	s.handleBackupCodes(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("bad form token: expected 403, got %d", w.Code)
	}
}

func TestRiskScore(t *testing.T) {
	ua := "Mozilla/5.0 (X11; Linux x86_64) Firefox/131"
	u := &User{}
	for i := 0; i < 6; i++ {
		u.History = append(u.History, loginRecord{
			Time: time.Date(2026, 7, 20, 10, 0, 0, 0, time.UTC),
			IP:   fmt.Sprintf("10.0.0.%d", i+1), UA: ua,
		})
	}
	now := time.Date(2026, 7, 27, 10, 30, 0, 0, time.UTC)
	if s := riskScore(u, "10.0.0.99", ua, now); s != 0 {
		t.Fatalf("familiar login scored %d, want 0", s)
	}
	if s := riskScore(u, "192.0.2.9", ua, now); s != 40 {
		t.Fatalf("new subnet: got %d, want 40", s)
	}
	if s := riskScore(u, "10.0.0.99", "curl/8.5", now); s != 30 {
		t.Fatalf("new UA: got %d, want 30", s)
	}
	if s := riskScore(u, "192.0.2.9", "curl/8.5", now); s != 70 {
		t.Fatalf("new subnet+UA: got %d, want 70", s)
	}
	if s := riskScore(u, "10.0.0.99", ua, time.Date(2026, 7, 27, 3, 0, 0, 0, time.UTC)); s != 20 {
		t.Fatalf("unusual hour: got %d, want 20", s)
	}
	if s := riskScore(&User{}, "192.0.2.9", "curl/8.5", now); s != 0 {
		t.Fatalf("no history: got %d, want 0", s)
	}
}

func TestRBAForcesTOTPDespiteTrustedDevice(t *testing.T) {
	c := testConfig(t)
	c.trustDevDays = 30
	path := filepath.Join(t.TempDir(), "users.json")
	st := newUserStore(path)
	if _, err := st.bootstrap("admin", "a-long-test-password", "JBSWY3DPEHPK3PXP"); err != nil {
		t.Fatal(err)
	}
	s := &server{cfg: c, users: st, reg: newSessionRegistry(time.Hour), tr: newThrottle(c), aud: newAuditor("", 10), log: slog.New(slog.NewTextHandler(io.Discard, nil)), ntf: newNotifier("", "raw", slog.Default())}
	// baseline history: one subnet, one UA, including the current hour
	if err := st.mutate("admin", func(u *User) bool {
		for i := 0; i < 6; i++ {
			u.History = append(u.History, loginRecord{
				Time: time.Now().Add(-time.Duration(i) * time.Hour),
				IP:   fmt.Sprintf("10.0.0.%d", i+1), UA: "old-ua",
			})
		}
		return true
	}); err != nil {
		t.Fatal(err)
	}

	login := func(ua string) *httptest.ResponseRecorder {
		f := url.Values{}
		f.Set("ft", c.issueForm())
		f.Set("username", "admin")
		f.Set("password", "a-long-test-password")
		r := httptest.NewRequest("POST", "http://auth/_auth/login", strings.NewReader(f.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("User-Agent", ua)
		r.AddCookie(&http.Cookie{Name: c.cookieName + "_dev", Value: c.issueDevice("admin", st.get("admin").DeviceGen)})
		w := httptest.NewRecorder()
		s.login(w, r)
		return w
	}

	// test requests come from 192.0.2.1 — an unseen subnet (+40).
	// anomalous login first: it never reaches finishLogin, so the history
	// stays untouched for the familiar case below
	w := login("brand-new-ua")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `action="/_auth/totp"`) {
		t.Fatalf("anomalous login (new subnet + new UA = 70) should demand TOTP despite trusted device, got %d", w.Code)
	}
	if w := login("old-ua"); w.Code != http.StatusFound {
		t.Fatalf("familiar UA on trusted device should skip TOTP (302), got %d", w.Code)
	}
}

func TestRecoveryTokenSingleUse(t *testing.T) {
	c := testConfig(t)
	path := filepath.Join(t.TempDir(), "users.json")
	st := newUserStore(path)
	if _, err := st.bootstrap("alice@example.com", "a-long-test-password", ""); err != nil {
		t.Fatal(err)
	}
	s := &server{cfg: c, users: st, reg: newSessionRegistry(time.Hour), tr: newThrottle(c), aud: newAuditor("", 10), log: slog.New(slog.NewTextHandler(io.Discard, nil)), ntf: newNotifier("", "raw", slog.Default())}

	u := st.get("alice@example.com")
	tok := c.issueRecoveryToken(u)
	if user, ok := s.checkRecoveryToken(tok); !ok || user != "alice@example.com" {
		t.Fatal("valid recovery token rejected")
	}
	if _, ok := s.checkRecoveryToken(tok + "x"); ok {
		t.Fatal("tampered recovery token accepted")
	}
	// unknown user
	if _, ok := s.checkRecoveryToken(c.issueRecoveryToken(&User{Username: "ghost", Hash: u.Hash})); ok {
		t.Fatal("token for unknown user accepted")
	}
	// expired
	body := "rec|" + strconv.FormatInt(time.Now().Add(-time.Minute).Unix(), 10) + "|alice@example.com|" + c.recoveryFP(u)
	expired := body + "|" + c.mac(body)
	if _, ok := s.checkRecoveryToken(expired); ok {
		t.Fatal("expired recovery token accepted")
	}
	// single-use: after the password hash changes, the token dies
	if err := st.mutate("alice@example.com", func(u *User) bool { u.Hash = "different-hash"; return true }); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.checkRecoveryToken(tok); ok {
		t.Fatal("recovery token survived a password change")
	}
}

func TestRecoveryRateLimit(t *testing.T) {
	now := time.Now()
	rl := rateLimiter{max: 2, window: time.Minute, now: func() time.Time { return now }}
	for i := 0; i < 2; i++ {
		if !rl.allow("1.2.3.4") {
			t.Fatalf("request %d denied", i+1)
		}
	}
	if rl.allow("1.2.3.4") {
		t.Fatal("third request within window allowed")
	}
	if !rl.allow("5.6.7.8") {
		t.Fatal("limiter leaks across keys")
	}
	now = now.Add(2 * time.Minute)
	if !rl.allow("1.2.3.4") {
		t.Fatal("request after window denied")
	}
}

// Expired keys must be pruned once their newest timestamp ages out — the
// old limiter kept inactive IPs forever.
func TestRateLimiterPrunesExpiredKeys(t *testing.T) {
	now := time.Now()
	rl := rateLimiter{max: 1, window: time.Minute, now: func() time.Time { return now }}
	if !rl.allow("1.1.1.1") {
		t.Fatal("first request denied")
	}
	if rl.allow("1.1.1.1") {
		t.Fatal("second request within window allowed")
	}
	now = now.Add(2 * time.Minute)
	// at capacity the expired key is pruned rather than kept (or evicting
	// a live key); a fresh window starts
	if !rl.allow("1.1.1.1") {
		t.Fatal("expired key not pruned / window not reset")
	}
	rl.mu.Lock()
	n := len(rl.m)
	rl.mu.Unlock()
	if n != 1 {
		t.Fatalf("limiter retains expired keys: %d", n)
	}
}

// Capacity pressure: the map is bounded; when full, the least-recently
// active key is evicted and live keys keep their limits.
func TestRateLimiterBoundedCapacity(t *testing.T) {
	now := time.Now()
	rl := rateLimiter{max: 1, window: time.Hour, maxKeys: 4, now: func() time.Time { return now }}
	for i := 0; i < 4; i++ {
		if !rl.allow(fmt.Sprintf("10.0.0.%d", i)) {
			t.Fatalf("fill request %d denied", i)
		}
		now = now.Add(time.Second) // establish an eviction order
	}
	// a 5th key evicts the oldest (10.0.0.0)
	if !rl.allow("10.0.0.9") {
		t.Fatal("new key denied under capacity pressure")
	}
	rl.mu.Lock()
	n := len(rl.m)
	_, evicted := rl.m["10.0.0.0"]
	_, kept := rl.m["10.0.0.3"]
	rl.mu.Unlock()
	if n > 4 {
		t.Fatalf("limiter map unbounded: %d", n)
	}
	if evicted {
		t.Fatal("oldest key was not evicted")
	}
	if !kept {
		t.Fatal("recent key wrongly evicted")
	}
	// the surviving keys are still limited
	if rl.allow("10.0.0.3") {
		t.Fatal("eviction reset a live key's limit")
	}
}

func TestRateLimiterConcurrent(t *testing.T) {
	rl := rateLimiter{max: 8, window: time.Hour, maxKeys: 16}
	var wg sync.WaitGroup
	allowed := make(chan bool, 8*16)
	for i := 0; i < 16; i++ {
		for j := 0; j < 8; j++ {
			wg.Add(1)
			go func(key string) {
				defer wg.Done()
				allowed <- rl.allow(key)
			}(fmt.Sprintf("10.1.0.%d", j%4))
		}
	}
	wg.Wait()
	close(allowed)
	count := 0
	for a := range allowed {
		if a {
			count++
		}
	}
	// 4 distinct keys × 8 allowed each, regardless of interleaving
	if count != 4*8 {
		t.Fatalf("allowed = %d, want %d", count, 4*8)
	}
}

func TestRecoverResetFlow(t *testing.T) {
	c := testConfig(t)
	c.smtpURL = "smtp://mail.example.com"
	path := filepath.Join(t.TempDir(), "users.json")
	st := newUserStore(path)
	if _, err := st.bootstrap("alice@example.com", "a-long-test-password", ""); err != nil {
		t.Fatal(err)
	}
	s := &server{cfg: c, users: st, reg: newSessionRegistry(time.Hour), tr: newThrottle(c), aud: newAuditor("", 10), log: slog.New(slog.NewTextHandler(io.Discard, nil)), ntf: newNotifier("", "raw", slog.Default()), recoverLimit: rateLimiter{max: 3, window: time.Hour}}

	var sentTo, sentBody string
	old := sendMailFunc
	sendMailFunc = func(_, from, to, subject, body string, _ bool) error {
		sentTo, sentBody = to, body
		return nil
	}
	t.Cleanup(func() { sendMailFunc = old })

	// request a reset: mail goes out, response is the generic notice
	f := url.Values{}
	f.Set("ft", c.issueForm())
	f.Set("username", "alice@example.com")
	r := httptest.NewRequest("POST", "http://auth/_auth/recover", strings.NewReader(f.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.recover(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "reset email is on its way") {
		t.Fatalf("request form: got %d", w.Code)
	}
	if sentTo != "alice@example.com" || !strings.Contains(sentBody, "/_auth/recover?token=") {
		t.Fatalf("no reset mail captured (to=%q)", sentTo)
	}
	rest := sentBody[strings.Index(sentBody, "token=")+len("token="):]
	tok, _ := url.QueryUnescape(strings.Fields(rest)[0])

	// reset with a common password: rejected, breach list applies
	post := func(tok, new1, new2 string) *httptest.ResponseRecorder {
		f := url.Values{}
		f.Set("token", tok)
		f.Set("new1", new1)
		f.Set("new2", new2)
		r := httptest.NewRequest("POST", "http://auth/_auth/recover", strings.NewReader(f.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		s.recover(w, r)
		return w
	}
	if w := post(tok, "passwordpassword", "passwordpassword"); !strings.Contains(w.Body.String(), "breach lists") {
		t.Fatal("common password not rejected on recovery reset")
	}

	// valid reset: password changes, generation bumps, token dies
	genBefore := st.get("alice@example.com").Gen
	w = post(tok, "brand-new-unique-pw-99", "brand-new-unique-pw-99")
	if w.Code != http.StatusFound {
		t.Fatalf("reset: expected 302, got %d", w.Code)
	}
	if !st.checkPassword("alice@example.com", "brand-new-unique-pw-99") {
		t.Fatal("new password not in effect")
	}
	if st.get("alice@example.com").Gen != genBefore+1 {
		t.Fatal("generation not bumped")
	}
	if _, ok := s.checkRecoveryToken(tok); ok {
		t.Fatal("used token still valid")
	}
	// GET with the dead token bounces back to the request form with an error
	r = httptest.NewRequest("GET", "http://auth/_auth/recover?token="+url.QueryEscape(tok), nil)
	w = httptest.NewRecorder()
	s.recover(w, r)
	if !strings.Contains(w.Body.String(), "invalid or has expired") {
		t.Fatal("dead token did not produce the expired-link page")
	}

	// unknown usernames get the identical generic notice (no enumeration)
	f = url.Values{}
	f.Set("ft", c.issueForm())
	f.Set("username", "ghost@example.com")
	r = httptest.NewRequest("POST", "http://auth/_auth/recover", strings.NewReader(f.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	s.recover(w, r)
	if !strings.Contains(w.Body.String(), "reset email is on its way") {
		t.Fatal("unknown user produced a different response")
	}
}

func TestRecoverDisabledRoute(t *testing.T) {
	c := testConfig(t) // no smtpURL
	s := &server{cfg: c, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	r := httptest.NewRequest("GET", "http://auth/_auth/recover", nil)
	w := httptest.NewRecorder()
	s.recover(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when SMTP_URL unset, got %d", w.Code)
	}
}

func TestWebhookSeverityMapping(t *testing.T) {
	for event, want := range map[string]string{
		"login_ok":            "info",
		"login_new_ip":        "info",
		"locked_out":          "warn",
		"bad_backup_code":     "warn",
		"login_fail:bad_totp": "warn",
		"backup_code_used":    "critical",
		"enroll_ok":           "critical",
	} {
		if got := severityFor(event); got != want {
			t.Errorf("severityFor(%q) = %q, want %q", event, got, want)
		}
	}
}

func TestWebhookSlackFormat(t *testing.T) {
	p := webhookPayload{Event: "locked_out", Severity: "warn", User: "alice", IP: "1.2.3.4", Host: "auth.example.com", Detail: "5 fails", Timestamp: time.Now()}
	body, headers, err := formatPayload("slack", p)
	if err != nil {
		t.Fatal(err)
	}
	if headers != nil {
		t.Fatal("slack should not set extra headers")
	}
	var out struct {
		Attachments []struct {
			Text  string `json:"text"`
			Color string `json:"color"`
		} `json:"attachments"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Attachments) != 1 {
		t.Fatalf("expected 1 attachment, got %d", len(out.Attachments))
	}
	if out.Attachments[0].Color != "warning" {
		t.Fatalf("warn severity should map to warning color, got %q", out.Attachments[0].Color)
	}
	if !strings.Contains(out.Attachments[0].Text, "locked_out") || !strings.Contains(out.Attachments[0].Text, "alice") {
		t.Fatalf("attachment text missing event/user: %q", out.Attachments[0].Text)
	}
}

func TestWebhookNtfyFormat(t *testing.T) {
	p := webhookPayload{RequestID: "rid", Service: "forward-auth", Event: "backup_code_used", Severity: "critical", User: "alice", IP: "1.2.3.4", Host: "auth.example.com", Timestamp: time.Now()}
	body, headers, err := formatPayload("ntfy", p)
	if err != nil {
		t.Fatal(err)
	}
	if headers["Priority"] != "4" {
		t.Fatalf("critical should map to ntfy priority 4, got %q", headers["Priority"])
	}
	if headers["Title"] == "" {
		t.Fatal("ntfy Title header missing")
	}
	// ntfy body stays the raw envelope
	var back webhookPayload
	if err := json.Unmarshal(body, &back); err != nil {
		t.Fatal(err)
	}
	if back.Event != "backup_code_used" || back.RequestID != "rid" || back.Severity != "critical" {
		t.Fatalf("raw envelope not preserved: %+v", back)
	}
}

func TestWebhookGotifyAndRawFormat(t *testing.T) {
	p := webhookPayload{Event: "enroll_ok", Severity: "critical", User: "alice", IP: "1.2.3.4", Host: "auth.example.com", Timestamp: time.Now()}
	body, _, err := formatPayload("gotify", p)
	if err != nil {
		t.Fatal(err)
	}
	var g struct {
		Title    string `json:"title"`
		Message  string `json:"message"`
		Priority int    `json:"priority"`
	}
	if err := json.Unmarshal(body, &g); err != nil {
		t.Fatal(err)
	}
	if g.Priority != 8 || g.Title == "" || g.Message == "" {
		t.Fatalf("bad gotify payload: %+v", g)
	}
	// raw (and unknown providers) produce the flat envelope
	body, _, err = formatPayload("raw", p)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"request_id", "service", "event", "severity", "timestamp"} {
		if _, ok := raw[k]; !ok {
			t.Fatalf("raw payload missing %q", k)
		}
	}
}

func TestCommonPasswordRejected(t *testing.T) {
	s, st, sess := newPasswordTestServer(t)
	if !isCommonPassword("passwordpassword") {
		t.Fatal("passwordpassword missing from embedded breach list")
	}
	w := postPasswordChange(s, sess, "passwordpassword", "passwordpassword")
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

func TestPasswordPolicy(t *testing.T) {
	s, st, sess := newPasswordTestServer(t)

	// too short (< 15 runes): rejected, password unchanged
	w := postPasswordChange(s, sess, "short-pw-1234", "short-pw-1234") // 12 chars
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "at least 15 characters") {
		t.Fatalf("short password not rejected with policy message: %d", w.Code)
	}
	if !st.checkPassword("admin", "a-long-test-password") {
		t.Fatal("password changed despite short rejection")
	}
	// over 72 bytes: rejected (legacy bcrypt truncation guard)
	long72 := strings.Repeat("a", 73)
	w = postPasswordChange(s, sess, long72, long72)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "72 bytes") {
		t.Fatalf("over-long password not rejected: %d", w.Code)
	}
	// boundary: exactly 15 runes passes the policy gate
	if err := validatePassword(strings.Repeat("x", 15)); err != nil {
		t.Fatalf("15-rune password rejected: %v", err)
	}
	if err := validatePassword(strings.Repeat("x", 14)); err == nil {
		t.Fatal("14-rune password accepted")
	}
	if err := validatePassword(strings.Repeat("é", 15)); err != nil { // 30 bytes, 15 runes
		t.Fatalf("multi-byte 15-rune password rejected: %v", err)
	}
}

func TestPasswordlessMode(t *testing.T) {
	c := testConfig(t)
	c.passwordless = true
	c.smtpURL = "smtp://mail.example.com" // recovery must still 404 in passkey-only mode
	path := filepath.Join(t.TempDir(), "users.json")
	st := newUserStore(path)
	if _, err := st.bootstrap("admin", "a-long-test-password", ""); err != nil {
		t.Fatal(err)
	}
	settings, err := loadSettingsStore(filepath.Join(t.TempDir(), "admin-settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	s := &server{cfg: c, users: st, reg: newSessionRegistry(time.Hour), tr: newThrottle(c),
		aud: newAuditor("", 10), log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		ntf: newNotifier("", "raw", slog.Default()), settings: settings}

	// login page: passkey button only — no password field, no recovery link
	r := httptest.NewRequest("GET", "http://auth/_auth/login", nil)
	w := httptest.NewRecorder()
	s.login(w, r)
	body := w.Body.String()
	if !strings.Contains(body, "passkey-login") {
		t.Fatal("passkey button missing in passwordless mode")
	}
	if strings.Contains(body, `name="password"`) {
		t.Fatal("password field rendered in passwordless mode")
	}
	if strings.Contains(body, "Forgot your password") {
		t.Fatal("recovery link rendered in passwordless mode")
	}

	// password POST is refused even with valid credentials
	f := url.Values{}
	f.Set("ft", c.issueForm())
	f.Set("username", "admin")
	f.Set("password", "a-long-test-password")
	r = httptest.NewRequest("POST", "http://auth/_auth/login", strings.NewReader(f.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	s.login(w, r)
	if !strings.Contains(w.Body.String(), "disabled") {
		t.Fatal("password POST not refused in passwordless mode")
	}
	for _, ck := range w.Result().Cookies() {
		if ck.Name == c.cookieName && ck.Value != "" {
			t.Fatal("session cookie issued via password in passwordless mode")
		}
	}

	// recovery route is off (a reset password would be useless)
	r = httptest.NewRequest("GET", "http://auth/_auth/recover", nil)
	w = httptest.NewRecorder()
	s.recover(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("recover route = %d, want 404 in passwordless mode", w.Code)
	}
}

func TestSanitizeLogField(t *testing.T) {
	// CR/LF and other control characters are stripped — no forged log lines
	if got := sanitizeLogField("alice\n2026-07-28 INFO auth event=login_ok"); strings.ContainsAny(got, "\n\r") {
		t.Fatalf("newline survived sanitizing: %q", got)
	}
	if got := sanitizeLogField("a\tb\x00c\x7fd"); got != "abcd" {
		t.Fatalf("control chars not stripped: %q", got)
	}
	// printable input passes through unchanged
	if got := sanitizeLogField("alice@example.com"); got != "alice@example.com" {
		t.Fatalf("clean input mangled: %q", got)
	}
	// capped length
	if got := sanitizeLogField(strings.Repeat("x", 500)); len(got) > 260 {
		t.Fatalf("field not capped: %d bytes", len(got))
	}
}
