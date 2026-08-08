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

func TestHostMatchesAnySupportsWildcardAndExact(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"admin.example.com", true},
		{"ADMIN.EXAMPLE.COM:443", true},
		{"sub.media.example.com", true},
		{"media.example.com", false}, // "*.dom" excludes dom itself, matching hostAllowed's own contract
		{"other.example.com", false},
		{"example.com", false},
	}
	patterns := []string{"admin.example.com", "*.media.example.com"}
	for _, c := range cases {
		if got := hostMatchesAny(normalizeHost(c.host), patterns); got != c.want {
			t.Errorf("hostMatchesAny(%q, %v) = %v, want %v", c.host, patterns, got, c.want)
		}
	}
}

func TestHostRequiresTOTPEmptyListMeansNothingExtra(t *testing.T) {
	u := &User{} // RequireTOTPHosts unset -- must NOT default to "everything", unlike AllowedHosts
	if u.hostRequiresTOTP("anything.example.com") {
		t.Fatal("empty RequireTOTPHosts should require nothing extra, not everything")
	}
	if u.hostRequiresTOTP("") {
		t.Fatal("empty host should never itself trigger the policy")
	}
}

func TestHostRequiresTOTPMatchesConfiguredHosts(t *testing.T) {
	u := &User{RequireTOTPHosts: []string{"admin.example.com", "*.finance.example.com"}}
	for _, host := range []string{"admin.example.com", "payroll.finance.example.com"} {
		if !u.hostRequiresTOTP(host) {
			t.Errorf("hostRequiresTOTP(%q) = false, want true", host)
		}
	}
	for _, host := range []string{"grafana.example.com", "finance.example.com"} {
		if u.hostRequiresTOTP(host) {
			t.Errorf("hostRequiresTOTP(%q) = true, want false", host)
		}
	}
}

// #67's actual point, end to end: a device trusted enough to skip TOTP
// entirely for a low-risk login must still be challenged when the target
// host is in the user's RequireTOTPHosts list -- isolated from the
// pre-existing risk-based step-up by keeping this login's risk score at 0
// (no login history at all, matching riskScore's own "first logins can't be
// anomalous" contract) so only the new host policy is under test.
func TestHostPolicyForcesTOTPDespiteTrustedDeviceAndLowRisk(t *testing.T) {
	c := testConfig(t)
	c.trustDevDays = 30
	path := filepath.Join(t.TempDir(), "users.json")
	st := newUserStore(path)
	if _, err := st.bootstrap("admin", "a-long-test-password", "JBSWY3DPEHPK3PXP"); err != nil {
		t.Fatal(err)
	}
	if err := st.mutate("admin", func(u *User) bool {
		u.RequireTOTPHosts = []string{"admin.example.com"}
		return true
	}); err != nil {
		t.Fatal(err)
	}
	s := &server{cfg: c, users: st, reg: newSessionRegistry(time.Hour), tr: newThrottle(c), aud: newAuditor("", 10), log: slog.New(slog.NewTextHandler(io.Discard, nil)), ntf: newNotifier("", "raw", slog.Default())}

	login := func(rd string) *httptest.ResponseRecorder {
		f := url.Values{}
		f.Set("ft", c.issueForm())
		f.Set("username", "admin")
		f.Set("password", "a-long-test-password")
		f.Set("rd", rd)
		r := httptest.NewRequest("POST", "http://auth/_auth/login?rd="+url.QueryEscape(rd), strings.NewReader(f.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(&http.Cookie{Name: c.cookieName + "_dev", Value: c.issueDevice("admin", st.get("admin").DeviceGen)})
		w := httptest.NewRecorder()
		s.login(w, r)
		return w
	}

	// Target host matches RequireTOTPHosts -- must be challenged even on a
	// trusted device with zero login history (risk score 0).
	w := login("https://admin.example.com/dashboard")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `action="/_auth/totp"`) {
		t.Fatalf("login to a RequireTOTPHosts target should demand TOTP despite trusted device, got %d body=%s", w.Code, w.Body.String())
	}

	// A DIFFERENT target host, not in RequireTOTPHosts, must skip TOTP as
	// normal on the same trusted device.
	if w := login("https://grafana.example.com/"); w.Code != http.StatusFound {
		t.Fatalf("login to an unlisted target should skip TOTP (302) on a trusted device, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestAdminSetRequireTOTPHosts(t *testing.T) {
	c := testConfig(t)
	st := newUserStore(filepath.Join(t.TempDir(), "users.json"))
	if _, err := st.bootstrap("admin", "a-long-test-password", ""); err != nil {
		t.Fatal(err)
	}
	if err := st.create(&User{Username: "target", Hash: "x", Role: roleUser, Gen: 1, DeviceGen: 1, Created: time.Now()}); err != nil {
		t.Fatal(err)
	}
	s := &server{cfg: c, users: st, reg: newSessionRegistry(time.Hour), tr: newThrottle(c), aud: newAuditor("", 10), log: slog.New(slog.NewTextHandler(io.Discard, nil)), ntf: newNotifier("", "raw", slog.Default())}

	admin := st.get("admin")
	cl := sessionClaims{user: "admin", gen: admin.Gen, sid: "adminsid", exp: time.Now().Add(time.Hour).Unix()}
	r := httptest.NewRequest(http.MethodPost, "http://auth/_auth/admin/api/action", strings.NewReader(`{"action":"set_require_totp_hosts","username":"target","require_totp_hosts":["admin.example.com","*.finance.example.com"]}`))
	r.Header.Set("Content-Type", "application/json")
	r.AddCookie(&http.Cookie{Name: c.cookieName, Value: mustIssuePASETO(t, c, cl)})
	r.Header.Set("X-Csrf", c.csrfToken(cl.sid))
	w := httptest.NewRecorder()
	s.adminAction(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("set_require_totp_hosts: %d %s", w.Code, w.Body.String())
	}
	got := st.get("target").RequireTOTPHosts
	want := []string{"admin.example.com", "*.finance.example.com"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("RequireTOTPHosts = %v, want %v", got, want)
	}
}
