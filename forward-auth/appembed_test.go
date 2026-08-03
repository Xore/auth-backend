package main

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// nonAdminSession creates a "bob" user and returns a valid session cookie
// for them, mirroring newPasswordTestServer's admin-only helper.
func nonAdminSession(t *testing.T, s *server, st *userStore) *http.Cookie {
	t.Helper()
	if err := st.create(&User{Username: "bob", Hash: "x", Role: roleUser, Gen: 1, Created: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	u := st.get("bob")
	cl := sessionClaims{user: u.Username, gen: u.Gen, sid: "bob-sid", exp: time.Now().Add(time.Minute).Unix()}
	return &http.Cookie{Name: s.cfg.cookieName, Value: mustIssuePASETO(t, s.cfg, cl)}
}

func TestIsFramedAppRequestRequiresIframeDestAndMatchingDomain(t *testing.T) {
	cases := []struct {
		name   string
		dest   string
		origin string
		domain string
		want   bool
	}{
		{"exact domain match", "iframe", "https://dash.example.com", "dash.example.com", true},
		{"subdomain match", "iframe", "https://settings.dash.example.com", "dash.example.com", true},
		{"unrelated domain", "iframe", "https://evil.com", "dash.example.com", false},
		{"suffix but not subdomain", "iframe", "https://notdash.example.com", "dash.example.com", false},
		{"top-level navigation, not framed", "document", "https://dash.example.com", "dash.example.com", false},
		{"missing Sec-Fetch-Dest", "", "https://dash.example.com", "dash.example.com", false},
		{"no embed domain configured", "iframe", "https://dash.example.com", "", false},
		{"http origin rejected", "iframe", "http://dash.example.com", "dash.example.com", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "https://auth.example.com/auth/app", nil)
			if tc.dest != "" {
				r.Header.Set("Sec-Fetch-Dest", tc.dest)
			}
			r.Header.Set("Origin", tc.origin)
			if got := isFramedAppRequest(r, tc.domain); got != tc.want {
				t.Fatalf("isFramedAppRequest(dest=%q, origin=%q, domain=%q) = %v, want %v", tc.dest, tc.origin, tc.domain, got, tc.want)
			}
		})
	}
}

func TestIsFramedAppRequestFallsBackToReferer(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "https://auth.example.com/auth/app", nil)
	r.Header.Set("Sec-Fetch-Dest", "iframe")
	r.Header.Set("Referer", "https://dash.example.com/some/page?x=1")
	if !isFramedAppRequest(r, "example.com") {
		t.Fatal("expected Referer-derived origin to satisfy the example.com subdomain check")
	}
}

func TestRenderAppRestrictsNonAdminTopLevelVisitWhenEmbedDomainConfigured(t *testing.T) {
	s, st, _ := newPasswordTestServer(t)
	s.cfg.appEmbedDomain = "dash.example.com"
	cookie := nonAdminSession(t, s, st)

	r := httptest.NewRequest(http.MethodGet, "https://auth.example.com/auth/app", nil)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	s.renderApp(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "settings-nav") {
		t.Fatalf("non-admin top-level visit must not receive the full settings shell, got: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "dashboard") {
		t.Fatalf("expected the restricted notice pointing back to the dashboard, got: %s", w.Body.String())
	}
}

func TestRenderAppAllowsNonAdminWhenFramedFromEmbedDomain(t *testing.T) {
	s, st, _ := newPasswordTestServer(t)
	s.cfg.appEmbedDomain = "dash.example.com"
	cookie := nonAdminSession(t, s, st)

	r := httptest.NewRequest(http.MethodGet, "https://auth.example.com/auth/app", nil)
	r.AddCookie(cookie)
	r.Header.Set("Sec-Fetch-Dest", "iframe")
	r.Header.Set("Origin", "https://dash.example.com")
	w := httptest.NewRecorder()
	s.renderApp(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "settings-nav") {
		t.Fatalf("framed non-admin visit from the embed domain must still get the settings shell, got: %s", w.Body.String())
	}
}

func TestRenderAppAllowsAdminTopLevelVisitEvenWithEmbedDomainConfigured(t *testing.T) {
	s, _, cookie := newPasswordTestServer(t)
	s.cfg.appEmbedDomain = "dash.example.com"

	r := httptest.NewRequest(http.MethodGet, "https://auth.example.com/auth/app", nil)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	s.renderApp(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "settings-nav") {
		t.Fatalf("admins must always get the full standalone site, got: %s", w.Body.String())
	}
}

func TestRenderAppUnrestrictedWhenNoEmbedDomainConfigured(t *testing.T) {
	s, st, _ := newPasswordTestServer(t)
	// s.cfg.appEmbedDomain left unset.
	cookie := nonAdminSession(t, s, st)

	r := httptest.NewRequest(http.MethodGet, "https://auth.example.com/auth/app", nil)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	s.renderApp(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "settings-nav") {
		t.Fatalf("with no APP_EMBED_DOMAIN configured, non-admins must keep standalone access, got: %s", w.Body.String())
	}
}

func TestParseEmbedDomainRejectsMalformedValues(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cases := map[string]string{
		"dash.example.com":         "dash.example.com",
		" DASH.example.com ":       "dash.example.com",
		"":                         "",
		"https://dash.example.com": "",
		"dash.example.com/path":    "",
		"dash.example.com:8443":    "",
		"user@dash.example.com":    "",
	}
	for in, want := range cases {
		if got := parseEmbedDomain(in, logger); got != want {
			t.Fatalf("parseEmbedDomain(%q) = %q, want %q", in, got, want)
		}
	}
}
