package main

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseFrameAncestorsAcceptsHTTPSOrigins(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	got := parseFrameAncestors("https://dash.example.com, https://dash.example.com:8443/", logger)
	want := []string{"https://dash.example.com", "https://dash.example.com:8443"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestParseFrameAncestorsRejectsUnsafeEntries(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	got := parseFrameAncestors("http://dash.example.com, https://dash.example.com/path, https://user@dash.example.com, not-a-url, , https://ok.example.com?x=1, https://ok.example.com", logger)
	if len(got) != 1 || got[0] != "https://ok.example.com" {
		t.Fatalf("got %v, want [https://ok.example.com]", got)
	}
}

func TestParseFrameAncestorsEmptyMeansDenied(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if got := parseFrameAncestors("", logger); len(got) != 0 {
		t.Fatalf("empty APP_FRAME_ANCESTORS must deny all framing, got %v", got)
	}
}

func TestAllowAppFramingLeavesDefaultHeadersAlone(t *testing.T) {
	h := http.Header{}
	h.Set("X-Frame-Options", "DENY")
	h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
	allowAppFraming(h, nil)
	if h.Get("X-Frame-Options") != "DENY" {
		t.Fatal("X-Frame-Options must stay DENY without configured ancestors")
	}
	if h.Get("Content-Security-Policy") != "default-src 'none'; frame-ancestors 'none'; base-uri 'none'" {
		t.Fatal("CSP must stay untouched without configured ancestors")
	}
}

func TestAllowAppFramingAllowlistsConfiguredOrigins(t *testing.T) {
	h := http.Header{}
	h.Set("X-Frame-Options", "DENY")
	h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
	allowAppFraming(h, []string{"https://dash.example.com"})
	if h.Get("X-Frame-Options") != "" {
		t.Fatal("X-Frame-Options must be removed when ancestors are configured")
	}
	csp := h.Get("Content-Security-Policy")
	if !strings.Contains(csp, "frame-ancestors 'self' https://dash.example.com") {
		t.Fatalf("CSP must allowlist the configured origin, got %q", csp)
	}
	if !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "base-uri 'none'") {
		t.Fatalf("other CSP directives must be preserved, got %q", csp)
	}
}

func TestFrameAncestorsJSONHandlesNilAndConfiguredValues(t *testing.T) {
	if got := frameAncestorsJSON(nil); string(got) != "[]" {
		t.Fatalf("frameAncestorsJSON(nil) = %q, want []", got)
	}
	got := frameAncestorsJSON([]string{"https://dash.example.com", "https://other.example.org"})
	want := `["https://dash.example.com","https://other.example.org"]`
	if string(got) != want {
		t.Fatalf("frameAncestorsJSON(...) = %q, want %q", got, want)
	}
}

// TestRenderAppEmbedsFrameAncestorsForEmbedderPostMessage proves the app
// shell's postMessage sender (issue #93 in honeypot-stack) gets the same
// allowlist allowAppFraming already enforces via CSP, so it can signal
// close/expiry to every origin CSP permits to frame this page.
func TestRenderAppEmbedsFrameAncestorsForEmbedderPostMessage(t *testing.T) {
	s, _, cookie := newPasswordTestServer(t)
	s.cfg.frameAncestors = []string{"https://dash.example.com", "https://other.example.org"}

	r := httptest.NewRequest(http.MethodGet, "https://auth.example.com/auth/app", nil)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	s.renderApp(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	want := `var FRAME_ANCESTORS = ["https://dash.example.com","https://other.example.org"];`
	if !strings.Contains(w.Body.String(), want) {
		t.Fatalf("rendered app shell missing %q", want)
	}
}

func TestRenderAppFrameAncestorsEmptyByDefault(t *testing.T) {
	s, _, cookie := newPasswordTestServer(t)
	// s.cfg.frameAncestors left at testConfig's zero value (unset).

	r := httptest.NewRequest(http.MethodGet, "https://auth.example.com/auth/app", nil)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	s.renderApp(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "var FRAME_ANCESTORS = [];") {
		t.Fatalf("rendered app shell must default FRAME_ANCESTORS to an empty array, got body: %s", w.Body.String())
	}
}
