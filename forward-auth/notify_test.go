package main

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestDisallowedWebhookIP(t *testing.T) {
	disallowed := []string{
		"127.0.0.1", "::1", // loopback
		"10.0.0.1", "172.16.0.1", "192.168.1.1", // RFC1918
		"169.254.1.1", // link-local unicast
		"224.0.0.1",   // link-local multicast
		"0.0.0.0",     // unspecified
		"fe80::1",     // IPv6 link-local
		"fc00::1",     // IPv6 unique local (net.IP.IsPrivate covers this)
	}
	for _, s := range disallowed {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("test bug: %q did not parse as an IP", s)
		}
		if !disallowedWebhookIP(ip) {
			t.Errorf("disallowedWebhookIP(%s) = false, want true", s)
		}
	}

	allowed := []string{"8.8.8.8", "1.1.1.1", "203.0.113.5", "2001:4860:4860::8888"}
	for _, s := range allowed {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("test bug: %q did not parse as an IP", s)
		}
		if disallowedWebhookIP(ip) {
			t.Errorf("disallowedWebhookIP(%s) = true, want false", s)
		}
	}
}

// TestNotifierRefusesToDialLoopback is the actual point of #65: a webhook
// URL resolving to loopback (the same class of address a private-network
// SSRF target would resolve to) must never be dialed, even though nothing
// about the URL string itself looks malicious. httptest.NewServer binds to
// 127.0.0.1, so this exercises the real safeDialContext path end-to-end
// (SplitHostPort on a literal IP, no DNS mocking needed) rather than only
// unit-testing the classifier in isolation.
func TestNotifierRefusesToDialLoopback(t *testing.T) {
	var hit atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := newNotifier(srv.URL, "raw", slog.New(slog.NewTextHandler(io.Discard, nil)))
	n.send("test_event", "user", "203.0.113.1", "auth.example.com", "detail")

	// send() dispatches over its own goroutine (bounded by n.sem); give it a
	// moment to attempt (and fail) the dial before asserting.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if hit.Load() {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if hit.Load() {
		t.Fatal("webhook request reached the loopback-bound test server -- SSRF guard did not block the dial")
	}
}
