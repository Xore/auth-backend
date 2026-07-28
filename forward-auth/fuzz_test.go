package main

import (
	"net/url"
	"strings"
	"testing"
	"time"

	pasetov4 "zntr.io/paseto/v4"
)

func fuzzConfig(f *testing.F) config {
	f.Helper()
	key, err := deriveKey([]byte("01234567890123456789012345678901"), "paseto-v4-local")
	if err != nil {
		f.Fatal(err)
	}
	return config{
		authHost:  "auth.example.com",
		cookieDom: ".example.com",
		pasetoKey: pasetov4.LocalKey(key),
		ttl:       time.Hour,
	}
}

func FuzzSafeRedirect(f *testing.F) {
	cfg := fuzzConfig(f)
	for _, seed := range []string{
		"",
		"/auth/app",
		"https://grafana.example.com/path?q=1",
		"https://example.com.evil.test/",
		"//evil.test/",
		`https:\\evil.test\`,
		"https://user@example.com/",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		got := cfg.safeRedirect(raw)
		parsed, err := url.Parse(got)
		if err != nil {
			t.Fatalf("safeRedirect returned an invalid URL %q: %v", got, err)
		}
		if parsed.IsAbs() {
			host := normalizeHost(parsed.Hostname())
			if parsed.Scheme != "https" ||
				(host != "example.com" && !strings.HasSuffix(host, ".example.com")) {
				t.Fatalf("safeRedirect escaped the allowed HTTPS domain: input=%q output=%q", raw, got)
			}
			return
		}
		if !strings.HasPrefix(parsed.Path, "/") {
			t.Fatalf("safeRedirect returned a non-absolute relative path: input=%q output=%q", raw, got)
		}
	})
}

func FuzzParseSessionPASETO(f *testing.F) {
	cfg := fuzzConfig(f)
	valid, err := cfg.issueSessionPASETO(sessionClaims{
		user: "alice",
		gen:  1,
		sid:  "seed-session",
		exp:  time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		f.Fatal(err)
	}
	for _, seed := range []string{
		"",
		"v4.local.",
		"v4.local.invalid",
		valid,
		valid[:len(valid)/2],
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, token string) {
		// The core invariant is that attacker-controlled cookie bytes always
		// produce either validated claims or a clean rejection, never a panic.
		_, _, _ = cfg.parseSessionPASETO(token)
	})
}
