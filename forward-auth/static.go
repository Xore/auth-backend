package main

// static.go — embedded UI assets (theme.css and friends) served under
// /static/. Pages link these instead of inlining the theme palette, so the
// CSP style-src can stay nonce-based plus 'self'.
//
// Only the assets pages actually link are servable here — never the whole
// embedded ui/ directory, which also holds the page *templates* (login.html,
// verify.html, app.html) that page.go/apppage.go parse and render
// server-side via mustReadUI. Mounting the whole tree used to make those
// raw, un-rendered templates fetchable directly at e.g. /static/login.html:
// a real page on the real origin, with a real login form, but with none of
// the frame-ancestors/X-Frame-Options protection the properly-rendered
// /_auth/login response enforces everywhere else — a clickjacking hole this
// allowlist closes at the root instead of trying to patch per-template.

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed ui
var uiFS embed.FS

// staticAssets is the complete allowlist of files servable under /static/.
var staticAssets = map[string]bool{
	"theme.css":        true,
	"tailwind.min.css": true,
}

// staticHandler serves only the allowlisted embedded assets at /static/;
// anything else — including the page templates that also live in the
// embedded ui/ directory — 404s.
func staticHandler() http.Handler {
	sub, err := fs.Sub(uiFS, "ui")
	if err != nil {
		panic("embed ui: " + err.Error())
	}
	fileServer := http.FileServer(http.FS(sub))
	return http.StripPrefix("/static/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !staticAssets[r.URL.Path] {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		fileServer.ServeHTTP(w, r)
	}))
}
