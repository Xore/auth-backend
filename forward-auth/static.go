package main

// static.go — embedded UI assets (claude-theme.css and friends) served
// under /static/. Pages link these instead of inlining the theme palette,
// so the CSP style-src can stay nonce-based plus 'self'.

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed ui
var uiFS embed.FS

// staticHandler serves the embedded ui/ directory at /static/.
func staticHandler() http.Handler {
	sub, err := fs.Sub(uiFS, "ui")
	if err != nil {
		panic("embed ui: " + err.Error())
	}
	return http.StripPrefix("/static/", http.FileServer(http.FS(sub)))
}
