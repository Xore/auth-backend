package main

// apppage.go — the /auth/app shell: post-login landing page hosting the
// settings modal (ui/app.html). Session-gated; injects the username, admin
// flag and per-session CSRF token into the template.

import (
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"strings"
)

// mustReadUI reads an embedded file from the ui/ directory or panics —
// the same fail-fast pattern as template.Must.
func mustReadUI(name string) []byte {
	b, err := uiFS.ReadFile("ui/" + name)
	if err != nil {
		panic("embed ui/" + name + ": " + err.Error())
	}
	return b
}

var appTmpl = template.Must(template.New("app").Parse(string(mustReadUI("app.html"))))

// AppPageData is passed to ui/app.html.
type AppPageData struct {
	User    string
	IsAdmin bool
	CSRF    string
	FT      string // form token for in-shell POST forms (backup codes)
	Nonce   string
	// FrameAncestors is the same allowlist allowAppFraming already enforces
	// via CSP, JSON-marshaled for the page's own postMessage("close"/"expired")
	// signal to the embedding parent (honeypot-stack issue #93): a framed page
	// cannot read its parent's origin cross-origin, so it targets every origin
	// CSP already permits to frame it, one postMessage call per origin.
	FrameAncestors template.JS
}

// frameAncestorsJSON JSON-marshals ancestors for embedding as a JS array
// literal. Marshaling a []string cannot fail.
func frameAncestorsJSON(ancestors []string) template.JS {
	if ancestors == nil {
		ancestors = []string{}
	}
	encoded, _ := json.Marshal(ancestors)
	return template.JS(encoded)
}

// allowAppFraming relaxes clickjacking protection for /auth/app only, and
// only towards operator-configured origins (APP_FRAME_ANCESTORS) such as the
// honeypot dashboard's settings popup. The login, verify, and recovery pages
// always keep framing denied; with no configured ancestors the default
// headers from secHeaders are untouched.
func allowAppFraming(h http.Header, ancestors []string) {
	if len(ancestors) == 0 {
		return
	}
	h.Del("X-Frame-Options")
	h.Set("Content-Security-Policy", strings.Replace(
		h.Get("Content-Security-Policy"),
		"frame-ancestors 'none'",
		"frame-ancestors 'self' "+strings.Join(ancestors, " "),
		1,
	))
}

// isFramedAppRequest reports whether r looks like it was loaded inside an
// <iframe> on APP_EMBED_DOMAIN itself or one of its subdomains (the
// honeypot dashboard's account modal is the intended one) rather than
// typed/clicked as a top-level navigation straight to /auth/app.
// Sec-Fetch-Dest is sent by every browser this app already requires for its
// other security headers (see secHeaders) and cannot be set by the page
// content itself, only by the browser's own navigation type — a much
// stronger signal than Referer, which some browsers/extensions strip. A
// missing header (very old browser, or a non-browser client) is treated as
// "not framed": failing closed here only ever narrows a non-admin from the
// full standalone site down to the same personal-settings pane the
// dashboard's modal already gives them, so there's no functionality lost by
// erring toward the restricted view when the signal is absent.
func isFramedAppRequest(r *http.Request, embedDomain string) bool {
	if embedDomain == "" || r.Header.Get("Sec-Fetch-Dest") != "iframe" {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		if ref := r.Header.Get("Referer"); ref != "" {
			if u, err := url.Parse(ref); err == nil {
				origin = u.Scheme + "://" + u.Host
			}
		}
	}
	if origin == "" {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	return host == embedDomain || strings.HasSuffix(host, "."+embedDomain)
}

func (s *server) renderApp(w http.ResponseWriter, r *http.Request) {
	cl, u, ok := s.session(w, r)
	if !ok {
		http.Redirect(w, r, "https://"+s.cfg.authHost+"/_auth/login", http.StatusFound)
		return
	}
	n := nonce()
	secHeaders(w, n)
	allowAppFraming(w.Header(), s.cfg.frameAncestors)
	// #473: the standalone /auth/app site is admin-only. Regular users only
	// ever reach their account settings through the dashboard's own account
	// modal (an iframe of this same page) -- a top-level visit gets a small
	// notice instead of the full settings shell with its sidebar nav. Only
	// enforced once APP_EMBED_DOMAIN names an embedding domain at all; a
	// deployment with none configured has no modal to send a non-admin back
	// to, so the standalone site stays their only way in.
	if s.cfg.appEmbedDomain != "" && u.Role != roleAdmin && !isFramedAppRequest(r, s.cfg.appEmbedDomain) {
		s.renderRestrictedApp(w, cl.sid, n)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := appTmpl.Execute(w, AppPageData{
		User:    u.Username,
		IsAdmin: u.Role == roleAdmin,
		CSRF:    s.cfg.csrfToken(cl.sid),
		// Session-bound, not the pre-auth issueForm() — the backup-codes
		// form this feeds is a session-gated mutation (see checkSessionCSRF).
		FT:             s.cfg.csrfToken(cl.sid),
		Nonce:          n,
		FrameAncestors: frameAncestorsJSON(s.cfg.frameAncestors),
	}); err != nil {
		s.log.Error("render app shell", "error", err)
	}
}
