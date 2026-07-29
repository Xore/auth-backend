package main

// apppage.go — the /auth/app shell: post-login landing page hosting the
// settings modal (ui/app.html). Session-gated; injects the username, admin
// flag and per-session CSRF token into the template.

import (
	"html/template"
	"net/http"
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

func (s *server) renderApp(w http.ResponseWriter, r *http.Request) {
	cl, u, ok := s.session(w, r)
	if !ok {
		http.Redirect(w, r, "https://"+s.cfg.authHost+"/_auth/login", http.StatusFound)
		return
	}
	n := nonce()
	secHeaders(w, n)
	allowAppFraming(w.Header(), s.cfg.frameAncestors)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := appTmpl.Execute(w, AppPageData{
		User:    u.Username,
		IsAdmin: u.Role == roleAdmin,
		CSRF:    s.cfg.csrfToken(cl.sid),
		FT:      s.cfg.issueForm(),
		Nonce:   n,
	}); err != nil {
		s.log.Error("render app shell", "error", err)
	}
}
