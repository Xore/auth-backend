package main

// routes.go — HTTP route registration for the portal mux.

import (
	"io"
	"net/http"
	"net/url"
	"strings"
)

// registerRoutes wires every portal endpoint into mux.
func (s *server) registerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/_auth/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := s.users.writable(); err != nil {
			http.Error(w, "storage unavailable", http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, "ok")
	})
	mux.HandleFunc("/_auth/verify", s.verify)
	mux.HandleFunc("POST /_auth/introspect", s.introspect)
	mux.HandleFunc("/_auth/login", s.login)
	mux.HandleFunc("/_auth/totp", s.totp)
	mux.HandleFunc("/_auth/logout", s.logout)
	mux.HandleFunc("/_auth/enroll", s.enroll)
	mux.HandleFunc("/_auth/password", s.password)
	mux.HandleFunc("/_auth/backup-codes", s.handleBackupCodes)
	mux.HandleFunc("/_auth/recover", s.recover)
	mux.HandleFunc("/_auth/passkeys", settingsRedirect("passkeys"))
	mux.HandleFunc("/_auth/passkeys/list", s.passkeyList)
	mux.HandleFunc("/_auth/passkeys/register/begin", s.passkeyRegisterBegin)
	mux.HandleFunc("/_auth/passkeys/register/finish", s.passkeyRegisterFinish)
	mux.HandleFunc("/_auth/passkeys/delete", s.passkeyDelete)
	mux.HandleFunc("/_auth/passkeys/login/begin", s.passkeyLoginBegin)
	mux.HandleFunc("/_auth/passkeys/login/finish", s.passkeyLoginFinish)
	mux.HandleFunc("/_auth/metrics", s.metrics)
	mux.HandleFunc("/_auth/ok", settingsRedirect(""))
	mux.HandleFunc("/_auth/admin", settingsRedirect(""))
	mux.HandleFunc("/_auth/admin/api/state", s.adminState)
	mux.HandleFunc("/_auth/admin/api/user", s.adminCreateUser)
	mux.HandleFunc("/_auth/admin/api/action", s.adminAction)
	mux.HandleFunc("/_auth/admin/api/system", s.handleAdminSystem)
	mux.HandleFunc("/_auth/admin/api/settings", s.handleAdminSettings)
	mux.HandleFunc("POST /_auth/admin/api/sessions/{sid}/revoke", s.adminRevokeSession)
	mux.HandleFunc("/_auth/sessions/mine", s.handleMySessions)
	mux.HandleFunc("/_auth/sessions/trusted", s.handleTrustedDevices)
	mux.HandleFunc("/_auth/admin/audit", s.adminAudit) // legacy JSON endpoint
	mux.HandleFunc("/_auth/setup", func(w http.ResponseWriter, r *http.Request) {
		// the old public FIRST_RUN page; enrollment is session-gated now
		http.Redirect(w, r, "https://"+s.cfg.authHost+"/_auth/enroll", http.StatusFound)
	})
	if s.cfg.ssoURL != "" {
		mux.HandleFunc("/_auth/sso", func(w http.ResponseWriter, r *http.Request) {
			rd := r.URL.Query().Get("rd")
			sep := "?"
			if strings.Contains(s.cfg.ssoURL, "?") {
				sep = "&"
			}
			// The redirect target is the operator-configured SSO_URL (validated
			// as https:// at startup); rd is appended only as an escaped query
			// parameter, never as the target.
			http.Redirect(w, r, s.cfg.ssoURL+sep+"rd="+url.QueryEscape(rd), http.StatusFound)
		})
	}
	mux.HandleFunc("/auth/app", s.renderApp)
	mux.Handle("/static/", staticHandler())
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/_auth/login", http.StatusFound)
	})
}
