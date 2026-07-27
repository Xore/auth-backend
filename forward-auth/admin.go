package main

// admin.go — the admin panel's JSON API. All endpoints require an admin
// session with no pending flags; mutating endpoints additionally require the
// per-session CSRF token in the X-Csrf header. The HTML shell itself is in
// adminpage.go.

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"regexp"
	"time"
)

var usernameRe = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,32}$`)

// adminGate validates the session, role and (for mutations) CSRF token.
func (s *server) adminGate(w http.ResponseWriter, r *http.Request, csrf bool) (sessionClaims, *User, bool) {
	cl, u, ok := s.session(r)
	if !ok {
		http.Redirect(w, r, "https://"+s.cfg.authHost+"/_auth/login", http.StatusFound)
		return cl, nil, false
	}
	if u.Role != roleAdmin || cl.flags != "" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return cl, nil, false
	}
	if csrf {
		got := r.Header.Get("X-Csrf")
		want := s.cfg.csrfToken(cl.sid)
		if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			http.Error(w, "bad csrf token", http.StatusForbidden)
			return cl, nil, false
		}
	}
	return cl, u, true
}

func jsonOut(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func jsonErr(w http.ResponseWriter, msg string) {
	jsonOut(w, http.StatusBadRequest, map[string]string{"error": msg})
}

// adminUserView is a User with secrets stripped for the panel.
type adminUserView struct {
	Username     string    `json:"username"`
	Role         string    `json:"role"`
	Disabled     bool      `json:"disabled"`
	MustChange   bool      `json:"must_change"`
	TOTPEnrolled bool      `json:"totp_enrolled"`
	BackupCodes  int       `json:"backup_codes"`
	AllowedHosts []string  `json:"allowed_hosts"`
	Created      time.Time `json:"created"`
	LastLogin    time.Time `json:"last_login"`
	LastIP       string    `json:"last_ip"`
	Passkeys     int       `json:"passkeys"`
}

func (s *server) adminPanel(w http.ResponseWriter, r *http.Request) {
	cl, u, ok := s.adminGate(w, r, false)
	if !ok {
		return
	}
	n := nonce()
	secHeaders(w, n)
	s.renderAdmin(w, u.Username, s.cfg.csrfToken(cl.sid), n)
}

func (s *server) adminState(w http.ResponseWriter, r *http.Request) {
	_, _, ok := s.adminGate(w, r, false)
	if !ok {
		return
	}
	secHeaders(w, nonce())
	n := min(max(atoi(r.URL.Query().Get("n"), 100), 0), 1000)
	views := []adminUserView{}
	for _, u := range s.users.list() {
		hosts := u.AllowedHosts
		if hosts == nil {
			hosts = []string{}
		}
		views = append(views, adminUserView{
			Username: u.Username, Role: u.Role, Disabled: u.Disabled,
			MustChange: u.MustChange, TOTPEnrolled: u.TOTPSecret != "",
			BackupCodes: len(u.BackupCodes), AllowedHosts: hosts,
			Created: u.Created, LastLogin: u.LastLogin, LastIP: u.LastIP,
			Passkeys: len(u.Passkeys),
		})
	}
	jsonOut(w, http.StatusOK, map[string]any{
		"users":    views,
		"audit":    s.aud.snapshot(n),
		"locked":   s.tr.snapshot(),
		"sessions": s.reg.list(),
	})
}

func (s *server) adminCreateUser(w http.ResponseWriter, r *http.Request) {
	cl, actor, ok := s.adminGate(w, r, true)
	if !ok {
		return
	}
	_ = cl
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Username     string   `json:"username"`
		Role         string   `json:"role"`
		AllowedHosts []string `json:"allowed_hosts"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || dec.Decode(&struct{}{}) != io.EOF {
		jsonErr(w, "bad json")
		return
	}
	if !usernameRe.MatchString(req.Username) {
		jsonErr(w, "username must be 1-32 chars of a-z 0-9 . _ -")
		return
	}
	if req.Role != roleAdmin && req.Role != roleUser {
		jsonErr(w, "role must be admin or user")
		return
	}
	temp := newTempPassword()
	hash, err := hashPassword(temp)
	if err != nil {
		jsonErr(w, "hash failed")
		return
	}
	err = s.users.create(&User{
		Username: req.Username, Hash: hash, Role: req.Role,
		MustChange: true, AllowedHosts: req.AllowedHosts,
		Gen: 1, DeviceGen: 1, PasskeyUserID: randomBytes(32), Created: time.Now().UTC(),
	})
	if err != nil {
		jsonErr(w, err.Error())
		return
	}
	ip := s.clientIP(r)
	s.audit("admin_create_user:"+req.Username, ip, actor.Username, r)
	s.ntf.send("admin_create_user", actor.Username, ip, s.cfg.authHost, "created "+req.Username)
	jsonOut(w, http.StatusOK, map[string]string{"temp_password": temp})
}

func (s *server) adminAction(w http.ResponseWriter, r *http.Request) {
	_, actor, ok := s.adminGate(w, r, true)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Action   string   `json:"action"`
		Username string   `json:"username"`
		Role     string   `json:"role"`
		Hosts    []string `json:"hosts"`
		IP       string   `json:"ip"`
		SID      string   `json:"sid"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || dec.Decode(&struct{}{}) != io.EOF {
		jsonErr(w, "bad json")
		return
	}

	ip := s.clientIP(r)
	done := func(extra map[string]string) {
		s.audit("admin_"+req.Action+":"+firstNonEmpty(req.Username, req.IP, req.SID), ip, actor.Username, r)
		s.ntf.send("admin_"+req.Action, actor.Username, ip, s.cfg.authHost,
			"target "+firstNonEmpty(req.Username, req.IP, req.SID))
		out := map[string]string{"ok": "1"}
		for k, v := range extra {
			out[k] = v
		}
		jsonOut(w, http.StatusOK, out)
	}

	// guards for actions that could lock the panel out entirely
	self := req.Username == actor.Username
	target := s.users.get(req.Username)
	lastAdmin := target != nil && target.Role == roleAdmin && !target.Disabled && s.users.adminCount() <= 1

	switch req.Action {
	case "disable":
		if self {
			jsonErr(w, "cannot disable yourself")
			return
		}
		if lastAdmin {
			jsonErr(w, "cannot disable the last admin")
			return
		}
		if err := s.users.mutate(req.Username, func(u *User) bool { u.Disabled = true; u.Gen++; u.DeviceGen++; return true }); err != nil {
			jsonErr(w, err.Error())
			return
		}
		done(nil)
	case "enable":
		if err := s.users.mutate(req.Username, func(u *User) bool { u.Disabled = false; return true }); err != nil {
			jsonErr(w, err.Error())
			return
		}
		done(nil)
	case "delete":
		if self {
			jsonErr(w, "cannot delete yourself")
			return
		}
		if lastAdmin {
			jsonErr(w, "cannot delete the last admin")
			return
		}
		if err := s.users.delete(req.Username); err != nil {
			jsonErr(w, err.Error())
			return
		}
		done(nil)
	case "reset_password":
		temp := newTempPassword()
		hash, err := hashPassword(temp)
		if err != nil {
			jsonErr(w, "hash failed")
			return
		}
		if err := s.users.mutate(req.Username, func(u *User) bool {
			u.Hash = hash
			u.MustChange = true
			u.Gen++
			u.DeviceGen++
			return true
		}); err != nil {
			jsonErr(w, err.Error())
			return
		}
		done(map[string]string{"temp_password": temp})
	case "reset_totp":
		if err := s.users.mutate(req.Username, func(u *User) bool {
			u.TOTPSecret = ""
			u.PendingTOTP = ""
			u.BackupCodes = nil
			u.Gen++
			u.DeviceGen++
			return true
		}); err != nil {
			jsonErr(w, err.Error())
			return
		}
		done(nil)
	case "logout_user":
		if err := s.users.mutate(req.Username, func(u *User) bool { u.Gen++; u.DeviceGen++; return true }); err != nil {
			jsonErr(w, err.Error())
			return
		}
		done(nil)
	case "set_role":
		if req.Role != roleAdmin && req.Role != roleUser {
			jsonErr(w, "role must be admin or user")
			return
		}
		if self && req.Role != roleAdmin {
			jsonErr(w, "cannot demote yourself")
			return
		}
		if lastAdmin && req.Role != roleAdmin {
			jsonErr(w, "cannot demote the last admin")
			return
		}
		if err := s.users.mutate(req.Username, func(u *User) bool { u.Role = req.Role; return true }); err != nil {
			jsonErr(w, err.Error())
			return
		}
		done(nil)
	case "set_hosts":
		if err := s.users.mutate(req.Username, func(u *User) bool { u.AllowedHosts = req.Hosts; return true }); err != nil {
			jsonErr(w, err.Error())
			return
		}
		done(nil)
	case "reset_passkeys":
		if err := s.users.mutate(req.Username, func(u *User) bool {
			u.Passkeys = nil
			u.Gen++
			u.DeviceGen++
			return true
		}); err != nil {
			jsonErr(w, err.Error())
			return
		}
		done(nil)
	case "unlock":
		if req.IP == "" {
			jsonErr(w, "ip required")
			return
		}
		s.tr.reset(req.IP)
		done(nil)
	case "revoke_session":
		if req.SID == "" {
			jsonErr(w, "sid required")
			return
		}
		if err := s.reg.revoke(req.SID); err != nil {
			http.Error(w, "authentication storage unavailable", http.StatusServiceUnavailable)
			return
		}
		done(nil)
	default:
		jsonErr(w, "unknown action")
	}
}

// adminAudit is the legacy JSON snapshot endpoint, now admin-only.
func (s *server) adminAudit(w http.ResponseWriter, r *http.Request) {
	_, _, ok := s.adminGate(w, r, false)
	if !ok {
		return
	}
	secHeaders(w, nonce())
	n := min(max(atoi(r.URL.Query().Get("n"), 50), 0), 1000)
	jsonOut(w, http.StatusOK, map[string]any{
		"audit":  s.aud.snapshot(n),
		"locked": s.tr.snapshot(),
	})
}

// version is the build identifier shown on the admin System pane; override
// at build time with -ldflags "-X main.version=<tag>".
var version = "dev"

// SystemInfo backs GET /_auth/admin/api/system (ADMIN-UI-GUIDE.md §11).
type SystemInfo struct {
	Version      string    `json:"version"`
	Uptime       string    `json:"uptime"`
	DataDir      string    `json:"data_dir"`
	AuthHost     string    `json:"auth_host"`
	SessionTTL   string    `json:"session_ttl"`
	OrgID        string    `json:"org_id"`
	TotpRequired bool      `json:"totp_required"`
	PasskeyCount int       `json:"passkey_count"`
	UserCount    int       `json:"user_count"`
	AdminCount   int       `json:"admin_count"`
	StartedAt    time.Time `json:"started_at"`
}

// handleAdminSystem returns system-level information for the System pane.
func (s *server) handleAdminSystem(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := s.adminGate(w, r, false); !ok {
		return
	}
	secHeaders(w, nonce())
	passkeyCount := 0
	for _, u := range s.users.list() {
		passkeyCount += len(u.Passkeys)
	}
	jsonOut(w, http.StatusOK, SystemInfo{
		Version:      version,
		Uptime:       formatUptime(time.Since(s.startedAt)),
		DataDir:      filepath.Dir(s.cfg.usersFile),
		AuthHost:     s.cfg.authHost,
		SessionTTL:   s.cfg.ttl.String(),
		OrgID:        s.cfg.orgID,
		TotpRequired: s.cfg.requireTOTP,
		PasskeyCount: passkeyCount,
		UserCount:    s.users.count(),
		AdminCount:   s.users.adminCount(),
		StartedAt:    s.startedAt,
	})
}

func formatUptime(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	if days > 0 {
		return fmt.Sprintf("%dd %dh", days, hours)
	}
	return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
}

// adminRevokeSession revokes a single session by SID.
// Route: POST /_auth/admin/api/sessions/{sid}/revoke
func (s *server) adminRevokeSession(w http.ResponseWriter, r *http.Request) {
	_, actor, ok := s.adminGate(w, r, true)
	if !ok {
		return
	}
	sid := r.PathValue("sid")
	if sid == "" {
		jsonErr(w, "sid required")
		return
	}
	if err := s.reg.revoke(sid); err != nil {
		s.log.Error("persist session revocation", "sid", sid, "error", err)
		http.Error(w, "authentication storage unavailable", http.StatusServiceUnavailable)
		return
	}
	ip := s.clientIP(r)
	s.audit("admin_revoke_session:"+sid, ip, actor.Username, r)
	s.ntf.send("admin_revoke_session", actor.Username, ip, s.cfg.authHost, "sid "+sid)
	jsonOut(w, http.StatusOK, map[string]string{"ok": "1"})
}
