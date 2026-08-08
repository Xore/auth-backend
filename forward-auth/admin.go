package main

// admin.go — the admin JSON API. All endpoints require an admin session with
// no pending flags; mutating endpoints additionally require the per-session
// CSRF token in the X-Csrf header. The admin UI lives in the app shell
// (ui/app.html via apppage.go); /_auth/admin redirects there.

import (
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var usernameRe = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,32}$`)

// adminGate validates the session, role and (for mutations) CSRF token.
func (s *server) adminGate(w http.ResponseWriter, r *http.Request, csrf bool) (sessionClaims, *User, bool) {
	cl, u, ok := s.session(w, r)
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
	Username         string              `json:"username"`
	DisplayName      string              `json:"display_name"`
	Description      string              `json:"description"`
	Role             string              `json:"role"`
	Email            string              `json:"email"`
	Disabled         bool                `json:"disabled"`
	MustChange       bool                `json:"must_change"`
	TOTPEnrolled     bool                `json:"totp_enrolled"`
	BackupCodes      int                 `json:"backup_codes"`
	AllowedHosts     []string            `json:"allowed_hosts"`
	RequireTOTPHosts []string            `json:"require_totp_hosts"`
	Permissions      map[string][]string `json:"permissions"`
	Created          time.Time           `json:"created"`
	LastLogin        time.Time           `json:"last_login"`
	LastIP           string              `json:"last_ip"`
	Passkeys         int                 `json:"passkeys"`
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
		totpHosts := u.RequireTOTPHosts
		if totpHosts == nil {
			totpHosts = []string{}
		}
		perms := u.Permissions
		if perms == nil {
			perms = map[string][]string{}
		}
		views = append(views, adminUserView{
			Username: u.Username, DisplayName: u.DisplayName, Description: u.Description,
			Role: u.Role, Email: u.Email, Disabled: u.Disabled,
			MustChange: u.MustChange, TOTPEnrolled: u.TOTPSecret != "",
			BackupCodes: len(u.BackupCodes), AllowedHosts: hosts, RequireTOTPHosts: totpHosts, Permissions: perms,
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
	secHeaders(w, nonce())
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Username     string   `json:"username"`
		Role         string   `json:"role"`
		Email        string   `json:"email"`
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
	email, err := normalizeEmail(req.Email)
	if err != nil {
		jsonErr(w, err.Error())
		return
	}
	temp := newTempPassword()
	hash, err := hashPassword(temp)
	if err != nil {
		jsonErr(w, "hash failed")
		return
	}
	err = s.users.create(&User{
		Username: req.Username, Hash: hash, Role: req.Role, Email: email,
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
	secHeaders(w, nonce())
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Action           string   `json:"action"`
		Username         string   `json:"username"`
		Role             string   `json:"role"`
		Email            string   `json:"email"`
		Hosts            []string `json:"hosts"`
		RequireTOTPHosts []string `json:"require_totp_hosts"`
		IP               string   `json:"ip"`
		SID              string   `json:"sid"`
		NewUsername      string   `json:"new_username"`
		DisplayName      string   `json:"display_name"`
		Description      string   `json:"description"`
		Host             string   `json:"host"`
		Permissions      []string `json:"permissions"`
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

	// self is checked up front (it depends only on the request/session, not
	// store state that could change concurrently); the last-admin guard
	// below runs atomically with its mutation instead — see
	// mutateAdminGuarded/deleteAdminGuarded.
	self := req.Username == actor.Username

	switch req.Action {
	case "disable":
		if self {
			jsonErr(w, "cannot disable yourself")
			return
		}
		if err := s.users.mutateAdminGuarded(req.Username, func(u *User, otherAdmins int) error {
			if u.Role == roleAdmin && !u.Disabled && otherAdmins == 0 {
				return errLastAdmin
			}
			u.Disabled = true
			u.Gen++
			u.DeviceGen++
			return nil
		}); err != nil {
			if errors.Is(err, errLastAdmin) {
				jsonErr(w, "cannot disable the last admin")
			} else {
				jsonErr(w, err.Error())
			}
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
		if err := s.users.deleteAdminGuarded(req.Username); err != nil {
			if errors.Is(err, errLastAdmin) {
				jsonErr(w, "cannot delete the last admin")
			} else {
				jsonErr(w, err.Error())
			}
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
		if err := s.users.mutateAdminGuarded(req.Username, func(u *User, otherAdmins int) error {
			if u.Role == roleAdmin && !u.Disabled && otherAdmins == 0 && req.Role != roleAdmin {
				return errLastAdmin
			}
			u.Role = req.Role
			return nil
		}); err != nil {
			if errors.Is(err, errLastAdmin) {
				jsonErr(w, "cannot demote the last admin")
			} else {
				jsonErr(w, err.Error())
			}
			return
		}
		done(nil)
	case "set_hosts":
		if err := s.users.mutate(req.Username, func(u *User) bool { u.AllowedHosts = req.Hosts; return true }); err != nil {
			jsonErr(w, err.Error())
			return
		}
		done(nil)
	case "set_require_totp_hosts":
		// #67: no TOTPSecret requirement enforced here -- setting this for a
		// password-only or passkey-only user is a harmless no-op (the login
		// path's own `u.TOTPSecret != ""` guard already covers that), not
		// worth refusing and adding friction to a config an admin might
		// reasonably set in advance of enrollment.
		if err := s.users.mutate(req.Username, func(u *User) bool { u.RequireTOTPHosts = req.RequireTOTPHosts; return true }); err != nil {
			jsonErr(w, err.Error())
			return
		}
		done(nil)
	case "set_email":
		email, err := normalizeEmail(req.Email)
		if err != nil {
			jsonErr(w, err.Error())
			return
		}
		if err := s.users.mutate(req.Username, func(u *User) bool { u.Email = email; return true }); err != nil {
			jsonErr(w, err.Error())
			return
		}
		done(nil)
	case "set_display_name":
		name, err := normalizeDisplayName(req.DisplayName)
		if err != nil {
			jsonErr(w, err.Error())
			return
		}
		var before string
		if err := s.users.mutate(req.Username, func(u *User) bool {
			before = u.DisplayName
			u.DisplayName = name
			return true
		}); err != nil {
			jsonErr(w, err.Error())
			return
		}
		s.audit(fmt.Sprintf("admin_set_display_name:%s before=%q after=%q", req.Username, before, name), ip, actor.Username, r)
		s.ntf.send("admin_set_display_name", actor.Username, ip, s.cfg.authHost, "target "+req.Username)
		jsonOut(w, http.StatusOK, map[string]string{"ok": "1"})
	case "set_description":
		desc, err := normalizeDescription(req.Description)
		if err != nil {
			jsonErr(w, err.Error())
			return
		}
		if err := s.users.mutate(req.Username, func(u *User) bool { u.Description = desc; return true }); err != nil {
			jsonErr(w, err.Error())
			return
		}
		s.audit("admin_set_description:"+req.Username, ip, actor.Username, r)
		s.ntf.send("admin_set_description", actor.Username, ip, s.cfg.authHost, "target "+req.Username)
		jsonOut(w, http.StatusOK, map[string]string{"ok": "1"})
	case "rename_user":
		if err := s.users.rename(req.Username, req.NewUsername); err != nil {
			jsonErr(w, err.Error())
			return
		}
		s.audit(fmt.Sprintf("admin_rename_user:%s before=%q after=%q", req.NewUsername, req.Username, req.NewUsername), ip, actor.Username, r)
		s.ntf.send("admin_rename_user", actor.Username, ip, s.cfg.authHost, "target "+req.Username+" -> "+req.NewUsername)
		jsonOut(w, http.StatusOK, map[string]string{"ok": "1"})
	case "set_permissions":
		if req.Host == "" || normalizeHost(req.Host) == "" {
			jsonErr(w, "host required")
			return
		}
		host := normalizeHost(req.Host)
		perms, err := normalizePermissions(req.Permissions)
		if err != nil {
			jsonErr(w, err.Error())
			return
		}
		var before []string
		var hostCapExceeded bool
		applied, err := s.users.mutateIf(req.Username, func(u *User) bool {
			before = u.Permissions[host]
			if len(perms) == 0 {
				if u.Permissions != nil {
					delete(u.Permissions, host)
				}
				return true
			}
			if u.Permissions == nil {
				u.Permissions = map[string][]string{}
			}
			if _, exists := u.Permissions[host]; !exists && len(u.Permissions) >= maxPermissionsHost {
				hostCapExceeded = true
				return false
			}
			u.Permissions[host] = perms
			return true
		})
		if err != nil {
			jsonErr(w, err.Error())
			return
		}
		if !applied && hostCapExceeded {
			jsonErr(w, fmt.Sprintf("at most %d hosts can carry permission grants for one user", maxPermissionsHost))
			return
		}
		s.audit(fmt.Sprintf("admin_set_permissions:%s host=%s before=%v after=%v", req.Username, host, before, perms), ip, actor.Username, r)
		s.ntf.send("admin_set_permissions", actor.Username, ip, s.cfg.authHost, "target "+req.Username+" host "+host)
		jsonOut(w, http.StatusOK, map[string]string{"ok": "1"})
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

// SystemInfo backs GET /_auth/admin/api/system.
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

type adminConfigField struct {
	Key               string `json:"key"`
	Label             string `json:"label"`
	Kind              string `json:"kind"`
	Description       string `json:"description"`
	Value             string `json:"value,omitempty"`
	Sensitive         bool   `json:"sensitive"`
	Configured        bool   `json:"configured"`
	ExternallyManaged bool   `json:"externally_managed"`
	Pending           bool   `json:"pending"`
}

type adminSettingsResponse struct {
	BrandTitle    string             `json:"brand_title"`
	BrandSubtitle string             `json:"brand_subtitle"`
	BrandFooter   string             `json:"brand_footer"`
	Fields        []adminConfigField `json:"fields"`
	RestartNeeded bool               `json:"restart_needed"`
}

func (s *server) settingsResponse() adminSettingsResponse {
	saved := s.settings.snapshot()
	fields := make([]adminConfigField, 0, len(editableConfigFields))
	restartNeeded := false
	for _, spec := range sortedFieldSpecs() {
		current := currentConfigValue(s.cfg, spec.Key)
		staged, pending := saved.Overrides[spec.Key]
		external := os.Getenv(spec.Key+"_FILE") != ""
		if pending && staged == current {
			pending = false
		}
		restartNeeded = restartNeeded || pending
		value := current
		if pending {
			value = staged
		}
		if spec.Sensitive {
			value = ""
		}
		fields = append(fields, adminConfigField{
			Key: spec.Key, Label: spec.Label, Kind: spec.Kind,
			Description: spec.Description, Value: value, Sensitive: spec.Sensitive,
			Configured: current != "", ExternallyManaged: external, Pending: pending,
		})
	}
	return adminSettingsResponse{
		BrandTitle: saved.BrandTitle, BrandSubtitle: saved.BrandSubtitle,
		BrandFooter: saved.BrandFooter, Fields: fields, RestartNeeded: restartNeeded,
	}
}

// handleAdminSettings exposes redacted configuration metadata and persists
// environment-compatible overrides. Branding applies immediately; service and
// cryptographic settings are activated by a process restart.
func (s *server) handleAdminSettings(w http.ResponseWriter, r *http.Request) {
	_, actor, ok := s.adminGate(w, r, r.Method != http.MethodGet)
	if !ok {
		return
	}
	secHeaders(w, nonce())
	if r.Method == http.MethodGet {
		jsonOut(w, http.StatusOK, s.settingsResponse())
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		BrandTitle    *string           `json:"brand_title"`
		BrandSubtitle *string           `json:"brand_subtitle"`
		BrandFooter   *string           `json:"brand_footer"`
		Updates       map[string]string `json:"updates"`
		Rotate        string            `json:"rotate"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		jsonErr(w, "invalid JSON")
		return
	}
	next := s.settings.snapshot()
	if req.BrandTitle != nil {
		next.BrandTitle = strings.TrimSpace(*req.BrandTitle)
		if next.BrandTitle == "" || len(next.BrandTitle) > 80 {
			jsonErr(w, "title must contain 1 to 80 characters")
			return
		}
	}
	if req.BrandSubtitle != nil {
		next.BrandSubtitle = strings.TrimSpace(*req.BrandSubtitle)
		if len(next.BrandSubtitle) > 200 {
			jsonErr(w, "subtitle must not exceed 200 characters")
			return
		}
	}
	if req.BrandFooter != nil {
		next.BrandFooter = strings.TrimSpace(*req.BrandFooter)
		if len(next.BrandFooter) > 200 {
			jsonErr(w, "footer must not exceed 200 characters")
			return
		}
	}
	for key, value := range req.Updates {
		spec, exists := editableConfigKeys[key]
		if !exists {
			jsonErr(w, "setting is not editable: "+key)
			return
		}
		if os.Getenv(key+"_FILE") != "" {
			jsonErr(w, key+" is managed by a secret file")
			return
		}
		value = strings.TrimSpace(value)
		if spec.Sensitive && value == "" {
			continue
		}
		if spec.Kind == "bool" && value != "true" && value != "false" {
			jsonErr(w, key+" must be true or false")
			return
		}
		if spec.Kind == "number" {
			n, err := strconv.Atoi(value)
			if err != nil || n < 0 {
				jsonErr(w, key+" must be a non-negative integer")
				return
			}
			switch key {
			case "SESSION_TTL_HOURS", "MAX_ATTEMPTS", "LOCKOUT_MINUTES", "FORM_TTL_MINUTES":
				if n == 0 {
					jsonErr(w, key+" must be positive")
					return
				}
			case "AUDIT_RING":
				if n < 1 || n > 100000 {
					jsonErr(w, "AUDIT_RING must be between 1 and 100000")
					return
				}
			case "MAX_BODY_KB":
				if n < 1 || n > 10240 {
					jsonErr(w, "MAX_BODY_KB must be between 1 and 10240")
					return
				}
			}
		}
		if key == "AUTH_HOST" && (value == "" || normalizeHost(value) != strings.ToLower(value)) {
			jsonErr(w, "AUTH_HOST must be a lowercase hostname without a scheme or port")
			return
		}
		if key == "COOKIE_SECRET" && len(value) < 32 {
			jsonErr(w, "COOKIE_SECRET must contain at least 32 characters")
			return
		}
		if key == "PASETO_KEY" {
			decoded, err := hex.DecodeString(value)
			if err != nil || len(decoded) != 32 {
				jsonErr(w, "PASETO_KEY must be exactly 64 hexadecimal characters")
				return
			}
		}
		if key == "TRUSTED_PROXIES" {
			valid := 0
			for _, part := range strings.Split(value, ",") {
				if _, _, err := net.ParseCIDR(strings.TrimSpace(part)); err == nil {
					valid++
				}
			}
			if valid == 0 {
				jsonErr(w, "TRUSTED_PROXIES must contain at least one valid CIDR")
				return
			}
		}
		if key == "SMTP_URL" && value != "" {
			u, err := url.Parse(value)
			if err != nil || (u.Scheme != "smtp" && u.Scheme != "smtps") || u.Hostname() == "" {
				jsonErr(w, "SMTP_URL must be smtp:// or smtps:// with a host")
				return
			}
		}
		if key == "WEBHOOK_PROVIDER" {
			switch value {
			case "", "raw", "slack", "ntfy", "gotify":
			default:
				jsonErr(w, "WEBHOOK_PROVIDER must be raw, slack, ntfy or gotify")
				return
			}
		}
		next.Overrides[key] = value
	}
	effectiveInt := func(key string, current int) int {
		if value, exists := next.Overrides[key]; exists {
			return atoi(value, current)
		}
		return current
	}
	formTTLSeconds := effectiveInt("FORM_TTL_MINUTES", int(s.cfg.formTTL.Minutes())) * 60
	minDwellSeconds := effectiveInt("MIN_DWELL_SECONDS", int(s.cfg.minDwell.Seconds()))
	if formTTLSeconds <= minDwellSeconds {
		jsonErr(w, "form token lifetime must exceed minimum login dwell")
		return
	}
	if req.Rotate != "" {
		key := strings.ToUpper(strings.TrimSpace(req.Rotate))
		if key != "COOKIE_SECRET" && key != "PASETO_KEY" {
			jsonErr(w, "only COOKIE_SECRET and PASETO_KEY support rotation")
			return
		}
		if os.Getenv(key+"_FILE") != "" {
			jsonErr(w, key+" is managed by a secret file")
			return
		}
		generated, err := randomHex(32)
		if err != nil {
			http.Error(w, "could not generate key", http.StatusInternalServerError)
			return
		}
		next.Overrides[key] = generated
		if key == "COOKIE_SECRET" {
			next.Overrides["COOKIE_SECRET_PREVIOUS"] = currentConfigValue(s.cfg, key)
		} else {
			next.Overrides["PASETO_KEY_PREVIOUS"] = currentConfigValue(s.cfg, key)
		}
	}
	if err := s.settings.save(next); err != nil {
		s.log.Error("persist admin settings", "error", err)
		http.Error(w, "could not persist settings", http.StatusInternalServerError)
		return
	}
	ip := s.clientIP(r)
	s.audit("admin_settings_updated", ip, actor.Username, r)
	jsonOut(w, http.StatusOK, s.settingsResponse())
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
	secHeaders(w, nonce())
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
