package main

import (
	"bytes"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

type passkeyCeremony struct {
	Kind, User, SID, IP, Redirect, Name string
	Data                                webauthn.SessionData
	Expires                             time.Time
}

type ceremonyStore struct {
	mu sync.Mutex
	m  map[string]passkeyCeremony
}

func newCeremonyStore() *ceremonyStore { return &ceremonyStore{m: map[string]passkeyCeremony{}} }

func (cs *ceremonyStore) put(c passkeyCeremony) string {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	now := time.Now()
	for id, old := range cs.m {
		if now.After(old.Expires) {
			delete(cs.m, id)
		}
	}
	for len(cs.m) >= 1024 {
		for id := range cs.m {
			delete(cs.m, id)
			break
		}
	}
	id := hex.EncodeToString(randomBytes(24))
	c.Expires = now.Add(5 * time.Minute)
	cs.m[id] = c
	return id
}

func (cs *ceremonyStore) take(id, kind string) (passkeyCeremony, bool) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	c, ok := cs.m[id]
	delete(cs.m, id)
	return c, ok && c.Kind == kind && time.Now().Before(c.Expires)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, maxBytes int64, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil || dec.Decode(&struct{}{}) != io.EOF {
		jsonErr(w, "bad json")
		return false
	}
	return true
}

func (s *server) passkeyPage(w http.ResponseWriter, r *http.Request) {
	cl, u, ok := s.session(w, r)
	if !ok {
		http.Redirect(w, r, "https://"+s.cfg.authHost+"/_auth/login", http.StatusFound)
		return
	}
	if rd := pendingRedirect(cl, s.cfg.authHost); rd != "" {
		http.Redirect(w, r, rd, http.StatusFound)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	n := nonce()
	secHeaders(w, n)
	s.renderPasskeys(w, u, s.cfg.csrfToken(cl.sid), n)
}

func (s *server) passkeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	secHeaders(w, nonce())
	cl, u, ok := s.passkeyGate(w, r)
	if !ok {
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if !decodeJSON(w, r, s.cfg.maxBodyBytes, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		req.Name = "passkey"
	}
	if len(req.Name) > 64 {
		jsonErr(w, "name is too long")
		return
	}
	options, data, err := s.wa.BeginRegistration(u)
	if err != nil {
		s.log.Error("begin passkey registration", "error", err)
		jsonErr(w, "could not start passkey registration")
		return
	}
	tx := s.ceremonies.put(passkeyCeremony{Kind: "register", User: u.Username, SID: cl.sid, Name: req.Name, Data: *data})
	jsonOut(w, http.StatusOK, map[string]any{"transaction": tx, "options": options})
}

func (s *server) passkeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	secHeaders(w, nonce())
	cl, u, ok := s.passkeyGate(w, r)
	if !ok {
		return
	}
	tx := r.Header.Get("X-WebAuthn-Transaction")
	c, ok := s.ceremonies.take(tx, "register")
	if !ok || c.User != u.Username || c.SID != cl.sid {
		jsonErr(w, "registration expired")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.maxBodyBytes)
	cred, err := s.wa.FinishRegistration(u, c.Data, r)
	if err != nil {
		s.audit("passkey_register_fail", s.clientIP(r), u.Username, r)
		jsonErr(w, "passkey verification failed")
		return
	}
	err = s.users.mutate(u.Username, func(current *User) bool {
		for _, key := range current.Passkeys {
			if bytes.Equal(key.Credential.ID, cred.ID) {
				return false
			}
		}
		current.Passkeys = append(current.Passkeys, Passkey{Name: c.Name, Credential: *cred, Created: time.Now().UTC()})
		return true
	})
	if err != nil {
		http.Error(w, "authentication storage unavailable", http.StatusServiceUnavailable)
		return
	}
	s.audit("passkey_registered", s.clientIP(r), u.Username, r)
	jsonOut(w, http.StatusOK, map[string]string{"ok": "1"})
}

func (s *server) passkeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	secHeaders(w, nonce())
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct{ Username, Redirect string }
	if !decodeJSON(w, r, s.cfg.maxBodyBytes, &req) {
		return
	}
	ip := s.clientIP(r)
	name := strings.TrimSpace(req.Username)
	if locked, _, err := s.tr.locked(ip); err != nil {
		s.log.Warn("throttle check failed — failing closed", "error", err)
		http.Error(w, "authentication storage unavailable", http.StatusServiceUnavailable)
		return
	} else if locked {
		http.Error(w, "temporarily unavailable", http.StatusTooManyRequests)
		return
	}
	if locked, _, err := s.tr.locked("user:" + strings.ToLower(name)); err != nil {
		s.log.Warn("throttle check failed — failing closed", "error", err)
		http.Error(w, "authentication storage unavailable", http.StatusServiceUnavailable)
		return
	} else if locked {
		http.Error(w, "temporarily unavailable", http.StatusTooManyRequests)
		return
	}
	u := s.users.get(name)
	if u == nil || u.Disabled || len(u.Passkeys) == 0 {
		if !s.passkeyThrottleOr503(w, r, ip, name, "unavailable") {
			return
		}
		jsonErr(w, "passkey sign-in unavailable")
		return
	}
	options, data, err := s.wa.BeginLogin(u)
	if err != nil {
		jsonErr(w, "passkey sign-in unavailable")
		return
	}
	tx := s.ceremonies.put(passkeyCeremony{Kind: "login", User: name, IP: ip, Redirect: s.cfg.safeRedirect(req.Redirect), Data: *data})
	jsonOut(w, http.StatusOK, map[string]any{"transaction": tx, "options": options})
}

func (s *server) passkeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	secHeaders(w, nonce())
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tx := r.Header.Get("X-WebAuthn-Transaction")
	c, ok := s.ceremonies.take(tx, "login")
	ip := s.clientIP(r)
	if !ok || c.IP != ip {
		if !s.passkeyThrottleOr503(w, r, ip, c.User, "expired") {
			return
		}
		jsonErr(w, "passkey sign-in failed")
		return
	}
	u := s.users.get(c.User)
	if u == nil || u.Disabled {
		if !s.passkeyThrottleOr503(w, r, ip, c.User, "user") {
			return
		}
		jsonErr(w, "passkey sign-in failed")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.maxBodyBytes)
	cred, err := s.wa.FinishLogin(u, c.Data, r)
	if err != nil {
		if !s.passkeyThrottleOr503(w, r, ip, c.User, "verify") {
			return
		}
		jsonErr(w, "passkey sign-in failed")
		return
	}
	previousIP := u.LastIP
	updated := false
	err = s.users.mutate(u.Username, func(current *User) bool {
		for i := range current.Passkeys {
			if bytes.Equal(current.Passkeys[i].Credential.ID, cred.ID) {
				current.Passkeys[i].Credential = *cred
				current.Passkeys[i].LastUsed = time.Now().UTC()
				current.LastLogin = time.Now().UTC()
				current.LastIP = ip
				updated = true
				return true
			}
		}
		return false
	})
	if err != nil {
		http.Error(w, "authentication storage unavailable", http.StatusServiceUnavailable)
		return
	}
	if !updated {
		if !s.passkeyThrottleOr503(w, r, ip, c.User, "revoked") {
			return
		}
		jsonErr(w, "passkey sign-in failed")
		return
	}
	if previousIP != "" && previousIP != ip {
		s.ntf.send("login_new_ip", u.Username, ip, s.cfg.authHost, "previous ip "+previousIP)
	}
	fresh := s.users.get(u.Username)
	cl := sessionClaims{user: u.Username, gen: fresh.Gen, sid: newSID(), flags: s.flagsFor(fresh), exp: time.Now().Add(s.cfg.ttl).Unix()}
	s.setCookie(w, cl)
	if err := s.reg.touch(cl.sid, u.Username, ip, r.UserAgent()); err != nil {
		s.log.Warn("session touch failed", "error", err)
	}
	s.tr.reset(ip)
	s.tr.reset("user:" + strings.ToLower(u.Username))
	s.audit("passkey_login_ok", ip, u.Username, r)
	redirect := c.Redirect
	if pending := pendingRedirect(cl, s.cfg.authHost); pending != "" {
		redirect = pending
	}
	jsonOut(w, http.StatusOK, map[string]string{"redirect": redirect})
}

func (s *server) passkeyDelete(w http.ResponseWriter, r *http.Request) {
	secHeaders(w, nonce())
	_, u, ok := s.passkeyGate(w, r)
	if !ok {
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if !decodeJSON(w, r, s.cfg.maxBodyBytes, &req) {
		return
	}
	id, err := hex.DecodeString(req.ID)
	if err != nil {
		jsonErr(w, "bad credential id")
		return
	}
	found := false
	err = s.users.mutate(u.Username, func(current *User) bool {
		for i := range current.Passkeys {
			if bytes.Equal(current.Passkeys[i].Credential.ID, id) {
				current.Passkeys = append(current.Passkeys[:i], current.Passkeys[i+1:]...)
				found = true
				return true
			}
		}
		return false
	})
	if err != nil {
		http.Error(w, "authentication storage unavailable", http.StatusServiceUnavailable)
		return
	}
	if !found {
		jsonErr(w, "no such passkey")
		return
	}
	s.audit("passkey_deleted", s.clientIP(r), u.Username, r)
	jsonOut(w, http.StatusOK, map[string]string{"ok": "1"})
}

func (s *server) passkeyList(w http.ResponseWriter, r *http.Request) {
	secHeaders(w, nonce())
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cl, u, ok := s.session(w, r)
	if !ok || cl.flags != "" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	type passkeyView struct {
		ID       string    `json:"id"`
		Name     string    `json:"name"`
		Created  time.Time `json:"created"`
		LastUsed time.Time `json:"last_used"`
	}
	views := make([]passkeyView, 0, len(u.Passkeys))
	for _, key := range u.Passkeys {
		views = append(views, passkeyView{
			ID: hex.EncodeToString(key.Credential.ID), Name: key.Name,
			Created: key.Created, LastUsed: key.LastUsed,
		})
	}
	jsonOut(w, http.StatusOK, views)
}

func (s *server) passkeyGate(w http.ResponseWriter, r *http.Request) (sessionClaims, *User, bool) {
	cl, u, ok := s.session(w, r)
	if !ok || cl.flags != "" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return cl, nil, false
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return cl, nil, false
	}
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Csrf")), []byte(s.cfg.csrfToken(cl.sid))) != 1 {
		http.Error(w, "bad csrf token", http.StatusForbidden)
		return cl, nil, false
	}
	return cl, u, true
}

// passkeyThrottleOr503 runs passkeyFailure; when the throttle backend is
// unavailable it answers a controlled 503 (fail closed) and reports false.
func (s *server) passkeyThrottleOr503(w http.ResponseWriter, r *http.Request, ip, user, reason string) bool {
	if err := s.passkeyFailure(r, ip, user, reason); err != nil {
		http.Error(w, "authentication storage unavailable", http.StatusServiceUnavailable)
		return false
	}
	return true
}

// passkeyFailure throttles and audits a failed passkey sign-in. A non-nil
// error means the throttle backend is unavailable — callers answer 503
// (fail closed) instead of letting attempts through unthrottled.
func (s *server) passkeyFailure(r *http.Request, ip, user, reason string) error {
	if _, err := s.tr.fail(ip); err != nil {
		s.log.Warn("throttle record failed", "error", err)
		return err
	}
	if user != "" {
		if _, err := s.tr.fail("user:" + strings.ToLower(user)); err != nil {
			s.log.Warn("throttle record failed", "error", err)
			return err
		}
	}
	s.audit("passkey_login_fail:"+reason, ip, user, r)
	return nil
}
