package main

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"strings"
)

type introspectionRequest struct {
	TargetHost string `json:"target_host"`
}

// cookieSink absorbs the Set-Cookie that session() emits when it transparently
// re-issues a token signed with a previous PASETO key. On the introspection
// path the response goes to the calling service, not the browser, so that
// cookie could never reach its owner — forwarding it would only risk the
// service replaying another user's session cookie. Rotation is not lost: the
// next browser-facing request re-issues it against the real writer.
type cookieSink struct{ h http.Header }

func (c cookieSink) Header() http.Header         { return c.h }
func (c cookieSink) Write(b []byte) (int, error) { return len(b), nil }
func (c cookieSink) WriteHeader(int)             {}

type introspectionResponse struct {
	Subject     string `json:"subject"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name,omitempty"`
	Role        string `json:"role"`
	Generation  int    `json:"generation"`
}

// introspect is a service-to-service identity lookup for applications that
// must not trust caller-controlled X-Auth-* headers. The caller authenticates
// with a separate bearer token and forwards the browser's auth cookie. The
// current session, account status, generation, role, and host allowlist are
// re-evaluated on every request.
func (s *server) introspect(w http.ResponseWriter, r *http.Request) {
	n := nonce()
	secHeaders(w, n)
	w.Header().Set("Cache-Control", "no-store")
	if s.cfg.introspectToken == "" {
		http.NotFound(w, r)
		return
	}
	const bearer = "Bearer "
	authorization := r.Header.Get("Authorization")
	if !strings.HasPrefix(authorization, bearer) ||
		subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(authorization, bearer)), []byte(s.cfg.introspectToken)) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || contentType != "application/json" {
		http.Error(w, "content type must be application/json", http.StatusUnsupportedMediaType)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var request introspectionRequest
	if err := decoder.Decode(&request); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	host := normalizeHost(request.TargetHost)
	if host == "" || host != strings.ToLower(strings.TrimSpace(request.TargetHost)) {
		http.Error(w, "invalid target host", http.StatusBadRequest)
		return
	}
	claims, user, ok := s.session(cookieSink{h: http.Header{}}, r)
	if !ok || claims.flags != "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !user.hostAllowed(host) {
		s.audit("introspection_forbidden_host", s.clientIP(r), user.Username, r)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(introspectionResponse{
		Subject: user.Subject, Username: user.Username, DisplayName: user.Username,
		Role: user.Role, Generation: user.Gen,
	})
}
