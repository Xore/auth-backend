package main

// mysessions.go — self-service session endpoints for the app shell: the
// current user's own sessions and trusted devices. Admin-wide views stay in
// admin.go. Device trust is cookie-based, so the trusted list is a stub
// until trust records are persisted.

import (
	"encoding/json"
	"net/http"
	"time"
)

// handleMySessions returns only the sessions belonging to the current user.
func (s *server) handleMySessions(w http.ResponseWriter, r *http.Request) {
	cl, _, ok := s.session(w, r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	secHeaders(w, nonce())
	sessions := s.reg.forUser(cl.user)
	currentSID := cl.sid
	type mySession struct {
		ID      string    `json:"id"`
		IP      string    `json:"ip"`
		UA      string    `json:"ua"`
		Current bool      `json:"current"`
		Created time.Time `json:"created"`
		Updated time.Time `json:"last_seen"`
	}
	out := make([]mySession, 0, len(sessions))
	for _, sess := range sessions {
		out = append(out, mySession{
			ID: sess.SID, IP: sess.IP, UA: sess.UA,
			Current: sess.SID == currentSID,
			Created: sess.Created, Updated: sess.LastSeen,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// handleTrustedDevices returns the user's device trust cookies as a list.
// Device trust is cookie-based, not registry-stored — empty for now.
func (s *server) handleTrustedDevices(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := s.session(w, r); !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	secHeaders(w, nonce())
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte("[]"))
}
