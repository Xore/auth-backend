package main

// sessions.go — best-effort registry of live sessions plus a revocation list.
//
// Cookies stay stateless (HMAC-signed, so they survive restarts); the
// registry only exists so the admin panel can show who is signed in and
// revoke a single session. After a restart the registry re-populates itself
// as sessions are seen on /_auth/verify. Durable "log this user out
// everywhere" is done by bumping the user's generation in the user store,
// not here.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

type sessionInfo struct {
	SID      string    `json:"sid"`
	User     string    `json:"user"`
	IP       string    `json:"ip"`
	UA       string    `json:"ua"`
	Created  time.Time `json:"created"`
	LastSeen time.Time `json:"last_seen"`
}

type sessionRegistry struct {
	mu      sync.Mutex
	m       map[string]*sessionInfo
	revoked map[string]time.Time // sid → when revoked; pruned after maxTTL
	maxTTL  time.Duration
	path    string
}

func newSessionRegistry(maxTTL time.Duration, paths ...string) *sessionRegistry {
	path := ""
	if len(paths) > 0 {
		path = paths[0]
	}
	return &sessionRegistry{m: map[string]*sessionInfo{}, revoked: map[string]time.Time{}, maxTTL: maxTTL, path: path}
}

func (sr *sessionRegistry) load() error {
	if sr.path == "" {
		return nil
	}
	raw, err := os.ReadFile(sr.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if err = json.Unmarshal(raw, &sr.revoked); err != nil {
		return err
	}
	sr.pruneLocked(time.Now())
	return nil
}

func (sr *sessionRegistry) touch(sid, user, ip, ua string) {
	if sid == "" {
		return
	}
	sr.mu.Lock()
	defer sr.mu.Unlock()
	now := time.Now()
	if s := sr.m[sid]; s != nil {
		s.LastSeen = now
		s.IP = ip
		return
	}
	sr.m[sid] = &sessionInfo{SID: sid, User: user, IP: ip, UA: ua, Created: now, LastSeen: now}
	sr.pruneLocked(now)
}

func (sr *sessionRegistry) revoke(sid string) error {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	sr.revoked[sid] = time.Now()
	delete(sr.m, sid)
	return sr.saveLocked()
}

func (sr *sessionRegistry) saveLocked() error {
	if sr.path == "" {
		return nil
	}
	dir := filepath.Dir(sr.path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	raw, err := json.Marshal(sr.revoked)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".revoked-*.tmp")
	if err != nil {
		return err
	}
	name := f.Name()
	defer func() { _ = os.Remove(name) }() // no-op once renamed on the success path
	if err = f.Chmod(0o600); err == nil {
		_, err = f.Write(append(raw, '\n'))
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, sr.path)
}

func (sr *sessionRegistry) isRevoked(sid string) bool {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	_, ok := sr.revoked[sid]
	return ok
}

func (sr *sessionRegistry) list() []sessionInfo {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	now := time.Now()
	sr.pruneLocked(now)
	out := make([]sessionInfo, 0, len(sr.m))
	for _, s := range sr.m {
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out
}

func (sr *sessionRegistry) active() int {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	sr.pruneLocked(time.Now())
	return len(sr.m)
}

func (sr *sessionRegistry) pruneLocked(now time.Time) {
	for sid, s := range sr.m {
		if now.Sub(s.LastSeen) > sr.maxTTL {
			delete(sr.m, sid)
		}
	}
	for sid, t := range sr.revoked {
		if now.Sub(t) > sr.maxTTL {
			delete(sr.revoked, sid)
		}
	}
}
