package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// --- brute-force throttle ---------------------------------------------------

// ThrottleBackend is the brute-force throttle contract. The default is the
// in-memory throttle below (with JSON file persistence); a Redis backend
// (redis.go) takes over when REDIS_URL is set.
//
// Error policy: a non-nil error means "backend unavailable", never "not
// locked". Callers must fail closed — return a controlled 503 rather than
// letting a request through with brute-force protection silently disabled.
// The in-memory implementation never errors.
type ThrottleBackend interface {
	locked(ip string) (bool, time.Duration, error)
	fail(ip string) (lockedNow bool, err error)
	reset(ip string)
	snapshot() []lockedIP
}

type entry struct {
	fails     int
	lockUntil time.Time
}

type throttle struct {
	mu   sync.Mutex
	m    map[string]*entry
	cfg  config
	path string
}

func newThrottle(cfg config) *throttle { return &throttle{m: map[string]*entry{}, cfg: cfg} }

// throttleEntryJSON is the on-disk shape of an entry (entry's fields are
// unexported, so encoding/json can't see them directly).
type throttleEntryJSON struct {
	Fails     int       `json:"fails"`
	LockUntil time.Time `json:"lock_until"`
}

// load reads persisted throttle state from path (missing file is not an
// error) and remembers the path for future persists.
func (t *throttle) load(path string) error {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		t.mu.Lock()
		t.path = path
		t.mu.Unlock()
		return nil
	}
	if err != nil {
		return err
	}
	var m map[string]throttleEntryJSON
	if err := json.Unmarshal(raw, &m); err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.path = path
	for k, v := range m {
		t.m[k] = &entry{fails: v.Fails, lockUntil: v.LockUntil}
	}
	t.pruneLocked(time.Now())
	return nil
}

// persist writes the throttle map to path atomically (temp file + rename).
func (t *throttle) persist(path string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.persistLocked(path)
}

// persistLocked persists with the caller holding t.mu. Expired entries are
// pruned first — no point writing lockouts that have already cleared.
func (t *throttle) persistLocked(path string) error {
	t.pruneLocked(time.Now())
	out := make(map[string]throttleEntryJSON, len(t.m))
	for k, v := range t.m {
		out[k] = throttleEntryJSON{Fails: v.fails, LockUntil: v.lockUntil}
	}
	raw, err := json.Marshal(out)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".throttle-*.tmp")
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
	return os.Rename(name, path)
}

func (t *throttle) locked(ip string) (bool, time.Duration, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.m[ip]
	if e == nil {
		return false, 0, nil
	}
	if e.lockUntil.IsZero() {
		// counting entry, no lock yet — keep it, the fails must accumulate
		return false, 0, nil
	}
	if d := time.Until(e.lockUntil); d > 0 {
		return true, d, nil
	}
	if time.Since(e.lockUntil) > t.cfg.lockout {
		delete(t.m, ip)
	}
	return false, 0, nil
}

func (t *throttle) fail(ip string) (lockedNow bool, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.m[ip]
	if e == nil {
		e = &entry{}
		t.m[ip] = e
	}
	e.fails++
	if len(t.m) > 8192 {
		t.pruneLocked(time.Now())
	}
	if e.fails >= t.cfg.maxAttempts {
		mult := time.Duration(1) << uint(min(e.fails-t.cfg.maxAttempts, 10))
		d := t.cfg.lockout * mult
		if d > 24*time.Hour {
			d = 24 * time.Hour
		}
		e.lockUntil = time.Now().Add(d)
		if t.path != "" {
			_ = t.persistLocked(t.path) // durable lockout; best-effort
		}
		return true, nil
	}
	return false, nil
}

func (t *throttle) pruneLocked(now time.Time) {
	for key, e := range t.m {
		if e.lockUntil.IsZero() {
			continue // counting entry — no lock timestamp to expire
		}
		if !e.lockUntil.After(now) && now.Sub(e.lockUntil) > t.cfg.lockout {
			delete(t.m, key)
		}
	}
	for key := range t.m {
		if len(t.m) <= 4096 {
			break
		}
		delete(t.m, key)
	}
}

func (t *throttle) reset(ip string) {
	t.mu.Lock()
	delete(t.m, ip)
	t.mu.Unlock()
}
