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
	// reserve atomically checks whether ip is locked and, if not,
	// provisionally records this attempt as a failure before the caller
	// runs its (slow) credential check — closing the check-then-act race
	// between a plain locked()+fail() pair spanning an Argon2id hash. The
	// caller MUST call reset(ip) on a successful login to undo the
	// provisional increment.
	reserve(ip string) (allowed bool, retryAfter time.Duration, err error)
	reset(ip string)
	snapshot() []lockedIP
}

type entry struct {
	fails     int
	lockUntil time.Time
	// cycles counts how many times this key has crossed maxAttempts and
	// (re)triggered a lock -- #62's escalation counter. permanent, once
	// set, is never cleared by time; only an explicit reset() (the existing
	// admin "unlock" action) clears it, same as it already clears a normal
	// lockUntil.
	cycles    int
	permanent bool
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
	Cycles    int       `json:"cycles,omitempty"`
	Permanent bool      `json:"permanent,omitempty"`
}

// permanentLockRetryAfter is the sentinel duration checkLocked/locked()
// report for a permanent lock -- large enough that nothing could mistake it
// for a real, finite retry window, and used by callers (lockoutMessage) to
// tell "come back later" apart from "an administrator must clear this."
// Deliberately not time.Duration's own max (that renders as a nonsensical
// giant number of hours if a caller forgets this check and formats it raw).
const permanentLockRetryAfter = 100 * 365 * 24 * time.Hour

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
		t.m[k] = &entry{fails: v.Fails, lockUntil: v.LockUntil, cycles: v.Cycles, permanent: v.Permanent}
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
		out[k] = throttleEntryJSON{Fails: v.fails, LockUntil: v.lockUntil, Cycles: v.cycles, Permanent: v.permanent}
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
	locked, d := t.checkLocked(ip, time.Now())
	return locked, d, nil
}

// checkLocked reports whether ip is currently locked. Caller must hold t.mu.
// A lock past its grace period is cleared so it doesn't hold a live entry
// locked forever, but a live counting entry (no lock yet) is left alone —
// the fails must keep accumulating. A permanent entry (#62) is checked
// first and never falls through to the time-based expiry logic below it —
// that logic exists specifically to clear a lock once its time is up, which
// is exactly the behavior a permanent lock must not have.
//
// #62: an expired (non-permanent) entry is only deleted outright when
// permaLockCycles is disabled (0) — the original, unchanged behavior for
// any deployment that hasn't opted in. With escalation enabled, the entry
// is instead reset to an idle counting state (fails/lockUntil cleared,
// cycles preserved): recordFailure's own wasLocked check needs a real,
// distinguishable "not currently locked" state to detect that the NEXT
// lock is a genuinely new cycle rather than a continuation of this one —
// deleting the entry here would silently lose that history on every single
// wait-out-the-timer-and-retry round, and cycles could never reach the
// escalation threshold no matter how many times an attacker did exactly
// that.
func (t *throttle) checkLocked(ip string, now time.Time) (bool, time.Duration) {
	e := t.m[ip]
	if e == nil {
		return false, 0
	}
	if e.permanent {
		return true, permanentLockRetryAfter
	}
	if e.lockUntil.IsZero() {
		return false, 0
	}
	if d := e.lockUntil.Sub(now); d > 0 {
		return true, d
	}
	if now.Sub(e.lockUntil) > t.cfg.lockout {
		if t.cfg.permaLockCycles > 0 {
			e.fails, e.lockUntil = 0, time.Time{}
		} else {
			delete(t.m, ip)
		}
	}
	return false, 0
}

func (t *throttle) fail(ip string) (lockedNow bool, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.recordFailure(ip), nil
}

// recordFailure increments ip's failure count and, once it reaches
// maxAttempts, starts (or extends) its lock. Caller must hold t.mu.
//
// #62: wasLocked is computed BEFORE this failure's own lockUntil update —
// it's true only when this same key was already inside an active lock
// window (a lock being extended by continued hammering, or a direct fail()
// call reaching an already-locked entry via a caller that doesn't gate on
// checkLocked first — TOTP/passkey failure recording does this). cycles
// increments only on the false case: a fresh violation against a key that
// was NOT already locked, whether because it's brand new or because a
// previous lock fully ran out and was reset (see checkLocked). That is
// deliberately the definition of "one lockout cycle" here — extending an
// already-active lock by continuing to hammer it is not a new cycle, only
// coming back after a lock actually ran its course and violating again is.
func (t *throttle) recordFailure(ip string) (lockedNow bool) {
	e := t.m[ip]
	if e == nil {
		e = &entry{}
		t.m[ip] = e
	}
	if e.permanent {
		return true
	}
	wasLocked := e.lockUntil.After(time.Now())
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
		if !wasLocked {
			e.cycles++
			if t.cfg.permaLockCycles > 0 && e.cycles >= t.cfg.permaLockCycles {
				e.permanent = true
				e.lockUntil = time.Now().Add(permanentLockRetryAfter)
			}
		}
		if t.path != "" {
			_ = t.persistLocked(t.path) // durable lockout; best-effort
		}
		return true
	}
	return false
}

func (t *throttle) reserve(ip string) (allowed bool, retryAfter time.Duration, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if locked, d := t.checkLocked(ip, time.Now()); locked {
		return false, d, nil
	}
	t.recordFailure(ip)
	return true, 0, nil
}

func (t *throttle) pruneLocked(now time.Time) {
	for key, e := range t.m {
		if e.permanent {
			continue // #62: only reset() (admin unlock) may clear this
		}
		if e.lockUntil.IsZero() {
			continue // counting entry — no lock timestamp to expire
		}
		if !e.lockUntil.After(now) && now.Sub(e.lockUntil) > t.cfg.lockout {
			// #62: same reset-not-delete choice as checkLocked's own expiry
			// branch, and for the same reason — deleting here would lose
			// cycle history on a sweep-triggered prune just as surely as on
			// checkLocked's own per-request one.
			if t.cfg.permaLockCycles > 0 {
				e.fails, e.lockUntil = 0, time.Time{}
			} else {
				delete(t.m, key)
			}
		}
	}
	for key, e := range t.m {
		if len(t.m) <= 4096 {
			break
		}
		if e.permanent || (!e.lockUntil.IsZero() && e.lockUntil.After(now)) {
			// never evict an entry serving an active lock — random
			// eviction here would let an attacker (or noisy scanner
			// traffic) clear their own or someone else's lockout early
			// simply by pushing the map past the eviction threshold.
			continue
		}
		delete(t.m, key)
	}
}

func (t *throttle) reset(ip string) {
	t.mu.Lock()
	delete(t.m, ip)
	t.mu.Unlock()
}
