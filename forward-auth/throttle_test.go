package main

// throttle_test.go — brute-force throttle atomicity and eviction safety.

import (
	"sync"
	"testing"
	"time"
)

// Concurrent reservations must never let more than maxAttempts callers
// through before the lock takes effect: reserve() has to combine the
// locked-check and the failure-increment into one atomic step, or a burst
// of concurrent requests can each observe "not locked" before any of them
// is counted (the exact race in #37).
func TestThrottleReserveIsAtomicUnderConcurrency(t *testing.T) {
	cfg := config{maxAttempts: 5, lockout: time.Minute}
	tr := newThrottle(cfg)

	const burst = 50
	var wg sync.WaitGroup
	var mu sync.Mutex
	allowed := 0
	wg.Add(burst)
	for i := 0; i < burst; i++ {
		go func() {
			defer wg.Done()
			if ok, _, err := tr.reserve("203.0.113.1"); err != nil {
				t.Errorf("reserve: %v", err)
			} else if ok {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	// Every reservation that arrives before the lock takes effect still
	// gets to "proceed" (matching the pre-existing fail() semantics where
	// the crossing attempt itself is allowed), but reserve() must have
	// locked the entry no later than the maxAttempts-th call, so the
	// number of goroutines that ever observed allowed=true is bounded —
	// not the full burst of 50 the old check-then-act code would have let
	// through.
	if allowed > cfg.maxAttempts {
		t.Fatalf("allowed = %d concurrent reservations, want <= maxAttempts (%d)", allowed, cfg.maxAttempts)
	}
	if locked, _, _ := tr.locked("203.0.113.1"); !locked {
		t.Fatal("entry should be locked after a burst exceeding maxAttempts")
	}
}

// reserve() must still reject once already locked, without incrementing
// further.
func TestThrottleReserveRejectsWhileLocked(t *testing.T) {
	cfg := config{maxAttempts: 2, lockout: time.Minute}
	tr := newThrottle(cfg)

	if ok, _, err := tr.reserve("203.0.113.5"); err != nil || !ok {
		t.Fatalf("reserve 1: ok=%v err=%v", ok, err)
	}
	if ok, _, err := tr.reserve("203.0.113.5"); err != nil || !ok {
		t.Fatalf("reserve 2 (crosses maxAttempts): ok=%v err=%v", ok, err)
	}
	ok, d, err := tr.reserve("203.0.113.5")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("reserve should reject once locked")
	}
	if d <= 0 {
		t.Fatal("locked reserve should report a positive retry-after")
	}
}

// reset() must fully undo a reservation, matching the "correct password"
// path in login().
func TestThrottleResetUndoesReservation(t *testing.T) {
	cfg := config{maxAttempts: 1, lockout: time.Minute}
	tr := newThrottle(cfg)

	if ok, _, err := tr.reserve("203.0.113.9"); err != nil || !ok {
		t.Fatalf("reserve: ok=%v err=%v", ok, err)
	}
	if locked, _, _ := tr.locked("203.0.113.9"); !locked {
		t.Fatal("single-attempt config should lock after one reservation")
	}
	tr.reset("203.0.113.9")
	if locked, _, _ := tr.locked("203.0.113.9"); locked {
		t.Fatal("reset should clear the lock set by the reservation")
	}
}

// pruneLocked's eviction pass must never remove an entry with an active
// lock — doing so lets an attacker (or unrelated traffic filling the map)
// clear their own or someone else's lockout early, simply by pushing the
// map past the eviction threshold (#48).
func TestThrottlePruneNeverEvictsActiveLock(t *testing.T) {
	cfg := config{maxAttempts: 5, lockout: time.Minute}
	tr := newThrottle(cfg)
	now := time.Now()

	tr.mu.Lock()
	tr.m["locked-victim"] = &entry{fails: 5, lockUntil: now.Add(10 * time.Minute)}
	for i := 0; i < 8192; i++ {
		tr.m[string(rune(i))+"-filler"] = &entry{fails: 1}
	}
	tr.mu.Unlock()

	tr.mu.Lock()
	tr.pruneLocked(now)
	_, stillLocked := tr.m["locked-victim"]
	tr.mu.Unlock()

	if !stillLocked {
		t.Fatal("pruneLocked evicted an entry with an active lock")
	}
}
