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

// #62: with permaLockCycles disabled (the zero value, matching every
// existing deployment that has never set PERMANENT_LOCKOUT_AFTER_CYCLES),
// an expired lock must still be deleted outright, exactly as before this
// feature existed -- not silently kept-but-idle. This pins that "off means
// truly unchanged" contract directly.
func TestThrottleExpiredLockDeletedWhenPermanentDisabled(t *testing.T) {
	cfg := config{maxAttempts: 1, lockout: time.Minute} // permaLockCycles: 0
	tr := newThrottle(cfg)
	now := time.Now()

	tr.mu.Lock()
	tr.m["203.0.113.1"] = &entry{fails: 1, lockUntil: now.Add(-2 * time.Minute)} // expired well past the grace period
	tr.mu.Unlock()

	tr.mu.Lock()
	locked, _ := tr.checkLocked("203.0.113.1", now)
	_, stillPresent := tr.m["203.0.113.1"]
	tr.mu.Unlock()

	if locked {
		t.Fatal("expired lock reported as still locked")
	}
	if stillPresent {
		t.Fatal("expired lock entry was kept instead of deleted (permaLockCycles is disabled -- behavior must be unchanged)")
	}
}

// #62's actual point: a key that gets locked, waits out the lock (or is
// swept by pruneLocked), and gets locked again — repeated enough times —
// escalates to permanent, which checkLocked and pruneLocked must both then
// refuse to ever clear on their own.
func TestThrottleEscalatesToPermanentAfterRepeatedCycles(t *testing.T) {
	cfg := config{maxAttempts: 1, lockout: time.Minute, permaLockCycles: 3}
	tr := newThrottle(cfg)

	simulateCycle := func() {
		tr.mu.Lock()
		tr.recordFailure("203.0.113.7")
		tr.mu.Unlock()
		// Simulate waiting out the lock: checkLocked's own expiry branch is
		// what resets fails/lockUntil (since permaLockCycles > 0) rather
		// than deleting the entry -- push lockUntil far enough into the
		// past that both the "is it still locked" and "has its grace period
		// also elapsed" checks fire in the same call.
		tr.mu.Lock()
		tr.m["203.0.113.7"].lockUntil = time.Now().Add(-2 * cfg.lockout)
		tr.mu.Unlock()
		tr.mu.Lock()
		tr.checkLocked("203.0.113.7", time.Now())
		tr.mu.Unlock()
	}

	simulateCycle() // cycle 1
	simulateCycle() // cycle 2
	tr.mu.Lock()
	if tr.m["203.0.113.7"].permanent {
		t.Fatal("escalated to permanent after only 2 of 3 configured cycles")
	}
	tr.mu.Unlock()

	simulateCycle() // cycle 3 -- crosses the threshold
	tr.mu.Lock()
	e := tr.m["203.0.113.7"]
	tr.mu.Unlock()
	if !e.permanent {
		t.Fatalf("did not escalate to permanent after %d cycles (threshold %d): %+v", e.cycles, cfg.permaLockCycles, e)
	}

	// A permanent lock must report locked with the sentinel duration...
	locked, d := tr.checkLocked("203.0.113.7", time.Now())
	if !locked || d != permanentLockRetryAfter {
		t.Fatalf("permanent lock checkLocked = (%v, %v), want (true, %v)", locked, d, permanentLockRetryAfter)
	}
	// ...and must never clear via pruneLocked, no matter how far in the future.
	tr.mu.Lock()
	tr.pruneLocked(time.Now().Add(permanentLockRetryAfter))
	_, stillPresent := tr.m["203.0.113.7"]
	tr.mu.Unlock()
	if !stillPresent {
		t.Fatal("pruneLocked cleared a permanent lock")
	}

	// Only an explicit reset (the existing admin "unlock" action) clears it.
	tr.reset("203.0.113.7")
	if locked, _, _ := tr.locked("203.0.113.7"); locked {
		t.Fatal("reset() did not clear a permanent lock")
	}
}

// Continuing to hammer an already-locked key (extending the same lock, or
// a fail() call reaching an already-locked entry via a caller that doesn't
// gate on checkLocked first) must not itself count as new cycles -- only
// genuinely coming back after a lock fully expired should.
func TestThrottleExtendingAnActiveLockDoesNotCountAsANewCycle(t *testing.T) {
	cfg := config{maxAttempts: 1, lockout: time.Minute, permaLockCycles: 2}
	tr := newThrottle(cfg)

	tr.mu.Lock()
	tr.recordFailure("203.0.113.9") // cycle 1
	for i := 0; i < 20; i++ {
		tr.recordFailure("203.0.113.9") // still inside the same active lock window every time
	}
	e := tr.m["203.0.113.9"]
	tr.mu.Unlock()

	if e.permanent {
		t.Fatal("repeatedly hammering the same still-active lock escalated to permanent -- only a genuinely new cycle should count")
	}
	if e.cycles != 1 {
		t.Fatalf("cycles = %d, want 1 (one lock, extended 20 times, is still one cycle)", e.cycles)
	}
}

// A permanent lock (and the cycle count that produced it) must survive a
// restart -- otherwise an attacker who's been escalated to permanent could
// simply wait for the next deploy/restart to get a clean slate, defeating
// the entire point of "only an admin can clear this."
func TestThrottlePersistRoundTripPreservesPermanentLock(t *testing.T) {
	cfg := config{maxAttempts: 5, lockout: time.Minute, permaLockCycles: 3}
	path := t.TempDir() + "/throttle.json"
	tr := newThrottle(cfg)
	if err := tr.load(path); err != nil {
		t.Fatal(err)
	}
	tr.mu.Lock()
	tr.m["203.0.113.42"] = &entry{fails: 5, lockUntil: time.Now().Add(permanentLockRetryAfter), cycles: 3, permanent: true}
	tr.mu.Unlock()
	if err := tr.persist(path); err != nil {
		t.Fatal(err)
	}

	tr2 := newThrottle(cfg)
	if err := tr2.load(path); err != nil {
		t.Fatal(err)
	}
	if locked, d, _ := tr2.locked("203.0.113.42"); !locked || d != permanentLockRetryAfter {
		t.Fatalf("permanent lock did not survive restart: locked=%v d=%v", locked, d)
	}
	tr2.mu.Lock()
	cycles := tr2.m["203.0.113.42"].cycles
	tr2.mu.Unlock()
	if cycles != 3 {
		t.Fatalf("cycles = %d after restart, want 3", cycles)
	}
}

func TestLockoutMessageDistinguishesPermanentFromTimedOut(t *testing.T) {
	if got := lockoutMessage(5 * time.Minute); got != "Too many attempts. Try again in 5m0s." {
		t.Fatalf("timed message = %q", got)
	}
	if got := lockoutMessage(permanentLockRetryAfter); got != "Access from this address is blocked. Contact an administrator." {
		t.Fatalf("permanent message = %q", got)
	}
}
