package main

import (
	"io"
	"log/slog"
	"net/http/httptest"
	"testing"
	"time"
)

func TestStuffingDetectorDisabledByZeroThreshold(t *testing.T) {
	d := newStuffingDetector(time.Minute, time.Minute, 0, 1) // failThreshold=0
	for i := 0; i < 1000; i++ {
		if alert, _, _ := d.record("user"); alert {
			t.Fatal("disabled detector (failThreshold=0) fired an alert")
		}
	}
}

// The actual point of #68: many failures against many DISTINCT usernames
// must fire, but the same volume of failures concentrated on ONE username
// must not -- that pattern is exactly what per-username throttling already
// catches, and re-alerting on it here would just be noise on top of the
// lockout that's already happening.
func TestStuffingDetectorRequiresBothFailuresAndDistinctUsers(t *testing.T) {
	now := time.Now()
	d := newStuffingDetector(10*time.Minute, 15*time.Minute, 20, 5)
	d.now = func() time.Time { return now }

	// 20 failures, all against the same single user: total-fails threshold
	// is met, but distinct-users is not.
	var lastAlert bool
	for i := 0; i < 20; i++ {
		lastAlert, _, _ = d.record("victim")
	}
	if lastAlert {
		t.Fatal("20 failures against one username alerted -- distinct-user threshold should have blocked this")
	}
}

func TestStuffingDetectorFiresOnceThresholdsBothCross(t *testing.T) {
	now := time.Now()
	d := newStuffingDetector(10*time.Minute, 15*time.Minute, 10, 5)
	d.now = func() time.Time { return now }

	users := []string{"alice", "bob", "carol", "dave", "erin"}
	fired := false
	var fails, distinct int
	for i := 0; i < 10; i++ {
		var alert bool
		alert, fails, distinct = d.record(users[i%len(users)])
		if alert {
			fired = true
		}
	}
	if !fired {
		t.Fatal("10 failures across 5 distinct usernames never fired an alert")
	}
	if fails != 10 || distinct != 5 {
		t.Fatalf("fails=%d distinct=%d, want 10 and 5", fails, distinct)
	}
}

// Once fired, a sustained attack that keeps feeding the detector must not
// re-fire on every subsequent failure -- that would turn a single
// actionable alert into a flood.
func TestStuffingDetectorAlertsAreCooldownRateLimited(t *testing.T) {
	now := time.Now()
	d := newStuffingDetector(10*time.Minute, 15*time.Minute, 5, 2)
	d.now = func() time.Time { return now }

	fireCount := 0
	for i := 0; i < 50; i++ {
		if alert, _, _ := d.record([]string{"alice", "bob"}[i%2]); alert {
			fireCount++
		}
	}
	if fireCount != 1 {
		t.Fatalf("fired %d times across a sustained attack with no time passing, want exactly 1 (cooldown should suppress the rest)", fireCount)
	}

	// After the cooldown elapses, a fresh crossing may alert again -- fires
	// as soon as both thresholds cross a second time (the 5th record here:
	// 5 fails, 2 distinct users), not specifically on any one particular call.
	now = now.Add(16 * time.Minute)
	d.events = nil // sliding window also would have emptied naturally; clear it directly for a clean re-cross
	refired := false
	for i := 0; i < 5; i++ {
		if alert, _, _ := d.record([]string{"alice", "bob"}[i%2]); alert {
			refired = true
		}
	}
	if !refired {
		t.Fatal("did not re-alert after the cooldown elapsed and thresholds crossed again")
	}
}

// Failures that aged out of the window must stop counting toward either
// threshold -- this is a SLIDING window, not a lifetime total.
func TestStuffingDetectorWindowExpiresOldFailures(t *testing.T) {
	now := time.Now()
	d := newStuffingDetector(5*time.Minute, time.Minute, 3, 2)
	d.now = func() time.Time { return now }

	d.record("alice")
	d.record("bob")
	// Advance well past the window; these two failures should no longer count.
	now = now.Add(10 * time.Minute)
	alert, fails, distinct := d.record("carol")
	if fails != 1 || distinct != 1 {
		t.Fatalf("fails=%d distinct=%d after the window expired, want 1 and 1 (only the newest event should remain)", fails, distinct)
	}
	if alert {
		t.Fatal("alerted with only 1 failure in the current window")
	}
}

// #68's audit() wiring must not panic against a bare &server{} literal that
// never set stuffing -- the pattern many existing tests already use.
func TestAuditNilStuffingDoesNotPanic(t *testing.T) {
	s := &server{cfg: testConfig(t), aud: newAuditor("", 10), log: slog.New(slog.NewTextHandler(io.Discard, nil)), ntf: newNotifier("", "raw", slog.Default())}
	r := httptest.NewRequest("POST", "http://auth/_auth/login", nil)
	s.audit("login_fail:bad_credentials", "203.0.113.1", "someone", r)
}

// #69: a fired stuffing alert must land in the durable audit trail, not
// only go out as a transient webhook -- same treatment locked_out already
// gets, and the only way a SIEM ingesting the JSONL audit log (rather than
// subscribing to the webhook stream) ever sees this signal at all.
func TestStuffingAlertIsWrittenToAuditTrail(t *testing.T) {
	c := testConfig(t)
	s := &server{
		cfg: c, aud: newAuditor("", 50), log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		ntf:      newNotifier("", "raw", slog.Default()),
		stuffing: newStuffingDetector(10*time.Minute, 15*time.Minute, 5, 2),
	}
	r := httptest.NewRequest("POST", "http://auth/_auth/login", nil)
	users := []string{"alice", "bob"}
	for i := 0; i < 5; i++ {
		s.audit("login_fail:bad_credentials", "203.0.113.1", users[i%2], r)
	}
	snap := s.aud.snapshot(50)
	found := false
	for _, e := range snap.Recent {
		if e.Event == "credential_stuffing_suspected" {
			found = true
		}
	}
	if !found {
		t.Fatalf("credential_stuffing_suspected not found in audit snapshot: %+v", snap.Recent)
	}
}
