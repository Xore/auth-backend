package main

// redis_test.go — tests for the Redis throttle/session backends against
// miniredis, so no real Redis server is needed.

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

func newTestRedis(t *testing.T) (*miniredis.Miniredis, *redisBackends) {
	t.Helper()
	mr := miniredis.RunT(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := config{maxAttempts: 3, lockout: time.Minute, ttl: time.Hour}
	rb, err := newRedisBackends("redis://"+mr.Addr(), cfg, log)
	if err != nil {
		t.Fatalf("newRedisBackends: %v", err)
	}
	t.Cleanup(func() { _ = rb.rdb.Close() })
	return mr, rb
}

// Counter must accumulate across interleaved locked() calls — mirrors the
// zero-lockUntil regression in the memory throttle, where a lookup deleted
// counting entries and the lockout never triggered.
func TestRedisThrottleCounterAccumulatesAcrossLocked(t *testing.T) {
	_, rb := newTestRedis(t)
	ip := "10.0.0.1"

	if rb.fail(ip) {
		t.Fatal("fail 1 should not lock")
	}
	if ok, _ := rb.locked(ip); ok {
		t.Fatal("should not be locked after 1 fail")
	}
	if rb.fail(ip) {
		t.Fatal("fail 2 should not lock")
	}
	if ok, _ := rb.locked(ip); ok {
		t.Fatal("should not be locked after 2 fails")
	}
	if !rb.fail(ip) {
		t.Fatal("fail 3 (maxAttempts) should trigger lock")
	}
	ok, d := rb.locked(ip)
	if !ok {
		t.Fatal("should be locked after maxAttempts")
	}
	if d <= 0 || d > time.Minute {
		t.Fatalf("remaining lock duration out of range: %v", d)
	}
}

func TestRedisThrottleReset(t *testing.T) {
	_, rb := newTestRedis(t)
	ip := "10.0.0.2"

	for i := 0; i < 3; i++ {
		rb.fail(ip)
	}
	if ok, _ := rb.locked(ip); !ok {
		t.Fatal("expected lock")
	}
	rb.reset(ip)
	if ok, _ := rb.locked(ip); ok {
		t.Fatal("reset should clear the lock")
	}
	// Counter must be gone too — the next fail is the first of a new run.
	if rb.fail(ip) {
		t.Fatal("counter should restart after reset")
	}
}

// Lock state lives in Redis, so a fresh backend instance (as after a
// process restart) must still see it.
func TestRedisThrottleSurvivesRestart(t *testing.T) {
	mr, rb := newTestRedis(t)
	ip := "10.0.0.3"

	for i := 0; i < 3; i++ {
		rb.fail(ip)
	}
	if ok, _ := rb.locked(ip); !ok {
		t.Fatal("expected lock on first backend")
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := config{maxAttempts: 3, lockout: time.Minute, ttl: time.Hour}
	rb2, err := newRedisBackends("redis://"+mr.Addr(), cfg, log)
	if err != nil {
		t.Fatalf("second newRedisBackends: %v", err)
	}
	defer func() { _ = rb2.rdb.Close() }()

	ok, d := rb2.locked(ip)
	if !ok {
		t.Fatal("lock must survive a new backend instance")
	}
	if d <= 0 || d > time.Minute {
		t.Fatalf("remaining lock duration out of range: %v", d)
	}
}

func TestRedisThrottleSnapshotExcludesUserKeys(t *testing.T) {
	_, rb := newTestRedis(t)

	// "user:bob" fails more often than the bare IP, which also checks the
	// fails-desc sort order.
	for i := 0; i < 3; i++ {
		rb.fail("10.0.0.4")
	}
	for i := 0; i < 5; i++ {
		rb.fail("user:bob")
	}

	snap := rb.snapshot()
	if len(snap) != 1 {
		t.Fatalf("snapshot should have exactly 1 entry (user: excluded), got %d: %+v", len(snap), snap)
	}
	if snap[0].IP != "10.0.0.4" {
		t.Fatalf("unexpected snapshot entry: %+v", snap[0])
	}
	if snap[0].Fails != 3 {
		t.Fatalf("fails = %d, want 3", snap[0].Fails)
	}
	if time.Until(snap[0].Until) <= 0 {
		t.Fatal("Until should be in the future")
	}
}

func TestRedisThrottleSnapshotSortedByFailsDesc(t *testing.T) {
	_, rb := newTestRedis(t)

	for i := 0; i < 3; i++ {
		rb.fail("10.0.1.1")
	}
	for i := 0; i < 6; i++ {
		rb.fail("10.0.1.2")
	}

	snap := rb.snapshot()
	if len(snap) != 2 {
		t.Fatalf("snapshot len = %d, want 2", len(snap))
	}
	if snap[0].IP != "10.0.1.2" || snap[1].IP != "10.0.1.1" {
		t.Fatalf("snapshot not sorted by fails desc: %+v", snap)
	}
}

func TestRedisSessionsTouchListForUserLastActive(t *testing.T) {
	_, rb := newTestRedis(t)

	rb.touch("sid1", "alice", "192.168.1.1", "agent-a")
	rb.touch("sid2", "alice", "192.168.1.2", "agent-b")
	rb.touch("sid3", "bob", "192.168.1.3", "agent-c")

	if n := rb.active(); n != 3 {
		t.Fatalf("active = %d, want 3", n)
	}
	lst := rb.list()
	if len(lst) != 3 {
		t.Fatalf("list len = %d, want 3", len(lst))
	}
	for i := 1; i < len(lst); i++ {
		if lst[i-1].LastSeen.Before(lst[i].LastSeen) {
			t.Fatal("list not sorted by LastSeen desc")
		}
	}
	alice := rb.forUser("alice")
	if len(alice) != 2 {
		t.Fatalf("forUser(alice) len = %d, want 2", len(alice))
	}
	if la := rb.lastActive("sid1"); la.IsZero() {
		t.Fatal("lastActive(sid1) should be set")
	}
	if la := rb.lastActive("nosuch"); !la.IsZero() {
		t.Fatal("lastActive(unknown) should be zero time")
	}
}

func TestRedisSessionsCreatedStableLastSeenAdvances(t *testing.T) {
	_, rb := newTestRedis(t)

	rb.touch("sid1", "alice", "192.168.1.1", "agent-a")
	first := rb.list()
	if len(first) != 1 {
		t.Fatalf("list len = %d, want 1", len(first))
	}
	created := first[0].Created
	seen1 := first[0].LastSeen
	if created.IsZero() || seen1.IsZero() {
		t.Fatal("created/last_seen should be set after touch")
	}

	time.Sleep(5 * time.Millisecond)
	rb.touch("sid1", "alice", "192.168.1.9", "agent-a") // IP changes, user same

	second := rb.list()
	if len(second) != 1 {
		t.Fatalf("list len = %d, want 1", len(second))
	}
	if !second[0].Created.Equal(created) {
		t.Fatalf("created changed across touches: %v → %v", created, second[0].Created)
	}
	if !second[0].LastSeen.After(seen1) {
		t.Fatal("last_seen should advance on touch")
	}
	if second[0].IP != "192.168.1.9" {
		t.Fatalf("ip not updated: %q", second[0].IP)
	}
}

func TestRedisSessionsRevoke(t *testing.T) {
	_, rb := newTestRedis(t)

	rb.touch("sid1", "alice", "192.168.1.1", "agent-a")
	if rb.isRevoked("sid1") {
		t.Fatal("should not be revoked before revoke()")
	}
	if err := rb.revoke("sid1"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if !rb.isRevoked("sid1") {
		t.Fatal("should be revoked after revoke()")
	}
	if n := rb.active(); n != 0 {
		t.Fatalf("active = %d, want 0 (live entry dropped)", n)
	}
	if lst := rb.list(); len(lst) != 0 {
		t.Fatalf("list len = %d, want 0", len(lst))
	}
	if la := rb.lastActive("sid1"); !la.IsZero() {
		t.Fatal("lastActive should be zero after revoke")
	}
}

func TestRedisSessionsEmptySIDIgnored(t *testing.T) {
	_, rb := newTestRedis(t)
	rb.touch("", "alice", "192.168.1.1", "agent-a")
	if n := rb.active(); n != 0 {
		t.Fatalf("active = %d, want 0", n)
	}
}

func TestNewRedisBackendsDialFailure(t *testing.T) {
	mr := miniredis.RunT(t)
	addr := mr.Addr()
	mr.Close() // nothing listening anymore

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := config{maxAttempts: 3, lockout: time.Minute, ttl: time.Hour}
	if _, err := newRedisBackends("redis://"+addr, cfg, log); err == nil {
		t.Fatal("expected dial error against closed server")
	}
	if _, err := newRedisBackends("not-a-url", cfg, log); err == nil {
		t.Fatal("expected parse error for bad URL")
	}
}
