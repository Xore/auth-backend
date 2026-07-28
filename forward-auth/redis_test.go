package main

// redis_test.go — tests for the Redis throttle/session backends against
// miniredis, so no real Redis server is needed.

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
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

	if locked, _ := rb.fail(ip); locked {
		t.Fatal("fail 1 should not lock")
	}
	if ok, _, _ := rb.locked(ip); ok {
		t.Fatal("should not be locked after 1 fail")
	}
	if locked, _ := rb.fail(ip); locked {
		t.Fatal("fail 2 should not lock")
	}
	if ok, _, _ := rb.locked(ip); ok {
		t.Fatal("should not be locked after 2 fails")
	}
	if locked, _ := rb.fail(ip); !locked {
		t.Fatal("fail 3 (maxAttempts) should trigger lock")
	}
	ok, d, _ := rb.locked(ip)
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
		_, _ = rb.fail(ip)
	}
	if ok, _, _ := rb.locked(ip); !ok {
		t.Fatal("expected lock")
	}
	rb.reset(ip)
	if ok, _, _ := rb.locked(ip); ok {
		t.Fatal("reset should clear the lock")
	}
	// Counter must be gone too — the next fail is the first of a new run.
	if locked, _ := rb.fail(ip); locked {
		t.Fatal("counter should restart after reset")
	}
}

// Lock state lives in Redis, so a fresh backend instance (as after a
// process restart) must still see it.
func TestRedisThrottleSurvivesRestart(t *testing.T) {
	mr, rb := newTestRedis(t)
	ip := "10.0.0.3"

	for i := 0; i < 3; i++ {
		_, _ = rb.fail(ip)
	}
	if ok, _, _ := rb.locked(ip); !ok {
		t.Fatal("expected lock on first backend")
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := config{maxAttempts: 3, lockout: time.Minute, ttl: time.Hour}
	rb2, err := newRedisBackends("redis://"+mr.Addr(), cfg, log)
	if err != nil {
		t.Fatalf("second newRedisBackends: %v", err)
	}
	defer func() { _ = rb2.rdb.Close() }()

	ok, d, _ := rb2.locked(ip)
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
		_, _ = rb.fail("10.0.0.4")
	}
	for i := 0; i < 5; i++ {
		_, _ = rb.fail("user:bob")
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
		_, _ = rb.fail("10.0.1.1")
	}
	for i := 0; i < 6; i++ {
		_, _ = rb.fail("10.0.1.2")
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

	_ = rb.touch("sid1", "alice", "192.168.1.1", "agent-a")
	_ = rb.touch("sid2", "alice", "192.168.1.2", "agent-b")
	_ = rb.touch("sid3", "bob", "192.168.1.3", "agent-c")

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
	if la, _ := rb.lastActive("sid1"); la.IsZero() {
		t.Fatal("lastActive(sid1) should be set")
	}
	if la, _ := rb.lastActive("nosuch"); !la.IsZero() {
		t.Fatal("lastActive(unknown) should be zero time")
	}
}

func TestRedisSessionsCreatedStableLastSeenAdvances(t *testing.T) {
	_, rb := newTestRedis(t)

	_ = rb.touch("sid1", "alice", "192.168.1.1", "agent-a")
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
	_ = rb.touch("sid1", "alice", "192.168.1.9", "agent-a") // IP changes, user same

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

	_ = rb.touch("sid1", "alice", "192.168.1.1", "agent-a")
	if revoked, _ := rb.isRevoked("sid1"); revoked {
		t.Fatal("should not be revoked before revoke()")
	}
	if err := rb.revoke("sid1"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if revoked, _ := rb.isRevoked("sid1"); !revoked {
		t.Fatal("should be revoked after revoke()")
	}
	if n := rb.active(); n != 0 {
		t.Fatalf("active = %d, want 0 (live entry dropped)", n)
	}
	if lst := rb.list(); len(lst) != 0 {
		t.Fatalf("list len = %d, want 0", len(lst))
	}
	if la, _ := rb.lastActive("sid1"); !la.IsZero() {
		t.Fatal("lastActive should be zero after revoke")
	}
}

func TestRedisSessionsEmptySIDIgnored(t *testing.T) {
	_, rb := newTestRedis(t)
	_ = rb.touch("", "alice", "192.168.1.1", "agent-a")
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

// newClosedRedis returns a backend whose server has gone away, simulating
// a mid-operation outage.
func newClosedRedis(t *testing.T) *redisBackends {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run: %v", err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := config{maxAttempts: 3, lockout: time.Minute, ttl: time.Hour}
	rb, err := newRedisBackends("redis://"+mr.Addr(), cfg, log)
	if err != nil {
		t.Fatalf("newRedisBackends: %v", err)
	}
	t.Cleanup(func() { _ = rb.rdb.Close() })
	if err := rb.touch("sid", "alice", "192.168.1.1", "agent-a"); err != nil {
		t.Fatalf("touch before outage: %v", err)
	}
	mr.Close() // the outage
	return rb
}

// An outage must surface as an error from every security-relevant read and
// write — never as a safe-looking zero/false value.
func TestRedisOutageReturnsErrors(t *testing.T) {
	rb := newClosedRedis(t)

	if locked, _, err := rb.locked("10.0.0.1"); err == nil || locked {
		t.Fatalf("locked() during outage = (%v, %v), want (false, error)", locked, err)
	}
	if locked, err := rb.fail("10.0.0.1"); err == nil || locked {
		t.Fatalf("fail() during outage = (%v, %v), want (false, error)", locked, err)
	}
	if revoked, err := rb.isRevoked("sid"); err == nil || revoked {
		t.Fatalf("isRevoked() during outage = (%v, %v), want (false, error)", revoked, err)
	}
	if last, err := rb.lastActive("sid"); err == nil || !last.IsZero() {
		t.Fatalf("lastActive() during outage = (%v, %v), want (zero, error)", last, err)
	}
	if err := rb.touch("sid", "alice", "192.168.1.1", "agent-a"); err == nil {
		t.Fatal("touch() during outage silently dropped the activity record")
	}
	if err := rb.revoke("sid"); err == nil {
		t.Fatal("revoke() during outage reported success")
	}
}

// Concurrent failures during an outage: every caller gets an error, nothing
// panics, nothing races (run with -race).
func TestRedisOutageConcurrentFailures(t *testing.T) {
	rb := newClosedRedis(t)
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				_, err := rb.fail("10.9.9.9")
				errs <- err
			} else {
				_, _, err := rb.locked("10.9.9.9")
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err == nil {
			t.Fatal("an operation succeeded during the outage")
		}
	}
}

// The fail Lua script applies counter + TTL + lock atomically: after the
// lock triggers, the counter exists WITH a TTL and the lock key holds the
// count. No partial state.
func TestRedisThrottleFailIsAtomic(t *testing.T) {
	mr, rb := newTestRedis(t)
	ip := "10.0.0.20"
	for i := 0; i < 3; i++ {
		if _, err := rb.fail(ip); err != nil {
			t.Fatalf("fail: %v", err)
		}
	}
	if got, _ := mr.Get(throttleFailKey(ip)); got != "3" {
		t.Fatalf("counter = %q, want 3", got)
	}
	if ttl := mr.TTL(throttleFailKey(ip)); ttl != redisFailKeyTTL {
		t.Fatalf("counter TTL = %v, want %v", ttl, redisFailKeyTTL)
	}
	if got, _ := mr.Get(throttleLockKey(ip)); got != "3" {
		t.Fatalf("lock value = %q, want 3", got)
	}
	if ttl := mr.TTL(throttleLockKey(ip)); ttl <= 0 || ttl > time.Minute {
		t.Fatalf("lock TTL out of range: %v", ttl)
	}
}

// The touch Lua script applies fields + TTL atomically, and created
// survives later touches.
func TestRedisSessionTouchIsAtomic(t *testing.T) {
	mr, rb := newTestRedis(t)
	if err := rb.touch("sidA", "alice", "192.168.1.1", "agent-a"); err != nil {
		t.Fatalf("touch: %v", err)
	}
	key := sessionKey("sidA")
	if ttl := mr.TTL(key); ttl != time.Hour {
		t.Fatalf("session TTL = %v, want %v", ttl, time.Hour)
	}
	created := mr.HGet(key, "created")
	if created == "" {
		t.Fatal("created not set on first touch")
	}
	mr.FastForward(time.Second)
	if err := rb.touch("sidA", "mallory", "192.168.1.2", "agent-b"); err != nil {
		t.Fatalf("second touch: %v", err)
	}
	if got := mr.HGet(key, "created"); got != created {
		t.Fatal("created changed on second touch")
	}
	if got := mr.HGet(key, "user"); got != "alice" {
		t.Fatalf("user changed on second touch: %q", got)
	}
	if got := mr.HGet(key, "ip"); got != "192.168.1.2" {
		t.Fatalf("ip not refreshed: %q", got)
	}
	if ttl := mr.TTL(key); ttl != time.Hour {
		t.Fatalf("TTL not refreshed: %v", ttl)
	}
}

// The revoke Lua script writes the marker and drops the live entry
// atomically; both expire with cfg.ttl.
func TestRedisRevokeIsAtomicAndExpires(t *testing.T) {
	mr, rb := newTestRedis(t)
	if err := rb.touch("sidR", "alice", "192.168.1.1", "agent-a"); err != nil {
		t.Fatalf("touch: %v", err)
	}
	if err := rb.revoke("sidR"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if mr.Exists(sessionKey("sidR")) {
		t.Fatal("live session survived revoke")
	}
	if !mr.Exists(revokedKey("sidR")) {
		t.Fatal("revocation marker missing")
	}
	if ttl := mr.TTL(revokedKey("sidR")); ttl != time.Hour {
		t.Fatalf("revocation TTL = %v, want %v", ttl, time.Hour)
	}
	mr.FastForward(2 * time.Hour)
	if revoked, _ := rb.isRevoked("sidR"); revoked {
		t.Fatal("revocation marker survived past cfg.ttl")
	}
	if last, _ := rb.lastActive("sidR"); !last.IsZero() {
		t.Fatal("session survived past cfg.ttl")
	}
}

// Session gate and login throttle fail closed while Redis is down: a valid
// session cookie is rejected and the login POST answers a controlled 503
// instead of running unthrottled.
func TestRedisOutageServerFailsClosed(t *testing.T) {
	rb := newClosedRedis(t)
	c := testConfig(t)
	c.idleTimeout = time.Hour
	path := filepath.Join(t.TempDir(), "users.json")
	st := newUserStore(path)
	if _, err := st.bootstrap("alice", "a-long-test-password", ""); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := &server{cfg: c, users: st, reg: rb, tr: rb, aud: newAuditor("", 10),
		log: log, ntf: newNotifier("", "raw", slog.Default())}

	u := st.get("alice")
	cl := sessionClaims{user: u.Username, gen: u.Gen, sid: "sid", exp: time.Now().Add(time.Hour).Unix()}
	r := httptest.NewRequest("GET", "http://auth/_auth/verify", nil)
	r.AddCookie(&http.Cookie{Name: c.cookieName, Value: mustIssuePASETO(t, c, cl)})
	if _, _, ok := s.session(httptest.NewRecorder(), r); ok {
		t.Fatal("session accepted while Redis was down — fail-open authorization")
	}

	f := url.Values{}
	f.Set("ft", c.issueForm())
	f.Set("username", "alice")
	f.Set("password", "a-long-test-password")
	lr := httptest.NewRequest("POST", "http://auth/_auth/login", strings.NewReader(f.Encode()))
	lr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.login(w, lr)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("login during outage = %d, want 503", w.Code)
	}
}
