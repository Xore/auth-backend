package main

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"
)

// realRedisBackend connects to the disposable Redis service supplied by CI.
// The test is skipped during ordinary local runs.
func realRedisBackend(t *testing.T, cfg config) *redisBackends {
	t.Helper()
	rawURL := os.Getenv("REDIS_TEST_URL")
	if rawURL == "" {
		t.Skip("REDIS_TEST_URL is not set")
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	rb, err := newRedisBackends(rawURL, cfg, log)
	if err != nil {
		t.Fatalf("connect to real Redis: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := rb.op()
		defer cancel()
		keys, err := rb.scanKeys(ctx, redisKeyPrefix+"*")
		if err == nil && len(keys) > 0 {
			_ = rb.rdb.Del(ctx, keys...).Err()
		}
		_ = rb.rdb.Close()
	})
	return rb
}

func TestRedisIntegrationConcurrentThrottle(t *testing.T) {
	const failures = 64
	cfg := config{maxAttempts: 10, lockout: time.Minute, ttl: time.Hour}
	rb := realRedisBackend(t, cfg)
	key := fmt.Sprintf("integration:%d", time.Now().UnixNano())

	var wg sync.WaitGroup
	wg.Add(failures)
	for range failures {
		go func() {
			defer wg.Done()
			rb.fail(key)
		}()
	}
	wg.Wait()

	ctx, cancel := rb.op()
	defer cancel()
	got, err := rb.rdb.Get(ctx, throttleFailKey(key)).Int()
	if err != nil {
		t.Fatalf("read failure counter: %v", err)
	}
	if got != failures {
		t.Fatalf("failure counter = %d, want %d", got, failures)
	}
	if locked, remaining := rb.locked(key); !locked || remaining <= 0 {
		t.Fatalf("concurrent failures did not produce a live lock: locked=%v remaining=%v", locked, remaining)
	}
}

func TestRedisIntegrationSessionExpiryAndRevocation(t *testing.T) {
	cfg := config{maxAttempts: 3, lockout: time.Minute, ttl: 150 * time.Millisecond}
	rb := realRedisBackend(t, cfg)

	rb.touch("expiring", "alice", "192.0.2.1", "integration-test")
	if rb.lastActive("expiring").IsZero() {
		t.Fatal("session was not written")
	}
	time.Sleep(250 * time.Millisecond)
	if !rb.lastActive("expiring").IsZero() {
		t.Fatal("session survived beyond its Redis TTL")
	}

	rb.touch("revoked", "alice", "192.0.2.1", "integration-test")
	if err := rb.revoke("revoked"); err != nil {
		t.Fatalf("revoke session: %v", err)
	}
	if !rb.isRevoked("revoked") {
		t.Fatal("revocation marker was not written")
	}
	if !rb.lastActive("revoked").IsZero() {
		t.Fatal("revoked live session was not removed")
	}
}
