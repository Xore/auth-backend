package main

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
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

// redisProxy forwards connections to the real Redis and can be cut to
// simulate a mid-operation outage.
type redisProxy struct {
	ln    net.Listener
	done  chan struct{}
	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

func startRedisProxy(t *testing.T, target string) *redisProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	p := &redisProxy{ln: ln, done: make(chan struct{}), conns: map[net.Conn]struct{}{}}
	go func() {
		defer close(p.done)
		for {
			client, err := ln.Accept()
			if err != nil {
				return
			}
			p.mu.Lock()
			p.conns[client] = struct{}{}
			p.mu.Unlock()
			go func() {
				defer func() { _ = client.Close() }()
				defer func() {
					p.mu.Lock()
					delete(p.conns, client)
					p.mu.Unlock()
				}()
				upstream, err := net.DialTimeout("tcp", target, 2*time.Second)
				if err != nil {
					return
				}
				defer func() { _ = upstream.Close() }()
				half := make(chan struct{})
				go func() {
					_, _ = io.Copy(upstream, client)
					close(half)
				}()
				_, _ = io.Copy(client, upstream)
				<-half
			}()
		}
	}()
	return p
}

// cut closes the listener and every live proxied connection: pooled client
// connections die too, so every subsequent backend operation fails.
func (p *redisProxy) cut() {
	_ = p.ln.Close()
	<-p.done
	p.mu.Lock()
	for c := range p.conns {
		_ = c.Close()
	}
	p.mu.Unlock()
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
			if _, err := rb.fail(key); err != nil {
				t.Errorf("fail: %v", err)
			}
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
	// the counter always carries a TTL — no partial state from the script
	if ttl := rb.rdb.TTL(ctx, throttleFailKey(key)).Val(); ttl <= 0 {
		t.Fatalf("failure counter has no TTL: %v", ttl)
	}
	locked, remaining, err := rb.locked(key)
	if err != nil || !locked || remaining <= 0 {
		t.Fatalf("concurrent failures did not produce a live lock: locked=%v remaining=%v err=%v", locked, remaining, err)
	}
}

func TestRedisIntegrationSessionExpiryAndRevocation(t *testing.T) {
	cfg := config{maxAttempts: 3, lockout: time.Minute, ttl: 150 * time.Millisecond}
	rb := realRedisBackend(t, cfg)

	if err := rb.touch("expiring", "alice", "192.0.2.1", "integration-test"); err != nil {
		t.Fatalf("touch: %v", err)
	}
	if la, _ := rb.lastActive("expiring"); la.IsZero() {
		t.Fatal("session was not written")
	}
	time.Sleep(250 * time.Millisecond)
	if la, _ := rb.lastActive("expiring"); !la.IsZero() {
		t.Fatal("session survived beyond its Redis TTL")
	}

	if err := rb.touch("revoked", "alice", "192.0.2.1", "integration-test"); err != nil {
		t.Fatalf("touch: %v", err)
	}
	if err := rb.revoke("revoked"); err != nil {
		t.Fatalf("revoke session: %v", err)
	}
	if revoked, _ := rb.isRevoked("revoked"); !revoked {
		t.Fatal("revocation marker was not written")
	}
	if la, _ := rb.lastActive("revoked"); !la.IsZero() {
		t.Fatal("revoked live session was not removed")
	}
	// the revocation marker expires with the session TTL, like the memory
	// registry's "durable for maxTTL" revocation
	ctx, cancel := rb.op()
	defer cancel()
	if pttl := rb.rdb.PTTL(ctx, revokedKey("revoked")).Val(); pttl <= 0 || pttl > cfg.ttl {
		t.Fatalf("revocation marker TTL out of range: %v", pttl)
	}
	time.Sleep(250 * time.Millisecond)
	if revoked, _ := rb.isRevoked("revoked"); revoked {
		t.Fatal("revocation marker survived beyond its TTL")
	}
}

// A mid-operation Redis outage must surface errors — never safe-looking
// zero values — and the session gate must fail closed.
func TestRedisIntegrationOutageFailsClosed(t *testing.T) {
	cfg := testConfig(t)
	cfg.idleTimeout = time.Hour
	rawURL := os.Getenv("REDIS_TEST_URL")
	if rawURL == "" {
		t.Skip("REDIS_TEST_URL is not set")
	}
	opt, err := redis.ParseURL(rawURL)
	if err != nil {
		t.Fatalf("parse REDIS_TEST_URL: %v", err)
	}
	proxy := startRedisProxy(t, opt.Addr)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	rb, err := newRedisBackends("redis://"+proxy.ln.Addr().String(), cfg, log)
	if err != nil {
		t.Fatalf("connect via proxy: %v", err)
	}
	t.Cleanup(func() { _ = rb.rdb.Close() })

	// sanity: everything works through the proxy
	if err := rb.touch("sid-outage", "alice", "192.0.2.1", "integration-test"); err != nil {
		t.Fatalf("touch through proxy: %v", err)
	}

	proxy.cut()

	if _, _, err := rb.locked("192.0.2.1"); err == nil {
		t.Fatal("locked() collapsed an outage into 'not locked'")
	}
	if _, err := rb.fail("192.0.2.1"); err == nil {
		t.Fatal("fail() collapsed an outage into 'no lock'")
	}
	if _, err := rb.isRevoked("sid-outage"); err == nil {
		t.Fatal("isRevoked() collapsed an outage into 'not revoked'")
	}
	if _, err := rb.lastActive("sid-outage"); err == nil {
		t.Fatal("lastActive() collapsed an outage into 'no idle data'")
	}
	if err := rb.touch("sid-outage", "alice", "192.0.2.1", "integration-test"); err == nil {
		t.Fatal("touch() silently dropped the activity record during an outage")
	}

	// a perfectly valid session cookie must be rejected while the registry
	// cannot be verified
	path := t.TempDir() + "/users.json"
	st := newUserStore(path)
	if _, err := st.bootstrap("alice", "a-long-test-password", ""); err != nil {
		t.Fatal(err)
	}
	s := &server{cfg: cfg, users: st, reg: rb, tr: rb,
		aud: newAuditor("", 10), log: log, ntf: newNotifier("", "raw", slog.Default())}
	u := st.get("alice")
	cl := sessionClaims{user: u.Username, gen: u.Gen, sid: "sid-outage", exp: time.Now().Add(time.Hour).Unix()}
	r := httptest.NewRequest("GET", "http://auth/_auth/verify", nil)
	r.AddCookie(&http.Cookie{Name: cfg.cookieName, Value: mustIssuePASETO(t, cfg, cl)})
	if _, _, ok := s.session(httptest.NewRecorder(), r); ok {
		t.Fatal("session accepted while Redis was down — fail-open authorization")
	}
}
