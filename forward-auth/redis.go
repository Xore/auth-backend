package main

// redis.go — Redis-backed ThrottleBackend and SessionBackend (roadmap
// Step 23). Activated from main() when REDIS_URL is set; the single
// redisBackends value implements both interfaces.
//
// Key layout (all under the "fa:" prefix):
//
//	fa:thr:fail:<key>   string counter, INCR per failure, 24h TTL refreshed
//	                    on every increment so counters self-clean
//	fa:thr:lock:<key>   string holding the fail count, PX = lock duration;
//	                    key expiry IS the lock expiry
//	fa:sess:<sid>       hash {user, ip, ua, created, last_seen} with
//	                    RFC3339Nano timestamps, TTL = cfg.ttl; "created" is
//	                    written with HSetNX so later touches preserve it
//	fa:revoked:<sid>    string marker, PX = cfg.ttl (matches the memory
//	                    registry's "durable for maxTTL" revocation)
//
// <key> in the throttle keys is opaque: bare client IPs and "user:<name>"
// strings both appear and are never parsed, only suffixed.
//
// Error policy: every Redis error is logged via the passed logger and
// treated as fail-OPEN — locked() reports unlocked, fail() reports no new
// lock, isRevoked() reports not revoked — so a Redis blip cannot DoS the
// login portal for everyone. The one exception is revoke(): it returns the
// error so an admin revoking a session sees the failure instead of a false
// success. list()/forUser() return what they can (nil on error). Every
// call runs under its own 2-second context timeout.
//
// All key enumeration uses SCAN, never KEYS.

import (
	"context"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	redisOpTimeout     = 2 * time.Second
	redisDialTimeout   = 3 * time.Second
	redisFailKeyTTL    = 24 * time.Hour
	redisMaxLockDur    = 24 * time.Hour
	redisKeyPrefix     = "fa:"
	redisUserKeyPrefix = "user:"
)

type redisBackends struct {
	rdb *redis.Client
	cfg config
	log *slog.Logger
}

var (
	_ ThrottleBackend = (*redisBackends)(nil)
	_ SessionBackend  = (*redisBackends)(nil)
)

// newRedisBackends parses rawURL, dials Redis and verifies connectivity
// with a PING under a 3-second timeout. Any failure is returned to the
// caller (main exits — silently dropping brute-force protection is worse).
func newRedisBackends(rawURL string, cfg config, log *slog.Logger) (*redisBackends, error) {
	opt, err := redis.ParseURL(rawURL)
	if err != nil {
		return nil, err
	}
	rdb := redis.NewClient(opt)
	ctx, cancel := context.WithTimeout(context.Background(), redisDialTimeout)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		_ = rdb.Close()
		return nil, err
	}
	return &redisBackends{rdb: rdb, cfg: cfg, log: log}, nil
}

// op returns a fresh context with the per-call timeout.
func (rb *redisBackends) op() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), redisOpTimeout)
}

func throttleFailKey(key string) string { return redisKeyPrefix + "thr:fail:" + key }
func throttleLockKey(key string) string { return redisKeyPrefix + "thr:lock:" + key }
func sessionKey(sid string) string      { return redisKeyPrefix + "sess:" + sid }
func revokedKey(sid string) string      { return redisKeyPrefix + "revoked:" + sid }

// scanKeys enumerates keys matching pattern with SCAN (never KEYS).
func (rb *redisBackends) scanKeys(ctx context.Context, pattern string) ([]string, error) {
	var keys []string
	iter := rb.rdb.Scan(ctx, 0, pattern, 200).Iterator()
	for iter.Next(ctx) {
		keys = append(keys, iter.Val())
	}
	return keys, iter.Err()
}

// --- ThrottleBackend --------------------------------------------------------

// locked reports whether key is currently locked and, if so, the remaining
// lock duration. The fail counter is never touched here — a lookup must not
// reset or expire accumulating failures (the zero-lockUntil regression in
// the memory throttle).
func (rb *redisBackends) locked(key string) (bool, time.Duration) {
	ctx, cancel := rb.op()
	defer cancel()
	d, err := rb.rdb.PTTL(ctx, throttleLockKey(key)).Result()
	if err != nil {
		rb.log.Warn("redis locked() failed — fail-open", "key", key, "error", err)
		return false, 0
	}
	if d <= 0 { // missing (-2) or expired (-1)
		return false, 0
	}
	return true, d
}

// fail increments the failure counter and, once it reaches maxAttempts,
// sets the lock key with exponential backoff (lockout * 2^min(over, 10),
// capped at 24h). It returns true when a lock was (re)triggered.
func (rb *redisBackends) fail(key string) (lockedNow bool) {
	ctx, cancel := rb.op()
	defer cancel()
	n, err := rb.rdb.Incr(ctx, throttleFailKey(key)).Result()
	if err != nil {
		rb.log.Warn("redis fail() incr failed — fail-open", "key", key, "error", err)
		return false
	}
	// Refresh the counter TTL after each increment so idle counters
	// self-clean but active attackers keep accumulating.
	if err := rb.rdb.Expire(ctx, throttleFailKey(key), redisFailKeyTTL).Err(); err != nil {
		rb.log.Warn("redis fail() expire failed", "key", key, "error", err)
	}
	if int(n) < rb.cfg.maxAttempts {
		return false
	}
	mult := time.Duration(1) << uint(min(int(n)-rb.cfg.maxAttempts, 10))
	d := rb.cfg.lockout * mult
	if d > redisMaxLockDur {
		d = redisMaxLockDur
	}
	if err := rb.rdb.Set(ctx, throttleLockKey(key), n, d).Err(); err != nil {
		rb.log.Warn("redis fail() lock set failed — fail-open", "key", key, "error", err)
		return false
	}
	return true
}

// reset deletes all throttle state for key (counter and lock).
func (rb *redisBackends) reset(key string) {
	ctx, cancel := rb.op()
	defer cancel()
	if err := rb.rdb.Del(ctx, throttleFailKey(key), throttleLockKey(key)).Err(); err != nil {
		rb.log.Warn("redis reset() failed", "key", key, "error", err)
	}
}

// snapshot lists currently-locked entries, excluding "user:" keys, sorted
// by fail count descending — same shape as the memory throttle's snapshot.
func (rb *redisBackends) snapshot() []lockedIP {
	ctx, cancel := rb.op()
	defer cancel()
	keys, err := rb.scanKeys(ctx, throttleLockKey("*"))
	if err != nil {
		rb.log.Warn("redis snapshot() scan failed", "error", err)
		return nil
	}
	now := time.Now()
	out := make([]lockedIP, 0, len(keys))
	for _, k := range keys {
		suffix := strings.TrimPrefix(k, redisKeyPrefix+"thr:lock:")
		if strings.HasPrefix(suffix, redisUserKeyPrefix) {
			continue
		}
		d, err := rb.rdb.PTTL(ctx, k).Result()
		if err != nil || d <= 0 {
			continue // expired between SCAN and PTTL, or a transient error
		}
		fails, _ := rb.rdb.Get(ctx, k).Int()
		out = append(out, lockedIP{IP: suffix, Fails: fails, Until: now.Add(d)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Fails > out[j].Fails })
	return out
}

// --- SessionBackend ---------------------------------------------------------

// touch records activity for sid: on first sight the entry is created with
// user/ua/created set; afterwards only ip and last_seen are refreshed
// (created survives via HSetNX). The entry TTL is refreshed to cfg.ttl.
func (rb *redisBackends) touch(sid, user, ip, ua string) {
	if sid == "" {
		return
	}
	ctx, cancel := rb.op()
	defer cancel()
	key := sessionKey(sid)
	now := time.Now().Format(time.RFC3339Nano)
	isNew, err := rb.rdb.HSetNX(ctx, key, "created", now).Result()
	if err != nil {
		rb.log.Warn("redis touch() failed", "sid", sid, "error", err)
		return
	}
	fields := []any{"ip", ip, "last_seen", now}
	if isNew {
		fields = append(fields, "user", user, "ua", ua)
	}
	if err := rb.rdb.HSet(ctx, key, fields...).Err(); err != nil {
		rb.log.Warn("redis touch() hset failed", "sid", sid, "error", err)
		return
	}
	if err := rb.rdb.Expire(ctx, key, rb.cfg.ttl).Err(); err != nil {
		rb.log.Warn("redis touch() expire failed", "sid", sid, "error", err)
	}
}

// revoke durably marks sid revoked for cfg.ttl and drops the live entry.
// Unlike the other methods this returns Redis errors — an admin revoking a
// session must see the failure, not a false success.
func (rb *redisBackends) revoke(sid string) error {
	ctx, cancel := rb.op()
	defer cancel()
	if err := rb.rdb.Set(ctx, revokedKey(sid), time.Now().Format(time.RFC3339Nano), rb.cfg.ttl).Err(); err != nil {
		rb.log.Warn("redis revoke() failed", "sid", sid, "error", err)
		return err
	}
	if err := rb.rdb.Del(ctx, sessionKey(sid)).Err(); err != nil {
		rb.log.Warn("redis revoke() session drop failed", "sid", sid, "error", err)
		return err
	}
	return nil
}

// isRevoked reports whether sid is on the revocation list. Fail-open: a
// Redis error reports "not revoked" so the portal stays up.
func (rb *redisBackends) isRevoked(sid string) bool {
	ctx, cancel := rb.op()
	defer cancel()
	n, err := rb.rdb.Exists(ctx, revokedKey(sid)).Result()
	if err != nil {
		rb.log.Warn("redis isRevoked() failed — fail-open", "sid", sid, "error", err)
		return false
	}
	return n > 0
}

// readSession loads one session hash; ok is false when the entry is gone or
// unreadable. Malformed timestamps parse as the zero time.
func (rb *redisBackends) readSession(ctx context.Context, key string) (s sessionInfo, ok bool) {
	m, err := rb.rdb.HGetAll(ctx, key).Result()
	if err != nil || len(m) == 0 {
		return sessionInfo{}, false
	}
	s = sessionInfo{
		SID:  strings.TrimPrefix(key, redisKeyPrefix+"sess:"),
		User: m["user"],
		IP:   m["ip"],
		UA:   m["ua"],
	}
	s.Created, _ = time.Parse(time.RFC3339Nano, m["created"])
	s.LastSeen, _ = time.Parse(time.RFC3339Nano, m["last_seen"])
	return s, true
}

// list returns all live sessions sorted by LastSeen descending.
func (rb *redisBackends) list() []sessionInfo {
	ctx, cancel := rb.op()
	defer cancel()
	keys, err := rb.scanKeys(ctx, sessionKey("*"))
	if err != nil {
		rb.log.Warn("redis list() scan failed", "error", err)
		return nil
	}
	out := make([]sessionInfo, 0, len(keys))
	for _, k := range keys {
		if s, ok := rb.readSession(ctx, k); ok {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out
}

// active counts live session entries.
func (rb *redisBackends) active() int {
	ctx, cancel := rb.op()
	defer cancel()
	keys, err := rb.scanKeys(ctx, sessionKey("*"))
	if err != nil {
		rb.log.Warn("redis active() scan failed", "error", err)
		return 0
	}
	return len(keys)
}

// forUser returns the live sessions belonging to username.
func (rb *redisBackends) forUser(username string) []sessionInfo {
	ctx, cancel := rb.op()
	defer cancel()
	keys, err := rb.scanKeys(ctx, sessionKey("*"))
	if err != nil {
		rb.log.Warn("redis forUser() scan failed", "error", err)
		return nil
	}
	var out []sessionInfo
	for _, k := range keys {
		if s, ok := rb.readSession(ctx, k); ok && s.User == username {
			out = append(out, s)
		}
	}
	return out
}

// lastActive returns when sid was last seen, or the zero time when unknown
// (caller treats that as "no idle data", matching the memory registry).
func (rb *redisBackends) lastActive(sid string) time.Time {
	ctx, cancel := rb.op()
	defer cancel()
	raw, err := rb.rdb.HGet(ctx, sessionKey(sid), "last_seen").Result()
	if err != nil {
		if err != redis.Nil {
			rb.log.Warn("redis lastActive() failed", "sid", sid, "error", err)
		}
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}
	}
	return t
}
