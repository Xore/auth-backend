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
// Error policy: FAIL CLOSED. A Redis error is returned to the caller as a
// non-nil error meaning "backend unavailable" — never collapsed into a
// safe-looking zero value. locked() erroring produces a controlled 503 at
// the login/TOTP/passkey endpoints (brute-force protection is not silently
// disabled); isRevoked()/lastActive() erroring rejects the session (a
// revoked or idle-unverifiable session is never accepted during an outage).
// list()/snapshot()/forUser() are admin-panel conveniences and return what
// they can (nil on error). Every call runs under its own 2-second context
// timeout.
//
// Multi-command transitions (throttle increment+lock, session touch,
// revocation) run as Lua scripts so they are atomic: a crash or failover
// mid-operation cannot leave a counter incremented without its TTL, a
// session without expiry, or a revocation marker without the session drop.
//
// All key enumeration uses SCAN, never KEYS.

import (
	"context"
	"fmt"
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

// failScript atomically increments the failure counter, refreshes its TTL
// and, once the count reaches maxAttempts, (re)sets the lock key with
// exponential backoff. Returns the lock duration in ms, or 0 when no lock
// was triggered. KEYS: 1=failKey 2=lockKey. ARGV: 1=failTTL seconds
// 2=maxAttempts 3=lockout ms 4=maxLock ms.
var failScript = redis.NewScript(`
local n = redis.call('INCR', KEYS[1])
redis.call('EXPIRE', KEYS[1], ARGV[1])
local maxAttempts = tonumber(ARGV[2])
if n < maxAttempts then
	return 0
end
local over = math.min(n - maxAttempts, 10)
local d = tonumber(ARGV[3]) * (2 ^ over)
local maxLock = tonumber(ARGV[4])
if d > maxLock then
	d = maxLock
end
redis.call('SET', KEYS[2], n, 'PX', d)
return d
`)

// reserveScript atomically checks the lock and, if not locked, performs the
// same increment+lock transition as failScript — collapsing the check
// (locked) and the increment (fail) that callers used to issue as two
// separate round trips on either side of an expensive credential check.
// Doing them separately let a burst of concurrent requests each observe
// "not locked" before any of them recorded a failure. KEYS: 1=failKey
// 2=lockKey. ARGV: 1=failTTL seconds 2=maxAttempts 3=lockout ms 4=maxLock
// ms. Returns {allowed 0/1, retryAfterMs}.
var reserveScript = redis.NewScript(`
local ttl = redis.call('PTTL', KEYS[2])
if ttl > 0 then
	return {0, ttl}
end
local n = redis.call('INCR', KEYS[1])
redis.call('EXPIRE', KEYS[1], ARGV[1])
local maxAttempts = tonumber(ARGV[2])
if n < maxAttempts then
	return {1, 0}
end
local over = math.min(n - maxAttempts, 10)
local d = tonumber(ARGV[3]) * (2 ^ over)
local maxLock = tonumber(ARGV[4])
if d > maxLock then
	d = maxLock
end
redis.call('SET', KEYS[2], n, 'PX', d)
return {1, 0}
`)

// touchScript atomically creates-or-refreshes a session entry and its TTL:
// "created" survives via HSETNX, ip/last_seen always refresh, user/ua are
// only written for a new entry. KEYS: 1=sessionKey. ARGV: 1=now
// 2=ip 3=user 4=ua 5=TTL milliseconds.
var touchScript = redis.NewScript(`
local isNew = redis.call('HSETNX', KEYS[1], 'created', ARGV[1])
redis.call('HSET', KEYS[1], 'ip', ARGV[2], 'last_seen', ARGV[1])
if isNew == 1 then
	redis.call('HSET', KEYS[1], 'user', ARGV[3], 'ua', ARGV[4])
end
redis.call('PEXPIRE', KEYS[1], ARGV[5])
return isNew
`)

// revokeScript atomically writes the revocation marker (PX = ttl) and drops
// the live session entry. KEYS: 1=revokedKey 2=sessionKey. ARGV: 1=now
// 2=TTL ms.
var revokeScript = redis.NewScript(`
redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
redis.call('DEL', KEYS[2])
return 1
`)

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
// the memory throttle). A Redis error is returned, not collapsed: callers
// answer 503 rather than letting attempts through unthrottled.
func (rb *redisBackends) locked(key string) (bool, time.Duration, error) {
	ctx, cancel := rb.op()
	defer cancel()
	d, err := rb.rdb.PTTL(ctx, throttleLockKey(key)).Result()
	if err != nil {
		rb.log.Warn("redis locked() failed", "key", sanitizeLogField(key), "error", err)
		return false, 0, err
	}
	if d <= 0 { // missing (-2) or expired (-1)
		return false, 0, nil
	}
	return true, d, nil
}

// fail increments the failure counter and, once it reaches maxAttempts,
// sets the lock key with exponential backoff (lockout * 2^min(over, 10),
// capped at 24h). It returns true when a lock was (re)triggered. The whole
// increment + TTL refresh + lock transition is one Lua script, so a partial
// application is impossible.
func (rb *redisBackends) fail(key string) (lockedNow bool, err error) {
	ctx, cancel := rb.op()
	defer cancel()
	d, err := failScript.Run(ctx, rb.rdb,
		[]string{throttleFailKey(key), throttleLockKey(key)},
		int(redisFailKeyTTL.Seconds()), rb.cfg.maxAttempts,
		rb.cfg.lockout.Milliseconds(), redisMaxLockDur.Milliseconds()).Int64()
	if err != nil {
		rb.log.Warn("redis fail() failed", "key", sanitizeLogField(key), "error", err)
		return false, err
	}
	return d > 0, nil
}

// reserve atomically checks whether key is locked and, if not, provisionally
// records this attempt as a failure before the caller's (slow) credential
// check runs — see reserveScript. Callers must call reset(key) on success to
// undo the provisional increment.
func (rb *redisBackends) reserve(key string) (allowed bool, retryAfter time.Duration, err error) {
	ctx, cancel := rb.op()
	defer cancel()
	res, err := reserveScript.Run(ctx, rb.rdb,
		[]string{throttleFailKey(key), throttleLockKey(key)},
		int(redisFailKeyTTL.Seconds()), rb.cfg.maxAttempts,
		rb.cfg.lockout.Milliseconds(), redisMaxLockDur.Milliseconds()).Result()
	if err != nil {
		rb.log.Warn("redis reserve() failed", "key", sanitizeLogField(key), "error", err)
		return false, 0, err
	}
	arr, ok := res.([]interface{})
	if !ok || len(arr) != 2 {
		return false, 0, fmt.Errorf("redis: unexpected reserve script result %T(%v)", res, res)
	}
	allowedN, _ := arr[0].(int64)
	retryMs, _ := arr[1].(int64)
	return allowedN == 1, time.Duration(retryMs) * time.Millisecond, nil
}

// reset deletes all throttle state for key (counter and lock) — a single
// DEL command, already atomic.
func (rb *redisBackends) reset(key string) {
	ctx, cancel := rb.op()
	defer cancel()
	if err := rb.rdb.Del(ctx, throttleFailKey(key), throttleLockKey(key)).Err(); err != nil {
		rb.log.Warn("redis reset() failed", "key", sanitizeLogField(key), "error", err)
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
// (created survives via HSETNX). The entry TTL is refreshed to cfg.ttl.
// One Lua script — a session can never be left without an expiry.
func (rb *redisBackends) touch(sid, user, ip, ua string) error {
	if sid == "" {
		return nil
	}
	ctx, cancel := rb.op()
	defer cancel()
	now := time.Now().Format(time.RFC3339Nano)
	err := touchScript.Run(ctx, rb.rdb, []string{sessionKey(sid)},
		now, ip, user, ua, rb.cfg.ttl.Milliseconds()).Err()
	if err != nil {
		rb.log.Warn("redis touch() failed", "sid", sid, "error", err)
		return err
	}
	return nil
}

// revoke durably marks sid revoked for cfg.ttl and drops the live entry in
// one Lua script, so the marker and the drop cannot be separated by a
// failure. Errors are returned — an admin revoking a session must see the
// failure, not a false success.
func (rb *redisBackends) revoke(sid string) error {
	ctx, cancel := rb.op()
	defer cancel()
	err := revokeScript.Run(ctx, rb.rdb,
		[]string{revokedKey(sid), sessionKey(sid)},
		time.Now().Format(time.RFC3339Nano), rb.cfg.ttl.Milliseconds()).Err()
	if err != nil {
		rb.log.Warn("redis revoke() failed", "sid", sanitizeLogField(sid), "error", err)
		return err
	}
	return nil
}

// isRevoked reports whether sid is on the revocation list. Fail CLOSED: a
// Redis error is returned so the caller rejects the session — a session
// whose revocation state cannot be verified is never accepted.
func (rb *redisBackends) isRevoked(sid string) (bool, error) {
	ctx, cancel := rb.op()
	defer cancel()
	n, err := rb.rdb.Exists(ctx, revokedKey(sid)).Result()
	if err != nil {
		rb.log.Warn("redis isRevoked() failed", "sid", sid, "error", err)
		return false, err
	}
	return n > 0, nil
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

// lastActive returns when sid was last seen. A missing entry is the zero
// time with a nil error ("no idle data", matching the memory registry); a
// Redis error is a non-nil error so idle enforcement fails closed instead
// of being silently skipped.
func (rb *redisBackends) lastActive(sid string) (time.Time, error) {
	ctx, cancel := rb.op()
	defer cancel()
	raw, err := rb.rdb.HGet(ctx, sessionKey(sid), "last_seen").Result()
	if err == redis.Nil {
		return time.Time{}, nil
	}
	if err != nil {
		rb.log.Warn("redis lastActive() failed", "sid", sid, "error", err)
		return time.Time{}, err
	}
	t, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, nil
	}
	return t, nil
}
