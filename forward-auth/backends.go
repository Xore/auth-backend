package main

// backends.go — selection and construction of the throttle and session
// backends: in-memory + JSON file persistence by default; Redis when
// REDIS_URL is set (roadmap Step 23).

import (
	"log/slog"
	"path/filepath"
)

// openBackends builds the throttle and session backends for cfg. Redis
// failures are fatal to the caller — silently dropping brute-force
// protection is worse than refusing to start. throttlePath is the JSON
// persistence path for the in-memory throttle (used again at shutdown).
func openBackends(cfg config, log *slog.Logger, throttlePath string) (ThrottleBackend, SessionBackend) {
	if cfg.redisURL != "" {
		rb, err := newRedisBackends(cfg.redisURL, cfg, log)
		if err != nil {
			// fail hard: silently dropping brute-force protection is worse
			log.Error("cannot connect to Redis", "error", err)
			return nil, nil
		}
		log.Info("using Redis throttle + session backends")
		return rb, rb
	}
	th := newThrottle(cfg)
	if err := th.load(throttlePath); err != nil {
		// losing lockout state on a corrupt file beats refusing to start
		log.Error("cannot load throttle state — starting fresh", "path", throttlePath, "error", err)
	}
	sr := newSessionRegistry(cfg.ttl, filepath.Join(filepath.Dir(cfg.usersFile), "revoked-sessions.json"))
	if err := sr.load(); err != nil {
		log.Error("cannot load session revocations", "error", err)
		return nil, nil
	}
	return th, sr
}
