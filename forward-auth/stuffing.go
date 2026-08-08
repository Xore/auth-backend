package main

import (
	"sync"
	"time"
)

// stuffing.go — #68: detect distributed/low-and-slow credential stuffing.
//
// throttle.go's per-IP and per-username lockouts are the right primary
// defense, but structurally blind to an attack that stays under both
// thresholds at once: many distinct source IPs, many distinct usernames,
// each individual (IP, username) pair never crossing MAX_ATTEMPTS. This is
// a known class of gap in per-entity rate limiting generally, not specific
// to this project. stuffingDetector tracks a global sliding window of
// recent failed-login usernames and fires a webhook alert (feeding the
// existing notifier, not a second alerting mechanism) once both the total
// failure count and the distinct-username count in that window cross their
// configured thresholds.

// stuffingEvent is one failed-login attempt kept only long enough to fall
// out of the sliding window.
type stuffingEvent struct {
	at   time.Time
	user string
}

// stuffingMaxTracked bounds the window regardless of configured size or
// attack rate — a sustained real attack could otherwise grow this slice
// without limit within a single window.
const stuffingMaxTracked = 20000

// stuffingDetector is a global (not per-key) sliding-window counter.
// failThreshold<=0 disables it entirely (record always reports no alert) —
// the default, matching every other opt-in hardening control in this
// codebase. now is replaceable so tests can drive the clock instead of
// sleeping, the same pattern rateLimiter (recover.go) already uses.
type stuffingDetector struct {
	mu            sync.Mutex
	window        time.Duration
	cooldown      time.Duration
	failThreshold int
	userThreshold int
	events        []stuffingEvent
	lastAlert     time.Time
	now           func() time.Time
}

func newStuffingDetector(window, cooldown time.Duration, failThreshold, userThreshold int) *stuffingDetector {
	return &stuffingDetector{window: window, cooldown: cooldown, failThreshold: failThreshold, userThreshold: userThreshold}
}

// record adds one failed-login event for user and reports whether an alert
// should fire now. Alerts are themselves rate-limited to at most once per
// cooldown — without this, a sustained attack that keeps the window full
// would re-alert on every single subsequent failure, defeating the point of
// an alert (a thing to act on) by turning it into noise.
func (d *stuffingDetector) record(user string) (alert bool, totalFails, distinctUsers int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.failThreshold <= 0 {
		return false, 0, 0
	}
	now := time.Now()
	if d.now != nil {
		now = d.now()
	}

	d.events = append(d.events, stuffingEvent{at: now, user: user})
	cutoff := now.Add(-d.window)
	live := d.events[:0]
	for _, e := range d.events {
		if e.at.After(cutoff) {
			live = append(live, e)
		}
	}
	d.events = live
	if len(d.events) > stuffingMaxTracked {
		d.events = d.events[len(d.events)-stuffingMaxTracked:]
	}

	users := map[string]struct{}{}
	for _, e := range d.events {
		users[e.user] = struct{}{}
	}
	totalFails, distinctUsers = len(d.events), len(users)

	if totalFails < d.failThreshold || distinctUsers < d.userThreshold {
		return false, totalFails, distinctUsers
	}
	if !d.lastAlert.IsZero() && now.Sub(d.lastAlert) < d.cooldown {
		return false, totalFails, distinctUsers
	}
	d.lastAlert = now
	return true, totalFails, distinctUsers
}
