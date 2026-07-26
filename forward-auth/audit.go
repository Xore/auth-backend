package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type authEvent struct {
	Time  time.Time `json:"time"`
	Event string    `json:"event"`
	IP    string    `json:"ip"`
	User  string    `json:"user,omitempty"`
	UA    string    `json:"ua,omitempty"`
	Host  string    `json:"host,omitempty"`
}

type auditor struct {
	mu       sync.Mutex
	ring     []authEvent
	capacity int
	file     *os.File
	total    int
	success  int
	failed   int
	failByIP map[string]int
}

func newAuditor(path string, capacity int) *auditor {
	a := &auditor{capacity: capacity, failByIP: map[string]int{}}
	if path != "" {
		if f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640); err == nil {
			a.file = f
		}
	}
	return a
}

func (a *auditor) record(e authEvent) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.total++
	switch {
	case e.Event == "login_ok", e.Event == "passkey_login_ok":
		a.success++
	case strings.HasPrefix(e.Event, "login_fail"), e.Event == "locked_out":
		a.failed++
		if e.IP != "" {
			a.failByIP[e.IP]++
		}
	}

	// Bound failByIP: internet scanners hit a public login page from
	// thousands of IPs, and this map would otherwise grow forever. Evict
	// one-hit entries first (noise); the repeat offenders survive.
	if len(a.failByIP) > 4096 {
		for ip, n := range a.failByIP {
			if n <= 1 {
				delete(a.failByIP, ip)
			}
			if len(a.failByIP) <= 2048 {
				break
			}
		}
		for ip := range a.failByIP {
			if len(a.failByIP) <= 2048 {
				break
			}
			delete(a.failByIP, ip)
		}
	}

	a.ring = append(a.ring, e)
	if len(a.ring) > a.capacity {
		a.ring = a.ring[len(a.ring)-a.capacity:]
	}
	if a.file != nil {
		if line, err := json.Marshal(e); err == nil {
			if _, err := a.file.Write(append(line, '\n')); err != nil {
				fmt.Fprintf(os.Stderr, "audit: write failed: %v\n", err)
			}
		}
	}
}

type ipCount struct {
	IP    string
	Count int
}

type auditSnapshot struct {
	Total, Success, Failed int
	Recent                 []authEvent
	TopFail                []ipCount
}

func (a *auditor) snapshot(n int) auditSnapshot {
	a.mu.Lock()
	defer a.mu.Unlock()
	if n < 0 {
		n = 0
	}
	if n > 1000 {
		n = 1000
	}

	recent := make([]authEvent, 0, n)
	for i := len(a.ring) - 1; i >= 0 && len(recent) < n; i-- {
		recent = append(recent, a.ring[i])
	}
	top := make([]ipCount, 0, len(a.failByIP))
	for ip, c := range a.failByIP {
		top = append(top, ipCount{ip, c})
	}
	sort.Slice(top, func(i, j int) bool {
		if top[i].Count != top[j].Count {
			return top[i].Count > top[j].Count
		}
		return top[i].IP < top[j].IP
	})
	if len(top) > n {
		top = top[:n]
	}
	return auditSnapshot{a.total, a.success, a.failed, recent, top}
}

type lockedIP struct {
	IP    string
	Fails int
	Until time.Time
}

func (t *throttle) snapshot() []lockedIP {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	t.pruneLocked(now)
	out := []lockedIP{}
	for ip, e := range t.m {
		if !strings.HasPrefix(ip, "user:") && e.lockUntil.After(now) {
			out = append(out, lockedIP{ip, e.fails, e.lockUntil})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Fails > out[j].Fails })
	return out
}
