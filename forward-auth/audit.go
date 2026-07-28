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
	// Tamper-evidence chain (present when the auditor was given a key):
	// Seq increments per entry, Prev is the previous entry's MAC, and MAC
	// is HMAC-SHA256(key, seq|prev|time|event|ip|user|ua|host). Deleting
	// or editing any line breaks the chain (verifyAuditLines).
	Seq  int    `json:"seq,omitempty"`
	Prev string `json:"prev,omitempty"`
	MAC  string `json:"mac,omitempty"`
}

// auditMAC computes the chain MAC for an event. Keep in sync with
// verifyAuditLines.
func auditMAC(key []byte, e authEvent) string {
	body := strings.Join([]string{
		fmt.Sprint(e.Seq), e.Prev, e.Time.UTC().Format(time.RFC3339Nano),
		e.Event, e.IP, e.User, e.UA, e.Host,
	}, "|")
	return macWith(key, body)
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

	// chain state for the signed audit log (empty key = unsigned)
	key     []byte
	seq     int
	lastMAC string
}

// newAuditor opens the audit ring and optional JSONL file. When a key is
// supplied (main passes COOKIE_SECRET), every recorded event is chained and
// signed; if the file already ends with a chained entry, the chain resumes
// from it so a restart does not break tamper evidence.
func newAuditor(path string, capacity int, keys ...[]byte) *auditor {
	a := &auditor{capacity: capacity, failByIP: map[string]int{}}
	if len(keys) > 0 {
		a.key = keys[0]
	}
	if path != "" {
		if f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640); err == nil {
			a.file = f
			if len(a.key) > 0 {
				a.resumeChain(path)
			}
		}
	}
	return a
}

// resumeChain reads the last line of an existing audit file and adopts its
// seq/MAC so the chain continues across restarts.
func (a *auditor) resumeChain(path string) {
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 {
		return
	}
	const tail = 64 << 10
	if len(raw) > tail {
		raw = raw[len(raw)-tail:]
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	var last authEvent
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &last); err != nil {
		return // tail corrupt or unsigned — start a fresh chain
	}
	if last.MAC != "" && last.MAC == auditMAC(a.key, last) {
		a.seq, a.lastMAC = last.Seq, last.MAC
	}
}

// verifyAuditLines checks a sequence of audit lines (as read from the JSONL
// file) for chain integrity: strictly increasing Seq, linked Prev values,
// and valid MACs. Unsigned lines fail — a stripped signature is tampering.
func verifyAuditLines(lines []string, key []byte) error {
	prev := ""
	prevSeq := 0
	for i, line := range lines {
		var e authEvent
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return fmt.Errorf("line %d: unparseable: %w", i+1, err)
		}
		if e.MAC == "" || e.MAC != auditMAC(key, e) {
			return fmt.Errorf("line %d: bad MAC", i+1)
		}
		if e.Prev != prev || e.Seq != prevSeq+1 {
			return fmt.Errorf("line %d: chain broken (seq %d, prev %q)", i+1, e.Seq, e.Prev)
		}
		prev, prevSeq = e.MAC, e.Seq
	}
	return nil
}

func (a *auditor) record(e authEvent) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if len(a.key) > 0 {
		a.seq++
		e.Seq = a.seq
		e.Prev = a.lastMAC
		e.MAC = auditMAC(a.key, e)
		a.lastMAC = e.MAC
	}

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

	recent := make([]authEvent, 0, min(n, len(a.ring)))
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
