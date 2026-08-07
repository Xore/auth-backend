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
//
// Fields are netstring-encoded ("<len>:<content>,") rather than joined with a
// plain "|" separator: several fields (User, UA, Host) are request-derived
// and may themselves contain "|", which would otherwise let two different
// field assignments collapse to the same signed byte string (e.g. moving a
// "|" from Event into IP). Length-prefixing each field makes the encoding
// injective — there is exactly one way to decompose the signed body into the
// original fields — so no redistribution of content across a field boundary
// can preserve the MAC.
func auditMAC(key []byte, e authEvent) string {
	fields := []string{
		fmt.Sprint(e.Seq), e.Prev, e.Time.UTC().Format(time.RFC3339Nano),
		e.Event, e.IP, e.User, e.UA, e.Host,
	}
	var body strings.Builder
	for _, f := range fields {
		fmt.Fprintf(&body, "%d:%s,", len(f), f)
	}
	return macWith(key, body.String())
}

// auditMACValid reports whether e.MAC matches auditMAC under any of the
// given keys, newest first. Multiple keys let verification span a
// COOKIE_SECRET rotation: entries written before the rotation were signed
// with the previous key and remain verifiable as long as that key is still
// supplied (main passes it via COOKIE_SECRET_PREVIOUS).
func auditMACValid(keys [][]byte, e authEvent) bool {
	if e.MAC == "" {
		return false
	}
	for _, k := range keys {
		if e.MAC == auditMAC(k, e) {
			return true
		}
	}
	return false
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
	key      []byte
	prevKeys [][]byte
	seq      int
	lastMAC  string
}

// newAuditor opens the audit ring and optional JSONL file. The first key
// (main passes COOKIE_SECRET) signs every newly recorded event; any further
// keys (COOKIE_SECRET_PREVIOUS) are accepted only when verifying entries
// already on disk, so a key rotation doesn't strand the pre-rotation tail.
// If the file already ends with a chained entry, the chain resumes from it
// so a restart does not break tamper evidence.
func newAuditor(path string, capacity int, keys ...[]byte) *auditor {
	a := &auditor{capacity: capacity, failByIP: map[string]int{}}
	if len(keys) > 0 {
		a.key = keys[0]
		a.prevKeys = keys[1:]
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

// resumeChain verifies the entire existing audit file (not just its last
// line) before trusting it, then adopts the last entry's seq/MAC so the
// chain continues across restarts. A file that fails verification is never
// silently accepted: it's reported loudly and a fresh chain is started, so
// tampering anywhere in the file — not only in the final line — is visible
// to whoever operates this service instead of vanishing into a passing
// resumeChain call that nobody was checking.
func (a *auditor) resumeChain(path string) {
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 {
		return
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	keys := append([][]byte{a.key}, a.prevKeys...)
	if err := verifyAuditLines(lines, keys); err != nil {
		fmt.Fprintf(os.Stderr,
			"audit: EXISTING LOG AT %s FAILED INTEGRITY VERIFICATION (%v) — starting a new chain from seq 1; "+
				"investigate before trusting entries prior to this restart\n", path, err)
		return
	}
	var last authEvent
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &last); err != nil {
		return
	}
	a.seq, a.lastMAC = last.Seq, last.MAC
}

// verifyAuditLines checks a sequence of audit lines (as read from the JSONL
// file) for chain integrity: strictly increasing Seq, linked Prev values,
// and a MAC valid under at least one of the given keys. Unsigned lines fail
// — a stripped signature is tampering. Accepting any key in keys (rather
// than a single fixed key) lets a chain that spans a COOKIE_SECRET rotation
// still verify: entries before the rotation validate under the previous
// key, entries after it validate under the current one.
func verifyAuditLines(lines []string, keys [][]byte) error {
	prev := ""
	prevSeq := 0
	for i, line := range lines {
		var e authEvent
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return fmt.Errorf("line %d: unparseable: %w", i+1, err)
		}
		if !auditMACValid(keys, e) {
			return fmt.Errorf("line %d: bad MAC", i+1)
		}
		if e.Prev != prev || e.Seq != prevSeq+1 {
			return fmt.Errorf("line %d: chain broken (seq %d, prev %q)", i+1, e.Seq, e.Prev)
		}
		prev, prevSeq = e.MAC, e.Seq
	}
	return nil
}

// Close releases the audit log file handle, if one is open. Safe to call on
// an auditor with no file backing (e.g. AUDIT_LOG unset, or in tests that
// never open one).
func (a *auditor) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.file == nil {
		return nil
	}
	err := a.file.Close()
	a.file = nil
	return err
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
