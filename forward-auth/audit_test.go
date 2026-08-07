package main

// audit_test.go — signed audit log chain (tamper evidence).

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func readAuditLines(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
}

func TestAuditChainSignsAndVerifies(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	path := filepath.Join(t.TempDir(), "audit.log")
	a := newAuditor(path, 10, key)
	t.Cleanup(func() { _ = a.Close() })
	for i, ev := range []string{"login_ok", "login_fail:bad_credentials", "locked_out"} {
		a.record(authEvent{Time: time.Now(), Event: ev, IP: "192.0.2.1", User: "alice"})
		_ = i
	}
	lines := readAuditLines(t, path)
	if len(lines) != 3 {
		t.Fatalf("lines = %d, want 3", len(lines))
	}
	if err := verifyAuditLines(lines, [][]byte{key}); err != nil {
		t.Fatalf("valid chain rejected: %v", err)
	}
	if err := verifyAuditLines(lines, [][]byte{[]byte("wrong-key-wrong-key-wrong-key!!")}); err == nil {
		t.Fatal("chain verified under the wrong key")
	}
	// ring entries carry the chain fields too (admin UI shows them)
	snap := a.snapshot(1)
	if len(snap.Recent) != 1 || snap.Recent[0].MAC == "" || snap.Recent[0].Seq != 3 {
		t.Fatalf("ring entry not signed: %+v", snap.Recent)
	}
}

func TestAuditChainDetectsTamper(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	path := filepath.Join(t.TempDir(), "audit.log")
	a := newAuditor(path, 10, key)
	t.Cleanup(func() { _ = a.Close() })
	for _, ev := range []string{"login_ok", "admin_disable:bob", "recover_ok", "logout"} {
		a.record(authEvent{Time: time.Now(), Event: ev, IP: "192.0.2.1"})
	}
	lines := readAuditLines(t, path)

	// edit a line (cover up the admin action): MAC must fail
	edited := append([]string(nil), lines...)
	edited[1] = strings.Replace(edited[1], "admin_disable:bob", "login_ok", 1)
	if err := verifyAuditLines(edited, [][]byte{key}); err == nil {
		t.Fatal("edited line not detected")
	}
	// delete a middle line: chain must break
	deleted := append([]string(nil), lines[:1]...)
	deleted = append(deleted, lines[2:]...)
	if err := verifyAuditLines(deleted, [][]byte{key}); err == nil {
		t.Fatal("deleted line not detected")
	}
	// truncate the tail: verifiable, but shorter — the last line's MAC is
	// intact, so tail truncation is detectable only against a known seq.
	if err := verifyAuditLines(lines[:2], [][]byte{key}); err != nil {
		t.Fatalf("prefix of a valid chain should verify: %v", err)
	}
	// strip signatures: rejected as tampering
	unsigned := []string{`{"time":"2026-07-28T00:00:00Z","event":"login_ok","ip":"192.0.2.1"}`}
	if err := verifyAuditLines(unsigned, [][]byte{key}); err == nil {
		t.Fatal("unsigned line accepted")
	}
}

func TestAuditChainResumesAcrossRestart(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	path := filepath.Join(t.TempDir(), "audit.log")
	a1 := newAuditor(path, 10, key)
	a1.record(authEvent{Time: time.Now(), Event: "login_ok", IP: "192.0.2.1"})
	a1.record(authEvent{Time: time.Now(), Event: "logout", IP: "192.0.2.1"})
	_ = a1.Close()

	// simulate a restart: fresh auditor over the same file continues the chain
	a2 := newAuditor(path, 10, key)
	t.Cleanup(func() { _ = a2.Close() })
	a2.record(authEvent{Time: time.Now(), Event: "login_ok", IP: "192.0.2.2"})
	lines := readAuditLines(t, path)
	if len(lines) != 3 {
		t.Fatalf("lines = %d, want 3", len(lines))
	}
	if err := verifyAuditLines(lines, [][]byte{key}); err != nil {
		t.Fatalf("chain broken across restart: %v", err)
	}
}

// A rotated COOKIE_SECRET must not strand the pre-rotation tail: entries
// signed with the outgoing key still verify, and the chain (seq/prev)
// continues unbroken into entries signed with the new key, as long as the
// outgoing key is still supplied as a previous key.
func TestAuditChainSurvivesKeyRotation(t *testing.T) {
	oldKey := []byte("01234567890123456789012345678901")
	newKey := []byte("98765432109876543210987654321098")
	path := filepath.Join(t.TempDir(), "audit.log")

	a1 := newAuditor(path, 10, oldKey)
	a1.record(authEvent{Time: time.Now(), Event: "login_ok", IP: "192.0.2.1"})
	_ = a1.Close()

	// restart with a rotated key, old key retained as "previous"
	a2 := newAuditor(path, 10, newKey, oldKey)
	t.Cleanup(func() { _ = a2.Close() })
	a2.record(authEvent{Time: time.Now(), Event: "login_ok", IP: "192.0.2.2"})

	lines := readAuditLines(t, path)
	if len(lines) != 2 {
		t.Fatalf("lines = %d, want 2", len(lines))
	}
	if err := verifyAuditLines(lines, [][]byte{newKey, oldKey}); err != nil {
		t.Fatalf("chain spanning rotation should verify: %v", err)
	}
	// the second entry must chain onto the first (seq 2, prev = first's MAC),
	// proving resumeChain actually adopted the pre-rotation tail rather than
	// silently starting a fresh chain at seq 1.
	var second authEvent
	if err := json.Unmarshal([]byte(lines[1]), &second); err != nil {
		t.Fatal(err)
	}
	if second.Seq != 2 {
		t.Fatalf("seq = %d, want 2 (chain reset instead of resumed across rotation)", second.Seq)
	}
	// without the retired key, the pre-rotation entry can no longer verify —
	// this is the expected, loud failure mode once the transition window ends.
	if err := verifyAuditLines(lines, [][]byte{newKey}); err == nil {
		t.Fatal("chain verified without the retired key")
	}
}

// The signed body must be unambiguous: moving delimiter-shaped content
// across a field boundary (e.g. from Event into IP) must not produce a
// colliding MAC, even though the old "|"-joined body would have.
func TestAuditMACRejectsFieldBoundaryForgery(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	base := authEvent{Seq: 1, Time: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}

	a := base
	a.Event, a.IP = "login|ok", "192.0.2.1"
	b := base
	b.Event, b.IP = "login", "ok|192.0.2.1"

	if auditMAC(key, a) == auditMAC(key, b) {
		t.Fatal("MAC collided across a field boundary — forgery is possible without the key")
	}
}

// An auditor without a key behaves exactly as before (unsigned entries).
func TestAuditUnsignedWithoutKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	a := newAuditor(path, 10)
	t.Cleanup(func() { _ = a.Close() })
	a.record(authEvent{Time: time.Now(), Event: "login_ok", IP: "192.0.2.1"})
	lines := readAuditLines(t, path)
	if strings.Contains(lines[0], "mac") {
		t.Fatalf("unsigned auditor wrote chain fields: %s", lines[0])
	}
}
