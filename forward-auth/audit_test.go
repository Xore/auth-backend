package main

// audit_test.go — signed audit log chain (tamper evidence).

import (
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
	for i, ev := range []string{"login_ok", "login_fail:bad_credentials", "locked_out"} {
		a.record(authEvent{Time: time.Now(), Event: ev, IP: "192.0.2.1", User: "alice"})
		_ = i
	}
	lines := readAuditLines(t, path)
	if len(lines) != 3 {
		t.Fatalf("lines = %d, want 3", len(lines))
	}
	if err := verifyAuditLines(lines, key); err != nil {
		t.Fatalf("valid chain rejected: %v", err)
	}
	if err := verifyAuditLines(lines, []byte("wrong-key-wrong-key-wrong-key!!")); err == nil {
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
	for _, ev := range []string{"login_ok", "admin_disable:bob", "recover_ok", "logout"} {
		a.record(authEvent{Time: time.Now(), Event: ev, IP: "192.0.2.1"})
	}
	lines := readAuditLines(t, path)

	// edit a line (cover up the admin action): MAC must fail
	edited := append([]string(nil), lines...)
	edited[1] = strings.Replace(edited[1], "admin_disable:bob", "login_ok", 1)
	if err := verifyAuditLines(edited, key); err == nil {
		t.Fatal("edited line not detected")
	}
	// delete a middle line: chain must break
	deleted := append([]string(nil), lines[:1]...)
	deleted = append(deleted, lines[2:]...)
	if err := verifyAuditLines(deleted, key); err == nil {
		t.Fatal("deleted line not detected")
	}
	// truncate the tail: verifiable, but shorter — the last line's MAC is
	// intact, so tail truncation is detectable only against a known seq.
	if err := verifyAuditLines(lines[:2], key); err != nil {
		t.Fatalf("prefix of a valid chain should verify: %v", err)
	}
	// strip signatures: rejected as tampering
	unsigned := []string{`{"time":"2026-07-28T00:00:00Z","event":"login_ok","ip":"192.0.2.1"}`}
	if err := verifyAuditLines(unsigned, key); err == nil {
		t.Fatal("unsigned line accepted")
	}
}

func TestAuditChainResumesAcrossRestart(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	path := filepath.Join(t.TempDir(), "audit.log")
	a1 := newAuditor(path, 10, key)
	a1.record(authEvent{Time: time.Now(), Event: "login_ok", IP: "192.0.2.1"})
	a1.record(authEvent{Time: time.Now(), Event: "logout", IP: "192.0.2.1"})
	_ = a1.file.Close()

	// simulate a restart: fresh auditor over the same file continues the chain
	a2 := newAuditor(path, 10, key)
	a2.record(authEvent{Time: time.Now(), Event: "login_ok", IP: "192.0.2.2"})
	lines := readAuditLines(t, path)
	if len(lines) != 3 {
		t.Fatalf("lines = %d, want 3", len(lines))
	}
	if err := verifyAuditLines(lines, key); err != nil {
		t.Fatalf("chain broken across restart: %v", err)
	}
}

// An auditor without a key behaves exactly as before (unsigned entries).
func TestAuditUnsignedWithoutKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	a := newAuditor(path, 10)
	a.record(authEvent{Time: time.Now(), Event: "login_ok", IP: "192.0.2.1"})
	lines := readAuditLines(t, path)
	if strings.Contains(lines[0], "mac") {
		t.Fatalf("unsigned auditor wrote chain fields: %s", lines[0])
	}
}
