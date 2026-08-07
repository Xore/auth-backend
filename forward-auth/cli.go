package main

// cli.go — command-line subcommands handled before the server starts:
// `-healthcheck` (used by the Docker HEALTHCHECK), `-hash` (Argon2id helper
// for tooling), and `-verify-audit` (offline chain-integrity check for
// AUDIT_LOG). Anything else falls through to normal startup.

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// handleCLICommand runs the -healthcheck / -hash subcommands, exiting the
// process when one matches. It returns normally when no subcommand (or an
// unknown one) was given.
func handleCLICommand() {
	if len(os.Args) <= 1 {
		return
	}
	switch os.Args[1] {
	case "-healthcheck":
		addr := getenv("LISTEN_ADDR", ":4181")
		if strings.HasPrefix(addr, ":") {
			addr = "127.0.0.1" + addr
		}
		c := http.Client{Timeout: 3 * time.Second}
		if resp, err := c.Get("http://" + addr + "/_auth/health"); err != nil || resp.StatusCode != 200 {
			os.Exit(1)
		}
		os.Exit(0)
	case "-hash":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: forward-auth -hash <password>")
			os.Exit(2)
		}
		h, err := hashPassword(os.Args[2])
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		fmt.Println(h)
		os.Exit(0)
	case "-verify-audit":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: forward-auth -verify-audit <path>  (reads COOKIE_SECRET / COOKIE_SECRET_PREVIOUS from the environment)")
			os.Exit(2)
		}
		verifyAuditFile(os.Args[2])
	}
}

// verifyAuditFile is the offline counterpart of the startup check in
// resumeChain: it lets an operator confirm chain integrity on demand,
// without running the server, using the same keys the running service
// would use.
func verifyAuditFile(path string) {
	secret := getenvFile("COOKIE_SECRET", "")
	if secret == "" {
		fmt.Fprintln(os.Stderr, "COOKIE_SECRET must be set in the environment to verify the audit chain")
		os.Exit(2)
	}
	keys := [][]byte{[]byte(secret)}
	for _, old := range strings.Split(getenvFile("COOKIE_SECRET_PREVIOUS", ""), ",") {
		if old = strings.TrimSpace(old); old != "" {
			keys = append(keys, []byte(old))
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read:", err)
		os.Exit(1)
	}
	if len(raw) == 0 {
		fmt.Println("audit log is empty — nothing to verify")
		os.Exit(0)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if err := verifyAuditLines(lines, keys); err != nil {
		fmt.Fprintln(os.Stderr, "AUDIT CHAIN INTEGRITY FAILURE:", err)
		os.Exit(1)
	}
	fmt.Printf("audit chain OK: %d entries verified\n", len(lines))
	os.Exit(0)
}
