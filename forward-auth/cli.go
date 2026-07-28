package main

// cli.go — command-line subcommands handled before the server starts:
// `-healthcheck` (used by the Docker HEALTHCHECK) and `-hash` (Argon2id
// helper for tooling). Anything else falls through to normal startup.

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
	}
}
