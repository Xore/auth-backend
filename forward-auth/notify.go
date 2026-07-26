package main

// notify.go — fire-and-forget webhook notifications for security events.
//
// When WEBHOOK_URL is set, selected events (lockouts, logins from a new IP,
// enrollment, backup-code use, admin actions) are POSTed to it as JSON:
//
//	{"service":"forward-auth","event":"locked_out","user":"…","ip":"…",
//	 "host":"…","detail":"…","time":"…"}
//
// A plain JSON POST works out of the box with ntfy (use the JSON publish
// endpoint), Discord/Slack via a small relay, or anything self-written.
// Failures are logged and never block the request path.

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"time"
)

type notifier struct {
	url string
	log *slog.Logger
	c   *http.Client
	sem chan struct{}
}

func newNotifier(url string, log *slog.Logger) *notifier {
	return &notifier{url: url, log: log, c: &http.Client{Timeout: 5 * time.Second}, sem: make(chan struct{}, 8)}
}

func (n *notifier) send(event, user, ip, host, detail string) {
	if n.url == "" {
		return
	}
	body, _ := json.Marshal(map[string]string{
		"service": "forward-auth",
		"event":   event,
		"user":    user,
		"ip":      ip,
		"host":    host,
		"detail":  detail,
		"time":    time.Now().UTC().Format(time.RFC3339),
	})
	select {
	case n.sem <- struct{}{}:
	default:
		n.log.Warn("webhook dropped", "event", event)
		return
	}
	go func() {
		defer func() { <-n.sem }()
		resp, err := n.c.Post(n.url, "application/json", bytes.NewReader(body))
		if err != nil {
			n.log.Warn("webhook failed", "event", event, "error", err)
			return
		}
		_, _ = io.CopyN(io.Discard, resp.Body, 4096)
		_ = resp.Body.Close()
		if resp.StatusCode >= 300 {
			n.log.Warn("webhook rejected", "event", event, "status", resp.StatusCode)
		}
	}()
}
