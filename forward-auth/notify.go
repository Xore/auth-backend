package main

// notify.go — fire-and-forget webhook notifications for security events.
//
// When WEBHOOK_URL is set, selected events (lockouts, logins from a new IP,
// enrollment, backup-code use, admin actions) are POSTed to it as JSON.
// WEBHOOK_PROVIDER selects the payload shape:
//
//	raw    — flat JSON (default): {"service":"forward-auth","event":"…",…}
//	slack  — {"attachments":[{"text":…,"color":…}]} (good/warning/danger)
//	ntfy   — raw JSON body + Priority/Title headers
//	gotify — {"title":…,"message":…,"priority":…}
//
// Failures are logged and never block the request path.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// webhookPayload is the canonical event envelope (the "raw" provider shape).
type webhookPayload struct {
	RequestID string    `json:"request_id"`
	Service   string    `json:"service"`
	Event     string    `json:"event"`
	Severity  string    `json:"severity"` // "info" | "warn" | "critical"
	User      string    `json:"user"`
	IP        string    `json:"ip"`
	Host      string    `json:"host"`
	Detail    string    `json:"detail"`
	Timestamp time.Time `json:"timestamp"`
}

// severityFor maps events to alert severity: credential-affecting events are
// critical, abuse signals are warnings, everything else is informational.
func severityFor(event string) string {
	switch {
	case event == "backup_code_used" || event == "enroll_ok":
		return "critical"
	case event == "locked_out" || event == "bad_backup_code" || strings.HasPrefix(event, "login_fail"):
		return "warn"
	default:
		return "info"
	}
}

// summary renders the one-line human description used by chat providers.
func (p webhookPayload) summary() string {
	s := "[" + p.Event + "]"
	if p.User != "" {
		s += " " + p.User
	}
	if p.Detail != "" {
		s += " — " + p.Detail
	}
	return fmt.Sprintf("%s (%s from %s)", s, p.Host, p.IP)
}

// formatPayload renders the provider-specific body and extra HTTP headers.
func formatPayload(provider string, p webhookPayload) (body []byte, headers map[string]string, err error) {
	switch provider {
	case "slack":
		color := map[string]string{"info": "good", "warn": "warning", "critical": "danger"}[p.Severity]
		body, err = json.Marshal(map[string]any{
			"attachments": []map[string]string{{"text": p.summary(), "color": color}},
		})
		return body, nil, err
	case "ntfy":
		prio := map[string]string{"info": "1", "warn": "3", "critical": "4"}[p.Severity]
		body, err = json.Marshal(p)
		return body, map[string]string{
			"Priority": prio,
			"Title":    "forward-auth: " + p.Event,
		}, err
	case "gotify":
		prio := map[string]int{"info": 2, "warn": 5, "critical": 8}[p.Severity]
		body, err = json.Marshal(map[string]any{
			"title":    "forward-auth: " + p.Event,
			"message":  p.summary(),
			"priority": prio,
		})
		return body, nil, err
	default: // raw
		body, err = json.Marshal(p)
		return body, nil, err
	}
}

type notifier struct {
	url      string
	provider string
	log      *slog.Logger
	c        *http.Client
	sem      chan struct{}
}

func newNotifier(url, provider string, log *slog.Logger) *notifier {
	if provider == "" {
		provider = "raw"
	}
	return &notifier{url: url, provider: provider, log: log, c: &http.Client{Timeout: 5 * time.Second}, sem: make(chan struct{}, 8)}
}

func (n *notifier) send(event, user, ip, host, detail string) {
	if n.url == "" {
		return
	}
	p := webhookPayload{
		RequestID: newSID(),
		Service:   "forward-auth",
		Event:     event,
		Severity:  severityFor(event),
		User:      user,
		IP:        ip,
		Host:      host,
		Detail:    detail,
		Timestamp: time.Now().UTC(),
	}
	body, headers, err := formatPayload(n.provider, p)
	if err != nil {
		n.log.Warn("webhook encode failed", "event", sanitizeLogField(event), "error", err)
		return
	}
	select {
	case n.sem <- struct{}{}:
	default:
		n.log.Warn("webhook dropped", "event", sanitizeLogField(event))
		return
	}
	go func() {
		defer func() { <-n.sem }()
		req, err := http.NewRequest(http.MethodPost, n.url, bytes.NewReader(body))
		if err != nil {
			n.log.Warn("webhook failed", "event", sanitizeLogField(event), "error", err)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := n.c.Do(req)
		if err != nil {
			n.log.Warn("webhook failed", "event", sanitizeLogField(event), "error", err)
			return
		}
		_, _ = io.CopyN(io.Discard, resp.Body, 4096)
		_ = resp.Body.Close()
		if resp.StatusCode >= 300 {
			n.log.Warn("webhook rejected", "event", sanitizeLogField(event), "status", resp.StatusCode)
		}
	}()
}
