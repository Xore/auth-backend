// forward-auth — a hardened single-sign-on gate for Traefik's forwardAuth
// middleware. One login at auth.<domain> protects every service you attach the
// `forward-auth` middleware to, via a PASETO v4.local session cookie scoped to the whole
// parent domain (SSO across all subdomains).
//
// Endpoints (all under /_auth so they never clash with a protected app):
//
//	GET  /_auth/verify        — Traefik calls this; 2xx = allow, 302 = go log in
//	GET  /_auth/login         — the login page (served on auth.<domain>)
//	POST /_auth/login         — validate credentials (+ per-user TOTP), set cookie
//	GET  /_auth/logout        — clear the cookie (requires ?csrf=<session token>)
//	GET  /_auth/health        — unauthenticated health probe
//	GET  /_auth/enroll        — session-gated TOTP enrollment (QR + confirm)
//	GET  /_auth/password      — self-service password change
//	GET  /auth/app            — app shell: settings + admin UI (session-gated)
//	GET  /_auth/admin         — legacy route, redirects to /auth/app
//	GET  /_auth/admin/api/*   — admin JSON API (CSRF-protected)
//	GET  /_auth/metrics       — Prometheus metrics (METRICS_TOKEN-gated)
//
// Users live in a JSON file (USERS_FILE, default /data/users.json) with
// Argon2id password hashes, per-user TOTP secrets, backup codes, roles and
// per-user host allowlists. On first start with an empty store, an admin
// user is bootstrapped from AUTH_USERNAME / AUTH_PASSWORD / TOTP_SECRET so
// existing deployments upgrade in place. TOTP enrollment happens in-session
// at /_auth/enroll — the old public FIRST_RUN setup page is gone.
//
// Hardening: Argon2id password hashes, per-IP brute-force lockout with
// exponential backoff, TOTP replay protection, constant-time compares,
// session revocation (per-user generation + per-session ID), trusted-proxy
// client IP validation, signed CSRF+timing token, hidden bot-trap field,
// minimum form dwell time, open-redirect protection, generic errors (no user
// enumeration), Secure/HttpOnly/SameSite cookies, JSON audit logging and
// optional webhook alerts.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

func main() {
	handleCLICommand()

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	settings, err := loadSettingsStore(settingsPath())
	if err != nil {
		log.Error("cannot read admin settings", "error", err)
		os.Exit(1)
	}
	applySavedOverrides(settings)
	cfg := loadConfig(log)
	if err := cfg.validate(); err != nil {
		log.Error("invalid configuration", "error", err)
		os.Exit(2)
	}
	if cfg.smtpAllowInsecure && cfg.smtpURL != "" {
		log.Warn("SMTP_ALLOW_INSECURE=true — recovery mail may be sent without TLS; development only")
	}
	aud := newAuditor(cfg.auditLog, cfg.ringCap, append([][]byte{cfg.secret}, cfg.oldSecrets...)...)

	users := newUserStore(cfg.usersFile)
	if err := users.load(); err != nil {
		log.Error("cannot read user store — refusing to start with a possibly corrupt file",
			"path", cfg.usersFile, "error", err)
		os.Exit(1)
	}
	if created, err := users.bootstrap(cfg.username, cfg.password, cfg.totpSecret); err != nil {
		log.Error("bootstrap failed", "error", err)
		os.Exit(1)
	} else if created {
		log.Info("bootstrapped admin user from environment", "user", cfg.username,
			"totp_enrolled", cfg.totpSecret != "", "store", cfg.usersFile)
	}
	if cfg.passwordless && !users.hasEnabledAdminWithPasskey() {
		// PASSWORDLESS disables password login and password recovery, and
		// passkey enrollment (/_auth/enroll's passkey equivalent) requires
		// an authenticated session to reach — so a deployment that reaches
		// this state with no admin passkey already registered has no way
		// for anyone to ever authenticate again. Refuse to start rather
		// than silently boot into a permanently locked-out server.
		log.Error("PASSWORDLESS=true but no enabled administrator has a registered passkey — refusing to start; " +
			"this would lock every administrator out, since password login/recovery are disabled and passkey " +
			"enrollment itself requires a session. Set PASSWORDLESS=false, sign in, register a passkey for an " +
			"administrator, then re-enable PASSWORDLESS")
		os.Exit(1)
	}
	if os.Getenv("FIRST_RUN") != "" {
		log.Warn("FIRST_RUN is deprecated and ignored — TOTP enrollment now happens per-user at /_auth/enroll after login")
	}

	// Backends: in-memory + JSON file persistence by default; Redis when
	// REDIS_URL is set (roadmap Step 23).
	throttlePath := filepath.Join(filepath.Dir(cfg.usersFile), "throttle.json")
	tb, sb := openBackends(cfg, log, throttlePath)
	if tb == nil {
		os.Exit(1)
	}

	s := &server{
		cfg: cfg, settings: settings, log: log, tr: tb, aud: aud,
		users: users,
		reg:   sb,
		ntf:   newNotifier(cfg.webhookURL, cfg.webhookProvider, log),

		startedAt:    time.Now(),
		recoverLimit: rateLimiter{max: 3, window: time.Hour, maxKeys: rateLimiterMaxKeys},
		magicLimit:   rateLimiter{max: 3, window: time.Hour, maxKeys: rateLimiterMaxKeys},
	}
	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: cfg.totpIssuer,
		RPID:          cfg.authHost,
		RPOrigins:     []string{"https://" + cfg.authHost},
	})
	if err != nil {
		log.Error("initialize passkeys", "error", err)
		os.Exit(2)
	}
	s.wa = wa
	s.ceremonies = newCeremonyStore()

	mux := http.NewServeMux()
	s.registerRoutes(mux)

	sum := sha256.Sum256(cfg.secret)
	log.Info("forward-auth starting",
		"listen", cfg.listen, "auth_host", cfg.authHost,
		"cookie_domain", cfg.cookieDom, "users", users.count(),
		"require_totp", cfg.requireTOTP, "trust_device_days", cfg.trustDevDays,
		"secret_fp", hex.EncodeToString(sum[:4]),
		"audit_log", cfg.auditLog, "audit_ring", cfg.ringCap,
		"webhook", cfg.webhookURL != "", "metrics", cfg.metricsToken != "")

	srv := &http.Server{
		Addr: cfg.listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second,
		IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 20,
	}

	go s.awaitShutdown(srv, throttlePath)

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Error("server stopped", "error", err)
		os.Exit(1)
	}
}
