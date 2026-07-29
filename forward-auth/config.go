package main

// config.go — environment-driven configuration: the config struct, env
// loading (including _FILE docker-secrets support), validation, and the
// HKDF key-stretching helper.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"log/slog"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"
	pasetov4 "zntr.io/paseto/v4"
)

type config struct {
	listen            string
	authHost          string
	cookieName        string
	cookieDom         string
	secret            []byte
	oldSecrets        [][]byte
	username          string // bootstrap only
	password          string // bootstrap only (plaintext or bcrypt hash)
	totpSecret        string // bootstrap only
	totpIssuer        string
	usersFile         string
	requireTOTP       bool
	passwordless      bool // PASSWORDLESS=true: passkey-only sign-in
	trustDevDays      int
	ttl               time.Duration
	idleTimeout       time.Duration
	maxAttempts       int
	lockout           time.Duration
	minDwell          time.Duration
	formTTL           time.Duration
	secure            bool
	auditLog          string
	ringCap           int
	webhookURL        string
	webhookProvider   string
	metricsToken      string
	introspectToken   string
	trustedNets       []*net.IPNet
	maxBodyBytes      int64
	orgID             string
	ssoURL            string
	smtpURL           string
	smtpFrom          string
	smtpAllowInsecure bool // dev-only: permit smtp:// without STARTTLS
	redisURL          string
	pasetoKey         pasetov4.LocalKey // XChaCha20 + BLAKE2b key for PASETO v4.local session tokens
	pasetoKeySet      bool              // true when PASETO_KEY was set explicitly
	oldPasetoKeys     []pasetov4.LocalKey
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// getenvFile supports docker secrets: FOO_FILE=/run/secrets/foo takes
// precedence over FOO.
func getenvFile(k, def string) string {
	if p := os.Getenv(k + "_FILE"); p != "" {
		if raw, err := os.ReadFile(p); err == nil {
			return strings.TrimSpace(string(raw))
		}
	}
	return getenv(k, def)
}

func requireEnv(k string) string {
	v := os.Getenv(k)
	if v == "" {
		log.Fatalf("required env var %s is not set", k)
	}
	return v
}

func requireEnvFile(k string) string {
	v := getenvFile(k, "")
	if v == "" {
		log.Fatalf("required env var %s is not set", k)
	}
	return v
}

func atoi(s string, def int) int {
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return def
}

// Default trusted proxies: loopback + RFC1918 + ULA, i.e. the docker network
// Traefik connects from. Forwarded-for headers are only honored from these.
const defaultTrustedProxies = "127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7,::1/128"

func parseCIDRs(s string, logger *slog.Logger) []*net.IPNet {
	var nets []*net.IPNet
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(part); err == nil {
			nets = append(nets, n)
		} else {
			logger.Warn("ignoring invalid TRUSTED_PROXIES entry", "entry", part)
		}
	}
	return nets
}

func loadConfig(logger *slog.Logger) config {
	secret := []byte(getenvFile("COOKIE_SECRET", ""))
	if len(secret) == 0 {
		secret = make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			panic("crypto/rand failed: " + err.Error())
		}
		logger.Warn("COOKIE_SECRET not set — generated a random key; sessions drop on restart and won't match across replicas")
	}
	authHost := getenv("AUTH_HOST", "")
	if authHost == "" {
		log.Fatal("AUTH_HOST must be set")
	}
	var oldSecrets [][]byte
	for _, old := range strings.Split(getenvFile("COOKIE_SECRET_PREVIOUS", ""), ",") {
		if old = strings.TrimSpace(old); old != "" {
			oldSecrets = append(oldSecrets, []byte(old))
		}
	}
	if len(oldSecrets) > 0 {
		// Session cookies are PASETO now — old cookie secrets only cover the
		// remaining HMAC tokens (device trust, form, pending). Session-key
		// rotation goes through PASETO_KEY_PREVIOUS.
		logger.Info("COOKIE_SECRET_PREVIOUS is set — covers only legacy HMAC device/form tokens, not sessions")
	}
	// PASETO_KEY must be exactly 64 hex chars (32 bytes) and is required.
	// When unset, a key is still derived from COOKIE_SECRET so the config
	// object is usable, but validate() rejects the deployment — silent
	// derivation was only allowed during the migration window.
	var pasetoKey pasetov4.LocalKey
	pasetoKeySet := false
	if hex64 := getenvFile("PASETO_KEY", ""); hex64 != "" {
		decoded, err := hex.DecodeString(hex64)
		if err != nil || len(decoded) != 32 {
			log.Fatal("PASETO_KEY must be exactly 64 hex chars (32 bytes)")
		}
		copy(pasetoKey[:], decoded)
		pasetoKeySet = true
	} else {
		k, err := deriveKey(secret, "paseto-v4-local")
		if err != nil {
			log.Fatalf("derive PASETO key: %v", err)
		}
		pasetoKey = pasetov4.LocalKey(k)
		logger.Warn("PASETO_KEY not set — derived from COOKIE_SECRET for now; set it explicitly, derived keys are rejected at startup")
	}
	var oldPasetoKeys []pasetov4.LocalKey
	for _, old := range strings.Split(getenvFile("PASETO_KEY_PREVIOUS", ""), ",") {
		if old = strings.TrimSpace(old); old != "" {
			decoded, err := hex.DecodeString(old)
			if err != nil || len(decoded) != 32 {
				log.Fatal("each PASETO_KEY_PREVIOUS value must be exactly 64 hex chars (32 bytes)")
			}
			var k pasetov4.LocalKey
			copy(k[:], decoded)
			oldPasetoKeys = append(oldPasetoKeys, k)
		}
	}
	return config{
		listen:            getenv("LISTEN_ADDR", ":4181"),
		authHost:          authHost,
		cookieName:        getenv("COOKIE_NAME", "xore_sso"),
		cookieDom:         getenv("COOKIE_DOMAIN", ""),
		secret:            secret,
		oldSecrets:        oldSecrets,
		username:          requireEnv("AUTH_USERNAME"),
		password:          requireEnvFile("AUTH_PASSWORD"),
		totpSecret:        normalizeB32(getenvFile("TOTP_SECRET", "")),
		totpIssuer:        getenv("TOTP_ISSUER", authHost),
		usersFile:         getenv("USERS_FILE", "/data/users.json"),
		requireTOTP:       getenv("REQUIRE_TOTP", "true") != "false",
		passwordless:      getenv("PASSWORDLESS", "false") == "true",
		trustDevDays:      atoi(os.Getenv("TRUST_DEVICE_DAYS"), 0),
		ttl:               time.Duration(atoi(os.Getenv("SESSION_TTL_HOURS"), 12)) * time.Hour,
		idleTimeout:       time.Duration(atoi(os.Getenv("IDLE_TIMEOUT_MINUTES"), 60)) * time.Minute,
		maxAttempts:       atoi(os.Getenv("MAX_ATTEMPTS"), 5),
		lockout:           time.Duration(atoi(os.Getenv("LOCKOUT_MINUTES"), 15)) * time.Minute,
		minDwell:          time.Duration(atoi(os.Getenv("MIN_DWELL_SECONDS"), 2)) * time.Second,
		formTTL:           time.Duration(atoi(os.Getenv("FORM_TTL_MINUTES"), 15)) * time.Minute,
		secure:            getenv("COOKIE_SECURE", "true") != "false",
		auditLog:          getenv("AUDIT_LOG", ""),
		ringCap:           atoi(os.Getenv("AUDIT_RING"), 500),
		webhookURL:        getenv("WEBHOOK_URL", ""),
		webhookProvider:   getenv("WEBHOOK_PROVIDER", "raw"),
		metricsToken:      getenvFile("METRICS_TOKEN", ""),
		introspectToken:   getenvFile("AUTH_INTROSPECTION_TOKEN", ""),
		trustedNets:       parseCIDRs(getenv("TRUSTED_PROXIES", defaultTrustedProxies), logger),
		maxBodyBytes:      int64(atoi(os.Getenv("MAX_BODY_KB"), 64)) * 1024,
		orgID:             getenv("ORG_ID", ""),
		ssoURL:            getenv("SSO_URL", ""),
		smtpURL:           getenv("SMTP_URL", ""),
		smtpFrom:          getenv("SMTP_FROM", "forward-auth@"+authHost),
		smtpAllowInsecure: getenv("SMTP_ALLOW_INSECURE", "false") == "true",
		redisURL:          getenv("REDIS_URL", ""),
		pasetoKey:         pasetoKey,
		pasetoKeySet:      pasetoKeySet,
		oldPasetoKeys:     oldPasetoKeys,
	}
}

// deriveKey stretches secret into a purpose-labelled 32-byte key with
// HKDF-SHA-256 (RFC 5869; salt nil, info = label).
func deriveKey(secret []byte, label string) ([32]byte, error) {
	var key [32]byte
	r := hkdf.New(sha256.New, secret, nil, []byte(label))
	if _, err := io.ReadFull(r, key[:]); err != nil {
		return [32]byte{}, err
	}
	return key, nil
}

func (c config) validate() error {
	var problems []string
	if c.authHost == "" || normalizeHost(c.authHost) != strings.ToLower(c.authHost) {
		problems = append(problems, "AUTH_HOST must be a hostname without a scheme or port")
	}
	if len(c.secret) < 32 {
		problems = append(problems, "COOKIE_SECRET must be at least 32 bytes")
	}
	for _, old := range c.oldSecrets {
		if len(old) < 32 {
			problems = append(problems, "each COOKIE_SECRET_PREVIOUS value must be at least 32 bytes")
		}
	}
	if string(c.secret) == "CHANGE_ME_openssl_rand_hex_32" {
		problems = append(problems, "COOKIE_SECRET still uses the public placeholder")
	}
	if c.password == "change-me-auth" {
		problems = append(problems, "AUTH_PASSWORD still uses the public placeholder")
	}
	if c.ttl <= 0 {
		problems = append(problems, "SESSION_TTL_HOURS must be positive")
	}
	if c.maxAttempts < 1 {
		problems = append(problems, "MAX_ATTEMPTS must be positive")
	}
	if c.lockout <= 0 {
		problems = append(problems, "LOCKOUT_MINUTES must be positive")
	}
	if c.minDwell < 0 || c.formTTL <= c.minDwell {
		problems = append(problems, "form TTL must exceed non-negative dwell time")
	}
	if c.ringCap < 1 || c.ringCap > 100000 {
		problems = append(problems, "AUDIT_RING must be between 1 and 100000")
	}
	if c.maxBodyBytes < 1024 || c.maxBodyBytes > 10<<20 {
		problems = append(problems, "MAX_BODY_KB must be between 1 and 10240")
	}
	if c.introspectToken != "" && len(c.introspectToken) < 32 {
		problems = append(problems, "AUTH_INTROSPECTION_TOKEN must be at least 32 bytes when configured")
	}
	if len(c.trustedNets) == 0 {
		problems = append(problems, "TRUSTED_PROXIES must contain at least one valid CIDR")
	}
	switch c.webhookProvider {
	case "", "raw", "slack", "ntfy", "gotify":
	default:
		problems = append(problems, "WEBHOOK_PROVIDER must be raw, slack, ntfy or gotify")
	}
	if c.webhookURL != "" {
		if u, err := url.Parse(c.webhookURL); err != nil || u.Scheme != "https" || u.Hostname() == "" {
			problems = append(problems, "WEBHOOK_URL must be https:// with a host — alert payloads contain user and IP data and must not travel in cleartext")
		}
	}
	if !c.pasetoKeySet {
		problems = append(problems, "PASETO_KEY must be set explicitly (64 hex chars) — silent derivation is no longer supported")
	}
	if c.smtpURL != "" {
		if u, err := url.Parse(c.smtpURL); err != nil || (u.Scheme != "smtp" && u.Scheme != "smtps") || u.Hostname() == "" {
			problems = append(problems, "SMTP_URL must be smtp:// or smtps:// with a host")
		}
	}
	if c.ssoURL != "" {
		if u, err := url.Parse(c.ssoURL); err != nil || u.Scheme != "https" || u.Hostname() == "" {
			problems = append(problems, "SSO_URL must be https:// with a host")
		}
	}
	if len(problems) == 0 {
		return nil
	}
	return errors.New(strings.Join(problems, "; "))
}
