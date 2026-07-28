package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

const (
	defaultBrandTitle    = "xore//auth"
	defaultBrandSubtitle = "One sign-on for every service behind the gate."
	defaultBrandFooter   = "protected ◆ all activity logged"
)

// adminSettings is separate from config. Branding is read live, while
// environment-compatible overrides are applied on the next process start.
type adminSettings struct {
	BrandTitle    string            `json:"brand_title"`
	BrandSubtitle string            `json:"brand_subtitle"`
	BrandFooter   string            `json:"brand_footer"`
	Overrides     map[string]string `json:"overrides,omitempty"`
}

type settingsStore struct {
	mu   sync.RWMutex
	path string
	data adminSettings
}

func settingsPath() string {
	usersFile := getenv("USERS_FILE", "/data/users.json")
	return filepath.Join(filepath.Dir(usersFile), "admin-settings.json")
}

func defaultAdminSettings() adminSettings {
	return adminSettings{
		BrandTitle:    defaultBrandTitle,
		BrandSubtitle: defaultBrandSubtitle,
		BrandFooter:   defaultBrandFooter,
		Overrides:     map[string]string{},
	}
}

func loadSettingsStore(path string) (*settingsStore, error) {
	st := &settingsStore{path: path, data: defaultAdminSettings()}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &st.data); err != nil {
		return nil, fmt.Errorf("decode admin settings: %w", err)
	}
	if st.data.BrandTitle == "" {
		st.data.BrandTitle = defaultBrandTitle
	}
	if st.data.Overrides == nil {
		st.data.Overrides = map[string]string{}
	}
	return st, nil
}

func (s *settingsStore) snapshot() adminSettings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := s.data
	out.Overrides = make(map[string]string, len(s.data.Overrides))
	for k, v := range s.data.Overrides {
		out.Overrides[k] = v
	}
	return out
}

func (s *settingsStore) save(next adminSettings) error {
	if next.Overrides == nil {
		next.Overrides = map[string]string{}
	}
	raw, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	s.mu.Lock()
	s.data = next
	s.mu.Unlock()
	return nil
}

func (s *settingsStore) branding() (string, string, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.BrandTitle, s.data.BrandSubtitle, s.data.BrandFooter
}

// Docker secret files keep precedence and cannot accidentally be displaced by
// a UI override.
func applySavedOverrides(st *settingsStore) {
	for key, value := range st.snapshot().Overrides {
		if os.Getenv(key+"_FILE") != "" {
			continue
		}
		_ = os.Setenv(key, value)
	}
}

type configFieldSpec struct {
	Key         string
	Label       string
	Kind        string
	Description string
	Sensitive   bool
}

var editableConfigFields = []configFieldSpec{
	{"AUTH_HOST", "Authentication host", "text", "Public hostname used for redirects and WebAuthn.", false},
	{"COOKIE_DOMAIN", "Cookie domain", "text", "Domain scope shared by protected services.", false},
	{"COOKIE_NAME", "Cookie name", "text", "Browser session cookie name.", false},
	{"COOKIE_SECURE", "Secure cookies", "bool", "Only send cookies over HTTPS.", false},
	{"SESSION_TTL_HOURS", "Session lifetime (hours)", "number", "Maximum session lifetime.", false},
	{"IDLE_TIMEOUT_MINUTES", "Idle timeout (minutes)", "number", "Reauthenticate inactive sessions; 0 disables.", false},
	{"FORM_TTL_MINUTES", "Form token lifetime (minutes)", "number", "Lifetime of anti-replay form tokens.", false},
	{"REQUIRE_TOTP", "Require two-factor authentication", "bool", "Require TOTP enrollment for users.", false},
	{"TRUST_DEVICE_DAYS", "Trusted-device lifetime (days)", "number", "Allow remembered devices; 0 disables.", false},
	{"TOTP_ISSUER", "TOTP issuer", "text", "Issuer displayed by authenticator applications.", false},
	{"MAX_ATTEMPTS", "Attempts before lockout", "number", "Failed attempts before throttling begins.", false},
	{"LOCKOUT_MINUTES", "Base lockout (minutes)", "number", "Initial lockout duration before exponential backoff.", false},
	{"MIN_DWELL_SECONDS", "Minimum login dwell (seconds)", "number", "Minimum response time used to reduce timing leakage.", false},
	{"AUDIT_RING", "In-memory audit entries", "number", "Maximum recent events retained in memory.", false},
	{"AUDIT_LOG", "Audit log path", "text", "Optional append-only JSON audit file.", false},
	{"MAX_BODY_KB", "Maximum request body (KiB)", "number", "Request-size limit for JSON admin actions.", false},
	{"TRUSTED_PROXIES", "Trusted proxy networks", "text", "Comma-separated CIDR networks allowed to set forwarded headers.", false},
	{"ORG_ID", "Organization ID", "text", "Optional organization identifier.", false},
	{"SSO_URL", "External SSO URL", "text", "Optional upstream SSO entry point.", false},
	{"SMTP_URL", "SMTP URL", "password", "Recovery mail transport. The current value is never returned.", true},
	{"SMTP_FROM", "SMTP sender", "text", "From address for recovery messages.", false},
	{"SMTP_ALLOW_INSECURE", "Allow insecure SMTP", "bool", "Development-only plaintext SMTP permission.", false},
	{"REDIS_URL", "Redis URL", "password", "Shared session and throttle backend. The current value is never returned.", true},
	{"WEBHOOK_URL", "Notification webhook URL", "password", "Security notification destination. The current value is never returned.", true},
	{"WEBHOOK_PROVIDER", "Webhook provider", "text", "Webhook payload format.", false},
	{"METRICS_TOKEN", "Metrics bearer token", "password", "Protects the metrics endpoint. The current value is never returned.", true},
	{"LISTEN_ADDR", "Listen address", "text", "HTTP bind address inside the container.", false},
	{"USERS_FILE", "User database path", "text", "Persistent user database location.", false},
	{"COOKIE_SECRET", "Cookie/form signing secret", "password", "HMAC root secret. Prefer Rotate.", true},
	{"PASETO_KEY", "PASETO session key", "password", "64 hexadecimal characters. Prefer Rotate.", true},
}

var editableConfigKeys = func() map[string]configFieldSpec {
	m := make(map[string]configFieldSpec, len(editableConfigFields))
	for _, field := range editableConfigFields {
		m[field.Key] = field
	}
	return m
}()

func currentConfigValue(cfg config, key string) string {
	switch key {
	case "AUTH_HOST":
		return cfg.authHost
	case "COOKIE_DOMAIN":
		return cfg.cookieDom
	case "COOKIE_NAME":
		return cfg.cookieName
	case "COOKIE_SECURE":
		return fmt.Sprint(cfg.secure)
	case "SESSION_TTL_HOURS":
		return fmt.Sprint(int(cfg.ttl.Hours()))
	case "IDLE_TIMEOUT_MINUTES":
		return fmt.Sprint(int(cfg.idleTimeout.Minutes()))
	case "FORM_TTL_MINUTES":
		return fmt.Sprint(int(cfg.formTTL.Minutes()))
	case "REQUIRE_TOTP":
		return fmt.Sprint(cfg.requireTOTP)
	case "TRUST_DEVICE_DAYS":
		return fmt.Sprint(cfg.trustDevDays)
	case "TOTP_ISSUER":
		return cfg.totpIssuer
	case "MAX_ATTEMPTS":
		return fmt.Sprint(cfg.maxAttempts)
	case "LOCKOUT_MINUTES":
		return fmt.Sprint(int(cfg.lockout.Minutes()))
	case "MIN_DWELL_SECONDS":
		return fmt.Sprint(int(cfg.minDwell.Seconds()))
	case "AUDIT_RING":
		return fmt.Sprint(cfg.ringCap)
	case "AUDIT_LOG":
		return cfg.auditLog
	case "MAX_BODY_KB":
		return fmt.Sprint(cfg.maxBodyBytes / 1024)
	case "TRUSTED_PROXIES":
		var values []string
		for _, network := range cfg.trustedNets {
			values = append(values, network.String())
		}
		return strings.Join(values, ",")
	case "ORG_ID":
		return cfg.orgID
	case "SSO_URL":
		return cfg.ssoURL
	case "SMTP_URL":
		return cfg.smtpURL
	case "SMTP_FROM":
		return cfg.smtpFrom
	case "SMTP_ALLOW_INSECURE":
		return fmt.Sprint(cfg.smtpAllowInsecure)
	case "REDIS_URL":
		return cfg.redisURL
	case "WEBHOOK_URL":
		return cfg.webhookURL
	case "WEBHOOK_PROVIDER":
		return cfg.webhookProvider
	case "METRICS_TOKEN":
		return cfg.metricsToken
	case "LISTEN_ADDR":
		return cfg.listen
	case "USERS_FILE":
		return cfg.usersFile
	case "COOKIE_SECRET":
		return string(cfg.secret)
	case "PASETO_KEY":
		return hex.EncodeToString(cfg.pasetoKey[:])
	default:
		return ""
	}
}

func randomHex(bytes int) (string, error) {
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func sortedFieldSpecs() []configFieldSpec {
	out := append([]configFieldSpec(nil), editableConfigFields...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}
