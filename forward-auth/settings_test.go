package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSettingsStorePersistsBrandingAndOverrides(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin-settings.json")
	store, err := loadSettingsStore(path)
	if err != nil {
		t.Fatal(err)
	}
	next := store.snapshot()
	next.BrandTitle = "Example Login"
	next.BrandSubtitle = "Private access"
	next.BrandFooter = "Authorized users only"
	next.Overrides["SESSION_TTL_HOURS"] = "24"
	if err := store.save(next); err != nil {
		t.Fatal(err)
	}
	next.BrandFooter = "Second saved value"
	if err := store.save(next); err != nil {
		t.Fatalf("replace existing settings file: %v", err)
	}
	reloaded, err := loadSettingsStore(path)
	if err != nil {
		t.Fatal(err)
	}
	got := reloaded.snapshot()
	if got.BrandTitle != "Example Login" || got.BrandSubtitle != "Private access" ||
		got.BrandFooter != "Second saved value" {
		t.Fatalf("branding not persisted: %#v", got)
	}
	if got.Overrides["SESSION_TTL_HOURS"] != "24" {
		t.Fatalf("override not persisted: %#v", got.Overrides)
	}
}

func TestAdminSettingsRedactsAndStagesRotation(t *testing.T) {
	c := testConfig(t)
	dir := t.TempDir()
	users := newUserStore(filepath.Join(dir, "users.json"))
	if _, err := users.bootstrap("admin", "a-long-test-password", ""); err != nil {
		t.Fatal(err)
	}
	settings, err := loadSettingsStore(filepath.Join(dir, "admin-settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := &server{
		cfg: c, settings: settings, users: users,
		reg: newSessionRegistry(time.Hour), tr: newThrottle(c),
		aud: newAuditor("", 10), log: logger, ntf: newNotifier("", "raw", logger),
	}
	request := func(method, body string) *httptest.ResponseRecorder {
		u := users.get("admin")
		cl := sessionClaims{user: "admin", gen: u.Gen, sid: "adminsid", exp: time.Now().Add(time.Hour).Unix()}
		r := httptest.NewRequest(method, "http://auth/_auth/admin/api/settings", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.AddCookie(&http.Cookie{Name: c.cookieName, Value: mustIssuePASETO(t, c, cl)})
		if method != http.MethodGet {
			r.Header.Set("X-Csrf", c.csrfToken(cl.sid))
		}
		w := httptest.NewRecorder()
		s.handleAdminSettings(w, r)
		return w
	}

	w := request(http.MethodGet, "")
	if w.Code != http.StatusOK {
		t.Fatalf("GET settings: %d %s", w.Code, w.Body.String())
	}
	var response adminSettingsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	for _, field := range response.Fields {
		if field.Sensitive && field.Value != "" {
			t.Fatalf("sensitive field %s leaked a value", field.Key)
		}
	}

	w = request(http.MethodPost, `{"brand_title":"Example","rotate":"PASETO_KEY"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("POST settings: %d %s", w.Code, w.Body.String())
	}
	saved := settings.snapshot()
	if saved.BrandTitle != "Example" {
		t.Fatalf("brand title = %q", saved.BrandTitle)
	}
	if len(saved.Overrides["PASETO_KEY"]) != 64 {
		t.Fatalf("new PASETO key length = %d", len(saved.Overrides["PASETO_KEY"]))
	}
	if saved.Overrides["PASETO_KEY_PREVIOUS"] != currentConfigValue(c, "PASETO_KEY") {
		t.Fatal("current PASETO key was not retained as previous")
	}
}
