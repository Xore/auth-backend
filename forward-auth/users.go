package main

// users.go — persistent multi-user store backed by a single JSON file.
//
// The file lives on a mounted volume (USERS_FILE, default /data/users.json)
// and is rewritten atomically (temp file + rename) on every mutation, so a
// crash mid-write can never corrupt it. All access goes through userStore,
// which keeps the parsed users in memory under a mutex — with a handful of
// users there is no need for anything heavier.
//
// Passwords are stored as Argon2id hashes (PHC format). Existing bcrypt
// hashes are still accepted and transparently upgraded to Argon2id on the
// next successful login. TOTP secrets are per-user; a secret generated
// during enrollment sits in PendingTOTP until the user confirms a code, so
// a half-finished enrollment never locks anyone out. Backup codes are
// stored as SHA-256 hashes and removed on use.
//
// lastStep (TOTP replay protection) is now persisted in the same JSON file
// under "last_step" so that replay protection survives container restarts.

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

const (
	roleAdmin = "admin"
	roleUser  = "user"
)

// errNoSuchUser is returned by store mutations for a missing username.
var errNoSuchUser = errors.New("no such user")

// errLastAdmin is returned by mutateAdminGuarded/deleteAdminGuarded when an
// action would leave the deployment with no enabled administrator.
var errLastAdmin = errors.New("cannot remove the last admin")

// normalizeEmail validates and normalizes an email address for storage.
// The local part is kept verbatim (it is case-sensitive per RFC 5321); the
// domain is lowercased. An empty input normalizes to "" (field cleared).
// The username is never derived from or rewritten by this — it only ever
// feeds the dedicated Email field.
func normalizeEmail(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	if len(s) > 254 {
		return "", errors.New("email address too long")
	}
	a, err := mail.ParseAddress(s)
	if err != nil || a.Address != s {
		return "", errors.New("invalid email address")
	}
	local, domain, ok := strings.Cut(a.Address, "@")
	if !ok || local == "" || domain == "" {
		return "", errors.New("invalid email address")
	}
	return local + "@" + strings.ToLower(domain), nil
}

const (
	maxDisplayNameLen  = 80
	maxDescriptionLen  = 500
	maxPermissionsHost = 32 // distinct hosts a user can have grants under
	maxPermissionsKey  = 16 // grants per host
	maxPermissionLen   = 64 // bytes per permission string
)

// permissionKeyRe bounds the opaque, consumer-app-defined permission
// strings. auth-backend never interprets them, but still bounds their shape
// so a consumer's own key format can't be used to smuggle arbitrary bytes
// through this store.
var permissionKeyRe = regexp.MustCompile(`^[a-zA-Z0-9._:-]{1,64}$`)

// normalizeDisplayName trims and bounds an admin-supplied display name. An
// empty result clears the field; introspection then falls back to Username.
func normalizeDisplayName(s string) (string, error) {
	s = strings.TrimSpace(s)
	if len(s) > maxDisplayNameLen {
		return "", fmt.Errorf("display name must not exceed %d characters", maxDisplayNameLen)
	}
	return s, nil
}

// normalizeDescription trims and bounds an admin-supplied user description.
func normalizeDescription(s string) (string, error) {
	s = strings.TrimSpace(s)
	if len(s) > maxDescriptionLen {
		return "", fmt.Errorf("description must not exceed %d characters", maxDescriptionLen)
	}
	return s, nil
}

// normalizePermissions validates and de-duplicates an admin-supplied
// permission grant list for one host. An empty list clears any existing
// grants for that host (deny-by-default: nothing is implicitly kept).
func normalizePermissions(perms []string) ([]string, error) {
	if len(perms) > maxPermissionsKey {
		return nil, fmt.Errorf("at most %d permissions per host", maxPermissionsKey)
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(perms))
	for _, p := range perms {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if len(p) > maxPermissionLen || !permissionKeyRe.MatchString(p) {
			return nil, fmt.Errorf("invalid permission key %q: 1-%d chars of a-z A-Z 0-9 . _ : -", p, maxPermissionLen)
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	sort.Strings(out)
	return out, nil
}

// recoveryEmail returns the address recovery mail is sent to: the validated
// Email field when set, otherwise — for backward compatibility with
// email-shaped usernames — the username itself when it parses as an email
// address. "" means the account is not reachable by recovery mail.
func (u *User) recoveryEmail() string {
	if u.Email != "" {
		return u.Email
	}
	if e, err := normalizeEmail(u.Username); err == nil {
		return e
	}
	return ""
}

type User struct {
	Subject      string   `json:"subject"`
	Username     string   `json:"username"`
	DisplayName  string   `json:"display_name,omitempty"` // admin-editable; introspection falls back to Username when empty
	Description  string   `json:"description,omitempty"`  // admin-editable free text, never shown to the user themselves as a credential
	Hash         string   `json:"hash"`
	Role         string   `json:"role"`
	Email        string   `json:"email,omitempty"` // optional recovery address; usernames stay opaque IDs
	Disabled     bool     `json:"disabled,omitempty"`
	MustChange   bool     `json:"must_change,omitempty"`
	TOTPSecret   string   `json:"totp_secret,omitempty"`
	PendingTOTP  string   `json:"pending_totp,omitempty"`
	BackupCodes  []string `json:"backup_codes,omitempty"` // sha256 hex, removed on use
	Gen          int      `json:"gen"`                    // bump to kill all sessions
	AllowedHosts []string `json:"allowed_hosts,omitempty"`
	// RequireTOTPHosts (#67) is additive to AllowedHosts, not a replacement:
	// same pattern syntax ("*", "*.dom", exact host), but an empty list
	// means no extra requirement (the opposite default from AllowedHosts'
	// own empty-means-everything). A host matching here always demands a
	// fresh TOTP challenge regardless of trusted-device state, on top of
	// (never instead of) the existing risk-based step-up.
	RequireTOTPHosts []string `json:"require_totp_hosts,omitempty"`
	// Permissions carries opaque, consumer-app-defined capability strings
	// per host, deny-by-default: an absent host key or absent string grants
	// nothing beyond whatever the coarse Role already gives a consumer.
	// auth-backend stores and serves this; it never interprets the strings.
	Permissions   map[string][]string `json:"permissions,omitempty"`
	Created       time.Time           `json:"created"`
	LastLogin     time.Time           `json:"last_login,omitempty"`
	LastIP        string              `json:"last_ip,omitempty"`
	PasskeyUserID []byte              `json:"webauthn_id,omitempty"`
	Passkeys      []Passkey           `json:"passkeys,omitempty"`
	DeviceGen     int                 `json:"device_gen,omitempty"`
	MagicSeq      int                 `json:"magic_seq,omitempty"` // magic-link single-use counter
	History       []loginRecord       `json:"history,omitempty"`   // recent successful logins, for risk scoring
	// PasswordHistory holds the Argon2id hashes of the user's most recent
	// PREVIOUS passwords (the current password is Hash, not duplicated
	// here), newest first, capped at config's passwordHistoryCount (#63).
	// Always Argon2id regardless of what Hash itself currently is: every
	// entry was written by hashPassword at the moment it stopped being the
	// live password, and hashPassword only ever produces Argon2id -- a
	// legacy bcrypt Hash (pre-upgrade) never ends up here.
	PasswordHistory []string `json:"password_history,omitempty"`
}

// loginRecord is one successful sign-in, kept (capped) for risk-based
// authentication scoring (roadmap Step 24).
type loginRecord struct {
	Time time.Time `json:"time"`
	IP   string    `json:"ip"`
	UA   string    `json:"ua"`
}

type Passkey struct {
	Name       string              `json:"name"`
	Credential webauthn.Credential `json:"credential"`
	Created    time.Time           `json:"created"`
	LastUsed   time.Time           `json:"last_used,omitempty"`
}

func (u *User) WebAuthnID() []byte          { return append([]byte(nil), u.PasskeyUserID...) }
func (u *User) WebAuthnName() string        { return u.Username }
func (u *User) WebAuthnDisplayName() string { return u.Username }
func (u *User) WebAuthnCredentials() []webauthn.Credential {
	out := make([]webauthn.Credential, 0, len(u.Passkeys))
	for _, key := range u.Passkeys {
		out = append(out, key.Credential)
	}
	return out
}

// hostMatchesAny reports whether host matches any of patterns ("*" matches
// everything, "*.dom" matches any subdomain of dom but not dom itself,
// anything else is an exact match). The shared core hostAllowed and
// hostRequiresTOTP (#67) both need — what differs between them is the
// empty-list default, which each applies on top of this.
func hostMatchesAny(host string, patterns []string) bool {
	for _, pat := range patterns {
		pat = strings.ToLower(strings.TrimSpace(pat))
		if !strings.HasPrefix(pat, "*.") && pat != "*" {
			pat = normalizeHost(pat)
		}
		switch {
		case pat == "*" || pat == host:
			return true
		case strings.HasPrefix(pat, "*."):
			if strings.HasSuffix(host, pat[1:]) {
				return true
			}
		}
	}
	return false
}

// hostAllowed reports whether this user may access the given
// X-Forwarded-Host. An empty list means everything is allowed.
func (u *User) hostAllowed(host string) bool {
	host = normalizeHost(host)
	if host == "" {
		return false
	}
	if len(u.AllowedHosts) == 0 {
		return true
	}
	return hostMatchesAny(host, u.AllowedHosts)
}

// hostRequiresTOTP reports whether host is in this user's RequireTOTPHosts
// list (#67). Unlike hostAllowed, an empty list means nothing extra is
// required — this is additive to the existing risk-based step-up, not a
// second access-control gate with its own default-everything posture.
func (u *User) hostRequiresTOTP(host string) bool {
	host = normalizeHost(host)
	if host == "" || len(u.RequireTOTPHosts) == 0 {
		return false
	}
	return hostMatchesAny(host, u.RequireTOTPHosts)
}

type userStore struct {
	mu    sync.Mutex
	path  string
	users map[string]*User

	// lastStep guards against TOTP replay: a code for time-step N is accepted
	// once; any code at or before the last accepted step is rejected.
	// Persisted to disk so replay protection survives container restarts.
	lastStep map[string]int64
}

// dummyArgon2Hash is compared against when the username doesn't exist, so a
// login attempt takes the same time whether or not the user is real.
var dummyArgon2Hash = "$argon2id$v=19$m=65536,t=3,p=4$AqEs8VKjYucHBmGSPfqyVQ$A8ilJSZbSUHYrR86d+hLXr4xA8z3DIpvZpaTdICHNLA"

func newUserStore(path string) *userStore {
	return &userStore{path: path, users: map[string]*User{}, lastStep: map[string]int64{}}
}

// load reads the store from disk; a missing file is not an error (bootstrap
// handles that case).
func (st *userStore) load() error {
	st.mu.Lock()
	defer st.mu.Unlock()
	raw, err := os.ReadFile(st.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var f struct {
		Users    []*User          `json:"users"`
		LastStep map[string]int64 `json:"last_step,omitempty"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		return fmt.Errorf("parse %s: %w", st.path, err)
	}
	m := map[string]*User{}
	subjects := map[string]string{}
	migrated := false
	for _, u := range f.Users {
		if u.Username != "" {
			if u.Subject == "" {
				u.Subject = uuid.NewString()
				migrated = true
			} else if _, err := uuid.Parse(u.Subject); err != nil {
				return fmt.Errorf("user %q has invalid subject", u.Username)
			}
			if existing := subjects[u.Subject]; existing != "" {
				return fmt.Errorf("users %q and %q share a subject", existing, u.Username)
			}
			subjects[u.Subject] = u.Username
			if len(u.PasskeyUserID) == 0 {
				u.PasskeyUserID = randomBytes(32)
				migrated = true
			}
			m[u.Username] = u
		}
	}
	st.users = m
	if f.LastStep != nil {
		st.lastStep = f.LastStep
	}
	if migrated {
		return st.saveLocked()
	}
	return nil
}

// saveLocked writes the store atomically. Callers must hold st.mu.
func (st *userStore) saveLocked() error {
	list := make([]*User, 0, len(st.users))
	for _, u := range st.users {
		list = append(list, u)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Username < list[j].Username })
	raw, err := json.MarshalIndent(struct {
		Users    []*User          `json:"users"`
		LastStep map[string]int64 `json:"last_step,omitempty"`
	}{list, st.lastStep}, "", "  ")
	if err != nil {
		return err
	}
	if dir := filepath.Dir(st.path); dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return err
		}
	}
	dir := filepath.Dir(st.path)
	tmp, err := os.CreateTemp(dir, ".users-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op once renamed on the success path
	if err = tmp.Chmod(0o600); err == nil {
		_, err = tmp.Write(append(raw, '\n'))
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(tmpName, st.path); err != nil {
		return err
	}
	if d, openErr := os.Open(dir); openErr == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func (st *userStore) writable() error {
	st.mu.Lock()
	defer st.mu.Unlock()
	f, err := os.OpenFile(st.path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	return f.Close()
}

// bootstrap creates the initial admin user from the legacy env vars when the
// store is empty, so an existing single-user deployment keeps working (same
// username, password and already-enrolled TOTP secret) across the upgrade.
func (st *userStore) bootstrap(username, password, totpSecret string) (created bool, err error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.users) > 0 {
		return false, nil
	}
	hash := password
	if !looksLikeBcrypt(password) {
		h, err := hashPassword(password)
		if err != nil {
			return false, err
		}
		hash = h
	}
	st.users[username] = &User{
		Subject:       uuid.NewString(),
		Username:      username,
		Hash:          hash,
		Role:          roleAdmin,
		TOTPSecret:    totpSecret,
		Gen:           1,
		Created:       time.Now().UTC(),
		PasskeyUserID: randomBytes(32),
		DeviceGen:     1,
	}
	if err := st.saveLocked(); err != nil {
		delete(st.users, username)
		return false, err
	}
	return true, nil
}

func looksLikeBcrypt(s string) bool {
	return strings.HasPrefix(s, "$2a$") || strings.HasPrefix(s, "$2b$") || strings.HasPrefix(s, "$2y$")
}

// get returns a deep copy so callers cannot race with mutations.
func (st *userStore) get(name string) *User {
	st.mu.Lock()
	defer st.mu.Unlock()
	return cloneUser(st.users[name])
}

func (st *userStore) list() []*User {
	st.mu.Lock()
	defer st.mu.Unlock()
	out := make([]*User, 0, len(st.users))
	for _, u := range st.users {
		out = append(out, cloneUser(u))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out
}

func (st *userStore) count() int {
	st.mu.Lock()
	defer st.mu.Unlock()
	return len(st.users)
}

func (st *userStore) adminCount() int {
	st.mu.Lock()
	defer st.mu.Unlock()
	n := 0
	for _, u := range st.users {
		if u.Role == roleAdmin && !u.Disabled {
			n++
		}
	}
	return n
}

// hasEnabledAdminWithPasskey reports whether at least one enabled
// administrator has a registered passkey. Used to guard PASSWORDLESS=true:
// enabling it with no such admin would disable password login and recovery
// while passkey enrollment itself requires an authenticated session,
// permanently locking every administrator out.
func (st *userStore) hasEnabledAdminWithPasskey() bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, u := range st.users {
		if u.Role == roleAdmin && !u.Disabled && len(u.Passkeys) > 0 {
			return true
		}
	}
	return false
}

// mutate runs fn on the named user under the lock and persists the store if
// fn returns true.
func (st *userStore) mutate(name string, fn func(*User) bool) error {
	_, err := st.mutateIf(name, fn)
	return err
}

// mutateIf is mutate with the application result exposed: fn runs under the
// store lock, so it can re-verify preconditions (e.g. a recovery token's
// password-hash fingerprint) and mutate atomically — no other mutation can
// interleave between check and write. applied is false when the user is
// missing (errNoSuchUser) or fn returned false (precondition failed).
func (st *userStore) mutateIf(name string, fn func(*User) bool) (applied bool, err error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	u := st.users[name]
	if u == nil {
		return false, errNoSuchUser
	}
	before := cloneUser(u)
	if !fn(u) {
		return false, nil
	}
	if err := st.saveLocked(); err != nil {
		st.users[name] = before
		return false, err
	}
	return true, nil
}

// mutateAll runs fn on every user under a single hold of the store lock,
// persisting once at the end rather than once per user -- #66's global
// "revoke every session now" admin action needs every user's Gen bumped
// atomically with respect to any concurrent per-user mutation (a login
// completing mid-sweep must not read a Gen this pass was about to bump but
// hadn't yet), which calling mutate() in a loop (lock/unlock per user)
// would not guarantee. Rolls back to the pre-mutation snapshot on save
// failure, the same all-or-nothing contract mutateIf gives a single user.
func (st *userStore) mutateAll(fn func(*User) bool) (changed int, err error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	before := make(map[string]*User, len(st.users))
	for name, u := range st.users {
		before[name] = cloneUser(u)
	}
	for _, u := range st.users {
		if fn(u) {
			changed++
		}
	}
	if changed == 0 {
		return 0, nil
	}
	if err := st.saveLocked(); err != nil {
		st.users = before
		return 0, err
	}
	return changed, nil
}

// mutateAdminGuarded runs fn on the named user under the store lock,
// passing the count of *other* enabled administrators computed under that
// same lock — so fn can atomically refuse an action that would leave zero
// enabled admins (disable, delete, demote). The previous approach called
// adminCount() and get() as two separate, independently-locked reads
// before the mutation; nothing held the lock across the gap, so two
// concurrent admin actions against different accounts could each see
// "not the last admin" and both proceed, driving the count to zero. fn
// returning a non-nil error (typically errLastAdmin) aborts without
// persisting; the same error is returned here.
func (st *userStore) mutateAdminGuarded(name string, fn func(u *User, otherEnabledAdmins int) error) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	u := st.users[name]
	if u == nil {
		return errNoSuchUser
	}
	others := 0
	for uname, other := range st.users {
		if uname != name && other.Role == roleAdmin && !other.Disabled {
			others++
		}
	}
	before := cloneUser(u)
	if err := fn(u, others); err != nil {
		return err
	}
	if err := st.saveLocked(); err != nil {
		st.users[name] = before
		return err
	}
	return nil
}

// deleteAdminGuarded removes name, refusing atomically (see
// mutateAdminGuarded) if name is the last enabled administrator.
func (st *userStore) deleteAdminGuarded(name string) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	u, ok := st.users[name]
	if !ok {
		return errNoSuchUser
	}
	others := 0
	for uname, other := range st.users {
		if uname != name && other.Role == roleAdmin && !other.Disabled {
			others++
		}
	}
	if u.Role == roleAdmin && !u.Disabled && others == 0 {
		return errLastAdmin
	}
	oldStep, hadStep := st.lastStep[name]
	delete(st.users, name)
	delete(st.lastStep, name)
	if err := st.saveLocked(); err != nil {
		st.users[name] = u
		if hadStep {
			st.lastStep[name] = oldStep
		}
		return err
	}
	return nil
}

func (st *userStore) create(u *User) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	if _, ok := st.users[u.Username]; ok {
		return errors.New("user already exists")
	}
	if u.Subject == "" {
		u.Subject = uuid.NewString()
	} else if _, err := uuid.Parse(u.Subject); err != nil {
		return errors.New("invalid user subject")
	}
	for _, existing := range st.users {
		if existing.Subject == u.Subject {
			return errors.New("user subject already exists")
		}
	}
	st.users[u.Username] = u
	if err := st.saveLocked(); err != nil {
		delete(st.users, u.Username)
		return err
	}
	return nil
}

// rename changes a user's username, the map key everything (sessions,
// TOTP-replay state, the login store itself) is keyed on. Subject, Created,
// and every other field are preserved unchanged. Session cookies embed the
// username directly (sessionClaims.user, token.go), so a rename cannot keep
// existing sessions valid the way disable/reset_password already don't —
// Gen and DeviceGen are bumped here for the same reason those actions bump
// them, forcing a fresh login under the new name.
func (st *userStore) rename(oldName, newName string) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	if !usernameRe.MatchString(newName) {
		return errors.New("username must be 1-32 chars of a-z 0-9 . _ -")
	}
	u, ok := st.users[oldName]
	if !ok {
		return errNoSuchUser
	}
	if oldName == newName {
		return nil
	}
	if _, taken := st.users[newName]; taken {
		return errors.New("username already taken")
	}
	oldStep, hadStep := st.lastStep[oldName]
	u.Username = newName
	u.Gen++
	u.DeviceGen++
	delete(st.users, oldName)
	st.users[newName] = u
	delete(st.lastStep, oldName)
	if hadStep {
		st.lastStep[newName] = oldStep
	}
	if err := st.saveLocked(); err != nil {
		// Roll back: restore the old key/name/counters and TOTP-replay state.
		u.Username = oldName
		u.Gen--
		u.DeviceGen--
		delete(st.users, newName)
		st.users[oldName] = u
		delete(st.lastStep, newName)
		if hadStep {
			st.lastStep[oldName] = oldStep
		}
		return err
	}
	return nil
}

// checkPassword verifies the password against the stored hash, burning
// comparable time on unknown users so the response can't be used for
// enumeration. Existing bcrypt hashes are accepted and transparently
// upgraded to Argon2id on successful login.
func (st *userStore) checkPassword(name, password string) bool {
	u := st.get(name)
	if u == nil {
		_, _ = verifyArgon2id(password, dummyArgon2Hash)
		return false
	}
	if looksLikeBcrypt(u.Hash) {
		if bcrypt.CompareHashAndPassword([]byte(u.Hash), []byte(password)) != nil {
			return false
		}
		// Transparent upgrade: re-hash with Argon2id and persist. A persist
		// failure is non-fatal — the upgrade is retried on the next login.
		if newHash, err := hashPassword(password); err == nil {
			_ = st.mutate(name, func(u *User) bool { u.Hash = newHash; return true })
		}
		return true
	}
	ok, _ := verifyArgon2id(password, u.Hash)
	return ok
}

// checkTOTP validates a code against the user's committed secret with replay
// protection: each 30s step is accepted at most once. lastStep is persisted
// to disk so replay protection survives container restarts.
func (st *userStore) checkTOTP(name, code string) bool {
	u := st.get(name)
	if u == nil || u.TOTPSecret == "" {
		return false
	}
	ok, step := totpValidStep(u.TOTPSecret, code)
	if !ok {
		return false
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if step <= st.lastStep[name] {
		return false
	}
	old, hadOld := st.lastStep[name]
	st.lastStep[name] = step
	if err := st.saveLocked(); err != nil {
		if hadOld {
			st.lastStep[name] = old
		} else {
			delete(st.lastStep, name)
		}
		return false
	}
	return true
}

// checkBackupCode consumes a one-time recovery code if it matches.
func (st *userStore) checkBackupCode(name, code string) bool {
	h := hashBackupCode(code)
	used := false
	err := st.mutate(name, func(u *User) bool {
		for i, c := range u.BackupCodes {
			if c == h {
				u.BackupCodes = append(u.BackupCodes[:i], u.BackupCodes[i+1:]...)
				used = true
				return true
			}
		}
		return false
	})
	return err == nil && used
}

// --- generation helpers -----------------------------------------------------

var b32enc = base32.StdEncoding.WithPadding(base32.NoPadding)

func newTOTPSecret() string {
	raw := randomBytes(20)
	return b32enc.EncodeToString(raw)
}

// newTempPassword returns a readable one-time password like "H4KQ-PW2N-XJ7R".
func newTempPassword() string {
	raw := randomBytes(8)
	s := b32enc.EncodeToString(raw)
	return s[0:4] + "-" + s[4:8] + "-" + s[8:12]
}

// newBackupCodes returns n plaintext codes ("ABCDE-23456") plus their hashes.
func newBackupCodes(n int) (plain, hashed []string) {
	for i := 0; i < n; i++ {
		raw := randomBytes(7)
		s := b32enc.EncodeToString(raw)[:10]
		code := s[:5] + "-" + s[5:]
		plain = append(plain, code)
		hashed = append(hashed, hashBackupCode(code))
	}
	return
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return b
}

func cloneUser(u *User) *User {
	if u == nil {
		return nil
	}
	raw, err := json.Marshal(u)
	if err != nil {
		panic(err)
	}
	var out User
	if err := json.Unmarshal(raw, &out); err != nil {
		panic(err)
	}
	return &out
}

func hashBackupCode(code string) string {
	norm := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(code), " ", ""))
	sum := sha256.Sum256([]byte(norm))
	return hex.EncodeToString(sum[:])
}

// --- password policy ---------------------------------------------------------

const (
	minPasswordLen   = 15
	maxPasswordBytes = 72
)

// validatePassword enforces the password policy for user-chosen passwords
// (NIST SP 800-63B aligned): at least 15 characters, and at most 72 bytes —
// legacy bcrypt hashes truncate at 72 bytes, so longer inputs are rejected
// rather than silently weakened. Existing stored passwords are unaffected;
// the policy applies only when a password is (re)set.
func validatePassword(pw string) error {
	if len([]rune(pw)) < minPasswordLen {
		return fmt.Errorf("must be at least %d characters", minPasswordLen)
	}
	if len(pw) > maxPasswordBytes {
		return fmt.Errorf("must not exceed %d bytes when UTF-8 encoded", maxPasswordBytes)
	}
	return nil
}

// passwordWasUsedBefore reports whether pw matches the user's current
// password or any retained previous one (#63). Checked against Hash with
// the same bcrypt-or-Argon2id awareness checkPassword uses (Hash can still
// be a legacy bcrypt hash for a user who hasn't logged in since the
// Argon2id upgrade shipped); PasswordHistory entries are always Argon2id
// (see the field's own doc comment), so those go straight to
// verifyArgon2id. Every comparison runs regardless of an early match --
// short-circuiting on the first hit would make how many prior passwords
// exist observable via timing, the same reasoning this codebase's other
// constant-time credential checks already document.
func passwordWasUsedBefore(pw string, u *User) bool {
	found := false
	if looksLikeBcrypt(u.Hash) {
		if bcrypt.CompareHashAndPassword([]byte(u.Hash), []byte(pw)) == nil {
			found = true
		}
	} else if ok, _ := verifyArgon2id(pw, u.Hash); ok {
		found = true
	}
	for _, h := range u.PasswordHistory {
		if ok, _ := verifyArgon2id(pw, h); ok {
			found = true
		}
	}
	return found
}

// recordPasswordHistory prepends the hash a password change is about to
// replace (not the new one) and trims to keep. keep<=0 clears/disables
// history entirely -- an operator turning PASSWORD_HISTORY_COUNT off is
// choosing not to retain this data, not just to stop checking it.
func recordPasswordHistory(u *User, replacedHash string, keep int) {
	if keep <= 0 {
		u.PasswordHistory = nil
		return
	}
	u.PasswordHistory = append([]string{replacedHash}, u.PasswordHistory...)
	if len(u.PasswordHistory) > keep {
		u.PasswordHistory = u.PasswordHistory[:keep]
	}
}

// --- Argon2id password hashing (PHC format) ----------------------------------

const (
	argon2Time    = 3
	argon2Memory  = 64 * 1024 // 64 MB
	argon2Threads = 4
	argon2KeyLen  = 32
	argon2SaltLen = 16
)

func hashPassword(pw string) (string, error) {
	salt := randomBytes(argon2SaltLen)
	hash := argon2.IDKey([]byte(pw), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argon2Memory, argon2Time, argon2Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash)), nil
}

// verifyArgon2id checks a password against an argon2id PHC string.
func verifyArgon2id(pw, encoded string) (bool, error) {
	salt, hash, time, memory, threads, keyLen, err := parseArgon2idPHC(encoded)
	if err != nil {
		return false, err
	}
	other := argon2.IDKey([]byte(pw), salt, time, memory, threads, keyLen)
	return subtle.ConstantTimeCompare(hash, other) == 1, nil
}

// parseArgon2idPHC decodes "$argon2id$v=19$m=…,t=…,p=…$salt$hash" (inline
// parser — short enough to avoid an extra dependency). Parameters are
// sanity-capped so a corrupt store can't cause an unbounded allocation.
func parseArgon2idPHC(encoded string) (salt, hash []byte, time, memory uint32, threads uint8, keyLen uint32, err error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return nil, nil, 0, 0, 0, 0, errors.New("not an argon2id PHC string")
	}
	var version int
	if _, err = fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return nil, nil, 0, 0, 0, 0, errors.New("unsupported argon2 version")
	}
	if _, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return nil, nil, 0, 0, 0, 0, errors.New("bad argon2 parameters")
	}
	if memory == 0 || memory > 1<<20 || time == 0 || time > 10 || threads == 0 {
		return nil, nil, 0, 0, 0, 0, errors.New("argon2 parameters out of range")
	}
	if salt, err = base64.RawStdEncoding.DecodeString(parts[4]); err != nil || len(salt) == 0 {
		return nil, nil, 0, 0, 0, 0, errors.New("bad argon2 salt")
	}
	if hash, err = base64.RawStdEncoding.DecodeString(parts[5]); err != nil || len(hash) == 0 {
		return nil, nil, 0, 0, 0, 0, errors.New("bad argon2 hash")
	}
	return salt, hash, time, memory, threads, uint32(len(hash)), nil
}
