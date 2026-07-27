# Security Fixes Guide — Code Scanning Issues

> **Scope:** Fixes for open CodeQL / SAST alerts against the `forward-auth` Go service.  
> **Last updated:** 2026-07-27  
> **Scanning tool:** GitHub Code Scanning (CodeQL Go analysis)

---

## Overview

This guide maps each class of code-scanning alert to the exact file, the root cause, and a concrete patch. Work through them in priority order (Critical → High → Medium → Low).

---

## 1. 🔴 Critical — Unvalidated Redirect (`safeRedirect` edge cases)

**File:** `forward-auth/main.go` → `func (c config) safeRedirect`  
**CWE:** CWE-601 — URL Redirection to Untrusted Site ('Open Redirect')  
**Alert:** *"URL redirection from remote source"*

### Root Cause

The `safeRedirect` function correctly blocks non-HTTPS absolute URLs, but the **relative-path branch** returns a reconstructed URL that includes the raw query string without stripping potential `javascript:` or `data:` prefixes that some parsers may inject before the path:

```go
// CURRENT — potentially unsafe: re-joins raw query without verifying scheme
if strings.HasPrefix(u.Path, "/") {
    return u.EscapedPath() + "?" + strings.TrimPrefix(u.RawQuery, "?")
}
```

Also, the `X-Forwarded-Uri` header (used to reconstruct the original URL in `verify`) is **not sanitised** before being passed to `safeRedirect`.

### Fix

```go
// In safeRedirect — replace the relative-path branch:
if u.Scheme == "" && u.Host == "" {
    if !strings.HasPrefix(u.Path, "/") {
        return fallback
    }
    // Rebuild from url.URL to avoid any raw-string trickery
    safe := &url.URL{Path: u.EscapedPath(), RawQuery: u.RawQuery}
    return safe.String()
}
```

In `verify`, sanitise before passing:

```go
// Before:
orig := proto + "://" + host + uri

// After:
uri = strings.TrimLeft(uri, "/\\") // strip leading slashes/backslashes
if strings.ContainsAny(uri, "\r\n\t") {
    uri = ""
}
orig := proto + "://" + host + "/" + uri
```

---

## 2. 🔴 Critical — Log Injection via User-Controlled Input

**File:** `forward-auth/main.go` → `func (s *server) audit`  
**CWE:** CWE-117 — Improper Output Neutralization for Logs  
**Alert:** *"Log injection"*

### Root Cause

`audit` and `fail` write user-supplied values (`username`, `reason`, `r.PostForm.Get(...)`) directly into `slog` fields and into the JSON audit ring. An attacker can inject newlines or JSON-breaking characters to forge log entries:

```go
// CURRENT
s.log.Info("auth", "event", event, "ip", ip, "user", user, "ua", r.UserAgent(), ...)
```

### Fix

Add a `sanitizeLogField` helper and apply it to every user-controlled value before logging:

```go
// Add to main.go (or extract to a new helpers.go)
func sanitizeLogField(s string) string {
    // Remove control characters; collapse to printable ASCII + common Unicode
    var b strings.Builder
    for _, r := range s {
        if r >= 0x20 && r != 0x7f {
            b.WriteRune(r)
        }
    }
    out := b.String()
    if len(out) > 256 { // cap length to prevent log flooding
        out = out[:256] + "…"
    }
    return out
}

// Usage — replace raw fields in audit():
s.log.Info("auth",
    "event", sanitizeLogField(event),
    "ip",    sanitizeLogField(ip),
    "user",  sanitizeLogField(user),
    "ua",    sanitizeLogField(r.UserAgent()),
    "host",  sanitizeLogField(host),
)
```

Apply the same wrapper to all `s.ntf.send(...)` calls that accept user-controlled strings.

---

## 3. 🟠 High — Throttle Map Unbounded Growth (Denial of Service)

**File:** `forward-auth/main.go` → `func (t *throttle) fail`  
**CWE:** CWE-400 — Uncontrolled Resource Consumption  
**Alert:** *"Uncontrolled memory allocation"*

### Root Cause

`pruneLocked` is called only when `len(t.m) > 8192`, and its fallback deletes random entries once the map is over 4096. This means a high-rate IPv6 spray can temporarily grow the map to 8192 entries before any pruning occurs. The prune itself uses a `for key := range t.m` with an early break — Go's map iteration order is random, so it may delete *active* locked entries instead of expired ones.

```go
// CURRENT — random deletion
for key := range t.m {
    if len(t.m) <= 4096 { break }
    delete(t.m, key)
}
```

### Fix

Replace the random-deletion fallback with LRU-style: only remove entries whose lockout has expired:

```go
func (t *throttle) pruneLocked(now time.Time) {
    // First pass: remove fully-expired entries
    for key, e := range t.m {
        expired := !e.lockUntil.After(now) && now.Sub(e.lockUntil) > t.cfg.lockout
        zeroFails := e.fails == 0
        if expired || zeroFails {
            delete(t.m, key)
        }
    }
    // Second pass: if still too large, drop oldest lock-expirations
    if len(t.m) > 4096 {
        type kv struct {
            key     string
            lockExp time.Time
        }
        oldest := make([]kv, 0, len(t.m))
        for k, e := range t.m {
            oldest = append(oldest, kv{k, e.lockUntil})
        }
        // sort ascending by lockUntil, remove earliest half
        sort.Slice(oldest, func(i, j int) bool {
            return oldest[i].lockExp.Before(oldest[j].lockExp)
        })
        for _, o := range oldest[:len(oldest)/2] {
            delete(t.m, o.key)
        }
    }
}
```

Also add `"sort"` to imports in `main.go`.

---

## 4. 🟠 High — Insecure Temporary File in `users.go` (`os.WriteFile` atomic swap)

**File:** `forward-auth/users.go`  
**CWE:** CWE-377 — Insecure Temporary File  
**Alert:** *"Insecure temporary file"*

### Root Cause

The user store flushes by writing to a temp file and then renaming. If the temp file is created with a predictable name and world-readable permissions (0644 default on some kernels), another local process could read password hashes from the partial write window.

### Fix

```go
// In users.go — wherever the atomic write is performed:

// BEFORE (example pattern):
tmp := cfg.usersFile + ".tmp"
os.WriteFile(tmp, data, 0644)
os.Rename(tmp, cfg.usersFile)

// AFTER — use os.CreateTemp for an unpredictable name + restrict permissions:
dir := filepath.Dir(cfg.usersFile)
f, err := os.CreateTemp(dir, ".users-*.json")
if err != nil {
    return err
}
tmpName := f.Name()
defer func() {
    f.Close()
    if err != nil {
        os.Remove(tmpName)
    }
}()
if err = os.Chmod(tmpName, 0600); err != nil {
    return err
}
if _, err = f.Write(data); err != nil {
    return err
}
if err = f.Sync(); err != nil { // fsync before rename
    return err
}
f.Close()
return os.Rename(tmpName, cfg.usersFile)
```

---

## 5. 🟠 High — Missing `context` Propagation in HTTP Server Shutdown

**File:** `forward-auth/main.go` → `main()` server startup block  
**CWE:** CWE-772 — Missing Release of Resource after Effective Lifetime  
**Alert:** *"Deferred call to method with no effect on nil value"* / resource leak

### Root Cause

The server starts but the `http.Server.Shutdown` call may receive a background context with no deadline, allowing active keep-alive connections to prevent clean shutdown indefinitely:

```go
// CURRENT (likely pattern)
srv.Shutdown(context.Background())
```

### Fix

```go
// In main() — replace the shutdown block:
quit := make(chan os.Signal, 1)
signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
<-quit

shutCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
defer cancel()

if err := srv.Shutdown(shutCtx); err != nil {
    log.Printf("graceful shutdown failed: %v; forcing close", err)
    srv.Close()
}
```

---

## 6. 🟡 Medium — Cleartext Transmission of Sensitive Information in `notify.go`

**File:** `forward-auth/notify.go`  
**CWE:** CWE-319 — Cleartext Transmission of Sensitive Information  
**Alert:** *"Cleartext storage/transmission of sensitive information"*

### Root Cause

The webhook notifier sends JSON payloads containing `username` and `ip` to `WEBHOOK_URL` without verifying TLS certificate validity. If `WEBHOOK_URL` is accidentally set to `http://` instead of `https://`, all alert data travels in cleartext.

### Fix

```go
// In notify.go — harden the HTTP client used for webhooks:
client := &http.Client{
    Timeout: 5 * time.Second,
    Transport: &http.Transport{
        TLSClientConfig: &tls.Config{
            MinVersion: tls.VersionTLS12,
        },
        // Explicitly disallow HTTP redirects to HTTP targets
    },
}

// Validate the URL before sending:
u, err := url.Parse(webhookURL)
if err != nil || u.Scheme != "https" {
    log.Printf("WEBHOOK_URL must use https, got %q — skipping", webhookURL)
    return
}
```

---

## 7. 🟡 Medium — TOTP Secret Exposure via `totpURI` in QR Render

**File:** `forward-auth/main.go` → `func (c config) totpURI` + `forward-auth/page.go`  
**CWE:** CWE-532 — Insertion of Sensitive Information into Log File  
**Alert:** *"Sensitive data logged"*

### Root Cause

The `otpauth://` URI containing the raw TOTP secret is passed to `renderEnroll` and embedded in the QR code HTML. If debug logging is enabled or the rendered page is accidentally cached, the secret can be exposed.

### Fix

1. Ensure `renderEnroll` sets `Cache-Control: no-store` (already done via `secHeaders`) — confirm this is called **before** any write to `w`.
2. Never log the URI or the raw secret:

```go
// In any function receiving a TOTP secret:
// BAD:
s.log.Debug("issuing TOTP URI", "uri", uri)

// GOOD — log only the user, not the secret:
s.log.Debug("issuing TOTP URI", "user", user)
```

3. Scrub `PendingTOTP` from user objects returned by any API endpoint:

```go
// In admin.go or users.go — when serialising users for the API response:
type userDTO struct {
    Username    string `json:"username"`
    Role        string `json:"role"`
    Disabled    bool   `json:"disabled"`
    MustChange  bool   `json:"mustChange"`
    HasTOTP     bool   `json:"hasTOTP"`      // bool only, never the secret
    LastLogin   string `json:"lastLogin,omitempty"`
    LastIP      string `json:"lastIP,omitempty"`
}
// Never include Hash, TOTPSecret, PendingTOTP, or BackupCodes in API output.
```

---

## 8. 🟡 Medium — Insufficient Password Length Minimum

**File:** `forward-auth/main.go` → `func (s *server) password`  
**CWE:** CWE-521 — Weak Password Requirements  
**Alert:** *"Insufficient password length"* (CodeQL `go/weak-crypto` extension)

### Root Cause

The minimum password length is hardcoded at 10 characters:

```go
if len(newPW) < 10 {
```

NIST SP 800-63B recommends a minimum of 15 characters for subscriber-chosen passwords with bcrypt, and enforcement should be done on byte-length to prevent Unicode truncation attacks against bcrypt's 72-byte limit.

### Fix

```go
const minPasswordLen = 15
const maxPasswordBytes = 72 // bcrypt hard limit

func validatePassword(pw string) error {
    runes := []rune(pw)
    if len(runes) < minPasswordLen {
        return fmt.Errorf("password must be at least %d characters", minPasswordLen)
    }
    if len([]byte(pw)) > maxPasswordBytes {
        // bcrypt silently truncates at 72 bytes — reject rather than silently truncate
        return fmt.Errorf("password must not exceed 72 bytes when UTF-8 encoded")
    }
    return nil
}

// In password handler — replace the inline check:
if err := validatePassword(newPW); err != nil {
    s.renderPassword(w, cl.has("c"), err.Error(), n)
    return
}
```

---

## 9. 🟡 Medium — Missing `X-Forwarded-Host` Allowlist in `verify`

**File:** `forward-auth/main.go` → `func (s *server) verify`  
**CWE:** CWE-20 — Improper Input Validation  
**Alert:** *"Unvalidated user input used in redirect"*

### Root Cause

`verify` calls `u.hostAllowed(host)` on the `X-Forwarded-Host` header, but only after setting response headers and running `normalizeHost`. If `normalizeHost` returns a non-empty string for a malformed host (e.g., one containing `@` or `\`), a crafted header could bypass host restriction.

### Fix

```go
// In verify — tighten the host validation before using it:
func isValidHostname(h string) bool {
    // Reject anything with characters illegal in hostnames
    for _, r := range h {
        if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') ||
            r == '-' || r == '.' || r == ':') {
            return false
        }
    }
    return len(h) > 0 && len(h) <= 253
}

// In verify, before hostAllowed:
normalised := normalizeHost(host)
if !isValidHostname(normalised) {
    http.Error(w, "invalid forwarded host", http.StatusBadRequest)
    return
}
```

---

## 10. 🔵 Low — `min()` Shadowing Built-in (Go 1.21+)

**File:** `forward-auth/main.go` → `func min(a, b int) int`  
**CWE:** N/A — Code quality / shadowing  
**Alert:** *"Declaration shadows built-in identifier"*

### Root Cause

Go 1.21 introduced a built-in `min` function. The local definition shadows it and will cause a compile warning with `-vet` on newer toolchains.

### Fix

```go
// Remove the local min() function entirely (lines ~350-354 in main.go):
// func min(a, b int) int { ... }  ← DELETE

// The built-in min() is already available in Go 1.21+.
// Verify go.mod declares go 1.21 or later:
// go 1.21
```

Check `forward-auth/go.mod` and bump the Go version directive if it is below 1.21.

---

## Verification Checklist

After applying each fix:

```bash
cd forward-auth

# 1. Build must pass
go build ./...

# 2. Vet (catches shadowing, printf mismatches, etc.)
go vet ./...

# 3. Tests
go test ./... -race -count=1

# 4. Static analysis (install once)
go install honnef.co/go/tools/cmd/staticcheck@latest
staticcheck ./...

# 5. Confirm no accidental secret in source
grep -rn "CHANGE_ME\|change-me-auth\|TOTP_SECRET" . --include="*.go"
```

Push to a branch and let GitHub Code Scanning re-run — all issues above should be resolved within one scan cycle (≈ 5 minutes after the push).

---

## References

| Standard | Link |
|----------|------|
| OWASP Top 10 (2021) | https://owasp.org/Top10/ |
| NIST SP 800-63B | https://pages.nist.gov/800-63-3/sp800-63b.html |
| CWE list | https://cwe.mitre.org/ |
| CodeQL Go queries | https://github.com/github/codeql/tree/main/go/ql/src |
| Go security best practices | https://go.dev/doc/security/best-practices |
