# Login UI Redesign Guide — Claude-style Dark Theme

This guide covers every step to wire the two new HTML templates
(`forward-auth/ui/login.html`, `forward-auth/ui/verify.html`) into the
existing Go `forward-auth` service.

---

## Table of Contents

1. [Design system](#1-design-system)
2. [File map](#2-file-map)
3. [Step 1 — Embed templates in Go](#3-step-1--embed-templates-in-go)
4. [Step 2 — Template data structs](#4-step-2--template-data-structs)
5. [Step 3 — Render the login page](#5-step-3--render-the-login-page)
6. [Step 4 — Render the verify/2FA page](#6-step-4--render-the-verify2fa-page)
7. [Step 5 — Add Go template helper functions](#7-step-5--add-go-template-helper-functions)
8. [Step 6 — Wire the TOTP route](#8-step-6--wire-the-totp-route)
9. [Step 7 — Wire the passkey buttons](#9-step-7--wire-the-passkey-buttons)
10. [Step 8 — Add a /auth/resend endpoint](#10-step-8--add-a-authresend-endpoint)
11. [Step 9 — Google OAuth button](#11-step-9--google-oauth-button)
12. [Step 10 — CSP + security headers](#12-step-10--csp--security-headers)
13. [Mobile & accessibility](#13-mobile--accessibility)
14. [Replacing Tailwind CDN with a build step](#14-replacing-tailwind-cdn-with-a-build-step)
15. [Checklist](#15-checklist)

---

## 1. Design system

The UI matches Claude's login aesthetics:

| Token | Value | Use |
|---|---|---|
| `bg` | `#1a1a1a` | Page background |
| `surface` | `#242424` | Card / input background |
| `border` | `#2e2e2e` | Borders, dividers |
| `muted` | `#8a8a8a` | Secondary text, placeholders |
| `primary` | `#d4764e` | Terracotta accent (focus rings, icons) |
| `inputbg` | `#1f1f1f` | Text input fill |

Typography:
- Headlines: `Georgia` (serif) — matches Claude's "Question what's next" heading.
- Body / UI: `Inter` (sans-serif) loaded from Google Fonts.

Layout:
- Centred column, `max-w-sm` (384 px) card.
- `rounded-2xl` card with `shadow-xl` and `border border-border`.
- Tailwind CDN for rapid prototyping (see §14 for production build).

---

## 2. File map

```
forward-auth/
  ui/
    login.html          ← Step 1 screen: email + Google + passkey
    verify.html         ← Step 2 screen: TOTP / email-OTP + alternatives
  page.go               ← existing: replace loginPage() / verifyPage()
  main.go               ← existing: no route changes needed
  totp.go               ← existing: add /auth/totp POST handler
```

---

## 3. Step 1 — Embed templates in Go

Add an `embed.FS` at the top of `page.go` (Go 1.16+):

```go
import (
    "embed"
    "html/template"
)

//go:embed ui/*.html
var uiFS embed.FS

var (
    loginTmpl  = template.Must(template.New("").Funcs(tmplFuncs).ParseFS(uiFS, "ui/login.html"))
    verifyTmpl = template.Must(template.New("").Funcs(tmplFuncs).ParseFS(uiFS, "ui/verify.html"))
)
```

The `tmplFuncs` map is defined in Step 5.

---

## 4. Step 2 — Template data structs

Add these structs to `page.go`:

```go
// LoginPageData is passed to ui/login.html
type LoginPageData struct {
    AppName      string
    CSRFToken    string
    Redirect     string
    GoogleOAuthURL string  // empty string disables the Google button
    Error        string
}

// VerifyPageData is passed to ui/verify.html
type VerifyPageData struct {
    AppName   string
    CSRFToken string
    Redirect  string
    // Mode = "email" → shows mailbox + OTP boxes
    // Mode = "totp"  → shows shield + TOTP boxes
    Mode      string
    Email     string // only used when Mode == "email"
    Error     string
}
```

---

## 5. Step 3 — Render the login page

Replace your existing `loginPage()` function in `page.go`:

```go
func (s *server) loginPage(w http.ResponseWriter, r *http.Request, errMsg string) {
    data := LoginPageData{
        AppName:       s.config.appName,
        CSRFToken:     s.config.csrfToken(r),
        Redirect:      r.URL.Query().Get("rd"),
        GoogleOAuthURL: s.config.googleOAuthURL(r),  // returns "" if GOOGLE_CLIENT_ID unset
        Error:         errMsg,
    }
    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    if err := loginTmpl.ExecuteTemplate(w, "login.html", data); err != nil {
        http.Error(w, "template error", http.StatusInternalServerError)
    }
}
```

In your login `POST` handler, after password verification fails, call:

```go
s.loginPage(w, r, "Incorrect password. Please try again.")
```

---

## 6. Step 4 — Render the verify/2FA page

```go
// verifyPage renders the TOTP or email-OTP screen.
// mode must be "totp" or "email".
func (s *server) verifyPage(w http.ResponseWriter, r *http.Request, mode, email, errMsg string) {
    data := VerifyPageData{
        AppName:   s.config.appName,
        CSRFToken: s.config.csrfToken(r),
        Redirect:  r.URL.Query().Get("rd"),
        Mode:      mode,
        Email:     email,
        Error:     errMsg,
    }
    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    if err := verifyTmpl.ExecuteTemplate(w, "verify.html", data); err != nil {
        http.Error(w, "template error", http.StatusInternalServerError)
    }
}
```

Call sites:

```go
// After password OK, user has TOTP enabled:
s.verifyPage(w, r, "totp", "", "")

// After email OTP sent:
s.verifyPage(w, r, "email", email, "")

// Wrong TOTP code:
s.verifyPage(w, r, "totp", "", "Invalid code — please try again.")
```

---

## 7. Step 5 — Add Go template helper functions

The `verify.html` template uses `seq` and `add` to generate the 6 OTP boxes.
Add this `FuncMap` before parsing templates:

```go
var tmplFuncs = template.FuncMap{
    // seq returns a slice [0, 1, 2, ... n-1] for ranging
    "seq": func(n int) []int {
        s := make([]int, n)
        for i := range s { s[i] = i }
        return s
    },
    // add is used for 1-indexed ARIA labels
    "add": func(a, b int) int { return a + b },
}
```

Update the template parse calls to use `tmplFuncs` as shown in Step 1.

---

## 8. Step 6 — Wire the TOTP route

In `main.go`, ensure this route exists:

```go
mux.HandleFunc("/auth/totp", s.handleTOTP)
```

In `totp.go`, add the POST handler:

```go
func (s *server) handleTOTP(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
        return
    }
    if err := s.config.checkCSRF(r); err != nil {
        http.Error(w, "CSRF", http.StatusForbidden)
        return
    }

    code := strings.TrimSpace(r.FormValue("code"))
    rd   := r.FormValue("rd")

    // Load the pending-2FA session (set after password OK)
    pending := s.config.getPendingSession(r)
    if pending == nil {
        http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
        return
    }

    // Validate the TOTP code (uses totp.go:validateTOTP)
    if !s.config.validateTOTP(pending.username, code) {
        s.verifyPage(w, r, "totp", "", "Invalid code — please try again.")
        return
    }

    // Upgrade to full session
    s.config.issueSession(w, r, pending.username, rd)
}
```

`getPendingSession` should read a short-lived (5 min) HMAC cookie set after
password verification succeeds, marking that 2FA is still required.

---

## 9. Step 7 — Wire the passkey buttons

The `login.html` passkey button calls `startPasskeyAuth()` which already hits:

- `POST /auth/passkey/authenticate/begin` — existing `passkeypage.go` endpoint
- `POST /auth/passkey/authenticate/finish` — existing `passkeys.go` endpoint

No route changes are needed — the JavaScript handles the full WebAuthn ceremony.

The `verify.html` "Use a passkey instead" link goes to `/auth/passkey`:

```go
// In main.go — already registered via passkeypage.go:
mux.HandleFunc("/auth/passkey", s.passkeyPage)
```

---

## 10. Step 8 — Add a /auth/resend endpoint

The `verify.html` email mode has a "Resend email" button that POSTs to `/auth/resend`.
Add this handler to `main.go` / `notify.go`:

```go
mux.HandleFunc("/auth/resend", s.handleResend)

func (s *server) handleResend(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }
    if err := s.config.checkCSRF(r); err != nil {
        http.Error(w, "CSRF", http.StatusForbidden)
        return
    }
    pending := s.config.getPendingSession(r)
    if pending == nil {
        http.Error(w, "no pending session", http.StatusBadRequest)
        return
    }
    // Re-send OTP/magic-link using existing notify.go helpers
    if err := s.config.sendLoginEmail(pending.username); err != nil {
        http.Error(w, "send failed", http.StatusInternalServerError)
        return
    }
    w.WriteHeader(http.StatusOK)
}
```

Rate-limit this endpoint: max 3 resends per 10 min per pending session.

```go
// Simple in-memory rate limit (add to config struct):
if s.resendLimiter.Allow(pending.username) == false {
    http.Error(w, "too many requests", http.StatusTooManyRequests)
    return
}
```

---

## 11. Step 9 — Google OAuth button

The Google button renders only when `GoogleOAuthURL` is non-empty in the template:

```go
// Add to config struct:
googleOAuthURL func(r *http.Request) string

// In loadConfig():
if clientID := os.Getenv("GOOGLE_CLIENT_ID"); clientID != "" {
    secret := os.Getenv("GOOGLE_CLIENT_SECRET")
    cfg.googleOAuthURL = func(r *http.Request) string {
        state := cfg.csrfToken(r)  // reuse CSRF token as OAuth state
        return fmt.Sprintf(
            "https://accounts.google.com/o/oauth2/auth?client_id=%s"+
            "&redirect_uri=%s&response_type=code&scope=openid+email+profile&state=%s",
            url.QueryEscape(clientID),
            url.QueryEscape(cfg.authHost+"/auth/google/callback"),
            url.QueryEscape(state),
        )
    }
} else {
    cfg.googleOAuthURL = func(_ *http.Request) string { return "" }
}
```

Add env vars to `.env.example`:

```
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
```

Add these to `.env.example` and leave blank — the button is hidden when unset.

---

## 12. Step 10 — CSP + security headers

The Tailwind CDN and Google Fonts require adjustments to the Content Security Policy.
Add to your Traefik `middlewares` or the Go response writer:

```
Content-Security-Policy:
  default-src 'none';
  script-src  'self' https://cdn.tailwindcss.com;
  style-src   'self' 'unsafe-inline' https://fonts.googleapis.com;
  font-src    https://fonts.gstatic.com;
  img-src     'self' data:;
  connect-src 'self';
  form-action 'self';
  frame-ancestors 'none';
```

> **Note**: For production, replace the Tailwind CDN `<script>` with a pre-built
> `tailwind.min.css` (see §14) and remove `cdn.tailwindcss.com` from `script-src`.

---

## 13. Mobile & accessibility

- All inputs have `autocomplete` attributes (`username`, `one-time-code`).
- OTP boxes have `aria-label="Digit N"` for screen readers.
- The form uses native `<form>` + `<button type="submit">` — works without JS.
- The passkey button degrades gracefully: if `navigator.credentials` is absent,
  `showError()` displays a message; the email path remains fully functional.
- Viewport is set to `width=device-width, initial-scale=1.0`.
- Touch target minimum: all buttons and inputs are `py-3` (≥ 48 px height).

---

## 14. Replacing Tailwind CDN with a build step

For production, generate a minified CSS file instead of loading the 100 KB CDN script:

```bash
# Install Tailwind CLI (no Node required)
curl -sLO https://github.com/tailwindlabs/tailwindcss/releases/latest/download/tailwindcss-linux-x64
chmod +x tailwindcss-linux-x64

# Create tailwind.config.js
cat > tailwind.config.js <<'EOF'
module.exports = {
  content: ["forward-auth/ui/**/*.html"],
  theme: {
    extend: {
      colors: {
        bg: '#1a1a1a', surface: '#242424', border: '#2e2e2e',
        muted: '#8a8a8a', primary: '#d4764e', primaryh: '#c4673f', inputbg: '#1f1f1f',
      }
    }
  }
}
EOF

# Build
./tailwindcss-linux-x64 -i /dev/null -o forward-auth/ui/tailwind.min.css --minify
```

Then in each HTML template replace:
```html
<script src="https://cdn.tailwindcss.com"></script>
<script>tailwind.config = { ... }</script>
```
With:
```html
<link rel="stylesheet" href="/auth/static/tailwind.min.css" />
```

And serve the static file from Go:
```go
//go:embed ui/tailwind.min.css
var tailwindCSS []byte

mux.HandleFunc("/auth/static/tailwind.min.css", func(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "text/css")
    w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
    w.Write(tailwindCSS)
})
```

Add the build step to the `Dockerfile`:
```dockerfile
RUN curl -sLO https://github.com/tailwindlabs/tailwindcss/releases/latest/download/tailwindcss-linux-amd64 \\
    && chmod +x tailwindcss-linux-amd64 \\
    && ./tailwindcss-linux-amd64 -i /dev/null \\
       -o forward-auth/ui/tailwind.min.css --minify \\
    && rm tailwindcss-linux-amd64
```

---

## 15. Checklist

### Templates
- [ ] `forward-auth/ui/login.html` created
- [ ] `forward-auth/ui/verify.html` created
- [ ] `//go:embed ui/*.html` added to `page.go`
- [ ] `tmplFuncs` (`seq`, `add`) registered before `template.ParseFS`

### Login page
- [ ] `LoginPageData` struct added to `page.go`
- [ ] `loginPage()` updated to render `login.html`
- [ ] Google button hidden when `GOOGLE_CLIENT_ID` unset
- [ ] Passkey button calls existing `/auth/passkey/authenticate/begin`

### 2FA / verify page
- [ ] `VerifyPageData` struct added to `page.go`
- [ ] `verifyPage(w, r, "totp", "", "")` called after password OK (TOTP users)
- [ ] `verifyPage(w, r, "email", email, "")` called after OTP email sent
- [ ] `/auth/totp` POST route wired in `main.go` → `handleTOTP`
- [ ] Pending-session cookie issued after password OK, consumed after TOTP OK

### Resend & alternatives
- [ ] `/auth/resend` POST endpoint added
- [ ] Rate limit: max 3 per 10 min per session
- [ ] "Use a passkey instead" links to `/auth/passkey`
- [ ] "Use a backup code" links to `/auth/login?backup=1`

### Security
- [ ] CSP updated for Tailwind CDN (or switch to pre-built CSS)
- [ ] `X-Frame-Options: DENY` set on all `/auth/*` responses
- [ ] `Referrer-Policy: no-referrer` set
- [ ] TOTP handler uses `subtle.ConstantTimeCompare` (via existing `validateTOTP`)
- [ ] OTP resend rate-limited

### Production
- [ ] Tailwind CDN replaced with pre-built `tailwind.min.css` (§14)
- [ ] `tailwind.min.css` built in `Dockerfile`
- [ ] Google Fonts self-hosted or proxied (for air-gapped deployments)
