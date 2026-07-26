# Login UI Redesign Guide — Claude-style Dark Theme

This guide covers every step to wire the two new HTML templates
(`forward-auth/ui/login.html`, `forward-auth/ui/verify.html`) into the
existing Go `forward-auth` service.

---

## Table of Contents

0. [Diff vs live claude.ai/login](#0-diff-vs-live-claudeailogin)
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
12. [Step 10 — SSO button](#12-step-10--sso-button)
13. [Step 11 — CSP + security headers](#13-step-11--csp--security-headers)
14. [Mobile & accessibility](#14-mobile--accessibility)
15. [Replacing Tailwind CDN with a build step](#15-replacing-tailwind-cdn-with-a-build-step)
16. [Checklist](#16-checklist)

---

## 0. Diff vs live claude.ai/login

This section documents every difference found when the current guide and templates
were verified against the **live** `claude.ai/login` page (July 2026).

| # | Element | Our previous version | Live Claude (correct) | Fixed in |
|---|---|---|---|---|
| 1 | **Headline** | "Question what's next" | **"Your ideas, amplified"** | `login.html` v2 |
| 2 | **Subtitle** | "Your thinking partner for big ambitions" | **"Privacy-first AI that helps you create in confidence."** | `login.html` v2 |
| 3 | **Button order** | Google → Passkey → OR → email | **Google → SSO → or → email** | `login.html` v2 |
| 4 | **Passkey button** | Present on login screen | **Not present** on Claude's main login screen | `login.html` v2 |
| 5 | **SSO button** | Missing | **"Continue with SSO"** is Claude's third option | `login.html` v2 |
| 6 | **Email label** | No label (placeholder only) | **"Email" label** above the input field | `login.html` v2 |
| 7 | **Legal copy** | "By continuing, you acknowledge our Privacy Policy." | **"By continuing, you agree to Anthropic's Consumer Terms and Usage Policy, and acknowledge our Privacy Policy."** (three links) | `login.html` v2 |
| 8 | **Divider text** | Uppercase `OR` | **Lowercase `or`** | `login.html` v2 |

> The `verify.html` (email OTP / TOTP) screen and the overall dark colour palette
> remained accurate — no changes needed there.

---

## 1. Design system

Colour tokens (verified against claude.ai computed styles, July 2026):

| Token | Value | Use |
|---|---|---|
| `bg` | `#1a1a1a` | Page background |
| `surface` | `#242424` | Card / button background |
| `border` | `#2e2e2e` | Borders, dividers |
| `muted` | `#8a8a8a` | Secondary text, labels, placeholders |
| `primary` | `#d4764e` | Terracotta accent — focus rings, verification icon |
| `inputbg` | `#1f1f1f` | Text input fill |

Typography:
- **Headlines**: `Georgia` (serif) — Claude uses a custom serif; Georgia is the closest
  system-font match.
- **Body / UI**: `Inter` (sans-serif) loaded from Google Fonts, weights 400/500/600.

Layout rules:
- Centered single column. Card `max-w-sm` (384 px), `rounded-2xl`, `shadow-xl`.
- All interactive elements `py-3` — minimum 48 px touch height.
- `or` divider is lowercase, flanked by `#2e2e2e` 1 px rules.

---

## 2. File map

```
forward-auth/
  ui/
    login.html          ← Login screen: Google + SSO + email (NO passkey here)
    verify.html         ← 2FA screen: TOTP or email-OTP + passkey alternative
  page.go               ← Add LoginPageData, VerifyPageData, render helpers
  main.go               ← Wire /auth/totp, /auth/resend, /auth/sso routes
  totp.go               ← Add handleTOTP POST handler
  notify.go             ← Add handleResend POST handler
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

```go
// LoginPageData is passed to ui/login.html
type LoginPageData struct {
    AppName        string
    CSRFToken      string
    Redirect       string
    GoogleOAuthURL string // empty → Google button hidden
    SSOEnabled     bool   // true → SSO button shown
    Error          string
}

// VerifyPageData is passed to ui/verify.html
type VerifyPageData struct {
    AppName   string
    CSRFToken string
    Redirect  string
    // Mode = "email" → mailbox + OTP boxes
    // Mode = "totp"  → shield icon + TOTP boxes
    Mode      string
    Email     string // only when Mode == "email"
    Error     string
}
```

---

## 5. Step 3 — Render the login page

```go
func (s *server) loginPage(w http.ResponseWriter, r *http.Request, errMsg string) {
    data := LoginPageData{
        AppName:        s.config.appName,
        CSRFToken:      s.config.csrfToken(r),
        Redirect:       r.URL.Query().Get("rd"),
        GoogleOAuthURL: s.config.googleOAuthURL(r), // "" when GOOGLE_CLIENT_ID unset
        SSOEnabled:     s.config.ssoEnabled,
        Error:          errMsg,
    }
    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    if err := loginTmpl.ExecuteTemplate(w, "login.html", data); err != nil {
        http.Error(w, "template error", http.StatusInternalServerError)
    }
}
```

---

## 6. Step 4 — Render the verify/2FA page

```go
// mode must be "totp" or "email"
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
s.verifyPage(w, r, "totp", "", "")         // password OK, TOTP required
s.verifyPage(w, r, "email", email, "")     // OTP email sent
s.verifyPage(w, r, "totp", "", "Invalid code — please try again.")
```

---

## 7. Step 5 — Add Go template helper functions

```go
var tmplFuncs = template.FuncMap{
    "seq": func(n int) []int {
        s := make([]int, n)
        for i := range s { s[i] = i }
        return s
    },
    "add": func(a, b int) int { return a + b },
}
```

---

## 8. Step 6 — Wire the TOTP route

```go
// main.go
mux.HandleFunc("/auth/totp", s.handleTOTP)

// totp.go
func (s *server) handleTOTP(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
        return
    }
    if err := s.config.checkCSRF(r); err != nil {
        http.Error(w, "CSRF", http.StatusForbidden)
        return
    }
    code    := strings.TrimSpace(r.FormValue("code"))
    rd      := r.FormValue("rd")
    pending := s.config.getPendingSession(r)
    if pending == nil {
        http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
        return
    }
    if !s.config.validateTOTP(pending.username, code) {
        s.verifyPage(w, r, "totp", "", "Invalid code — please try again.")
        return
    }
    s.config.issueSession(w, r, pending.username, rd)
}
```

`getPendingSession` reads a short-lived (5 min) HMAC cookie set after password
verification, consumed once TOTP succeeds.

---

## 9. Step 7 — Wire the passkey buttons

Passkeys are **not** on the main login screen (diff item #4). They appear on
`verify.html` as "Use a passkey instead" — a link to `/auth/passkey`.

The existing `passkeypage.go` endpoints handle the full WebAuthn ceremony:
- `POST /auth/passkey/authenticate/begin`
- `POST /auth/passkey/authenticate/finish`

No new routes needed. If you want passkey-**first** login on the main screen,
add the button after the SSO button in `login.html` with the `startPasskeyAuth()`
JS from the previous template version.

---

## 10. Step 8 — Add a /auth/resend endpoint

```go
// main.go
mux.HandleFunc("/auth/resend", s.handleResend)

// notify.go
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
    if !s.resendLimiter.Allow(pending.username) {  // max 3 / 10 min
        http.Error(w, "too many requests", http.StatusTooManyRequests)
        return
    }
    if err := s.config.sendLoginEmail(pending.username); err != nil {
        http.Error(w, "send failed", http.StatusInternalServerError)
        return
    }
    w.WriteHeader(http.StatusOK)
}
```

---

## 11. Step 9 — Google OAuth button

```go
// config struct
googleOAuthURL func(r *http.Request) string

// loadConfig()
if clientID := os.Getenv("GOOGLE_CLIENT_ID"); clientID != "" {
    cfg.googleOAuthURL = func(r *http.Request) string {
        return fmt.Sprintf(
            "https://accounts.google.com/o/oauth2/auth?client_id=%s"+
            "&redirect_uri=%s&response_type=code&scope=openid+email+profile&state=%s",
            url.QueryEscape(clientID),
            url.QueryEscape(cfg.authHost+"/auth/google/callback"),
            url.QueryEscape(cfg.csrfToken(r)),
        )
    }
} else {
    cfg.googleOAuthURL = func(_ *http.Request) string { return "" }
}
```

Add to `.env.example`:
```
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
```

---

## 12. Step 10 — SSO button

Claude shows a **"Continue with SSO"** button (diff item #5). This maps to
SAML/OIDC enterprise SSO. Wire it as a simple redirect to your IdP:

```go
// config struct
ssoEnabled bool
ssoURL     string  // e.g. https://your-idp.example.com/saml/sso

// loadConfig()
cfg.ssoEnabled = os.Getenv("SSO_URL") != ""
cfg.ssoURL     = os.Getenv("SSO_URL")

// main.go
if cfg.ssoEnabled {
    mux.HandleFunc("/auth/sso", func(w http.ResponseWriter, r *http.Request) {
        rd := r.URL.Query().Get("rd")
        http.Redirect(w, r, cfg.ssoURL+"?rd="+url.QueryEscape(rd), http.StatusFound)
    })
}
```

Add to `.env.example`:
```
# Set to your SAML/OIDC IdP SSO URL to show the "Continue with SSO" button
SSO_URL=
```

Leave blank to hide the button (the template uses `{{if .SSOEnabled}}`).

---

## 13. Step 11 — CSP + security headers

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

For production (Tailwind pre-built), remove `cdn.tailwindcss.com` from `script-src`.

---

## 14. Mobile & accessibility

- Email field has an explicit `<label>` (diff item #6) — required for screen readers.
- All inputs carry `autocomplete` attributes (`username`, `one-time-code`).
- OTP boxes carry `aria-label="Digit N"` in `verify.html`.
- Native `<form>` + `<button type="submit">` — functional without JavaScript.
- Minimum touch target `py-3` (≥ 48 px).
- Legal footer uses three separate links to match Claude's exact structure.

---

## 15. Replacing Tailwind CDN with a build step

```bash
curl -sLO https://github.com/tailwindlabs/tailwindcss/releases/latest/download/tailwindcss-linux-x64
chmod +x tailwindcss-linux-x64

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

./tailwindcss-linux-x64 -i /dev/null -o forward-auth/ui/tailwind.min.css --minify
```

Replace the CDN `<script>` tags with:
```html
<link rel="stylesheet" href="/auth/static/tailwind.min.css" />
```

Serve from Go:
```go
//go:embed ui/tailwind.min.css
var tailwindCSS []byte

mux.HandleFunc("/auth/static/tailwind.min.css", func(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "text/css")
    w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
    w.Write(tailwindCSS)
})
```

Dockerfile build step:
```dockerfile
RUN curl -sLO https://github.com/tailwindlabs/tailwindcss/releases/latest/download/tailwindcss-linux-amd64 \\
    && chmod +x tailwindcss-linux-amd64 \\
    && ./tailwindcss-linux-amd64 -i /dev/null \\
       -o forward-auth/ui/tailwind.min.css --minify \\
    && rm tailwindcss-linux-amd64
```

---

## 16. Checklist

### Templates
- [ ] `forward-auth/ui/login.html` created (v2 — correct headline, SSO button, no passkey on main screen)
- [ ] `forward-auth/ui/verify.html` created
- [ ] `//go:embed ui/*.html` added to `page.go`
- [ ] `tmplFuncs` (`seq`, `add`) registered before `template.ParseFS`

### Login page
- [ ] `LoginPageData` struct has `SSOEnabled bool` field
- [ ] `loginPage()` renders `login.html` with `SSOEnabled`, `GoogleOAuthURL`
- [ ] Google button hidden when `GOOGLE_CLIENT_ID` unset
- [ ] SSO button hidden when `SSO_URL` unset
- [ ] Email field has `<label>` element
- [ ] Legal footer has three links: Terms / Usage Policy / Privacy Policy
- [ ] Divider text is lowercase `or`

### 2FA / verify page
- [ ] `verifyPage(w, r, "totp", "", "")` called after password OK
- [ ] `verifyPage(w, r, "email", email, "")` called after OTP email sent
- [ ] `/auth/totp` POST wired in `main.go` → `handleTOTP`
- [ ] Pending-session cookie (5 min) issued after password OK
- [ ] Passkey option shown only on verify screen ("Use a passkey instead" link)

### Resend & alternatives
- [ ] `/auth/resend` POST endpoint added with rate limit (max 3 / 10 min)
- [ ] "Use a passkey instead" → `/auth/passkey`
- [ ] "Use a backup code" → `/auth/login?backup=1`
- [ ] "Use a different email" → `/auth/login`

### SSO
- [ ] `SSO_URL` env var added to `.env.example`
- [ ] `/auth/sso` redirect handler wired
- [ ] `SSOEnabled` passed to template

### Security
- [ ] CSP updated (Tailwind CDN or pre-built)
- [ ] `X-Frame-Options: DENY` on all `/auth/*` responses
- [ ] `Referrer-Policy: no-referrer`
- [ ] TOTP uses `subtle.ConstantTimeCompare`
- [ ] OTP resend rate-limited

### Production
- [ ] Tailwind CDN → pre-built `tailwind.min.css` (§15)
- [ ] `tailwind.min.css` built in Dockerfile
- [ ] Google Fonts self-hosted or proxied (air-gapped deployments)
