package main

// page.go — HTML rendering for the user-facing pages. All pages link the
// shared design system (/static/theme.css, embedded under ui/)
// plus a small nonce'd pageCSS block with layout-only rules — every colour
// comes from the theme's custom properties. The admin panel lives in
// adminpage.go.

import (
	"html"
	"html/template"
	"net/http"
	"strings"
)

// tmplFuncs are shared by the file-based templates in ui/ (login, verify).
var tmplFuncs = template.FuncMap{
	"seq": func(n int) []int {
		s := make([]int, n)
		for i := range s {
			s[i] = i
		}
		return s
	},
	"add": func(a, b int) int { return a + b },
}

var (
	loginTmpl  = template.Must(template.New("login").Funcs(tmplFuncs).Parse(string(mustReadUI("login.html"))))
	verifyTmpl = template.Must(template.New("verify").Funcs(tmplFuncs).Parse(string(mustReadUI("verify.html"))))
)

// LoginPageData is passed to ui/login.html.
type LoginPageData struct {
	Nonce          string
	FT             string // form (CSRF + timing) token
	RD             string // redirect target, already safeRedirect'ed
	Error          string
	Remember       bool // show the "trust this device" checkbox
	TrustDays      int
	SSOEnabled     bool
	RecoverEnabled bool // show the "forgot password?" link
	BrandTitle     string
	BrandSubtitle  string
	BrandFooter    string
}

// VerifyPageData is passed to ui/verify.html (the post-password 2FA step).
type VerifyPageData struct {
	Nonce string
	RD    string
	Error string
}

func (s *server) renderLogin(w http.ResponseWriter, rd, errMsg, nonce string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	title, subtitle, footer := s.settings.branding()
	if err := loginTmpl.Execute(w, LoginPageData{
		Nonce:          nonce,
		FT:             s.cfg.issueForm(),
		RD:             rd,
		Error:          errMsg,
		Remember:       s.cfg.trustDevDays > 0,
		TrustDays:      s.cfg.trustDevDays,
		SSOEnabled:     s.cfg.ssoURL != "",
		RecoverEnabled: s.recoverEnabled(),
		BrandTitle:     title,
		BrandSubtitle:  subtitle,
		BrandFooter:    footer,
	}); err != nil {
		s.log.Error("render login page", "error", err)
	}
}

// renderVerify shows the post-password 2FA page (pending cookie is set by
// the caller before rendering).
func (s *server) renderVerify(w http.ResponseWriter, rd, errMsg, nonce string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := verifyTmpl.Execute(w, VerifyPageData{
		Nonce: nonce,
		RD:    rd,
		Error: errMsg,
	}); err != nil {
		s.log.Error("render verify page", "error", err)
	}
}

func (s *server) renderEnroll(w http.ResponseWriter, u *User, errMsg, nonce string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	errHTML := ""
	if errMsg != "" {
		errHTML = `<p class="form-error">` + htmlEscape(errMsg) + `</p>`
	}
	uri := s.cfg.totpURI(u.Username, u.PendingTOTP)
	page := enrollPage
	page = strings.ReplaceAll(page, "{{QR}}", GenerateQRSVG(uri, 320))
	page = strings.ReplaceAll(page, "{{URI}}", htmlEscape(uri))
	page = strings.ReplaceAll(page, "{{SECRET}}", htmlEscape(u.PendingTOTP))
	page = strings.ReplaceAll(page, "{{USER}}", htmlEscape(u.Username))
	page = strings.ReplaceAll(page, "{{FT}}", s.cfg.issueForm())
	page = strings.ReplaceAll(page, "{{ERROR}}", errHTML)
	page = strings.ReplaceAll(page, "{{NONCE}}", nonce)
	_, _ = w.Write([]byte(page))
}

func (s *server) renderBackupCodes(w http.ResponseWriter, codes []string, nonce string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	var b strings.Builder
	for _, c := range codes {
		b.WriteString(`<li>` + htmlEscape(c) + `</li>`)
	}
	page := strings.ReplaceAll(backupCodesPage, "{{CODES}}", b.String())
	page = strings.ReplaceAll(page, "{{NONCE}}", nonce)
	_, _ = w.Write([]byte(page))
}

func (s *server) renderPassword(w http.ResponseWriter, mustChange bool, errMsg, nonce string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	errHTML := ""
	if errMsg != "" {
		errHTML = `<p class="form-error">` + htmlEscape(errMsg) + `</p>`
	}
	notice := ""
	if mustChange {
		notice = `<div class="notice"><span class="badge badge--orange">temporary password — change required</span></div>`
	}
	page := passwordPage
	page = strings.ReplaceAll(page, "{{FT}}", s.cfg.issueForm())
	page = strings.ReplaceAll(page, "{{ERROR}}", errHTML)
	page = strings.ReplaceAll(page, "{{NOTICE}}", notice)
	page = strings.ReplaceAll(page, "{{NONCE}}", nonce)
	_, _ = w.Write([]byte(page))
}

func (s *server) renderForbidden(w http.ResponseWriter, host, nonce string) {
	page := strings.ReplaceAll(forbiddenPage, "{{HOST}}", htmlEscape(host))
	page = strings.ReplaceAll(page, "{{NONCE}}", nonce)
	_, _ = w.Write([]byte(page))
}

// renderRecoverRequest shows the "request a reset link" form. sent renders
// the generic success notice (identical whether or not the account exists).
func (s *server) renderRecoverRequest(w http.ResponseWriter, errMsg string, sent bool, nonce string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	errHTML := ""
	if errMsg != "" {
		errHTML = `<p class="form-error">` + htmlEscape(errMsg) + `</p>`
	}
	sentHTML := ""
	if sent {
		sentHTML = `<p class="status-ok">If that account exists, a reset email is on its way — check your inbox.</p>`
	}
	page := recoverRequestPage
	page = strings.ReplaceAll(page, "{{FT}}", s.cfg.issueForm())
	page = strings.ReplaceAll(page, "{{ERROR}}", errHTML)
	page = strings.ReplaceAll(page, "{{SENT}}", sentHTML)
	page = strings.ReplaceAll(page, "{{NONCE}}", nonce)
	_, _ = w.Write([]byte(page))
}

func (s *server) renderRecoverReset(w http.ResponseWriter, token, errMsg, nonce string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	errHTML := ""
	if errMsg != "" {
		errHTML = `<p class="form-error">` + htmlEscape(errMsg) + `</p>`
	}
	page := recoverResetPage
	page = strings.ReplaceAll(page, "{{TOKEN}}", htmlEscape(token))
	page = strings.ReplaceAll(page, "{{ERROR}}", errHTML)
	page = strings.ReplaceAll(page, "{{NONCE}}", nonce)
	_, _ = w.Write([]byte(page))
}

func htmlEscape(s string) string {
	return html.EscapeString(s)
}

// pageCSS holds the page-specific layout rules shared by every user-facing
// page. All colours reference the theme.css custom properties — the
// theme palette is never redefined here. The QR wrapper keeps its functional
// white background (camera detection requires it).
const pageCSS = `
  .auth-body{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
  .auth-card{width:100%;max-width:400px}
  .auth-card--wide{max-width:480px}
  .auth-center{text-align:center}
  .auth-actions{display:flex;flex-direction:column;gap:10px;margin-top:4px}
  .auth-btn{width:100%;text-decoration:none}
  .brand{display:flex;align-items:center;justify-content:center;gap:10px;margin-bottom:4px}
  .brand__text{font-weight:600;letter-spacing:.12em;font-size:1.05rem}
  .brand__slash{color:var(--accent)}
  .sub{text-align:center;font-size:11px;font-weight:500;letter-spacing:.06em;
    text-transform:uppercase;color:var(--text-muted);margin-bottom:24px}
  .check{display:flex;align-items:center;gap:8px;font-size:12px;color:var(--text-secondary);
    margin-bottom:16px;cursor:pointer}
  .check input{width:auto;margin:0;accent-color:var(--accent)}
  .notice{display:flex;justify-content:center;margin-bottom:20px}
  .foot{margin-top:20px;text-align:center;font-size:11px;letter-spacing:.06em;
    color:var(--text-muted);text-transform:uppercase}
  .foot a{color:var(--text-muted)}
  .foot .dia{color:var(--accent);font-size:.55rem}
  .foot-flat{margin-top:0}
  .trap{position:absolute;left:-9999px;width:1px;height:1px;overflow:hidden}
  /* white, unrounded, isolated: rounded corners clip the finder patterns
     and a dark background breaks camera detection */
  .qr-wrap{display:flex;justify-content:center;margin:0 0 20px;padding:20px;background:#fff;isolation:isolate}
  .copy-box{background:var(--surface-2);border:1px solid var(--border-subtle);
    border-radius:var(--radius-sm);padding:10px 14px;
    font-family:'SF Mono','Fira Code','Cascadia Code',monospace;word-break:break-all;
    margin-bottom:14px;text-align:center;cursor:pointer;transition:background var(--transition)}
  .copy-box:hover{background:var(--surface-3)}
  .copy-box--accent{color:var(--accent);font-size:12px;letter-spacing:.06em}
  .copy-box--muted{color:var(--text-muted);font-size:11px}
  .copy-label{font-size:11px;letter-spacing:.06em;color:var(--text-muted);
    text-transform:uppercase;margin-bottom:6px;text-align:center}
  .copied{display:none;font-size:11px;color:var(--green);text-align:center;margin-bottom:14px}
  .codes-grid{list-style:none;display:grid;grid-template-columns:1fr 1fr;gap:8px;margin:0 0 18px;
    padding:0;font-family:'SF Mono','Fira Code','Cascadia Code',monospace;font-size:13px;
    color:var(--accent);letter-spacing:.06em;text-align:center}
  .status-ok{color:var(--green);font-size:15px;margin-bottom:18px}
  .status-err{color:var(--red);font-size:13px;margin-bottom:14px}
  .text-muted{font-size:13px;color:var(--text-secondary);line-height:1.6;margin-bottom:18px}
  .label-hint{text-transform:none;color:var(--text-muted)}
  .form-spaced{margin-top:10px}
  @media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
`

const pageHead = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>xore//auth</title>
<link rel="stylesheet" href="/static/theme.css">
<style nonce="{{NONCE}}">` + pageCSS + `</style>
</head>
<body class="auth-body">`

const brandHTML = `
    <div class="brand">
      <svg class="brand__mark" viewBox="0 0 32 32" width="26" height="26" aria-hidden="true">
        <path d="M6 6l20 20M26 6L6 26" stroke="url(#bg)" stroke-width="3.4" stroke-linecap="round"/>
        <defs><linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stop-color="#d4764e"/><stop offset="1" stop-color="#c4673f"/>
        </linearGradient></defs>
      </svg>
      <span class="brand__text">XORE<span class="brand__slash">//</span>AUTH</span>
    </div>`

const enrollPage = pageHead + `
  <div class="card auth-card auth-card--wide">` + brandHTML + `
    <div class="sub">2fa enrollment — {{USER}}</div>
    <div class="notice"><span class="badge badge--orange">two-factor setup required</span></div>
    <div class="qr-wrap" title="Scan with your authenticator app">{{QR}}</div>
    <p class="copy-label">manual entry secret — tap to copy</p>
    <div id="secret" title="Click to copy" class="copy-box copy-box--accent">{{SECRET}}</div>
    <p class="copy-label">otpauth uri — for 1password &amp; co, tap to copy</p>
    <div id="uri" title="Click to copy" class="copy-box copy-box--muted">{{URI}}</div>
    <div class="copied" id="copied">&#10003; copied to clipboard</div>
    <form method="post" action="/_auth/enroll" class="form-spaced">
      <input type="hidden" name="ft" value="{{FT}}">
      {{ERROR}}
      <div class="form-group">
        <label class="form-label" for="totp">enter the 6-digit code from your app to activate</label>
        <input class="form-input" id="totp" name="totp" inputmode="numeric" autocomplete="one-time-code"
               pattern="[0-9]*" maxlength="6" placeholder="000000" autofocus>
      </div>
      <button type="submit" class="btn btn-primary auth-btn">verify &amp; activate</button>
    </form>
    <div class="foot"><a href="/_auth/logout">cancel &amp; log out</a></div>
  </div>
  <script nonce="{{NONCE}}">
    function copyText(id) {
      var s = document.getElementById(id).innerText.replace(/\s/g,'');
      navigator.clipboard && navigator.clipboard.writeText(s).then(function(){
        var c = document.getElementById('copied');
        c.style.display = 'block';
        setTimeout(function(){ c.style.display = 'none'; }, 2000);
      });
    }
    document.getElementById('secret').addEventListener('click', function(){ copyText('secret'); });
    document.getElementById('uri').addEventListener('click', function(){ copyText('uri'); });
  </script>
</body>
</html>`

const backupCodesPage = pageHead + `
  <div class="card auth-card auth-card--wide">` + brandHTML + `
    <div class="sub">recovery codes</div>
    <div class="notice"><span class="badge badge--orange">shown once — store them now</span></div>
    <p class="text-muted">
      Two-factor is active. If you lose your authenticator, any of these one-time
      codes signs you in (enter it in the 2fa field). Each works once.</p>
    <ul id="codes" class="codes-grid">
      {{CODES}}
    </ul>
    <div class="auth-actions">
      <button id="copy-codes" class="btn btn-secondary auth-btn">copy all to clipboard</button>
      <a href="/auth/app" class="btn btn-primary auth-btn">i saved them — continue &rarr;</a>
    </div>
    <div class="copied" id="copied">&#10003; copied</div>
  </div>
  <script nonce="{{NONCE}}">
    function copyCodes() {
      var t = Array.from(document.querySelectorAll('#codes li')).map(function(li){return li.innerText}).join('\n');
      navigator.clipboard && navigator.clipboard.writeText(t).then(function(){
        var c = document.getElementById('copied');
        c.style.display = 'block';
        setTimeout(function(){ c.style.display = 'none'; }, 2000);
      });
    }
    document.getElementById('copy-codes').addEventListener('click', copyCodes);
  </script>
</body>
</html>`

const passwordPage = pageHead + `
  <form class="card auth-card" method="post" action="/_auth/password">` + brandHTML + `
    <div class="sub">change password</div>
    {{NOTICE}}
    <input type="hidden" name="ft" value="{{FT}}">
    {{ERROR}}
    <div class="form-group">
      <label class="form-label" for="cur">current password</label>
      <input class="form-input" id="cur" name="current" type="password" autocomplete="current-password" autofocus>
    </div>
    <div class="form-group">
      <label class="form-label" for="n1">new password <span class="label-hint">— min 10 chars</span></label>
      <input class="form-input" id="n1" name="new1" type="password" autocomplete="new-password">
    </div>
    <div class="form-group">
      <label class="form-label" for="n2">repeat new password</label>
      <input class="form-input" id="n2" name="new2" type="password" autocomplete="new-password">
    </div>
    <button type="submit" class="btn btn-primary auth-btn">change password</button>
    <div class="foot"><a href="/_auth/logout">log out</a></div>
  </form>
</body>
</html>`

const forbiddenPage = pageHead + `
  <div class="card auth-card auth-center">` + brandHTML + `
    <div class="sub">access denied</div>
    <p class="status-err">&#10007; not authorized for {{HOST}}</p>
    <p class="text-muted">
      Your account doesn't have access to this service. If it should,
      ask an admin to add it to your allowed hosts.</p>
    <div class="foot foot-flat"><a href="/_auth/logout">switch account</a></div>
  </div>
</body>
</html>`

const recoverRequestPage = pageHead + `
  <form class="card auth-card" method="post" action="/_auth/recover" autocomplete="off">` + brandHTML + `
    <div class="sub">reset your password</div>
    <input type="hidden" name="ft" value="{{FT}}">
    <div class="trap" aria-hidden="true">
      <label>Leave this field empty</label>
      <input type="text" name="website" tabindex="-1" autocomplete="off">
    </div>
    {{SENT}}
    {{ERROR}}
    <div class="form-group">
      <label class="form-label" for="u">username / email</label>
      <input class="form-input" id="u" name="username" autocomplete="username" autocapitalize="none" spellcheck="false" autofocus>
    </div>
    <button type="submit" class="btn btn-primary auth-btn">send reset link</button>
    <div class="foot"><a href="/_auth/login">back to sign in</a></div>
  </form>
</body>
</html>`

const recoverResetPage = pageHead + `
  <form class="card auth-card" method="post" action="/_auth/recover" autocomplete="off">` + brandHTML + `
    <div class="sub">choose a new password</div>
    <input type="hidden" name="token" value="{{TOKEN}}">
    {{ERROR}}
    <div class="form-group">
      <label class="form-label" for="n1">new password <span class="label-hint">— min 10 chars</span></label>
      <input class="form-input" id="n1" name="new1" type="password" autocomplete="new-password" autofocus>
    </div>
    <div class="form-group">
      <label class="form-label" for="n2">repeat new password</label>
      <input class="form-input" id="n2" name="new2" type="password" autocomplete="new-password">
    </div>
    <button type="submit" class="btn btn-primary auth-btn">reset password</button>
    <div class="foot"><a href="/_auth/login">back to sign in</a></div>
  </form>
</body>
</html>`
