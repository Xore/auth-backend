package main

// page.go — HTML rendering for the user-facing pages. All pages are inline
// (no assets, no external requests) and share the same dark design system.
// The admin panel lives in adminpage.go.

import (
	"net/http"
	"strconv"
	"strings"
)

func (s *server) renderLogin(w http.ResponseWriter, rd, errMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	errHTML := ""
	if errMsg != "" {
		errHTML = `<p class="err">` + htmlEscape(errMsg) + `</p>`
	}
	rememberHTML := ""
	if s.cfg.trustDevDays > 0 {
		rememberHTML = `<label class="check"><input type="checkbox" name="remember" value="1">
      trust this device for ` + strconv.Itoa(s.cfg.trustDevDays) + ` days (skips 2fa)</label>`
	}

	page := loginPage
	page = strings.ReplaceAll(page, "{{RD}}", htmlEscape(rd))
	page = strings.ReplaceAll(page, "{{FT}}", s.cfg.issueForm())
	page = strings.ReplaceAll(page, "{{ERROR}}", errHTML)
	page = strings.ReplaceAll(page, "{{REMEMBER}}", rememberHTML)
	_, _ = w.Write([]byte(page))
}

func (s *server) renderEnroll(w http.ResponseWriter, u *User, errMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	errHTML := ""
	if errMsg != "" {
		errHTML = `<p class="err">` + htmlEscape(errMsg) + `</p>`
	}
	uri := s.cfg.totpURI(u.Username, u.PendingTOTP)
	page := enrollPage
	page = strings.ReplaceAll(page, "{{QR}}", GenerateQRSVG(uri, 320))
	page = strings.ReplaceAll(page, "{{URI}}", htmlEscape(uri))
	page = strings.ReplaceAll(page, "{{SECRET}}", htmlEscape(u.PendingTOTP))
	page = strings.ReplaceAll(page, "{{USER}}", htmlEscape(u.Username))
	page = strings.ReplaceAll(page, "{{FT}}", s.cfg.issueForm())
	page = strings.ReplaceAll(page, "{{ERROR}}", errHTML)
	_, _ = w.Write([]byte(page))
}

func (s *server) renderBackupCodes(w http.ResponseWriter, codes []string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	var b strings.Builder
	for _, c := range codes {
		b.WriteString(`<li>` + htmlEscape(c) + `</li>`)
	}
	page := strings.ReplaceAll(backupCodesPage, "{{CODES}}", b.String())
	_, _ = w.Write([]byte(page))
}

func (s *server) renderPassword(w http.ResponseWriter, mustChange bool, errMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	errHTML := ""
	if errMsg != "" {
		errHTML = `<p class="err">` + htmlEscape(errMsg) + `</p>`
	}
	notice := ""
	if mustChange {
		notice = `<div class="badge"><span class="badge__dot"></span>temporary password — change required</div>`
	}
	page := passwordPage
	page = strings.ReplaceAll(page, "{{FT}}", s.cfg.issueForm())
	page = strings.ReplaceAll(page, "{{ERROR}}", errHTML)
	page = strings.ReplaceAll(page, "{{NOTICE}}", notice)
	_, _ = w.Write([]byte(page))
}

func (s *server) renderForbidden(w http.ResponseWriter, host string) {
	page := strings.ReplaceAll(forbiddenPage, "{{HOST}}", htmlEscape(host))
	_, _ = w.Write([]byte(page))
}

func htmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;").Replace(s)
}

// baseCSS is shared by every page: dark backdrop, card, brand, form fields.
const baseCSS = `
  :root{
    --bg:#06080b;--panel:#0f141b;--line:rgba(255,255,255,.07);--line-2:rgba(255,255,255,.11);
    --text:#e8edf3;--muted:#8a97a8;--faint:#5c697a;--cyan:#38bdf8;--green:#34d399;
    --red:#f87171;--orange:#fb923c;
    --radius:14px;--ease:cubic-bezier(.22,1,.36,1);
    --font:"Inter",system-ui,sans-serif;--mono:"JetBrains Mono",ui-monospace,monospace;
  }
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
  body{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;
    font-family:var(--font);color:var(--text);-webkit-font-smoothing:antialiased;
    background:radial-gradient(120% 80% at 50% -10%,#131a24 0%,#090c11 55%,#06080b 100%);}
  svg{display:block}
  .scene{position:fixed;inset:0;z-index:-1;overflow:hidden}
  .scene__glow{position:absolute;border-radius:50%;filter:blur(120px)}
  .scene__glow--warm{width:620px;height:620px;right:-180px;bottom:-140px;
    background:radial-gradient(circle,rgba(255,176,92,.22),transparent 70%)}
  .scene__glow--cool{width:720px;height:720px;left:-200px;top:-160px;
    background:radial-gradient(circle,rgba(56,189,248,.16),transparent 70%)}
  .scene__grid{position:absolute;inset:0;
    background-image:linear-gradient(rgba(255,255,255,.028) 1px,transparent 1px),
      linear-gradient(90deg,rgba(255,255,255,.028) 1px,transparent 1px);
    background-size:60px 60px;
    -webkit-mask-image:radial-gradient(ellipse 75% 60% at 50% 30%,#000 30%,transparent 78%);
    mask-image:radial-gradient(ellipse 75% 60% at 50% 30%,#000 30%,transparent 78%)}
  .scene__vignette{position:absolute;inset:0;
    background:radial-gradient(120% 100% at 50% 40%,transparent 55%,rgba(0,0,0,.6) 100%)}
  .gate{width:100%;max-width:400px;background:linear-gradient(180deg,#0c1119,#080b10);
    border:1px solid var(--line-2);border-radius:var(--radius);padding:34px 32px;
    box-shadow:0 30px 80px -30px rgba(0,0,0,.7)}
  .gate--wide{max-width:480px}
  .brand{display:flex;align-items:center;justify-content:center;gap:11px;margin-bottom:6px}
  .brand__mark{filter:drop-shadow(0 0 10px rgba(56,189,248,.5))}
  .brand__text{font-weight:800;letter-spacing:.12em;font-size:1.15rem}
  .brand__slash{color:var(--cyan)}
  .sub{text-align:center;font-family:var(--mono);font-size:.7rem;letter-spacing:.14em;
    color:var(--muted);text-transform:uppercase;margin-bottom:28px}
  .status__led{display:inline-block;width:7px;height:7px;border-radius:50%;background:var(--green);
    box-shadow:0 0 10px var(--green);margin-right:7px;vertical-align:middle;
    animation:pulse 2.2s var(--ease) infinite}
  @keyframes pulse{0%,100%{opacity:1}50%{opacity:.35}}
  label{display:block;font-family:var(--mono);font-size:.72rem;letter-spacing:.08em;
    color:var(--muted);text-transform:uppercase;margin:0 0 6px}
  input{width:100%;background:#080b10;border:1px solid var(--line-2);border-radius:8px;
    color:var(--text);font-family:var(--mono);font-size:.88rem;padding:11px 14px;outline:none;
    margin-bottom:16px;transition:border-color .2s}
  input:focus{border-color:rgba(56,189,248,.4)}
  button{width:100%;font-family:var(--mono);font-size:.78rem;letter-spacing:.08em;
    padding:12px;border-radius:8px;cursor:pointer;color:var(--cyan);
    background:rgba(56,189,248,.12);border:1px solid rgba(56,189,248,.3);
    transition:all .2s var(--ease)}
  button:hover{background:rgba(56,189,248,.2);border-color:var(--cyan)}
  button.secondary{margin-top:10px;background:transparent;color:var(--green);border-color:rgba(52,211,153,.3)}
  .err{font-family:var(--mono);font-size:.75rem;color:var(--red);margin-bottom:16px;text-align:center}
  .check{display:flex;align-items:center;gap:8px;text-transform:none;letter-spacing:0;
    font-size:.72rem;color:var(--muted);margin-bottom:16px;cursor:pointer}
  .check input{width:auto;margin:0;accent-color:var(--cyan)}
  .badge{display:inline-flex;align-items:center;gap:6px;background:rgba(251,146,60,.12);
    border:1px solid rgba(251,146,60,.3);border-radius:6px;padding:5px 10px;
    font-family:var(--mono);font-size:.68rem;letter-spacing:.08em;color:var(--orange);
    text-transform:uppercase;margin-bottom:24px;width:100%;justify-content:center}
  .badge__dot{width:6px;height:6px;border-radius:50%;background:var(--orange);
    box-shadow:0 0 8px var(--orange);animation:pulse 2s var(--ease) infinite}
  .foot{margin-top:24px;text-align:center;font-family:var(--mono);font-size:.66rem;
    letter-spacing:.1em;color:var(--faint);text-transform:uppercase}
  .foot .dia{color:var(--cyan);font-size:.55rem}
  .foot a{color:var(--faint)}
  @media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
`

const pageHead = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>xore//auth</title>
<style>` + baseCSS + `</style>
</head>
<body>
  <div class="scene" aria-hidden="true">
    <div class="scene__glow scene__glow--warm"></div>
    <div class="scene__glow scene__glow--cool"></div>
    <div class="scene__grid"></div>
    <div class="scene__vignette"></div>
  </div>`

const brandHTML = `
    <div class="brand">
      <svg class="brand__mark" viewBox="0 0 32 32" width="26" height="26" aria-hidden="true">
        <path d="M6 6l20 20M26 6L6 26" stroke="url(#bg)" stroke-width="3.4" stroke-linecap="round"/>
        <defs><linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stop-color="#38bdf8"/><stop offset="1" stop-color="#34d399"/>
        </linearGradient></defs>
      </svg>
      <span class="brand__text">XORE<span class="brand__slash">//</span>AUTH</span>
    </div>`

const loginPage = pageHead + `
  <form class="gate" method="post" action="/_auth/login" autocomplete="off">` + brandHTML + `
    <div class="sub"><span class="status__led"></span>single sign-on</div>
    <input type="hidden" name="rd" value="{{RD}}">
    <input type="hidden" name="ft" value="{{FT}}">
    <div class="trap" aria-hidden="true" style="position:absolute;left:-9999px;width:1px;height:1px;overflow:hidden">
      <label>Leave this field empty</label>
      <input type="text" name="website" tabindex="-1" autocomplete="off">
    </div>
    {{ERROR}}
    <label for="u">username</label>
    <input id="u" name="username" autocomplete="off" autocapitalize="none" spellcheck="false" autofocus>
    <label for="p">password</label>
    <input id="p" name="password" type="password" autocomplete="new-password">
    <label for="totp">2fa code <span style="text-transform:none;color:var(--faint)">— or backup code, if enrolled</span></label>
    <input id="totp" name="totp" inputmode="numeric" autocomplete="one-time-code"
           maxlength="12" placeholder="000000">
    {{REMEMBER}}
    <button type="submit">authenticate</button>
    <button type="button" class="secondary" id="passkey-login">sign in with a passkey</button>
    <div class="foot">
      <span>protected</span> <span class="dia">&#9670;</span>
      <span>all activity logged</span> <span class="dia">&#9670;</span>
      <span>cgnat gateway</span>
    </div>
  </form>
  <script>
    const b64buf = s => { s=s.replace(/-/g,'+').replace(/_/g,'/');s+='='.repeat((4-s.length%4)%4);return Uint8Array.from(atob(s),c=>c.charCodeAt(0)); };
    const b64url = b => { let s=''; new Uint8Array(b).forEach(v=>s+=String.fromCharCode(v)); return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); };
    const credentialJSON = c => ({id:c.id,type:c.type,rawId:b64url(c.rawId),response:{
      authenticatorData:c.response.authenticatorData?b64url(c.response.authenticatorData):undefined,
      clientDataJSON:b64url(c.response.clientDataJSON),signature:c.response.signature?b64url(c.response.signature):undefined,
      userHandle:c.response.userHandle?b64url(c.response.userHandle):null,
      attestationObject:c.response.attestationObject?b64url(c.response.attestationObject):undefined,
      transports:c.response.getTransports?c.response.getTransports():undefined}});
    document.getElementById('passkey-login').onclick = async function(){
      const user=document.getElementById('u').value.trim();
      if(!user){ document.getElementById('u').focus(); return; }
      this.disabled=true;
      try {
        const begin=await fetch('/_auth/passkeys/login/begin',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:user,redirect:document.querySelector('[name=rd]').value})});
        if(!begin.ok) throw new Error('Passkey sign-in is unavailable.');
        const data=await begin.json(), opts=data.options.publicKey;
        opts.challenge=b64buf(opts.challenge); (opts.allowCredentials||[]).forEach(x=>x.id=b64buf(x.id));
        const cred=await navigator.credentials.get({publicKey:opts});
        const finish=await fetch('/_auth/passkeys/login/finish',{method:'POST',headers:{'Content-Type':'application/json','X-WebAuthn-Transaction':data.transaction},body:JSON.stringify(credentialJSON(cred))});
        const result=await finish.json(); if(!finish.ok) throw new Error(result.error||'Passkey sign-in failed.');
        location.assign(result.redirect);
      } catch(e) { alert(e.message||'Passkey sign-in failed.'); this.disabled=false; }
    };
  </script>
</body>
</html>`

const okPage = pageHead + `
  <div class="gate" style="max-width:340px;text-align:center">` + brandHTML + `
    <div class="sub"><span class="status__led"></span>session active</div>
    <p style="font-family:var(--mono);color:var(--green);font-size:.9rem;margin-bottom:18px">&#10003; signed in</p>
    <div class="foot" style="margin-top:0">
      <a href="/_auth/password">change password</a> <span class="dia">&#9670;</span>
      <a href="/_auth/passkeys">passkeys</a> <span class="dia">&#9670;</span>
      <a href="/_auth/admin">admin</a> <span class="dia">&#9670;</span>
      <a href="/_auth/logout">log out</a>
    </div>
  </div>
</body>
</html>`

const enrollPage = pageHead + `
  <div class="gate gate--wide">` + brandHTML + `
    <div class="sub">2fa enrollment — {{USER}}</div>
    <div class="badge"><span class="badge__dot"></span>two-factor setup required</div>
    <!-- white, unrounded, isolated: rounded corners clip the finder patterns
         and background glow bleeding breaks camera detection -->
    <div style="display:flex;justify-content:center;margin:0 0 22px;padding:20px;background:#fff;isolation:isolate"
         title="Scan with your authenticator app">{{QR}}</div>
    <p style="font-family:var(--mono);font-size:.66rem;letter-spacing:.08em;color:var(--faint);text-transform:uppercase;margin-bottom:6px;text-align:center">manual entry secret — tap to copy</p>
    <div id="secret" onclick="copyText('secret')" title="Click to copy"
         style="background:#080b10;border:1px solid var(--line-2);border-radius:8px;padding:10px 14px;font-family:var(--mono);font-size:.78rem;color:var(--cyan);letter-spacing:.1em;word-break:break-all;margin-bottom:14px;text-align:center;cursor:pointer">{{SECRET}}</div>
    <p style="font-family:var(--mono);font-size:.66rem;letter-spacing:.08em;color:var(--faint);text-transform:uppercase;margin-bottom:6px;text-align:center">otpauth uri — for 1password &amp; co, tap to copy</p>
    <div id="uri" onclick="copyText('uri')" title="Click to copy"
         style="background:#080b10;border:1px solid var(--line-2);border-radius:8px;padding:10px 14px;font-family:var(--mono);font-size:.66rem;color:var(--muted);word-break:break-all;margin-bottom:8px;text-align:center;cursor:pointer">{{URI}}</div>
    <div class="copied" id="copied" style="display:none;font-family:var(--mono);font-size:.65rem;color:var(--green);text-align:center;margin-bottom:14px">&#10003; copied to clipboard</div>
    <form method="post" action="/_auth/enroll" style="margin-top:10px">
      <input type="hidden" name="ft" value="{{FT}}">
      {{ERROR}}
      <label for="totp">enter the 6-digit code from your app to activate</label>
      <input id="totp" name="totp" inputmode="numeric" autocomplete="one-time-code"
             pattern="[0-9]*" maxlength="6" placeholder="000000" autofocus>
      <button type="submit">verify &amp; activate</button>
    </form>
    <div class="foot"><a href="/_auth/logout">cancel &amp; log out</a></div>
  </div>
  <script>
    function copyText(id) {
      var s = document.getElementById(id).innerText.replace(/\s/g,'');
      navigator.clipboard && navigator.clipboard.writeText(s).then(function(){
        var c = document.getElementById('copied');
        c.style.display = 'block';
        setTimeout(function(){ c.style.display = 'none'; }, 2000);
      });
    }
  </script>
</body>
</html>`

const backupCodesPage = pageHead + `
  <div class="gate gate--wide">` + brandHTML + `
    <div class="sub">recovery codes</div>
    <div class="badge"><span class="badge__dot"></span>shown once — store them now</div>
    <p style="font-size:.82rem;color:var(--muted);line-height:1.6;margin-bottom:18px">
      Two-factor is active. If you lose your authenticator, any of these one-time
      codes signs you in (enter it in the 2fa field). Each works once.</p>
    <ul id="codes" style="list-style:none;display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:18px;
        font-family:var(--mono);font-size:.85rem;color:var(--cyan);letter-spacing:.08em;text-align:center">
      {{CODES}}
    </ul>
    <button onclick="copyCodes()" style="margin-bottom:10px">copy all to clipboard</button>
    <div class="copied" id="copied" style="display:none;font-family:var(--mono);font-size:.65rem;color:var(--green);text-align:center;margin-bottom:10px">&#10003; copied</div>
    <a href="/_auth/ok" style="display:block;text-align:center;font-family:var(--mono);font-size:.72rem;letter-spacing:.08em;color:var(--cyan);text-decoration:none;padding:11px;border-radius:8px;border:1px solid rgba(56,189,248,.25);background:rgba(56,189,248,.08)">i saved them — continue &rarr;</a>
  </div>
  <script>
    function copyCodes() {
      var t = Array.from(document.querySelectorAll('#codes li')).map(function(li){return li.innerText}).join('\n');
      navigator.clipboard && navigator.clipboard.writeText(t).then(function(){
        var c = document.getElementById('copied');
        c.style.display = 'block';
        setTimeout(function(){ c.style.display = 'none'; }, 2000);
      });
    }
  </script>
</body>
</html>`

const passwordPage = pageHead + `
  <form class="gate" method="post" action="/_auth/password">` + brandHTML + `
    <div class="sub">change password</div>
    {{NOTICE}}
    <input type="hidden" name="ft" value="{{FT}}">
    {{ERROR}}
    <label for="cur">current password</label>
    <input id="cur" name="current" type="password" autocomplete="current-password" autofocus>
    <label for="n1">new password <span style="text-transform:none;color:var(--faint)">— min 10 chars</span></label>
    <input id="n1" name="new1" type="password" autocomplete="new-password">
    <label for="n2">repeat new password</label>
    <input id="n2" name="new2" type="password" autocomplete="new-password">
    <button type="submit">change password</button>
    <div class="foot"><a href="/_auth/logout">log out</a></div>
  </form>
</body>
</html>`

const forbiddenPage = pageHead + `
  <div class="gate" style="max-width:420px;text-align:center">` + brandHTML + `
    <div class="sub">access denied</div>
    <p style="font-family:var(--mono);color:var(--red);font-size:.85rem;margin-bottom:14px">&#10007; not authorized for {{HOST}}</p>
    <p style="font-size:.8rem;color:var(--muted);line-height:1.6;margin-bottom:18px">
      Your account doesn't have access to this service. If it should,
      ask an admin to add it to your allowed hosts.</p>
    <div class="foot" style="margin-top:0"><a href="/_auth/logout">switch account</a></div>
  </div>
</body>
</html>`
