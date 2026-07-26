package main

import (
	"encoding/hex"
	"net/http"
	"strings"
)

func (s *server) renderPasskeys(w http.ResponseWriter, u *User, csrf string) {
	var rows strings.Builder
	for _, key := range u.Passkeys {
		last := "never"
		if !key.LastUsed.IsZero() {
			last = key.LastUsed.Format("2006-01-02 15:04 UTC")
		}
		rows.WriteString(`<div class="pk"><div><b>` + htmlEscape(key.Name) + `</b><small>created ` + key.Created.Format("2006-01-02") + ` · last used ` + last + `</small></div><button class="danger" data-id="` + hex.EncodeToString(key.Credential.ID) + `">remove</button></div>`)
	}
	if rows.Len() == 0 {
		rows.WriteString(`<p class="empty">No passkeys enrolled yet.</p>`)
	}
	page := strings.ReplaceAll(passkeysPage, "{{KEYS}}", rows.String())
	page = strings.ReplaceAll(page, "{{CSRF}}", csrf)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(page))
}

const passkeysPage = pageHead + `
  <div class="gate gate--wide">` + brandHTML + `
    <div class="sub">passkeys</div>
    <p style="font-size:.82rem;color:var(--muted);line-height:1.6;margin-bottom:18px">Passkeys provide phishing-resistant sign-in using your phone, computer, password manager, or hardware security key.</p>
    <div id="keys">{{KEYS}}</div>
    <label for="pk-name" style="margin-top:20px">new passkey name</label>
    <input id="pk-name" maxlength="64" placeholder="MacBook Touch ID">
    <button id="add">add a passkey</button>
    <div class="foot"><a href="/_auth/ok">back</a> <span class="dia">&#9670;</span> <a href="/_auth/logout">log out</a></div>
  </div>
  <style>
    .pk{display:flex;align-items:center;justify-content:space-between;gap:12px;border-bottom:1px solid var(--line);padding:12px 0}
    .pk b{font-family:var(--mono);font-size:.8rem}.pk small{display:block;color:var(--faint);font-size:.68rem;margin-top:4px}
    .pk button{width:auto;padding:7px 10px;color:var(--red);border-color:rgba(248,113,113,.3);background:transparent}
    .empty{font-family:var(--mono);color:var(--faint);font-size:.75rem;margin-bottom:12px}
  </style>
  <script>
    const csrf='{{CSRF}}';
    const b64buf = s => { s=s.replace(/-/g,'+').replace(/_/g,'/');s+='='.repeat((4-s.length%4)%4);return Uint8Array.from(atob(s),c=>c.charCodeAt(0)); };
    const b64url = b => { let s=''; new Uint8Array(b).forEach(v=>s+=String.fromCharCode(v)); return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); };
    const credentialJSON = c => ({id:c.id,type:c.type,rawId:b64url(c.rawId),response:{clientDataJSON:b64url(c.response.clientDataJSON),attestationObject:b64url(c.response.attestationObject),transports:c.response.getTransports?c.response.getTransports():[]}});
    document.getElementById('add').onclick=async function(){
      this.disabled=true;
      try{
        const begin=await fetch('/_auth/passkeys/register/begin',{method:'POST',headers:{'Content-Type':'application/json','X-Csrf':csrf},body:JSON.stringify({name:document.getElementById('pk-name').value})});
        const data=await begin.json(); if(!begin.ok) throw new Error(data.error||'Could not start registration.');
        const opts=data.options.publicKey; opts.challenge=b64buf(opts.challenge); opts.user.id=b64buf(opts.user.id); (opts.excludeCredentials||[]).forEach(x=>x.id=b64buf(x.id));
        const cred=await navigator.credentials.create({publicKey:opts});
        const finish=await fetch('/_auth/passkeys/register/finish',{method:'POST',headers:{'Content-Type':'application/json','X-Csrf':csrf,'X-WebAuthn-Transaction':data.transaction},body:JSON.stringify(credentialJSON(cred))});
        const result=await finish.json(); if(!finish.ok) throw new Error(result.error||'Registration failed.'); location.reload();
      }catch(e){alert(e.message||'Registration failed.');this.disabled=false;}
    };
    document.querySelectorAll('[data-id]').forEach(b=>b.onclick=async function(){
      if(!confirm('Remove this passkey?'))return;
      const r=await fetch('/_auth/passkeys/delete',{method:'POST',headers:{'Content-Type':'application/json','X-Csrf':csrf},body:JSON.stringify({id:this.dataset.id})});
      if(r.ok)location.reload();else alert('Could not remove passkey.');
    });
  </script>
</body></html>`
