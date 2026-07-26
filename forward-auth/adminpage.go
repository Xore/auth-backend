package main

// adminpage.go — the admin panel: a single self-contained HTML page (no
// external assets) that polls /_auth/admin/api/state and drives the JSON API
// in admin.go. Served only to admin sessions.

import (
	"net/http"
	"strings"
)

func (s *server) renderAdmin(w http.ResponseWriter, adminUser, csrf string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	page := adminPage
	page = strings.ReplaceAll(page, "{{ADMIN}}", htmlEscape(adminUser))
	page = strings.ReplaceAll(page, "{{CSRF}}", csrf)
	_, _ = w.Write([]byte(page))
}

const adminPage = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>xore//auth — admin</title>
<style>` + baseCSS + `
  body{align-items:flex-start;padding:32px 20px}
  .panel{width:100%;max-width:1060px;margin:0 auto}
  .top{display:flex;align-items:center;justify-content:space-between;margin-bottom:22px;flex-wrap:wrap;gap:10px}
  .top .brand{margin:0}
  .top__who{font-family:var(--mono);font-size:.7rem;color:var(--muted);letter-spacing:.06em}
  .top__who a{color:var(--cyan);text-decoration:none;margin-left:12px}
  .tabs{display:flex;gap:8px;margin-bottom:18px}
  .tabs button{width:auto;padding:9px 18px;background:transparent;border:1px solid var(--line-2);color:var(--muted)}
  .tabs button.on{background:rgba(56,189,248,.12);border-color:rgba(56,189,248,.4);color:var(--cyan)}
  .card{background:linear-gradient(180deg,#0c1119,#080b10);border:1px solid var(--line-2);
    border-radius:var(--radius);padding:22px;margin-bottom:18px;box-shadow:0 20px 60px -30px rgba(0,0,0,.7)}
  .card h3{font-family:var(--mono);font-size:.72rem;letter-spacing:.12em;color:var(--muted);
    text-transform:uppercase;margin-bottom:14px}
  table{width:100%;border-collapse:collapse;font-size:.78rem}
  th{font-family:var(--mono);font-size:.62rem;letter-spacing:.1em;text-transform:uppercase;
    color:var(--faint);text-align:left;padding:6px 10px;border-bottom:1px solid var(--line-2)}
  td{padding:7px 10px;border-bottom:1px solid var(--line);color:var(--text);vertical-align:middle}
  td.mono,th.mono{font-family:var(--mono);font-size:.72rem}
  .tag{display:inline-block;font-family:var(--mono);font-size:.62rem;letter-spacing:.06em;
    padding:2px 8px;border-radius:5px;text-transform:uppercase}
  .tag--admin{background:rgba(56,189,248,.14);color:var(--cyan);border:1px solid rgba(56,189,248,.3)}
  .tag--user{background:rgba(255,255,255,.06);color:var(--muted);border:1px solid var(--line-2)}
  .tag--ok{background:rgba(52,211,153,.12);color:var(--green);border:1px solid rgba(52,211,153,.3)}
  .tag--warn{background:rgba(251,146,60,.12);color:var(--orange);border:1px solid rgba(251,146,60,.3)}
  .tag--err{background:rgba(248,113,113,.12);color:var(--red);border:1px solid rgba(248,113,113,.3)}
  .row-actions{display:flex;gap:6px;flex-wrap:wrap}
  .row-actions button{width:auto;padding:4px 9px;font-size:.62rem;background:transparent;
    border:1px solid var(--line-2);color:var(--muted)}
  .row-actions button:hover{border-color:var(--cyan);color:var(--cyan);background:rgba(56,189,248,.08)}
  .row-actions button.danger:hover{border-color:var(--red);color:var(--red);background:rgba(248,113,113,.08)}
  .stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:18px}
  .stat{background:linear-gradient(180deg,#0c1119,#080b10);border:1px solid var(--line-2);
    border-radius:10px;padding:14px 16px}
  .stat__n{font-family:var(--mono);font-size:1.4rem;color:var(--text)}
  .stat__l{font-family:var(--mono);font-size:.6rem;letter-spacing:.1em;color:var(--faint);text-transform:uppercase;margin-top:4px}
  .filter{display:flex;gap:10px;margin-bottom:12px;flex-wrap:wrap}
  .filter input,.filter select{margin:0;width:auto;flex:1;min-width:160px}
  .filter select{background:#080b10;border:1px solid var(--line-2);border-radius:8px;
    color:var(--text);font-family:var(--mono);font-size:.75rem;padding:9px 12px}
  .newuser{display:grid;grid-template-columns:1fr 130px 1fr auto;gap:10px;align-items:end}
  .newuser label{margin-bottom:4px}
  .newuser input,.newuser select{margin:0}
  .newuser select{background:#080b10;border:1px solid var(--line-2);border-radius:8px;
    color:var(--text);font-family:var(--mono);font-size:.8rem;padding:11px 12px}
  .newuser button{width:auto;padding:11px 20px}
  #flash{position:fixed;top:18px;left:50%;transform:translateX(-50%);z-index:10;display:none;
    background:#0c1119;border:1px solid rgba(52,211,153,.4);border-radius:10px;padding:14px 20px;
    font-family:var(--mono);font-size:.78rem;color:var(--text);box-shadow:0 20px 60px rgba(0,0,0,.6);
    max-width:90vw;word-break:break-all;text-align:center}
  #flash.err{border-color:rgba(248,113,113,.5)}
  #flash b{color:var(--green)}
  .empty{color:var(--faint);font-family:var(--mono);font-size:.72rem;padding:14px 10px}
  @media(max-width:760px){.newuser{grid-template-columns:1fr}.hide-sm{display:none}}
</style>
</head>
<body>
  <div class="scene" aria-hidden="true">
    <div class="scene__glow scene__glow--warm"></div>
    <div class="scene__glow scene__glow--cool"></div>
    <div class="scene__grid"></div>
    <div class="scene__vignette"></div>
  </div>
  <div id="flash"></div>
  <div class="panel">
    <div class="top">` + brandHTML + `
      <div class="top__who">signed in as <span style="color:var(--cyan)">{{ADMIN}}</span>
        <a href="/_auth/password">password</a>
        <a href="/_auth/logout">log out</a></div>
    </div>
    <div class="tabs">
      <button id="tab-users" class="on" onclick="showTab('users')">users</button>
      <button id="tab-logs" onclick="showTab('logs')">logs</button>
      <button id="tab-sessions" onclick="showTab('sessions')">sessions</button>
    </div>

    <div id="pane-users">
      <div class="card">
        <h3>create user</h3>
        <div class="newuser">
          <div><label>username</label><input id="nu-name" autocomplete="off" autocapitalize="none" spellcheck="false"></div>
          <div><label>role</label><select id="nu-role"><option value="user">user</option><option value="admin">admin</option></select></div>
          <div><label>allowed hosts <span style="text-transform:none;color:var(--faint)">— blank = all; comma-sep, *.dom ok</span></label>
            <input id="nu-hosts" placeholder="grafana.xore.rocks, *.media.xore.rocks"></div>
          <button onclick="createUser()">create</button>
        </div>
      </div>
      <div class="card">
        <h3>users</h3>
        <table><thead><tr>
          <th>user</th><th>role</th><th>status</th><th>2fa</th>
          <th class="hide-sm">allowed hosts</th><th class="hide-sm">last login</th><th>actions</th>
        </tr></thead><tbody id="users-body"></tbody></table>
      </div>
    </div>

    <div id="pane-logs" style="display:none">
      <div class="stats">
        <div class="stat"><div class="stat__n" id="st-total">–</div><div class="stat__l">attempts</div></div>
        <div class="stat"><div class="stat__n" id="st-ok" style="color:var(--green)">–</div><div class="stat__l">successful</div></div>
        <div class="stat"><div class="stat__n" id="st-fail" style="color:var(--red)">–</div><div class="stat__l">failed</div></div>
        <div class="stat"><div class="stat__n" id="st-locked" style="color:var(--orange)">–</div><div class="stat__l">locked ips</div></div>
      </div>
      <div class="card">
        <h3>locked out</h3>
        <table><thead><tr><th>ip</th><th>fails</th><th>until</th><th></th></tr></thead>
        <tbody id="locked-body"></tbody></table>
      </div>
      <div class="card">
        <h3>audit log</h3>
        <div class="filter">
          <input id="lf-text" placeholder="filter: ip / user / host / event…" oninput="renderLogs()">
          <select id="lf-kind" onchange="renderLogs()">
            <option value="">all events</option>
            <option value="login_ok">login ok</option>
            <option value="login_fail">login failed</option>
            <option value="locked_out">lockouts</option>
            <option value="admin_">admin actions</option>
            <option value="enroll">enrollment</option>
          </select>
        </div>
        <table><thead><tr>
          <th>time</th><th>event</th><th>ip</th><th>user</th><th class="hide-sm">host</th><th class="hide-sm">agent</th>
        </tr></thead><tbody id="logs-body"></tbody></table>
      </div>
    </div>

    <div id="pane-sessions" style="display:none">
      <div class="card">
        <h3>active sessions <span style="text-transform:none;letter-spacing:0;color:var(--faint)">(best effort — repopulates after restart)</span></h3>
        <table><thead><tr>
          <th>user</th><th>ip</th><th class="hide-sm">agent</th><th>signed in</th><th>last seen</th><th></th>
        </tr></thead><tbody id="sess-body"></tbody></table>
      </div>
    </div>
  </div>

<script>
var CSRF = "{{CSRF}}";
var state = {users:[], audit:{Recent:[],Total:0,Success:0,Failed:0}, locked:[], sessions:[]};

function esc(s){return String(s==null?"":s).replace(/[&<>"']/g,function(c){
  return {"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c];});}
function ts(s){if(!s||s.startsWith("0001"))return "–";var d=new Date(s);
  return d.toLocaleDateString()+" "+d.toLocaleTimeString();}
function ago(s){if(!s||s.startsWith("0001"))return "–";var ms=Date.now()-new Date(s).getTime();
  var m=Math.floor(ms/60000);if(m<1)return "now";if(m<60)return m+"m ago";
  var h=Math.floor(m/60);if(h<24)return h+"h ago";return Math.floor(h/24)+"d ago";}

function flash(msg,isErr){var f=document.getElementById('flash');
  f.innerHTML=msg;f.className=isErr?'err':'';f.style.display='block';
  clearTimeout(f._t);f._t=setTimeout(function(){f.style.display='none'},isErr?6000:12000);}

function showTab(t){['users','logs','sessions'].forEach(function(x){
  document.getElementById('pane-'+x).style.display=(x===t)?'':'none';
  document.getElementById('tab-'+x).className=(x===t)?'on':'';});}

function api(path,body){return fetch('/_auth/admin/api/'+path,{
    method:'POST',headers:{'Content-Type':'application/json','X-Csrf':CSRF},
    body:JSON.stringify(body)})
  .then(function(r){return r.json().catch(function(){return {error:'http '+r.status}})})
  .then(function(j){if(j.error){flash(esc(j.error),true);throw j.error;}return j;});}

function act(action,extra){var b=extra||{};b.action=action;
  return api('action',b).then(function(j){refresh();return j;});}

function confirmAct(msg,action,extra){if(confirm(msg))act(action,extra).then(function(j){
  if(j.temp_password)flash('temp password for '+esc(extra.username)+': <b>'+esc(j.temp_password)+'</b><br>shown once — send it over a secure channel');});}

function createUser(){
  var name=document.getElementById('nu-name').value.trim();
  var role=document.getElementById('nu-role').value;
  var hosts=document.getElementById('nu-hosts').value.split(',').map(function(s){return s.trim()}).filter(Boolean);
  if(!name){flash('username required',true);return;}
  api('user',{username:name,role:role,allowed_hosts:hosts}).then(function(j){
    document.getElementById('nu-name').value='';document.getElementById('nu-hosts').value='';
    flash('created <b>'+esc(name)+'</b> — temp password: <b>'+esc(j.temp_password)+'</b><br>shown once — they must change it on first login');
    refresh();});}

function editHosts(name,cur){var v=prompt('Allowed hosts for '+name+' (comma-separated, blank = all, *.dom ok):',cur);
  if(v===null)return;
  var hosts=v.split(',').map(function(s){return s.trim()}).filter(Boolean);
  act('set_hosts',{username:name,hosts:hosts});}

function renderUsers(){var tb=document.getElementById('users-body');tb.innerHTML='';
  if(!state.users.length){tb.innerHTML='<tr><td colspan="7" class="empty">no users</td></tr>';return;}
  state.users.forEach(function(u){
    var tr=document.createElement('tr');
    var status=u.disabled?'<span class="tag tag--err">disabled</span>':
      (u.must_change?'<span class="tag tag--warn">temp pw</span>':'<span class="tag tag--ok">active</span>');
    var totp=u.totp_enrolled?'<span class="tag tag--ok">on</span> <span style="color:var(--faint);font-size:.65rem">'+u.backup_codes+' codes · '+u.passkeys+' keys</span>'
      :'<span class="tag tag--warn">pending</span>';
    var hosts=(u.allowed_hosts&&u.allowed_hosts.length)?esc(u.allowed_hosts.join(', ')):'<span style="color:var(--faint)">all</span>';
    var last=u.last_ip?ts(u.last_login)+' <span style="color:var(--faint)">('+esc(u.last_ip)+')</span>':'–';
    tr.innerHTML='<td class="mono">'+esc(u.username)+'</td>'+
      '<td><span class="tag tag--'+(u.role==='admin'?'admin':'user')+'">'+esc(u.role)+'</span></td>'+
      '<td>'+status+'</td><td>'+totp+'</td>'+
      '<td class="mono hide-sm" style="font-size:.65rem">'+hosts+'</td>'+
      '<td class="mono hide-sm" style="font-size:.65rem">'+last+'</td>'+
      '<td><div class="row-actions">'+
      (u.disabled?'<button onclick="act(\'enable\',{username:\''+esc(u.username)+'\'})">enable</button>'
        :'<button onclick="confirmAct(\'Disable '+esc(u.username)+'?\',\'disable\',{username:\''+esc(u.username)+'\'})">disable</button>')+
      '<button onclick="confirmAct(\'Reset password for '+esc(u.username)+'?\',\'reset_password\',{username:\''+esc(u.username)+'\'})">reset pw</button>'+
      '<button onclick="confirmAct(\'Reset 2FA for '+esc(u.username)+'? They will re-enroll on next login.\',\'reset_totp\',{username:\''+esc(u.username)+'\'})">reset 2fa</button>'+
      (u.passkeys?'<button onclick="confirmAct(\'Remove all passkeys for '+esc(u.username)+'?\',\'reset_passkeys\',{username:\''+esc(u.username)+'\'})">reset keys</button>':'')+
      '<button onclick="confirmAct(\'Log '+esc(u.username)+' out everywhere?\',\'logout_user\',{username:\''+esc(u.username)+'\'})">logout</button>'+
      '<button onclick="editHosts(\''+esc(u.username)+'\',\''+esc((u.allowed_hosts||[]).join(', '))+'\')">hosts</button>'+
      '<button onclick="act(\'set_role\',{username:\''+esc(u.username)+'\',role:\''+(u.role==='admin'?'user':'admin')+'\'})">'+(u.role==='admin'?'demote':'promote')+'</button>'+
      '<button class="danger" onclick="confirmAct(\'DELETE '+esc(u.username)+'? This cannot be undone.\',\'delete\',{username:\''+esc(u.username)+'\'})">delete</button>'+
      '</div></td>';
    tb.appendChild(tr);});}

function renderLogs(){
  document.getElementById('st-total').textContent=state.audit.Total;
  document.getElementById('st-ok').textContent=state.audit.Success;
  document.getElementById('st-fail').textContent=state.audit.Failed;
  document.getElementById('st-locked').textContent=state.locked.length;
  var lb=document.getElementById('locked-body');lb.innerHTML='';
  if(!state.locked.length){lb.innerHTML='<tr><td colspan="4" class="empty">nothing locked out</td></tr>';}
  state.locked.forEach(function(l){var tr=document.createElement('tr');
    tr.innerHTML='<td class="mono">'+esc(l.IP)+'</td><td class="mono">'+l.Fails+'</td>'+
      '<td class="mono">'+ts(l.Until)+'</td>'+
      '<td><div class="row-actions"><button onclick="act(\'unlock\',{ip:\''+esc(l.IP)+'\'})">unlock</button></div></td>';
    lb.appendChild(tr);});
  var q=document.getElementById('lf-text').value.toLowerCase();
  var kind=document.getElementById('lf-kind').value;
  var tb=document.getElementById('logs-body');tb.innerHTML='';
  var rows=(state.audit.Recent||[]).filter(function(e){
    if(kind && e.event.indexOf(kind)!==0)return false;
    if(q){var hay=(e.event+' '+e.ip+' '+(e.user||'')+' '+(e.host||'')).toLowerCase();
      if(hay.indexOf(q)<0)return false;}
    return true;});
  if(!rows.length){tb.innerHTML='<tr><td colspan="6" class="empty">no matching events</td></tr>';return;}
  rows.forEach(function(e){var tr=document.createElement('tr');
    var cls=e.event==='login_ok'?'tag--ok':(e.event.indexOf('login_fail')===0||e.event==='locked_out'?'tag--err':
      (e.event.indexOf('admin_')===0?'tag--admin':'tag--warn'));
    tr.innerHTML='<td class="mono" style="white-space:nowrap">'+ts(e.time)+'</td>'+
      '<td><span class="tag '+cls+'">'+esc(e.event)+'</span></td>'+
      '<td class="mono">'+esc(e.ip)+'</td><td class="mono">'+esc(e.user||'–')+'</td>'+
      '<td class="mono hide-sm" style="font-size:.65rem">'+esc(e.host||'–')+'</td>'+
      '<td class="mono hide-sm" style="font-size:.62rem;color:var(--faint);max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+esc(e.ua||'')+'</td>';
    tb.appendChild(tr);});}

function renderSessions(){var tb=document.getElementById('sess-body');tb.innerHTML='';
  if(!state.sessions.length){tb.innerHTML='<tr><td colspan="6" class="empty">no sessions seen yet</td></tr>';return;}
  state.sessions.forEach(function(s){var tr=document.createElement('tr');
    tr.innerHTML='<td class="mono">'+esc(s.user)+'</td><td class="mono">'+esc(s.ip)+'</td>'+
      '<td class="mono hide-sm" style="font-size:.62rem;color:var(--faint);max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+esc(s.ua)+'</td>'+
      '<td class="mono">'+ago(s.created)+'</td><td class="mono">'+ago(s.last_seen)+'</td>'+
      '<td><div class="row-actions"><button class="danger" onclick="confirmAct(\'Revoke this session?\',\'revoke_session\',{sid:\''+esc(s.sid)+'\'})">revoke</button></div></td>';
    tb.appendChild(tr);});}

function refresh(){fetch('/_auth/admin/api/state?n=300')
  .then(function(r){if(!r.ok)throw 'http '+r.status;return r.json()})
  .then(function(j){state=j;renderUsers();renderLogs();renderSessions();})
  .catch(function(e){/* transient poll error — keep last state */});}

refresh();
setInterval(refresh,5000);
</script>
</body>
</html>`
