package main

// adminpage.go — the admin panel: a single self-contained HTML page that
// polls /_auth/admin/api/state and drives the JSON API in admin.go. Served
// only to admin sessions. Styled with the Claude design system
// (/static/claude-theme.css) plus a small nonce'd adminCSS block with
// layout-only rules — every colour comes from the theme's custom properties.

import (
	"net/http"
	"strings"
)

func (s *server) renderAdmin(w http.ResponseWriter, adminUser, csrf, nonce string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	page := adminPage
	page = strings.ReplaceAll(page, "{{ADMIN}}", htmlEscape(adminUser))
	page = strings.ReplaceAll(page, "{{CSRF}}", csrf)
	page = strings.ReplaceAll(page, "{{NONCE}}", nonce)
	_, _ = w.Write([]byte(page))
}

// adminCSS holds the admin-panel layout rules. All colours reference the
// claude-theme.css custom properties — the theme palette is never redefined.
const adminCSS = `
  body{padding:32px 20px}
  svg{display:block}
  .panel{width:100%;max-width:1060px;margin:0 auto}
  .top{display:flex;align-items:center;justify-content:space-between;margin-bottom:22px;flex-wrap:wrap;gap:10px}
  .top .brand{margin:0}
  .top__who{font-size:11px;color:var(--text-muted);letter-spacing:.06em}
  .top__who a{color:var(--accent);text-decoration:none;margin-left:12px}
  .user-accent{color:var(--accent)}
  .brand{display:flex;align-items:center;justify-content:center;gap:10px;margin-bottom:4px}
  .brand__text{font-weight:600;letter-spacing:.12em;font-size:1.05rem;color:var(--text-primary)}
  .brand__slash{color:var(--accent)}
  .tabs{display:flex;gap:8px;margin-bottom:18px}
  .tabs button{width:auto;padding:8px 16px;background:transparent;border:1px solid var(--border-subtle);
    color:var(--text-secondary);border-radius:var(--radius-md);cursor:pointer;font-size:13px;
    font-weight:500;transition:background var(--transition),color var(--transition),border-color var(--transition)}
  .tabs button:hover{background:var(--surface-2);color:var(--text-primary)}
  .tabs button.on{background:var(--accent-subtle);border-color:var(--border-focus);color:var(--accent)}
  .card h3{font-size:11px;font-weight:500;letter-spacing:.06em;color:var(--text-muted);
    text-transform:uppercase;margin:0 0 14px}
  .stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:18px}
  .stat{padding:14px 16px;margin-bottom:0}
  .stat__n{font-size:22px;font-weight:700;color:var(--text-primary)}
  .stat__l{font-size:11px;letter-spacing:.06em;color:var(--text-muted);text-transform:uppercase;margin-top:4px}
  .filter{display:flex;gap:10px;margin-bottom:12px;flex-wrap:wrap}
  .filter input,.filter select{width:auto;flex:1;min-width:160px}
  .newuser{display:grid;grid-template-columns:1fr 130px 1fr auto;gap:10px;align-items:end}
  .newuser label{display:block;font-size:12px;font-weight:500;color:var(--text-secondary);margin-bottom:6px}
  .row-actions{display:flex;gap:6px;flex-wrap:wrap}
  #flash{position:fixed;top:18px;left:50%;transform:translateX(-50%);z-index:10;display:none;
    background:var(--surface-0);border:1px solid var(--green);border-radius:var(--radius-md);
    padding:14px 20px;font-size:13px;color:var(--text-primary);box-shadow:var(--shadow-modal);
    max-width:90vw;word-break:break-all;text-align:center}
  #flash.err{border-color:var(--red)}
  #flash b{color:var(--green)}
  .empty{color:var(--text-muted);font-size:12px;padding:14px 10px}
  .muted-inline{color:var(--text-muted);text-transform:none;letter-spacing:0}
  .hosts-hint{font-size:11px}
  .last-info{font-size:11px}
  .agent-cell{font-size:11px;color:var(--text-muted);max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .session-agent{font-size:11px;color:var(--text-muted);max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .nowrap{white-space:nowrap}
  .hidden{display:none}
  .stat-ok{color:var(--green)}
  .stat-fail{color:var(--red)}
  .stat-locked{color:var(--orange)}
  .small{font-size:11px}
  @media(max-width:760px){.newuser{grid-template-columns:1fr}.hide-sm{display:none}}
`

const adminPage = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<meta name="csrf-token" content="{{CSRF}}">
<title>xore//auth — admin</title>
<link rel="stylesheet" href="/static/claude-theme.css">
<style nonce="{{NONCE}}">` + adminCSS + `</style>
</head>
<body>
  <div id="flash"></div>
  <div class="panel">
    <div class="top">` + brandHTML + `
      <div class="top__who">signed in as <span class="user-accent">{{ADMIN}}</span>
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
          <div><label>username</label><input class="form-input" id="nu-name" autocomplete="off" autocapitalize="none" spellcheck="false"></div>
          <div><label>role</label><select class="form-input" id="nu-role"><option value="user">user</option><option value="admin">admin</option></select></div>
          <div><label>allowed hosts <span class="muted-inline">— blank = all; comma-sep, *.dom ok</span></label>
            <input class="form-input" id="nu-hosts" placeholder="grafana.xore.rocks, *.media.xore.rocks"></div>
          <button class="btn btn-primary" onclick="createUser()">create</button>
        </div>
      </div>
      <div class="card">
        <h3>users</h3>
        <table class="data-table"><thead><tr>
          <th>user</th><th>role</th><th>status</th><th>2fa</th>
          <th class="hide-sm">allowed hosts</th><th class="hide-sm">last login</th><th>actions</th>
        </tr></thead><tbody id="users-body"></tbody></table>
      </div>
    </div>

    <div id="pane-logs" class="hidden">
      <div class="stats">
        <div class="card stat"><div class="stat__n" id="st-total">–</div><div class="stat__l">attempts</div></div>
        <div class="card stat"><div class="stat__n stat-ok" id="st-ok">–</div><div class="stat__l">successful</div></div>
        <div class="card stat"><div class="stat__n stat-fail" id="st-fail">–</div><div class="stat__l">failed</div></div>
        <div class="card stat"><div class="stat__n stat-locked" id="st-locked">–</div><div class="stat__l">locked ips</div></div>
      </div>
      <div class="card">
        <h3>locked out</h3>
        <table class="data-table"><thead><tr><th>ip</th><th>fails</th><th>until</th><th></th></tr></thead>
        <tbody id="locked-body"></tbody></table>
      </div>
      <div class="card">
        <h3>audit log</h3>
        <div class="filter">
          <input class="form-input" id="lf-text" placeholder="filter: ip / user / host / event…" oninput="renderLogs()">
          <select class="form-input" id="lf-kind" onchange="renderLogs()">
            <option value="">all events</option>
            <option value="login_ok">login ok</option>
            <option value="login_fail">login failed</option>
            <option value="locked_out">lockouts</option>
            <option value="admin_">admin actions</option>
            <option value="enroll">enrollment</option>
          </select>
        </div>
        <table class="data-table"><thead><tr>
          <th>time</th><th>event</th><th>ip</th><th>user</th><th class="hide-sm">host</th><th class="hide-sm">agent</th>
        </tr></thead><tbody id="logs-body"></tbody></table>
      </div>
    </div>

    <div id="pane-sessions" class="hidden">
      <div class="card">
        <h3>active sessions <span class="muted-inline">(best effort — repopulates after restart)</span></h3>
        <table class="data-table"><thead><tr>
          <th>user</th><th>ip</th><th class="hide-sm">agent</th><th>signed in</th><th>last seen</th><th></th>
        </tr></thead><tbody id="sess-body"></tbody></table>
      </div>
    </div>
  </div>

<script nonce="{{NONCE}}">
var CSRF = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
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
    var status=u.disabled?'<span class="badge badge--red">disabled</span>':
      (u.must_change?'<span class="badge badge--orange">temp pw</span>':'<span class="badge badge--green">active</span>');
    var totp=u.totp_enrolled?'<span class="badge badge--green">on</span> <span class="muted-inline small">'+u.backup_codes+' codes · '+u.passkeys+' keys</span>'
      :'<span class="badge badge--orange">pending</span>';
    var hosts=(u.allowed_hosts&&u.allowed_hosts.length)?esc(u.allowed_hosts.join(', ')):'<span class="muted-inline">all</span>';
    var last=u.last_ip?ts(u.last_login)+' <span class="muted-inline">('+esc(u.last_ip)+')</span>':'–';
    tr.innerHTML='<td class="mono">'+esc(u.username)+'</td>'+
      '<td><span class="badge '+(u.role==='admin'?'badge--blue':'badge--muted')+'">'+esc(u.role)+'</span></td>'+
      '<td>'+status+'</td><td>'+totp+'</td>'+
      '<td class="mono hide-sm hosts-hint">'+hosts+'</td>'+
      '<td class="mono hide-sm last-info">'+last+'</td>'+
      '<td><div class="row-actions">'+
      (u.disabled?'<button class="btn btn-secondary btn-sm" onclick="act(\'enable\',{username:\''+esc(u.username)+'\'})">enable</button>'
        :'<button class="btn btn-secondary btn-sm" onclick="confirmAct(\'Disable '+esc(u.username)+'?\',\'disable\',{username:\''+esc(u.username)+'\'})">disable</button>')+
      '<button class="btn btn-secondary btn-sm" onclick="confirmAct(\'Reset password for '+esc(u.username)+'?\',\'reset_password\',{username:\''+esc(u.username)+'\'})">reset pw</button>'+
      '<button class="btn btn-secondary btn-sm" onclick="confirmAct(\'Reset 2FA for '+esc(u.username)+'? They will re-enroll on next login.\',\'reset_totp\',{username:\''+esc(u.username)+'\'})">reset 2fa</button>'+
      (u.passkeys?'<button class="btn btn-secondary btn-sm" onclick="confirmAct(\'Remove all passkeys for '+esc(u.username)+'?\',\'reset_passkeys\',{username:\''+esc(u.username)+'\'})">reset keys</button>':'')+
      '<button class="btn btn-secondary btn-sm" onclick="confirmAct(\'Log '+esc(u.username)+' out everywhere?\',\'logout_user\',{username:\''+esc(u.username)+'\'})">logout</button>'+
      '<button class="btn btn-secondary btn-sm" onclick="editHosts(\''+esc(u.username)+'\',\''+esc((u.allowed_hosts||[]).join(', '))+'\')">hosts</button>'+
      '<button class="btn btn-secondary btn-sm" onclick="act(\'set_role\',{username:\''+esc(u.username)+'\',role:\''+(u.role==='admin'?'user':'admin')+'\'})">'+(u.role==='admin'?'demote':'promote')+'</button>'+
      '<button class="btn btn-danger btn-sm" onclick="confirmAct(\'DELETE '+esc(u.username)+'? This cannot be undone.\',\'delete\',{username:\''+esc(u.username)+'\'})">delete</button>'+
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
      '<td><div class="row-actions"><button class="btn btn-secondary btn-sm" onclick="act(\'unlock\',{ip:\''+esc(l.IP)+'\'})">unlock</button></div></td>';
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
    var cls=e.event==='login_ok'?'badge--green':(e.event.indexOf('login_fail')===0||e.event==='locked_out'?'badge--red':
      (e.event.indexOf('admin_')===0?'badge--blue':'badge--orange'));
    tr.innerHTML='<td class="mono nowrap">'+ts(e.time)+'</td>'+
      '<td><span class="badge '+cls+'">'+esc(e.event)+'</span></td>'+
      '<td class="mono">'+esc(e.ip)+'</td><td class="mono">'+esc(e.user||'–')+'</td>'+
      '<td class="mono hide-sm hosts-hint">'+esc(e.host||'–')+'</td>'+
      '<td class="mono hide-sm agent-cell">'+esc(e.ua||'')+'</td>';
    tb.appendChild(tr);});}

function renderSessions(){var tb=document.getElementById('sess-body');tb.innerHTML='';
  if(!state.sessions.length){tb.innerHTML='<tr><td colspan="6" class="empty">no sessions seen yet</td></tr>';return;}
  state.sessions.forEach(function(s){var tr=document.createElement('tr');
    tr.innerHTML='<td class="mono">'+esc(s.user)+'</td><td class="mono">'+esc(s.ip)+'</td>'+
      '<td class="mono hide-sm session-agent">'+esc(s.ua)+'</td>'+
      '<td class="mono">'+ago(s.created)+'</td><td class="mono">'+ago(s.last_seen)+'</td>'+
      '<td><div class="row-actions"><button class="btn btn-danger btn-sm" onclick="confirmAct(\'Revoke this session?\',\'revoke_session\',{sid:\''+esc(s.sid)+'\'})">revoke</button></div></td>';
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
