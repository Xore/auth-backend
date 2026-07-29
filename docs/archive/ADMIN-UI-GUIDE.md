# Admin UI — Shared Settings Surface

> **Archived:** The admin settings surface described here has been implemented.
> Keep this document for historical design context; use the application and
> current README for operating instructions.

This guide covers how to build the **settings / admin panel modal** shown in
the screenshot: a split-pane surface with a left sidebar and right content area.
It uses the shared theme while preserving the existing `adminpage.go` and
`admin.go` API contracts.

---

## Table of Contents

1. [Architecture overview](#1-architecture-overview)
2. [When to open the modal](#2-when-to-open-the-modal)
3. [Modal HTML shell](#3-modal-html-shell)
4. [Sidebar — Settings section](#4-sidebar--settings-section)
5. [Sidebar — Administration section (admin-only)](#5-sidebar--administration-section-admin-only)
6. [Right pane: Account](#6-right-pane-account)
7. [Right pane: Privacy & Sessions](#7-right-pane-privacy--sessions)
8. [Right pane: Admin — Users](#8-right-pane-admin--users)
9. [Right pane: Admin — Audit Log](#9-right-pane-admin--audit-log)
10. [Right pane: Admin — Active Sessions](#10-right-pane-admin--active-sessions)
11. [Right pane: Admin — System](#11-right-pane-admin--system)
12. [Go integration — rendering the modal](#12-go-integration--rendering-the-modal)
13. [Go integration — data structs](#13-go-integration--data-structs)
14. [Pane routing (JS)](#14-pane-routing-js)
15. [Sidebar search](#15-sidebar-search)
16. [Checklist](#16-checklist)

---

## 1. Architecture overview

```
browser                  Go server
  |
  |-- GET /auth/app  -->  Renders shell page (app.html)
  |                       Contains modal markup, injects
  |                       {{.IsAdmin}}, {{.User}}, {{.OrgID}}
  |
  |  (user clicks avatar / settings icon)
  |-- JS opens modal
  |
  |-- GET /_auth/admin/api/state  (every 5 s, admin only)
  |                                 Returns JSON: users, audit, sessions
  |
  |-- POST /_auth/admin/api/action  (admin actions)
  |-- GET /_auth/sessions           (own sessions, all users)
  |-- POST /_auth/logout            (log out of all devices)
```

The modal lives **inside the app shell page** (not a separate route). It is
shown/hidden by toggling `.open` CSS classes. All data is fetched via the
existing JSON API.

---

## 2. When to open the modal

After a successful login, redirect to `/auth/app` (a new route that renders the
shell). The modal opens **automatically on page load** for first-time settings
setup, or on demand when the user clicks a settings button.

```go
// In main.go — add after existing login success redirect:
mux.HandleFunc("/auth/app", s.renderApp)

// In page.go or a new apppage.go:
func (s *server) renderApp(w http.ResponseWriter, r *http.Request) {
    // Require valid session
    username, isAdmin, err := s.config.validateSession(r)
    if err != nil {
        http.Redirect(w, r, "/auth/login?rd="+r.URL.RequestURI(), http.StatusFound)
        return
    }
    data := AppPageData{
        User:    username,
        IsAdmin: isAdmin,
        OrgID:   s.config.orgID, // from config, e.g. env var ORG_ID
        CSRF:    s.config.csrfToken(r),
    }
    appTmpl.Execute(w, data)
}

type AppPageData struct {
    User    string
    IsAdmin bool
    OrgID   string
    CSRF    string
}
```

Alternatively, embed the modal into the **existing forward-auth login-complete
redirect target** so it opens immediately post-login.

---

## 3. Modal HTML shell

The full modal structure to include inside `app.html`
(see `THEME-GUIDE.md §4` for the CSS):

```html
<!-- Trigger button (e.g. in a nav bar) -->
<button class="btn-ghost" onclick="openSettings()" aria-label="Settings">
  <svg width="20" height="20"><!-- gear icon --></svg>
</button>

<!-- Backdrop -->
<div class="modal-backdrop" id="settings-backdrop"
     onclick="closeSettings()" aria-hidden="true"></div>

<!-- Modal -->
<dialog class="modal" id="settings-modal"
        aria-modal="true" aria-labelledby="settings-title">

  <!-- Sidebar -->
  <aside class="modal__sidebar">
    <div class="sidebar__search">
      <svg class="sidebar__search-icon" width="14" height="14" viewBox="0 0 24 24"
           fill="none" stroke="currentColor" stroke-width="2">
        <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
      </svg>
      <input type="search" id="sidebar-search" placeholder="Search"
             aria-label="Search settings" oninput="filterSidebar(this.value)" />
    </div>
    <nav id="settings-nav" aria-label="Settings navigation"></nav>
  </aside>

  <!-- Content -->
  <div class="modal__content" id="settings-content">
    <button class="modal__close" onclick="closeSettings()" aria-label="Close settings">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none"
           stroke="currentColor" stroke-width="2.5">
        <path d="M18 6 6 18M6 6l12 12"/>
      </svg>
    </button>
    <!-- Panes rendered here by renderPane() -->
  </div>
</dialog>
```

JS to open/close:

```js
function openSettings(pane) {
  document.getElementById('settings-backdrop').classList.add('open');
  const modal = document.getElementById('settings-modal');
  modal.classList.add('open');
  modal.showModal?.(); // native <dialog> API
  document.body.style.overflow = 'hidden';
  renderNav();
  showPane(pane || 'account');
}

function closeSettings() {
  document.getElementById('settings-backdrop').classList.remove('open');
  const modal = document.getElementById('settings-modal');
  modal.classList.remove('open');
  modal.close?.();
  document.body.style.overflow = '';
}

// Keyboard: Esc closes
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeSettings(); });
```

---

## 4. Sidebar — Settings section

Items visible to **all authenticated users**. Icons are inline SVG.

```js
const SETTINGS_NAV = [
  { id: 'account',  label: 'Account',         icon: '<!-- user-circle svg -->' },
  { id: 'privacy',  label: 'Privacy',          icon: '<!-- shield svg -->' },
  { id: 'sessions', label: 'Sessions',         icon: '<!-- devices svg -->' },
];
```

Each sidebar item maps to a **pane ID** (see §§6–7).

Rendering:
```js
function renderNav() {
  const nav = document.getElementById('settings-nav');
  let html = '<div class="sidebar__section-label">Settings</div>';
  SETTINGS_NAV.forEach(item => {
    html += `<button class="sidebar__item ${activePane===item.id?'active':''}" 
               onclick="showPane('${item.id}')">
               ${item.icon} ${item.label}
             </button>`;
  });

  if (IS_ADMIN) {
    html += '<div class="sidebar__section-label" style="margin-top:12px">Administration</div>';
    ADMIN_NAV.forEach(item => {
      html += `<button class="sidebar__item ${activePane===item.id?'active':''}" 
                 onclick="showPane('${item.id}')">
                 ${item.icon} ${item.label}
               </button>`;
    });
  }

  nav.innerHTML = html;
}
```

The `IS_ADMIN` variable is injected from the Go template:
```html
<script>var IS_ADMIN = {{.IsAdmin}}; var CURRENT_USER = "{{.User}}"; var ORG_ID = "{{.OrgID}}";</script>
```

---

## 5. Sidebar — Administration section (admin-only)

```js
const ADMIN_NAV = [
  { id: 'admin-users',    label: 'Users',           icon: '<!-- users svg -->' },
  { id: 'admin-logs',     label: 'Audit Log',        icon: '<!-- list svg -->' },
  { id: 'admin-sessions', label: 'Active Sessions',  icon: '<!-- monitor svg -->' },
  { id: 'admin-system',   label: 'System',           icon: '<!-- server svg -->' },
];
```

This section is only rendered when `IS_ADMIN === true`. It replaces the
`Customize` label (Skills / Connectors / Plugins / Memory) with `Administration`.

---

## 6. Right pane: Account

Matches the **Account** section in the screenshot exactly:

```html
<!-- Rendered into #settings-content -->
<h2 id="settings-title">Account</h2>

<div class="card">
  <div class="card__row">
    <div>
      <div class="card__label">Log out of all devices</div>
    </div>
    <button class="btn btn-secondary btn-sm" onclick="logoutAll()">Log out</button>
  </div>
  <div class="card__row">
    <div>
      <div class="card__label">Delete account</div>
      <div class="card__value">Permanently remove your account and all data.</div>
    </div>
    <button class="btn btn-secondary btn-sm" onclick="deleteAccount()">Delete account</button>
  </div>
</div>

<div class="card">
  <div class="card__row">
    <span class="card__label">Organization ID</span>
    <span class="card__value--mono" onclick="copyToClipboard(ORG_ID)"
          title="Click to copy">{{ORG_ID}}</span>
  </div>
</div>

<!-- Trusted devices -->
<h3 style="margin-bottom:4px">Trusted devices</h3>
<p style="font-size:13px;color:var(--text-secondary);margin-bottom:16px">
  Devices that can control your local machine through remote sessions.
</p>
<table class="data-table" id="trusted-devices-table">
  <thead><tr><th>Device</th><th>Added</th><th></th></tr></thead>
  <tbody id="trusted-devices-body"></tbody>
</table>
```

Data source: add a `GET /_auth/sessions/trusted` endpoint that returns the
user's trusted devices. Populate `#trusted-devices-body` via JS on pane load.

---

## 7. Right pane: Privacy & Sessions

**Privacy** pane — link to data export + account deletion confirm flow.

**Sessions** pane — shows the user's **own** active sessions with a `Current`
badge on the current device:

```html
<h2>Active sessions</h2>
<table class="data-table">
  <thead>
    <tr>
      <th>Device</th><th>Location</th>
      <th>Created</th><th>Updated</th><th></th>
    </tr>
  </thead>
  <tbody id="my-sessions-body"></tbody>
</table>
```

JS to populate:
```js
function loadMySessions() {
  fetch('/_auth/sessions/mine')
    .then(r => r.json())
    .then(sessions => {
      const tb = document.getElementById('my-sessions-body');
      tb.innerHTML = sessions.map(s => `
        <tr>
          <td>
            ${esc(s.device)}
            ${s.current ? '<span class="badge badge--blue">Current</span>' : ''}
          </td>
          <td>${esc(s.location)}</td>
          <td>${fmtDate(s.created)}</td>
          <td>${fmtDate(s.updated)}</td>
          <td>
            ${!s.current
              ? `<button class="btn btn-secondary btn-sm"
                   onclick="revokeSession('${esc(s.id)}')">
                   Sign out
                 </button>`
              : ''}
          </td>
        </tr>`).join('');
    });
}
```

New Go endpoint to add (returns only the current user's sessions):
```go
mux.HandleFunc("/_auth/sessions/mine", s.handleMySessions)
```

---

## 8. Right pane: Admin — Users

Maps to the existing `pane-users` from `adminpage.go`, restyled with
the shared theme components.

Key changes from the current admin UI:
- Replace `.newuser` grid with a `.card` containing `form-group` / `form-input` elements.
- Replace raw `<table>` styles with `.data-table`.
- Replace `.tag` badges with `.badge` variants from the theme.
- Replace `.row-actions button` with `.btn .btn-secondary .btn-sm`.

Data still comes from `/_auth/admin/api/state` — **no backend changes needed**.

```js
// In showPane(), when pane is 'admin-users':
function loadAdminUsers(state) {
  const tb = document.getElementById('admin-users-body');
  tb.innerHTML = state.users.map(u => `
    <tr>
      <td class="mono">${esc(u.username)}</td>
      <td><span class="badge ${u.role==='admin'?'badge--blue':'badge--muted'}">${u.role}</span></td>
      <td><span class="badge ${u.disabled?'badge--red':u.must_change?'badge--orange':'badge--green'}">
          ${u.disabled?'disabled':u.must_change?'temp pw':'active'}</span></td>
      <td>${u.totp_enrolled
        ? `<span class="badge badge--green">2FA on</span>`
        : `<span class="badge badge--orange">pending</span>`}</td>
      <td class="hide-sm mono" style="font-size:11px">${esc((u.allowed_hosts||[]).join(', ')||'all')}</td>
      <td><!-- action buttons --></td>
    </tr>`).join('');
}
```

---

## 9. Right pane: Admin — Audit Log

Maps to `pane-logs`. Keep the same stat cards and filter row; just restyle.

Stat cards — use the `.card` component in a `display:grid` row:
```html
<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px">
  <div class="card" style="padding:16px">
    <div style="font-size:24px;font-weight:700" id="st-total">–</div>
    <div style="font-size:11px;color:var(--text-muted);text-transform:uppercase
                ;letter-spacing:.06em;margin-top:4px">Attempts</div>
  </div>
  <!-- repeat for ok / failed / locked -->
</div>
```

Filter row — use `form-input` and a `<select>` styled as `form-input`.

Table — use `.data-table`; badge event types with `.badge` colours.

All data still from `state.audit` — **no backend changes**.

---

## 10. Right pane: Admin — Active Sessions

Maps to `pane-sessions`. Shows **all** users' sessions (admin view).
Use `.data-table` and `.badge--blue` for current session indicator.

Revoke button — `.btn .btn-danger .btn-sm`.

Data still from `state.sessions` via `/_auth/admin/api/state`.

---

## 11. Right pane: Admin — System

New pane — shows system-level information about the auth-backend.
Requires a new `GET /_auth/admin/api/system` endpoint.

### Data to expose

```go
type SystemInfo struct {
    Version       string    `json:"version"`       // git tag or build hash
    Uptime        string    `json:"uptime"`        // e.g. "3d 4h"
    DataDir       string    `json:"data_dir"`      // redacted path
    AuthHost      string    `json:"auth_host"`     // e.g. auth.xore.rocks
    SessionTTL    string    `json:"session_ttl"`   // e.g. "7d"
    OrgID         string    `json:"org_id"`
    TotpRequired  bool      `json:"totp_required"`
    PasskeyCount  int       `json:"passkey_count"`
    UserCount     int       `json:"user_count"`
    AdminCount    int       `json:"admin_count"`
    StartedAt     time.Time `json:"started_at"`
}
```

### System pane layout

```html
<h2>System</h2>
<div class="card">
  <div class="card__row">
    <span class="card__label">Version</span>
    <span class="card__value--mono" id="sys-version">–</span>
  </div>
  <div class="card__row">
    <span class="card__label">Uptime</span>
    <span class="card__value" id="sys-uptime">–</span>
  </div>
  <div class="card__row">
    <span class="card__label">Auth host</span>
    <span class="card__value--mono" id="sys-host">–</span>
  </div>
  <div class="card__row">
    <span class="card__label">Session TTL</span>
    <span class="card__value" id="sys-session-ttl">–</span>
  </div>
  <div class="card__row">
    <span class="card__label">TOTP required</span>
    <span id="sys-totp">–</span>
  </div>
  <div class="card__row">
    <span class="card__label">Organization ID</span>
    <span class="card__value--mono" id="sys-org-id">–</span>
  </div>
</div>

<div class="card">
  <div class="card__row">
    <span class="card__label">Total users</span>
    <span class="card__value" id="sys-user-count">–</span>
  </div>
  <div class="card__row">
    <span class="card__label">Admin users</span>
    <span class="card__value" id="sys-admin-count">–</span>
  </div>
  <div class="card__row">
    <span class="card__label">Registered passkeys</span>
    <span class="card__value" id="sys-passkey-count">–</span>
  </div>
  <div class="card__row">
    <span class="card__label">Server started</span>
    <span class="card__value" id="sys-started">–</span>
  </div>
</div>
```

Fetch on pane open:
```js
function loadSystem() {
  fetch('/_auth/admin/api/system')
    .then(r => r.json())
    .then(info => {
      document.getElementById('sys-version').textContent = info.version;
      document.getElementById('sys-uptime').textContent  = info.uptime;
      document.getElementById('sys-host').textContent    = info.auth_host;
      document.getElementById('sys-session-ttl').textContent = info.session_ttl;
      document.getElementById('sys-totp').innerHTML =
        info.totp_required
          ? '<span class="badge badge--green">Required</span>'
          : '<span class="badge badge--orange">Optional</span>';
      document.getElementById('sys-org-id').textContent     = info.org_id;
      document.getElementById('sys-user-count').textContent = info.user_count;
      document.getElementById('sys-admin-count').textContent= info.admin_count;
      document.getElementById('sys-passkey-count').textContent = info.passkey_count;
      document.getElementById('sys-started').textContent    = fmtDate(info.started_at);
    });
}
```

### Backend — system endpoint

Add to `admin.go`:
```go
func (s *server) handleAdminSystem(w http.ResponseWriter, r *http.Request) {
    if !s.isAdminSession(r) {
        http.Error(w, "forbidden", http.StatusForbidden)
        return
    }
    users := s.config.listUsers()
    adminCount := 0
    passkeyCount := 0
    for _, u := range users {
        if u.Role == "admin" { adminCount++ }
        passkeyCount += u.Passkeys
    }
    info := SystemInfo{
        Version:      s.config.version,
        Uptime:       formatUptime(time.Since(s.startedAt)),
        AuthHost:     s.config.authHost,
        SessionTTL:   s.config.sessionTTL.String(),
        OrgID:        s.config.orgID,
        TotpRequired: s.config.totpRequired,
        PasskeyCount: passkeyCount,
        UserCount:    len(users),
        AdminCount:   adminCount,
        StartedAt:    s.startedAt,
    }
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(info)
}

func formatUptime(d time.Duration) string {
    days := int(d.Hours()) / 24
    hours := int(d.Hours()) % 24
    if days > 0 { return fmt.Sprintf("%dd %dh", days, hours) }
    return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
}
```

---

## 12. Go integration — rendering the modal

1. Create `forward-auth/ui/app.html` — the shell page that contains the
   modal markup, injects `IS_ADMIN`, `CURRENT_USER`, `ORG_ID`, `CSRF`.

2. Embed it:
```go
//go:embed ui/app.html
var appHTML []byte
var appTmpl = template.Must(template.New("app.html").Funcs(tmplFuncs).Parse(string(appHTML)))
```

3. Add to `main.go`:
```go
mux.HandleFunc("/auth/app",            s.renderApp)
mux.HandleFunc("/_auth/admin/api/system", s.handleAdminSystem)
mux.HandleFunc("/_auth/sessions/mine",    s.handleMySessions)
mux.HandleFunc("/_auth/sessions/trusted", s.handleTrustedDevices)
```

4. After successful login, redirect to `/auth/app` instead of the original `rd`
   URL when no `rd` param is set. When `rd` is set, respect it (Traefik forward-auth
   flow). The modal can be opened programmatically with `openSettings()` if you
   want it to appear immediately on first login.

---

## 13. Go integration — data structs

```go
// AppPageData is passed to ui/app.html
type AppPageData struct {
    User    string // current username
    IsAdmin bool
    OrgID   string
    CSRF    string
}

// MySession is one entry in /_auth/sessions/mine
type MySession struct {
    ID       string    `json:"id"`
    Device   string    `json:"device"`   // "Chrome on Windows · City"
    Location string    `json:"location"` // "City, Country"
    Current  bool      `json:"current"`
    Created  time.Time `json:"created"`
    Updated  time.Time `json:"updated"`
}

// TrustedDevice is one entry in /_auth/sessions/trusted
type TrustedDevice struct {
    ID     string    `json:"id"`
    Name   string    `json:"name"`   // "Electron on Windows · City"
    Added  time.Time `json:"added"`
}
```

`MySession.Device` should be built from the `User-Agent` header (use
`github.com/mssola/useragent` or a simple parser) plus the GeoIP city
resolved from the session IP.

---

## 14. Pane routing (JS)

```js
let activePane = 'account';

const PANE_LOADERS = {
  'account':        loadAccount,
  'sessions':       loadMySessions,
  'admin-users':    () => loadAdminUsers(state),
  'admin-logs':     () => loadAdminLogs(state),
  'admin-sessions': () => loadAdminSessions(state),
  'admin-system':   loadSystem,
};

function showPane(id) {
  activePane = id;
  renderNav(); // re-render sidebar to update .active class

  const content = document.getElementById('settings-content');
  content.innerHTML = PANE_TEMPLATES[id]; // static HTML shells
  content.scrollTop = 0;

  // Re-insert close button after innerHTML replacement
  content.insertAdjacentHTML('afterbegin', CLOSE_BTN_HTML);

  if (PANE_LOADERS[id]) PANE_LOADERS[id]();
}
```

Define `PANE_TEMPLATES` as a JS object keyed by pane ID, each value being the
static HTML skeleton (headings, empty tables, etc.) from §§6–11.

---

## 15. Sidebar search

```js
function filterSidebar(query) {
  const q = query.toLowerCase();
  document.querySelectorAll('.sidebar__item').forEach(btn => {
    const match = btn.textContent.toLowerCase().includes(q);
    btn.style.display = match ? '' : 'none';
  });
  // Hide empty section labels
  document.querySelectorAll('.sidebar__section-label').forEach(label => {
    const section = label.nextElementSibling;
    const hasVisible = [...label.parentElement.querySelectorAll('.sidebar__item')]
      .filter(b => b.previousElementSibling === label ||
                   b.closest('[data-section]') === label.closest('[data-section]'))
      .some(b => b.style.display !== 'none');
    label.style.display = hasVisible ? '' : 'none';
  });
}
```

---

## 16. Checklist

### Modal shell
- [ ] `forward-auth/ui/app.html` created with modal markup
- [ ] `theme.css` linked (see `THEME-GUIDE.md §12`)
- [ ] `IS_ADMIN`, `CURRENT_USER`, `ORG_ID`, `CSRF` injected from Go template
- [ ] `openSettings()` / `closeSettings()` JS functions
- [ ] Esc key closes modal
- [ ] Click on backdrop closes modal
- [ ] Mobile: modal stacks vertically, full-screen

### Sidebar
- [ ] Search input filters items live
- [ ] `Settings` section always shown
- [ ] `Administration` section shown only when `IS_ADMIN === true`
- [ ] Active pane highlighted with `.active` class
- [ ] Section labels hidden when all children are filtered out

### Account pane
- [ ] "Log out of all devices" button → `POST /_auth/logout`
- [ ] "Delete account" button with confirm dialog
- [ ] Organization ID displayed, click to copy
- [ ] Trusted devices table populated from `/_auth/sessions/trusted`
- [ ] Active sessions table populated from `/_auth/sessions/mine`
- [ ] Current session marked with `.badge--blue` "Current"

### Admin — Users
- [ ] Restyled with `.data-table`, `.badge`, `.btn` components
- [ ] Create user form in `.card` with `form-input`
- [ ] All actions (disable, reset pw, reset 2fa, delete) still use `/_auth/admin/api/action`

### Admin — Audit Log
- [ ] Stat cards use `.card` component
- [ ] Filter row uses `form-input`
- [ ] Table uses `.data-table`
- [ ] Badges use `.badge` colour variants

### Admin — Active Sessions
- [ ] Table uses `.data-table`
- [ ] Revoke uses `.btn-danger`

### Admin — System
- [ ] `GET /_auth/admin/api/system` endpoint added to `admin.go`
- [ ] `SystemInfo` struct populated
- [ ] `formatUptime()` helper added
- [ ] `s.startedAt` field added to server struct, set in `main()`
- [ ] System pane displays all fields from `SystemInfo`

### New Go routes
- [ ] `GET /auth/app` → `renderApp()`
- [ ] `GET /_auth/admin/api/system` → `handleAdminSystem()`
- [ ] `GET /_auth/sessions/mine` → `handleMySessions()`
- [ ] `GET /_auth/sessions/trusted` → `handleTrustedDevices()`

### Production
- [ ] `theme.css` built and embedded (see `THEME-GUIDE.md §12`)
- [ ] CSP updated: no new external origins needed (all JS/CSS is self-hosted)
- [ ] Modal tested on mobile (320 px min-width)
