# Claude Theme — CSS System & Page Boilerplate

This guide defines a CSS design-token system and component boilerplate that
exactly reproduces the dark theme used across **claude.ai** (verified July 2026).
All admin and auth pages in this repo should import this system.

---

## Table of Contents

1. [Design tokens](#1-design-tokens)
2. [Typography](#2-typography)
3. [Page boilerplate](#3-page-boilerplate)
4. [Component: Modal / settings panel](#4-component-modal--settings-panel)
5. [Component: Sidebar nav](#5-component-sidebar-nav)
6. [Component: Card](#6-component-card)
7. [Component: Table](#7-component-table)
8. [Component: Badges / tags](#8-component-badges--tags)
9. [Component: Buttons](#9-component-buttons)
10. [Component: Form inputs](#10-component-form-inputs)
11. [Tailwind config (if using Tailwind)](#11-tailwind-config-if-using-tailwind)
12. [Using with Go embed](#12-using-with-go-embed)

---

## 1. Design tokens

Defined as CSS custom properties on `:root`. Every component references these
variables only — never hard-code hex values in component CSS.

```css
:root {
  /* ── Surfaces ───────────────────────────────── */
  --bg:            #1a1a1a;   /* page / backdrop */
  --surface-0:     #1e1e1e;   /* modal background */
  --surface-1:     #242424;   /* cards, sidebar */
  --surface-2:     #2a2a2a;   /* hover states, active rows */
  --surface-3:     #313131;   /* pressed / selected */

  /* ── Borders ───────────────────────────────── */
  --border-subtle: #2e2e2e;   /* cards, modal edge */
  --border-strong: #3d3d3d;   /* active input ring */
  --border-focus:  rgba(212,118,78,0.55); /* terracotta focus */

  /* ── Text ─────────────────────────────────── */
  --text-primary:  #e8e8e8;   /* headings, body */
  --text-secondary:#a0a0a0;   /* labels, captions */
  --text-muted:    #6b6b6b;   /* placeholders, disabled */
  --text-link:     #d4764e;   /* inline links */

  /* ── Accent ───────────────────────────────── */
  --accent:        #d4764e;   /* terracotta — primary CTA, focus */
  --accent-hover:  #c4673f;
  --accent-subtle: rgba(212,118,78,0.12);

  /* ── Status colours ─────────────────────────── */
  --green:         #34d399;
  --green-subtle:  rgba(52,211,153,0.12);
  --blue:          #60a5fa;
  --blue-subtle:   rgba(96,165,250,0.12);
  --orange:        #fb923c;
  --orange-subtle: rgba(251,146,60,0.12);
  --red:           #f87171;
  --red-subtle:    rgba(248,113,113,0.12);

  /* ── Radii ───────────────────────────────── */
  --radius-sm:     8px;
  --radius-md:     12px;
  --radius-lg:     16px;
  --radius-xl:     20px;

  /* ── Shadows ──────────────────────────────── */
  --shadow-card:   0 1px 3px rgba(0,0,0,0.4), 0 8px 24px rgba(0,0,0,0.3);
  --shadow-modal:  0 24px 80px rgba(0,0,0,0.7);

  /* ── Transitions ───────────────────────────── */
  --transition:    150ms ease;
}
```

---

## 2. Typography

```css
/* Load in <head> before the stylesheet */
/* <link rel="preconnect" href="https://fonts.googleapis.com"> */
/* <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap" rel="stylesheet"> */

body {
  font-family: 'Inter', system-ui, -apple-system, sans-serif;
  font-size: 14px;
  line-height: 1.6;
  color: var(--text-primary);
  background: var(--bg);
  -webkit-font-smoothing: antialiased;
}

h1, h2, h3, h4 { font-weight: 600; color: var(--text-primary); }

/* Section labels (like "Settings" / "Customize" in the sidebar) */
.label-section {
  font-size: 11px;
  font-weight: 500;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  color: var(--text-muted);
}

/* Monospace — IDs, tokens, code */
.mono {
  font-family: 'SF Mono', 'Fira Code', 'Cascadia Code', monospace;
  font-size: 12px;
}

/* Serif heading — login screen only */
.heading-serif {
  font-family: Georgia, 'Times New Roman', serif;
  font-weight: 400;
}
```

---

## 3. Page boilerplate

Every page that uses this theme should start with this shell.
Replace `{{.Title}}` and `{{block "content" .}}` with Go template values.

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <meta name="robots" content="noindex, nofollow" />
  <title>{{.Title}}</title>

  <!-- Fonts -->
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap"
        rel="stylesheet">

  <!-- Theme stylesheet (see §12 for Go embed) -->
  <link rel="stylesheet" href="/auth/static/claude-theme.css" />

  <!-- Page-specific styles (optional) -->
  {{block "head" .}}{{end}}
</head>
<body>
  {{block "content" .}}
  {{end}}
</body>
</html>
```

---

## 4. Component: Modal / settings panel

The Claude settings UI is a **modal overlay** that slides over the current page.
It is not a separate route — it is rendered into the DOM on demand.

```html
<!-- Overlay backdrop -->
<div class="modal-backdrop" id="settings-backdrop" onclick="closeSettings()" aria-hidden="true"></div>

<!-- Modal shell -->
<dialog class="modal" id="settings-modal" aria-modal="true" aria-label="Settings">

  <!-- Left sidebar -->
  <aside class="modal__sidebar">
    <!-- Search -->
    <div class="sidebar__search">
      <svg class="sidebar__search-icon" ...></svg>
      <input type="search" placeholder="Search" aria-label="Search settings" />
    </div>

    <!-- Nav sections injected here by JS or Go template -->
    <nav class="sidebar__nav" id="settings-nav"></nav>
  </aside>

  <!-- Right content pane -->
  <div class="modal__content" id="settings-content">
    <!-- Close button -->
    <button class="modal__close" onclick="closeSettings()" aria-label="Close">
      &times;
    </button>
    <!-- Section content injected here -->
  </div>
</dialog>
```

```css
/* ── Backdrop ─────────────────────────────────── */
.modal-backdrop {
  position: fixed; inset: 0;
  background: rgba(0,0,0,0.6);
  backdrop-filter: blur(4px);
  z-index: 100;
  opacity: 0;
  transition: opacity var(--transition);
}
.modal-backdrop.open { opacity: 1; }

/* ── Modal shell ─────────────────────────────── */
.modal {
  position: fixed;
  top: 50%; left: 50%;
  transform: translate(-50%, -50%) scale(0.97);
  width: min(960px, calc(100vw - 32px));
  height: min(680px, calc(100vh - 32px));
  background: var(--surface-0);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-xl);
  box-shadow: var(--shadow-modal);
  display: flex;
  overflow: hidden;
  z-index: 101;
  opacity: 0;
  transition: opacity var(--transition), transform var(--transition);
  /* Remove default <dialog> styles */
  padding: 0; margin: 0;
  color: var(--text-primary);
}
.modal.open {
  opacity: 1;
  transform: translate(-50%, -50%) scale(1);
}

/* ── Close button ────────────────────────────── */
.modal__close {
  position: absolute; top: 14px; right: 14px;
  width: 28px; height: 28px;
  border-radius: 50%;
  background: var(--surface-2);
  border: none;
  color: var(--text-secondary);
  font-size: 18px; line-height: 1;
  cursor: pointer;
  transition: background var(--transition);
  display: flex; align-items: center; justify-content: center;
}
.modal__close:hover { background: var(--surface-3); color: var(--text-primary); }

/* ── Left sidebar ────────────────────────────── */
.modal__sidebar {
  width: 220px;
  flex-shrink: 0;
  border-right: 1px solid var(--border-subtle);
  padding: 12px 8px;
  overflow-y: auto;
  display: flex; flex-direction: column; gap: 4px;
}

/* ── Right content ───────────────────────────── */
.modal__content {
  flex: 1;
  overflow-y: auto;
  padding: 28px 32px;
  position: relative;
}

/* ── Mobile: stack vertically ────────────────────── */
@media (max-width: 600px) {
  .modal { flex-direction: column; height: 100dvh; width: 100vw;
           border-radius: 0; top: 0; left: 0; transform: none; }
  .modal__sidebar { width: 100%; border-right: none;
                    border-bottom: 1px solid var(--border-subtle); }
}
```

---

## 5. Component: Sidebar nav

Matches the Claude settings sidebar exactly:
`Settings` group → items; `Customize` group → items.
For admins, `Customize` is replaced by `Administration`.

```css
/* Search box inside sidebar */
.sidebar__search {
  display: flex; align-items: center; gap: 8px;
  background: var(--surface-2);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-md);
  padding: 7px 10px;
  margin-bottom: 12px;
}
.sidebar__search input {
  background: transparent; border: none;
  color: var(--text-primary); font-size: 13px;
  width: 100%; outline: none;
}
.sidebar__search input::placeholder { color: var(--text-muted); }
.sidebar__search-icon { color: var(--text-muted); flex-shrink: 0; }

/* Section label */
.sidebar__section-label {
  font-size: 11px; font-weight: 500;
  letter-spacing: 0.06em; text-transform: uppercase;
  color: var(--text-muted);
  padding: 8px 10px 4px;
}

/* Nav item */
.sidebar__item {
  display: flex; align-items: center; gap: 10px;
  padding: 8px 10px;
  border-radius: var(--radius-sm);
  cursor: pointer;
  font-size: 13px; font-weight: 500;
  color: var(--text-secondary);
  transition: background var(--transition), color var(--transition);
  user-select: none;
  border: none; background: transparent; width: 100%; text-align: left;
}
.sidebar__item:hover { background: var(--surface-2); color: var(--text-primary); }
.sidebar__item.active {
  background: var(--surface-2);
  color: var(--text-primary);
}
.sidebar__item svg { width: 16px; height: 16px; flex-shrink: 0; opacity: 0.7; }
.sidebar__item.active svg { opacity: 1; }
```

HTML structure:

```html
<nav class="sidebar__nav">
  <!-- Settings group -->
  <div class="sidebar__section-label">Settings</div>
  <button class="sidebar__item active" data-pane="account">
    <svg><!-- user-circle icon --></svg>
    Account
  </button>
  <button class="sidebar__item" data-pane="privacy">
    <svg><!-- shield icon --></svg>
    Privacy
  </button>
  <button class="sidebar__item" data-pane="sessions">
    <svg><!-- devices icon --></svg>
    Sessions
  </button>

  <!-- Customize / Administration group -->
  {{if .IsAdmin}}
  <div class="sidebar__section-label" style="margin-top:12px">Administration</div>
  <button class="sidebar__item" data-pane="admin-users">
    <svg><!-- users icon --></svg>
    Users
  </button>
  <button class="sidebar__item" data-pane="admin-logs">
    <svg><!-- log icon --></svg>
    Audit Log
  </button>
  <button class="sidebar__item" data-pane="admin-sessions">
    <svg><!-- session icon --></svg>
    Active Sessions
  </button>
  <button class="sidebar__item" data-pane="admin-system">
    <svg><!-- server icon --></svg>
    System
  </button>
  {{else}}
  <div class="sidebar__section-label" style="margin-top:12px">Customize</div>
  {{end}}
</nav>
```

---

## 6. Component: Card

```css
.card {
  background: var(--surface-1);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-lg);
  padding: 20px 24px;
  margin-bottom: 16px;
}
.card__title {
  font-size: 15px; font-weight: 600;
  color: var(--text-primary);
  margin-bottom: 4px;
}
.card__desc {
  font-size: 13px; color: var(--text-secondary);
  margin-bottom: 16px; line-height: 1.5;
}
.card__row {
  display: flex; align-items: center;
  justify-content: space-between;
  padding: 12px 0;
  border-bottom: 1px solid var(--border-subtle);
}
.card__row:last-child { border-bottom: none; }
.card__label { font-size: 13px; color: var(--text-primary); }
.card__value { font-size: 12px; color: var(--text-secondary); }
/* Monospace value (e.g. Org ID) */
.card__value--mono {
  font-family: 'SF Mono', monospace; font-size: 11px;
  background: var(--surface-2);
  padding: 3px 8px; border-radius: 6px;
  color: var(--text-secondary);
  cursor: pointer; /* click to copy */
  transition: background var(--transition);
}
.card__value--mono:hover { background: var(--surface-3); }
```

---

## 7. Component: Table

Matches the Device / Session tables in the screenshot:

```css
.data-table { width: 100%; border-collapse: collapse; }
.data-table thead tr {
  border-bottom: 1px solid var(--border-subtle);
}
.data-table th {
  font-size: 12px; font-weight: 500;
  color: var(--text-secondary);
  text-align: left; padding: 8px 12px;
}
.data-table td {
  font-size: 13px; color: var(--text-primary);
  padding: 12px 12px;
  border-bottom: 1px solid var(--border-subtle);
  vertical-align: middle;
}
.data-table tbody tr:last-child td { border-bottom: none; }
.data-table tbody tr:hover td { background: var(--surface-2); }
/* "Current" badge on active session row */
.badge--current {
  display: inline-flex; align-items: center;
  background: var(--blue-subtle);
  color: var(--blue);
  font-size: 11px; font-weight: 600;
  padding: 2px 8px; border-radius: 6px;
  margin-left: 8px;
}
```

---

## 8. Component: Badges / tags

```css
.badge {
  display: inline-flex; align-items: center;
  font-size: 11px; font-weight: 500;
  padding: 2px 8px; border-radius: 6px;
  white-space: nowrap;
}
.badge--green  { background: var(--green-subtle);  color: var(--green); }
.badge--blue   { background: var(--blue-subtle);   color: var(--blue); }
.badge--orange { background: var(--orange-subtle); color: var(--orange); }
.badge--red    { background: var(--red-subtle);    color: var(--red); }
.badge--muted  { background: var(--surface-2);     color: var(--text-secondary);
                 border: 1px solid var(--border-subtle); }
.badge--accent { background: var(--accent-subtle); color: var(--accent); }
```

---

## 9. Component: Buttons

```css
/* Primary — white on dark (matches Claude's CTA) */
.btn { display: inline-flex; align-items: center; justify-content: center;
       gap: 6px; font-size: 13px; font-weight: 500;
       padding: 8px 16px; border-radius: var(--radius-md);
       cursor: pointer; transition: background var(--transition),
       border-color var(--transition), color var(--transition);
       white-space: nowrap; border: none; }
.btn-primary { background: #fff; color: #111; }
.btn-primary:hover { background: #e8e8e8; }

/* Secondary — outlined */
.btn-secondary { background: transparent;
  border: 1px solid var(--border-subtle);
  color: var(--text-primary); }
.btn-secondary:hover { background: var(--surface-2);
  border-color: var(--border-strong); }

/* Danger — for destructive actions */
.btn-danger { background: var(--red-subtle);
  border: 1px solid rgba(248,113,113,0.3);
  color: var(--red); }
.btn-danger:hover { background: rgba(248,113,113,0.2); }

/* Ghost — icon buttons */
.btn-ghost { background: transparent; border: none;
  color: var(--text-secondary); padding: 6px; }
.btn-ghost:hover { background: var(--surface-2); color: var(--text-primary); }

/* Size modifier */
.btn-sm { font-size: 12px; padding: 5px 10px; }
```

---

## 10. Component: Form inputs

```css
.form-group { margin-bottom: 16px; }
.form-label {
  display: block; font-size: 12px; font-weight: 500;
  color: var(--text-secondary); margin-bottom: 6px;
}
.form-input {
  width: 100%; box-sizing: border-box;
  background: var(--surface-1);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-md);
  padding: 10px 14px;
  font-size: 13px; color: var(--text-primary);
  transition: border-color var(--transition), box-shadow var(--transition);
  outline: none;
}
.form-input::placeholder { color: var(--text-muted); }
.form-input:focus {
  border-color: var(--border-focus);
  box-shadow: 0 0 0 3px rgba(212,118,78,0.15);
}
.form-input:disabled { opacity: 0.5; cursor: not-allowed; }
.form-error { font-size: 12px; color: var(--red); margin-top: 4px; }
```

---

## 11. Tailwind config (if using Tailwind)

For pages still using the Tailwind CDN (login, verify), extend with these
tokens so ad-hoc utilities use the same values:

```js
tailwind.config = {
  theme: {
    extend: {
      colors: {
        bg:       '#1a1a1a',
        's0':     '#1e1e1e',
        's1':     '#242424',
        's2':     '#2a2a2a',
        's3':     '#313131',
        border:   '#2e2e2e',
        muted:    '#6b6b6b',
        accent:   '#d4764e',
        green:    '#34d399',
        blue:     '#60a5fa',
        orange:   '#fb923c',
        red:      '#f87171',
      },
      fontFamily: {
        serif: ['Georgia','Cambria','serif'],
        sans:  ['Inter','system-ui','sans-serif'],
      },
      borderRadius: {
        sm: '8px', md: '12px', lg: '16px', xl: '20px',
      },
    },
  },
}
```

---

## 12. Using with Go embed

1. Save the `:root` tokens + all component CSS into
   `forward-auth/ui/claude-theme.css`.

2. Embed and serve it from Go:

```go
//go:embed ui/claude-theme.css
var themeCSS []byte

// In your mux setup:
mux.HandleFunc("/auth/static/claude-theme.css", func(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "text/css")
    w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
    w.Write(themeCSS)
})
```

3. In every page template `<head>`:
```html
<link rel="stylesheet" href="/auth/static/claude-theme.css" />
```

4. For pages using Tailwind CDN, also drop in the `tailwind.config` block
   from §11 so the token values stay in sync.
