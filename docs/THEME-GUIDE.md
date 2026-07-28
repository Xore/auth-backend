# Shared Theme Integration

The reusable visual system for this application lives in
[`Xore/theme`](https://github.com/Xore/theme). Its root `theme.css` is the
authoritative source for tokens and shared components. The auth service embeds a
vendored copy at `forward-auth/ui/theme.css` so the interface remains
self-contained and its Content Security Policy can keep `style-src 'self'`.

The current integration baseline is theme commit `4e22d52`.

## Files and routes

| Purpose | Location |
|---|---|
| Shared source | `https://github.com/Xore/theme/blob/main/theme.css` |
| Embedded copy | `forward-auth/ui/theme.css` |
| Static route | `/static/theme.css` |
| Go embed | `forward-auth/static.go` |
| App shell | `forward-auth/ui/app.html` |
| Server-rendered pages | `forward-auth/page.go` |
| Two-step sign-in | `forward-auth/ui/login.html` |
| Two-factor verification | `forward-auth/ui/verify.html` |

## Rules for AI coding agents

1. Read the upstream [`README`](https://github.com/Xore/theme) and
   [`auth-backend migration guide`](https://github.com/Xore/theme/blob/main/docs/MIGRATE-AUTH-BACKEND.md)
   before changing shared styling.
2. Treat upstream tokens and component selectors as the contract. Put
   application-only layout rules next to the page that uses them.
3. Never fetch styles from a CDN at runtime. The service must remain deployable
   as a single embedded Go binary.
4. Never weaken CSP to make a visual change work.
5. Do not change form actions, input names, hidden fields, passkey calls, CSRF
   handling, or administrator authorization while changing presentation.
6. Keep destructive actions behind explicit confirmation dialogs.
7. Preserve the common-password dictionary exactly. Theme naming cleanup must
   exclude `forward-auth/data/common-passwords.txt`.

## Updating the vendored stylesheet

From the repository root:

```powershell
Copy-Item ..\theme\theme.css forward-auth\ui\theme.css
git diff -- forward-auth/ui/theme.css
```

If the sibling checkout is not available, download the exact reviewed upstream
revision and verify it before replacing the embedded file. Record the new source
commit in this guide in the same commit as the stylesheet update.

Do not copy `theme.js` into the Go application. The app shell already owns its
behavior and CSP nonce handling; the shared JavaScript is only a dependency-free
helper for standalone examples.

## Application-specific composition

- `page.go` provides compact auth-page layout classes while all colors come
  from shared tokens.
- `login.html` and `verify.html` may retain Tailwind layout utilities, but
  palette, radius, borders, shadows, and interactive states must resolve to
  shared variables.
- `app.html` owns the permanent settings-shell layout and administration
  behavior. Shared classes supply the visual primitives.
- The QR enrollment surface intentionally stays white and square because that
  is a functional scanning requirement.

## Required validation

Run these checks after every theme update:

```powershell
gofmt -w forward-auth
go test ./...
go vet ./...
go test -race ./...
rg -n "<legacy-theme-name>" . `
  --glob "!forward-auth/data/common-passwords.txt"
git diff --check
```

The legacy-name search must return no results outside the password dictionary.
Then test the sign-in, verification, account, users, audit, sessions, and system
pages at desktop and mobile widths. Confirm visible keyboard focus, table
containment, dialog focus behavior, Enter-to-save handling, and reduced motion.

## Upstream examples

Use the upstream example pages as the visual acceptance suite:

- `examples/components.html`
- `examples/workspace.html`
- `examples/settings.html`
- `examples/auth.html`

Add or change a shared primitive upstream first. Update this vendored copy only
after the upstream examples demonstrate the intended state.
