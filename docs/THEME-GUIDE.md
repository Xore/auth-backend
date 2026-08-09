# Keycloak theme implementation contract

`themes/apiary/` is the only deployable output of this repository. Theme code
may change markup, styling, images, and presentation-only messages. It must not
implement authentication, authorization, account provisioning, session logic,
MFA policy, or recovery policy.

## Layout

Keycloak theme types live directly below `themes/apiary/`, for example:

```text
themes/apiary/
├── login/
├── account/
└── email/
```

Each type must declare its supported Keycloak parent in `theme.properties`.
Prefer inherited upstream templates and small resource overrides; copied
FreeMarker templates must be reviewed again whenever the pinned Keycloak
version changes.

## Deployment contract

- APIARY owns the pinned Keycloak version and mounts this directory read-only.
- Assets must work without a CDN or runtime network fetch.
- Do not put secrets, realm exports, users, client configuration, or deployment
  scripts here.
- Preserve keyboard navigation, visible focus, reduced-motion preferences,
  screen-reader labels, and useful error states.
- Never hide or weaken the mandatory MFA enrollment flow.

Before merging, test login, first-login password replacement and TOTP
enrollment, invalid credentials, password reset, logout, and the admin-host
login at mobile and desktop widths against APIARY's pinned Keycloak image.
The pinned runtime does not expose a recovery-code required-action factory;
account recovery is an administrator-driven credential reset.

## Keycloak upgrades (#101)

`themes/apiary/keycloak.lock` is the compatibility record: the exact
image/digest APIARY deploys, sha256 hashes of the upstream `keycloak.v2`
files this theme's CSS actually depends on (`theme.properties`,
`template.ftl`, `resources/css/styles.css`), and the specific DOM IDs/classes
`login.css` reaches into. `.github/workflows/theme.yml` runs
`.github/scripts/verify-keycloak-compat.sh` on every push/PR, which
re-fetches those files fresh from the pinned tag and fails CI with a
readable diff if they've drifted from what's recorded — this is a CSS-only
child theme, so a change to keycloak.v2's markup or class names is a real
compatibility break even though no line in this repo changed.

A Keycloak version bump requires, in order:

1. Update `[keycloak]` in `keycloak.lock` to the new image, digest, and
   matching `git_tag`/`git_commit`.
2. Re-derive `[upstream_files]`'s hashes against the new tag (the same
   `raw.githubusercontent.com/keycloak/keycloak/<tag>/...` paths
   `verify-keycloak-compat.sh` fetches) and update them.
3. Re-derive `[required_dom_hooks]` if `login.css` gained/lost selectors
   (regenerate command is in the file's own comment).
4. Run the full pre-merge checklist above against the new image, plus every
   flow #103's interaction layer touches once that exists.
5. Only then does `verify-keycloak-compat.sh` pass again — do not edit the
   recorded hash to make a real drift finding go away without doing 1-4.

**Local development**: Keycloak's theme cache serves stale resources across
edits by default. Set `spi-theme-static-max-age=-1` and
`spi-theme-cache-themes=false` / `spi-theme-cache-templates=false` (start
options or realm `KC_SPI_THEME_*` env vars) while iterating locally so CSS/
template changes show up without a restart. **Production must not run with
these disabled** — APIARY's deployed Keycloak keeps the default caching
behavior; only ever disable it in a local/throwaway instance used for theme
development, never against the real stack.

## Regression suite (#102)

`test/` renders this theme against a real disposable Keycloak instance —
`test/docker-compose.test.yml`, pinned to `keycloak.lock`'s exact
image+digest, mounting `themes/apiary` read-only and importing
`test/fixtures/realm-export.json` (a throwaway `test-apiary` realm mirroring
the real realm's key settings: registration off, TOTP mandatory, no SSO
providers). No production credentials or external IdPs are involved.

Run locally:

```bash
cd test
docker compose -f docker-compose.test.yml up -d
# wait for it healthy: docker inspect test-keycloak-1 --format '{{.State.Health.Status}}'
npm ci
npx playwright install chromium
npx playwright test                    # all six viewport tiers
npx playwright test --project=desktop-1440   # one tier while iterating
docker compose -f docker-compose.test.yml down -v
```

Baseline screenshots live under `test/specs/login.spec.ts-snapshots/`, one
per viewport project. Updating a baseline is a real content decision, not a
formality — regenerate with `npx playwright test --update-snapshots`, then
**look at the diff in the actual PNG**, not just accept it, and say in the
PR which Xore/Keycloak pin (if any) motivated the change (#102's own
acceptance criterion). CI uploads the HTML report (including before/after/
diff images on any failure) as a workflow artifact.

This suite already caught two real bugs no static review had (both fixed
in the same change that added the suite): `#kc-header-wrapper`'s title text
was fully invisible in light mode (keycloak.v2's own `styles.css` sets
`color: ... !important`, silently beating this theme's non-`!important`
override), and the vendored `xore-theme.css` was pulling Fira Sans/Space
Grotesk/Fira Code from Google Fonts on every page load — a real violation
of the no-CDN deployment contract above, patched out with the removal
documented in `keycloak.lock`.

Not yet covered here (tracked in `docs/PAGE-MATRIX.md` as open, not
silently untested): WebAuthn/passkey ceremonies, `select-authenticator`,
consent/device-code flows, RTL, 200% zoom, forced-colors, and reduced-motion
interaction (only the static CSS rule is asserted, not simulated motion).
