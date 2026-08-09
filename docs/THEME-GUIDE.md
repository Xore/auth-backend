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
