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
