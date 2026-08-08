# APIARY Keycloak theme

This repository contains presentation-only customizations for the APIARY
Keycloak deployment. It does not own identity configuration or runtime
infrastructure.

## Scope

- Keycloak login, account, and email theme resources under `themes/apiary/`
- Theme accessibility, responsive behavior, and visual regression checks
- Documentation that is specific to implementing and reviewing the theme

The Dockge stack, PostgreSQL, realm configuration, clients, roles, MFA policy,
backups, and Traefik routes are owned by
[`Xore/APIARY`](https://github.com/Xore/APIARY).

APIARY mounts `themes/apiary` read-only into
`/opt/keycloak/themes/apiary`. No image is built by this repository.

## Archived former implementation

The original pre-Keycloak service is preserved in the archived
[`Xore/before-keycloak`](https://github.com/Xore/before-keycloak) repository.
Operational migration drafts are intentionally not retained in this public
theme repository.

See [docs/THEME-GUIDE.md](docs/THEME-GUIDE.md) before changing theme assets.
