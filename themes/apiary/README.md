# APIARY Keycloak theme

This directory is the deployment boundary for the presentation-only Keycloak
theme mounted by APIARY's Dockge-managed `honeypot-keycloak` stack.

`login/` inherits Keycloak's supported `keycloak.v2` templates and adds only
local presentation resources. `xore-theme.css` is the minified upstream
stylesheet pinned by content hash in `theme.lock`; `login.css` is the narrow
Keycloak adapter.

Prefer inherited templates. Any future `account/` or `email/` implementation
must follow the same presentation-only boundary. No authenticator, credential,
session, authorization, or recovery logic belongs here.
