# Authentication portal credential recovery

This guide assumes the standalone deployment from this repo's
`docker-compose.yml`, e.g. cloned to `/opt/auth-backend`:

- Compose project: `/opt/auth-backend/docker-compose.yml`
- Environment: `/opt/auth-backend/.env`
- Service/container: `auth-portal`
- Persistent store: `auth-data` volume, mounted at `/data`
- Active users: `/data/users.json`
- Revoked sessions: `/data/revoked-sessions.json`

Adjust paths below if you cloned this repo elsewhere or wired `auth-portal`
into another Compose project (e.g. folded into
[Xore/cgnat](https://github.com/Xore/cgnat)'s `vps/docker-compose.yml`).

> `AUTH_USERNAME`, `AUTH_PASSWORD`, and `TOTP_SECRET` are bootstrap settings.
> Changing them in `.env` does **not** alter an existing user in `users.json`.
> They are read only when the user store is empty.

## Choose the correct procedure

| Situation | Procedure |
|---|---|
| You can sign in as an administrator | Use the admin panel |
| You only need to change your own password | Use the password page |
| Another account lost its password, TOTP, passkey, or session | Reset that item in the admin panel |
| You are locked out of the last administrator account | Perform the full Compose reset |
| You want to delete every portal credential and bootstrap a new administrator | Perform the full Compose reset |

## Reset or delete one account from the admin panel

1. Sign in at `https://<AUTH_HOST>/_auth/login`.
2. Open `https://<AUTH_HOST>/_auth/admin`.
3. Find the account under **Users**.
4. Select the required action:

   - **reset pw** creates a one-time password, forces a password change, and
     invalidates that user's existing sessions and trusted devices.
   - **reset 2fa** removes the TOTP secret and backup codes and forces
     re-enrollment when TOTP is required.
   - **reset passkeys** removes every registered passkey.
   - **logout** invalidates all sessions and trusted devices for the user.
   - **disable** blocks the account without deleting its history.
   - **delete** permanently removes the account from `users.json`.

5. Copy a displayed temporary password immediately. The portal stores only its
   bcrypt hash and cannot display it again.
6. Verify the user can sign in and complete any required password or TOTP
   enrollment.

The portal deliberately prevents deleting, disabling, or demoting your own
session and prevents removal of the last enabled administrator. Create and test
a second administrator first if you need to delete the original administrator.

### What these actions invalidate

Every action above also kills outstanding **email tokens** — both password-reset
links (`/_auth/recover`) and, when `MAGIC_LINK=true`, sign-in links
(`/_auth/magic`). This matters when responding to a mailbox compromise: an
attacker who harvested an unclicked link from the user's inbox cannot redeem it
after you act.

All six revocation actions below invalidate all three, with no exceptions:

| Action | Sessions | Trusted devices | Outstanding email links |
|---|---|---|---|
| reset pw | invalidated | invalidated | invalidated |
| reset 2fa | invalidated | invalidated | invalidated |
| reset passkeys | invalidated | invalidated | invalidated |
| logout | invalidated | invalidated | invalidated |
| disable | invalidated | invalidated | invalidated |
| user changes own password | invalidated | invalidated | invalidated |

Each of these bumps the account's session and device generations. Email links
are bound to a fingerprint covering the password hash, the session generation,
and a per-user single-use counter, so any generation bump breaks the
fingerprint. Links also expire on their own after 15 minutes and work exactly
once.

**enable** and **unlock** are not revocation actions — they do not bump the
generations and do not invalidate anything.

If you are responding to a suspected mailbox compromise and want certainty
without waiting for the 15-minute expiry, use **logout** on the account — it is
the cheapest action that invalidates every outstanding link.

## Change your own password

1. Sign in normally.
2. Open `https://<AUTH_HOST>/_auth/password`.
3. Enter the current password and a new unique password.
4. Sign out and verify the new password in a private browser window.

## Clear an IP lockout

1. Open `https://<AUTH_HOST>/_auth/admin`.
2. Locate the address under **Locked IPs**.
3. Select **unlock**.

A container restart also clears in-memory rate-limit/lockout state, but it does
not reset a password, TOTP secret, passkey, or persisted user.

## Full reset using the Compose maintenance service

Use this only when the last administrator is inaccessible or every portal
credential must be replaced. The reset service is in the `auth-maintenance`
profile, so normal `docker compose up` never starts it.

The procedure:

- stops authentication before changing its data;
- writes a root-only backup under `./auth-backups`;
- removes only the active user and session-revocation files;
- creates a new administrator from `.env` on restart;
- rotates the cookie key so old signed SSO cookies cannot become valid again.

### 1. Become root and enter the project directory

```bash
sudo -i
cd /opt/auth-backend
docker compose config --quiet
```

### 2. Choose the new bootstrap credentials

Generate a new cookie key:

```bash
openssl rand -hex 32
```

Edit `.env`:

```bash
nano /opt/auth-backend/.env
```

Set at least:

```dotenv
AUTH_USERNAME=new-admin-name
AUTH_PASSWORD=replace-with-a-long-unique-password
TOTP_SECRET=
COOKIE_SECRET=paste-the-new-openssl-value
COOKIE_SECRET_PREVIOUS=
```

Do not commit `.env`. Leaving `TOTP_SECRET` empty lets the new account enroll
its own TOTP after login when `REQUIRE_TOTP=true`.

Rotating `COOKIE_SECRET` and leaving `COOKIE_SECRET_PREVIOUS` empty is mandatory
for a full security reset. Otherwise, a previously issued signed cookie for a
recreated username could remain usable.

### 3. Stop the portal

```bash
docker compose stop auth-portal
```

Do not remove the complete Compose project and do not use
`docker compose down -v`; `-v` deletes every named volume selected by the
project.

### 4. Run the guarded one-shot reset

```bash
install -d -m 0700 /opt/auth-backend/auth-backups
AUTH_RESET_CONFIRM=RESET_AUTH_PORTAL \
  docker compose --profile auth-maintenance run --rm auth-credentials-reset
```

The service refuses to run unless `AUTH_RESET_CONFIRM` exactly equals
`RESET_AUTH_PORTAL`. Do not save that confirmation setting in `.env`.

Expected output includes the backup filename followed by:

```text
Authentication credential store cleared.
```

### 5. Recreate the portal

```bash
docker compose up -d --build --force-recreate auth-portal
docker compose ps auth-portal
docker compose logs --tail=50 auth-portal
```

The logs should contain `bootstrapped admin user from environment`, and the
container should become healthy.

### 6. Verify recovery

```bash
curl -fsS https://<AUTH_HOST>/_auth/health
```

Then use a private browser window:

1. Sign in with the new `AUTH_USERNAME` and `AUTH_PASSWORD`.
2. Change the bootstrap password if prompted.
3. Enroll TOTP at `https://<AUTH_HOST>/_auth/enroll`.
4. Save the generated recovery codes offline.
5. Open `https://<AUTH_HOST>/_auth/admin` and verify that only the expected
   accounts exist.
6. Test one protected service behind `forward-auth`.

## Restore the pre-reset store

Each successful full reset creates a timestamped archive in
`/opt/auth-backend/auth-backups`. Treat these archives as secrets: they contain
password hashes, TOTP material, backup-code hashes, and passkey credentials.

1. Stop the portal:

   ```bash
   cd /opt/auth-backend
   docker compose stop auth-portal
   ls -l ./auth-backups
   ```

2. Resolve the exact Compose volume instead of guessing its name (replace
   `auth-backend` below with your actual Compose project name if you cloned
   this repo under a different directory name, or folded it into another
   project):

   ```bash
   AUTH_VOLUME="$(docker volume ls \
     --filter label=com.docker.compose.project=auth-backend \
     --filter label=com.docker.compose.volume=auth-data \
     --format '{{.Name}}')"
   test -n "$AUTH_VOLUME"
   ```

3. Replace `BACKUP_FILE` with the selected basename and restore:

   ```bash
   BACKUP_FILE=auth-data-YYYYMMDDTHHMMSSZ.tar.gz
   docker run --rm --network none \
     --mount type=volume,src="$AUTH_VOLUME",dst=/data \
     --mount type=bind,src=/opt/auth-backend/auth-backups,dst=/backup,readonly \
     alpine:3.20 sh -ec \
     'rm -f /data/users.json /data/revoked-sessions.json /data/.users-*.tmp /data/.revoked-*.tmp
      tar -xzf "/backup/$1" -C /data' -- "$BACKUP_FILE"
   ```

4. Restore the matching old `COOKIE_SECRET` in `.env` only if you
   intentionally want old signed sessions to be cryptographically readable.
   For incident recovery, keep the new key so every old cookie stays invalid.
5. Start and verify:

   ```bash
   docker compose up -d --force-recreate auth-portal
   docker compose ps auth-portal
   docker compose logs --tail=50 auth-portal
   ```

## Permanently remove reset backups

After the new administrator and protected routes have been tested, list and
select the exact archive to remove:

```bash
ls -l /opt/auth-backend/auth-backups
rm -- /opt/auth-backend/auth-backups/auth-data-YYYYMMDDTHHMMSSZ.tar.gz
```

Do not use a wildcard until you have verified every target. Deleting a backup
is irreversible.
