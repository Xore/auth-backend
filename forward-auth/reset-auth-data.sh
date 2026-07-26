#!/bin/sh
set -eu
umask 077

if [ "${AUTH_RESET_CONFIRM:-}" != "RESET_AUTH_PORTAL" ]; then
  echo "Refusing reset: set AUTH_RESET_CONFIRM=RESET_AUTH_PORTAL for this one command." >&2
  exit 2
fi

if [ ! -d /data ] || [ ! -d /backup ]; then
  echo "Required /data or /backup mount is missing." >&2
  exit 1
fi

set --
[ ! -f /data/users.json ] || set -- "$@" users.json
[ ! -f /data/revoked-sessions.json ] || set -- "$@" revoked-sessions.json

if [ "$#" -eq 0 ]; then
  echo "No authentication credential store exists; nothing to reset."
  exit 0
fi

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
archive="/backup/auth-data-$stamp.tar.gz"
tar -czf "$archive" -C /data "$@"
chmod 0600 "$archive"

rm -f \
  /data/users.json \
  /data/revoked-sessions.json \
  /data/.users-*.tmp \
  /data/.revoked-*.tmp
sync

echo "Backup written to $archive"
echo "Authentication credential store cleared."
echo "Recreate auth-portal with a new COOKIE_SECRET and bootstrap credentials."

