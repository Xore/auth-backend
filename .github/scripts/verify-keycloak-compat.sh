#!/usr/bin/env bash
# verify-keycloak-compat.sh -- #101.
#
# Re-fetches the exact upstream keycloak.v2 login files this theme was
# validated against (per themes/apiary/keycloak.lock's git_tag), hashes
# them fresh, and compares against the recorded hashes. A mismatch means
# either upstream changed these files after the pinned tag was cut (should
# not happen for a real release tag, but tags can technically move) or
# keycloak.lock is stale relative to a real intentional Keycloak upgrade --
# either way, this theme's CSS selectors/DOM assumptions have not been
# re-validated against whatever changed, so CI fails loudly instead of
# silently shipping a theme that may no longer match Keycloak's markup.
#
# Deliberately does not vendor/commit copies of these upstream files just to
# diff against -- same "do not copy upstream CSS locally" boundary #99's own
# acceptance criteria set, applied here to FTL/CSS provenance checking too.

set -euo pipefail

lock="themes/apiary/keycloak.lock"
[[ -f "$lock" ]] || { echo "missing $lock" >&2; exit 1; }

git_tag="$(sed -n 's/^git_tag = //p' "$lock")"
[[ -n "$git_tag" ]] || { echo "no git_tag found in $lock" >&2; exit 1; }

base_url="https://raw.githubusercontent.com/keycloak/keycloak/${git_tag}/themes/src/main/resources/theme/keycloak.v2/login"

fail=0
check_one() {
    local rel_path="$1" expected
    expected="$(sed -n "s#^${rel_path//./\\.} = ##p" "$lock")"
    if [[ -z "$expected" ]]; then
        echo "FAIL: no recorded hash for '$rel_path' in $lock" >&2
        fail=1
        return
    fi
    local actual
    actual="$(curl -fsSL "${base_url}/${rel_path}" | sha256sum | cut -d' ' -f1)"
    if [[ "$actual" != "$expected" ]]; then
        echo "FAIL: ${rel_path} drifted from the pinned Keycloak ${git_tag} release" >&2
        echo "  expected sha256: ${expected}" >&2
        echo "  actual   sha256: ${actual}" >&2
        echo "  This theme's CSS/DOM assumptions (theme.properties parent/styles," >&2
        echo "  template.ftl structure, or keycloak.v2's own stylesheet) have not" >&2
        echo "  been re-validated against this change. If this is an intentional" >&2
        echo "  Keycloak upgrade, update themes/apiary/keycloak.lock's git_tag/" >&2
        echo "  digest/hashes together with a full theme test pass -- see" >&2
        echo "  docs/THEME-GUIDE.md. If it isn't, something is wrong upstream or" >&2
        echo "  with this pin; do not just update the hash to make CI pass." >&2
        fail=1
    else
        echo "OK: ${rel_path} matches Keycloak ${git_tag}"
    fi
}

check_one "theme.properties"
check_one "template.ftl"
check_one "resources/css/styles.css"

exit "$fail"
