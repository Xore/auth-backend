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

fail=0
# $1: base_url  $2: rel_path  $3: section (for the hash lookup below)
check_one() {
    local base_url="$1" rel_path="$2" section="$3" expected
    expected="$(awk -v s="[$section]" 'BEGIN{RS="";FS="\n"} $0 ~ s' "$lock" | sed -n "s#^${rel_path//./\\.} = ##p")"
    if [[ -z "$expected" ]]; then
        echo "FAIL: no recorded hash for '$rel_path' in $lock's [$section]" >&2
        fail=1
        return
    fi
    local actual
    actual="$(curl -fsSL "${base_url}/${rel_path}" | sha256sum | cut -d' ' -f1)"
    if [[ "$actual" != "$expected" ]]; then
        echo "FAIL: ${rel_path} drifted from the pinned Keycloak ${git_tag} release" >&2
        echo "  expected sha256: ${expected}" >&2
        echo "  actual   sha256: ${actual}" >&2
        echo "  This theme's CSS/DOM/FTL assumptions have not been re-validated" >&2
        echo "  against this change. If this is an intentional Keycloak upgrade," >&2
        echo "  update themes/apiary/keycloak.lock's git_tag/digest/hashes together" >&2
        echo "  with a full theme test pass -- see docs/THEME-GUIDE.md. If it" >&2
        echo "  isn't, something is wrong upstream or with this pin; do not just" >&2
        echo "  update the hash to make CI pass." >&2
        fail=1
    else
        echo "OK: ${rel_path} matches Keycloak ${git_tag}"
    fi
}

login_base="https://raw.githubusercontent.com/keycloak/keycloak/${git_tag}/themes/src/main/resources/theme/keycloak.v2/login"
check_one "$login_base" "theme.properties" "upstream_files"
check_one "$login_base" "template.ftl" "upstream_files"
check_one "$login_base" "resources/css/styles.css" "upstream_files"

# #91: themes/apiary/email/html/template.ftl overrides base/email's own
# file, not keycloak.v2/login's -- a separate upstream tree, no
# theme.properties there to pin (base/email doesn't have one at all).
email_base="https://raw.githubusercontent.com/keycloak/keycloak/${git_tag}/themes/src/main/resources/theme/base/email"
check_one "$email_base" "html/template.ftl" "email_upstream_files"

exit "$fail"
