# Latest Commits: Security and Correctness Review

Review date: 2026-07-29

Repository: `Xore/auth-backend`

Reviewed range: `5296ee3..a789089`

Reviewed deployment: `auth.xore.rocks`

## Executive summary

The local checkout, GitHub `main`, and the VPS checkout at `/root/auth-backend` all point to:

```text
a789089fd85397c2ded300c6ac2a91f386b25fc6
```

The VPS is already running the production configuration. `auth-portal` and `auth-redis` are healthy, and the public health endpoint returns HTTP 200. No redeployment was required.

The GitHub checks for `a789089` pass:

- CI
- CodeQL Advanced
- Docker Build
- Secret Scan

This review found **five actionable issues**: three affecting the new audit-log integrity control, one possible passwordless-mode administrator lockout, and one cross-platform test failure.

## Reviewed commits

| Commit | Summary |
| --- | --- |
| `c3c659f` | Split `main.go` into focused files |
| `a177268` | Add stricter CSP styling and CSRF meta handling |
| `a824ab1` | Add password policy, signed audit chain, passwordless mode, and HTTPS webhook enforcement |
| `53fc200` | Address log injection, allocation bounds, and URL validation alerts |
| `a789089` | Remove inert CodeQL suppression markers |

## Findings

### 1. High: audit records can be changed without invalidating their MAC

**Affected code:** `forward-auth/audit.go:31-36`, `forward-auth/handlers.go:571-577`

`auditMAC` signs a string produced by joining fields with `|`:

```go
body := strings.Join([]string{
    fmt.Sprint(e.Seq), e.Prev, e.Time.UTC().Format(time.RFC3339Nano),
    e.Event, e.IP, e.User, e.UA, e.Host,
}, "|")
```

The signed fields are not escaped or length-prefixed. Several of them contain request-derived values and may themselves contain `|`. Consequently, two different JSON records can produce the same signed byte string. For example, these adjacent field assignments are indistinguishable to the MAC:

```text
Event = "login|ok", IP = "192.0.2.1"
Event = "login",    IP = "ok|192.0.2.1"
```

Someone able to edit the audit file could redistribute delimiter-containing content between adjacent fields while retaining the existing valid MAC. This defeats the stated field integrity guarantee without requiring the signing key.

**Recommended fix:** sign an unambiguous canonical representation. Suitable options include canonical JSON for a dedicated unsigned-record struct or a binary/length-prefixed encoding. Add a regression test that moves delimiter-containing content between two fields and verifies that validation fails.

### 2. High: enabling passwordless mode can lock every administrator out

**Affected code:** `forward-auth/config.go:198`, `forward-auth/handlers.go:137-140`, `forward-auth/recover.go:265`, `forward-auth/main.go:68-72`

When `PASSWORDLESS=true`:

- password login is rejected;
- password recovery is disabled; and
- passkey registration still requires an authenticated session.

Startup validation does not verify, after loading the user database, that at least one enabled administrator already has a passkey. A fresh installation therefore has a particularly dangerous path: the bootstrap administrator has a password but no passkey, passwordless mode disables that password, and nobody can authenticate to enroll the first passkey.

The same lockout can occur on an existing installation if the setting is enabled before an administrator has enrolled a passkey.

**Recommended fix:** refuse to start in passwordless mode unless at least one enabled administrator has a registered passkey. In the admin UI, use a guarded activation workflow that verifies the current administrator has a working passkey before persisting the setting. Document a recovery procedure that requires explicit server-side operator access.

### 3. Medium: the running service never verifies the complete audit chain

**Affected code:** `forward-auth/audit.go:77-115`

`verifyAuditLines` correctly walks all entries, but it is only called by tests. Production startup calls `resumeChain`, which reads and verifies only the final line.

As a result:

- edits or deletions in earlier lines are not detected at startup;
- an unsigned or corrupt final line causes `resumeChain` to silently start a new chain;
- the service emits no warning or failure when integrity cannot be established.

The chain is therefore only potentially verifiable by code that is not exposed through a command, startup check, health check, or documented operator procedure.

**Recommended fix:** verify the complete file before opening it for append. Refuse startup or enter an explicit degraded state on verification failure, and log a high-severity diagnostic. If startup cost is a concern, use signed checkpoints, but do not silently accept a broken tail. Also expose a documented offline verification command.

### 4. Medium: rotating `COOKIE_SECRET` silently breaks the audit chain

**Affected code:** `forward-auth/main.go:66`, `forward-auth/config.go:140-150`, `forward-auth/audit.go:77-93`

The audit signer receives only the active `COOKIE_SECRET`:

```go
aud := newAuditor(cfg.auditLog, cfg.ringCap, cfg.secret)
```

After a supported cookie-secret rotation and restart, the last existing audit record is signed with the previous key. Although `COOKIE_SECRET_PREVIOUS` is loaded for other token validation, it is not passed to the auditor. `resumeChain` cannot verify the tail and silently begins again at sequence 1 in the same JSONL file.

The resulting file cannot be verified as one continuous chain with either key, so routine key rotation destroys the new forensic continuity guarantee.

**Recommended fix:** use a dedicated, stable `AUDIT_HMAC_KEY` with its own rotation design. If audit-key rotation is required, record and sign explicit key epochs and link the final MAC of the old epoch to the first record of the new epoch. At minimum, detect a previous-key tail and fail safely instead of silently resetting the sequence.

### 5. Medium: all file-backed audit tests leak their log handle on Windows

**Affected code:** `forward-auth/audit_test.go:22-45`, `forward-auth/audit_test.go:47-78`, `forward-auth/audit_test.go:80-98`, `forward-auth/audit_test.go:101-109`

Every test that creates a file-backed auditor leaves its final file handle open. Windows consequently cannot remove the temporary directory during test cleanup. A normal local run fails with:

```text
TempDir RemoveAll cleanup: unlinkat ...\audit.log:
The process cannot access the file because it is being used by another process.
```

`TestAuditChainResumesAcrossRestart` closes `a1.file`, but leaves `a2.file` open. The other three tests never close their auditor file at all. Linux CI does not reveal this because Linux permits unlinking an open file.

**Recommended fix:** add an auditor `Close` method and register it with `t.Cleanup` immediately after each file-backed auditor is created. Use the same method during server shutdown so tests and production share the lifecycle implementation. Add a Windows CI job or, at minimum, a targeted Windows test job for filesystem-sensitive tests.

## Additional configuration gap

`PASSWORDLESS` was introduced in `forward-auth/config.go`, but it is absent from `editableConfigFields` and `currentConfigValue` in `forward-auth/settings.go`. It therefore cannot be managed through the administrator configuration page even though that page is intended to expose application settings.

Because enabling it has lockout implications, it should not be added as an ordinary boolean field. It should use the guarded workflow described in finding 2.

## Validation performed

| Check | Result |
| --- | --- |
| Local revision vs GitHub `main` | Identical (`a789089`) |
| VPS revision vs GitHub `main` | Identical (`a789089`) |
| VPS version configuration | `VERSION=production` |
| VPS application container | Healthy |
| VPS Redis container | Healthy |
| Public health endpoint | HTTP 200 |
| Recent VPS warning/error logs | None observed |
| GitHub CI checks | All passing |
| `go vet ./...` | Passing |
| `go test ./... -count=1` on Windows | Fails due to the audit-file handle leaks above |
| Targeted audit restart test | Reproduces the same handle leak |

## Vulnerability scanner note

Running `govulncheck` with the workstation's Go 1.26.3 toolchain reports three standard-library advisories fixed in Go 1.26.4 or 1.26.5. The repository's Docker builder and GitHub workflows are already pinned to Go 1.26.5, so those scanner results do **not** apply to the current GitHub build or deployed image. The local workstation Go installation should still be upgraded to 1.26.5 or newer to keep local validation representative.

## Suggested remediation order

1. Replace the ambiguous audit MAC encoding.
2. Add safe passwordless-mode activation and startup validation.
3. Verify the full audit chain at startup and fail visibly on corruption.
4. Separate audit signing from cookie-secret rotation.
5. Close audit files in tests and add Windows coverage.
