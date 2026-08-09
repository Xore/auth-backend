// #106/#107: enables select-authenticator's real trigger condition.
//
// Keycloak's built-in `browser` flow already ships a "WebAuthn Authenticator"
// alternative execution inside the "Browser - Conditional 2FA" subflow,
// alongside "OTP Form" -- it just imports DISABLED. When a user has more than
// one usable ("applicable") ALTERNATIVE credential in that subflow, Keycloak
// shows select-authenticator to let them pick; with exactly one applicable
// alternative it skips straight to it. So the only fixture change needed to
// exercise select-authenticator against real markup is flipping that one
// execution to ALTERNATIVE -- no custom flow copy, no client flow-binding
// override, and nothing realm-JSON-import can express directly (execution
// IDs are generated fresh per import, so this has to run once Keycloak is up).
//
// Test-fixture-only. The real APIARY realm has never added a WebAuthn
// executor to its browser flow (docs/PAGE-MATRIX.md's realm-facts table) --
// whether to do that in production is a separate product decision, not made
// here. This only ever runs against the disposable realm this compose file
// creates.
import type { FullConfig } from '@playwright/test';
import { adminToken } from './realm-admin';

const REALM = 'test-apiary';

export default async function globalSetup(config: FullConfig) {
  const base = config.projects[0]?.use.baseURL ?? process.env.KEYCLOAK_TEST_BASE_URL ?? 'http://localhost:8180';
  const token = await adminToken(base);
  const authHeaders = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };

  const executionsUrl = `${base}/admin/realms/${REALM}/authentication/flows/browser/executions`;
  const executionsRes = await fetch(executionsUrl, { headers: authHeaders });
  if (!executionsRes.ok) throw new Error(`failed to list browser flow executions: ${executionsRes.status}`);
  const executions = await executionsRes.json();

  const webauthn = executions.find((e: { providerId?: string }) => e.providerId === 'webauthn-authenticator');
  if (!webauthn) throw new Error('browser flow has no webauthn-authenticator execution -- Keycloak upgrade changed the default flow shape, see keycloak.lock');

  const putRes = await fetch(executionsUrl, {
    method: 'PUT',
    headers: authHeaders,
    body: JSON.stringify({ ...webauthn, requirement: 'ALTERNATIVE' }),
  });
  if (!putRes.ok) throw new Error(`failed to enable WebAuthn Authenticator as ALTERNATIVE: ${putRes.status} ${await putRes.text()}`);
}
