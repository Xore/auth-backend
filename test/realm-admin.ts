// Shared admin-token helper for test/global-setup.ts and specs that need to
// mutate the disposable realm at runtime (execution requirements can't be
// expressed in fixtures/realm-export.json's static import -- their IDs are
// generated fresh per import -- and some settings, like
// internationalizationEnabled below, are deliberately kept OFF the shared
// fixture so they don't change every other test's baseline screenshots).
export async function adminToken(base: string): Promise<string> {
  const res = await fetch(`${base}/realms/master/protocol/openid-connect/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'password',
      client_id: 'admin-cli',
      username: 'admin',
      password: 'test-only-not-a-real-secret',
    }),
  });
  if (!res.ok) throw new Error(`admin token request failed: ${res.status} ${await res.text()}`);
  const body = await res.json();
  return body.access_token as string;
}
