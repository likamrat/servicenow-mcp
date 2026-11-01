const assert = require("node:assert/strict");
const { test } = require("node:test");
const { once } = require("node:events");
const { createEntraVerifier, SCOPE, CoworkAuthError } = require("../src/cowork-auth.cjs");
const { createCoworkApp, tools, validateProfile } = require("../src/cowork-http.cjs");
const tenant = "11111111-1111-4111-8111-111111111111";
const oid = "22222222-2222-4222-8222-222222222222";
const client = "33333333-3333-4333-8333-333333333333";
const audience = "44444444-4444-4444-8444-444444444444";
const profile = { format: 1, tenant_id: tenant, audience, client_id: client,
  instance: "https://service.example.invalid", public_url: "https://mcp.example.invalid/mcp", writes_enabled: false };

test("Entra verification requires the delegated resource/client scope without a person allowlist", async () => {
  const { generateKeyPair, SignJWT } = await import("jose");
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const now = Math.floor(Date.now() / 1000);
  const sign = (changes, settings = {}) => new SignJWT({
    tid: tenant, oid, azp: client, ver: "2.0", scp: SCOPE, ...changes,
  }).setProtectedHeader({ alg: "RS256", kid: "synthetic" }).setIssuer(settings.issuer || `https://login.microsoftonline.com/${tenant}/v2.0`)
    .setAudience(settings.audience || audience).setIssuedAt(settings.iat ?? now).setNotBefore(settings.nbf ?? now)
    .setExpirationTime(settings.exp ?? now + 600).sign(settings.key || privateKey);
  const verify = await createEntraVerifier(profile, { key: publicKey });
  assert.deepEqual(await verify(await sign({})), { tenant_id: tenant, object_id: oid, client_id: client });
  const another = "55555555-5555-4555-8555-555555555555";
  assert.equal((await verify(await sign({ oid: another }))).object_id, another);
  for (const claims of [
    { scp: "Incident.Assign" }, { scp: undefined, roles: [SCOPE] }, { idtyp: "app" },
    { azp: another }, { tid: another }, { oid: undefined, preferred_username: "operator@example.invalid" },
    { oid: "not-an-object-id" }, { ver: "1.0" },
  ]) await assert.rejects(verify(await sign(claims)), error => [401, 403].includes(error.status));
  const other = await generateKeyPair("RS256");
  for (const settings of [
    { audience: `api://${audience}` }, { issuer: `https://login.microsoftonline.com/${client}/v2.0` },
    { iat: now - 120, nbf: now - 120, exp: now - 60 }, { nbf: now + 90 }, { key: other.privateKey },
  ]) await assert.rejects(verify(await sign({}, settings)), error => error.status === 401);
  const unavailable = await createEntraVerifier(profile, {
    key: async () => { throw new TypeError("Synthetic private key-provider detail"); },
  });
  await assert.rejects(unavailable(await sign({})), error =>
    error.status === 503 && error.message === "authorization_keys_unavailable");
});

test("the authenticated interface gates all ten tools and exposes only protected-resource discovery anonymously", async t => {
  const calls = [];
  const server = createCoworkApp({ profile, backend: { handle: async (...args) => { calls.push(args); return {}; } },
    verifyAccessToken: async token => {
      if (token !== "synthetic") throw new CoworkAuthError(401, "invalid_token");
      return { tenant_id: tenant, object_id: oid, client_id: client };
    },
  }).listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => { server.closeAllConnections(); server.close(); });
  const origin = `http://127.0.0.1:${server.address().port}`;
  const rpc = (method, params, headers = { Authorization: "Bearer synthetic" }) => fetch(`${origin}/mcp`, {
    method: "POST", headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const metadata = await (await fetch(`${origin}/.well-known/oauth-protected-resource/mcp`)).json();
  assert.deepEqual(metadata.scopes_supported, [`api://${audience}/Incident.Manage`]);
  assert.equal(metadata.resource, profile.public_url);
  assert.deepEqual(metadata.authorization_servers, [`https://login.microsoftonline.com/${tenant}/v2.0`]);
  for (const method of ["initialize", "tools/list", "tools/call"]) {
    const denied = await rpc(method, { name: "get_incident", arguments: { number: "INC0000001" } }, {});
    assert.equal(denied.status, 401);
    assert.match(denied.headers.get("WWW-Authenticate"), /oauth-protected-resource\/mcp/);
  }
  const listed = await (await rpc("tools/list")).json();
  assert.deepEqual(listed.result.tools, tools);
  assert.equal(tools.length, 10);
  const read = await (await rpc("tools/call", { name: "get_incident", arguments: { number: "INC0000001" } })).json();
  assert.notEqual(read.result.isError, true);
  assert.deepEqual(calls, [["get_incident", { number: "INC0000001" }, `${tenant}:${oid}:${client}`]]);
  for (const name of ["update_incident", "local_record_update", "local_admin_user_role_add"]) {
    const result = await (await rpc("tools/call", { name, arguments: {} })).json();
    assert.equal(result.result.isError, true);
  }
  const badOrigin = await rpc("tools/list", {}, { Authorization: "Bearer synthetic", Origin: "https://untrusted.example.invalid" });
  assert.equal(badOrigin.status, 403);
  assert.equal(calls.length, 1);
  assert.throws(() => validateProfile({ ...profile, allowed_callers: [oid] }), /Unexpected/);
});
