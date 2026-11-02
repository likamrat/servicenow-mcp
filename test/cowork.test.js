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
  assert.deepEqual(await verify(await sign({})), { tenant_id: tenant, object_id: oid, client_id: client, scopes: [SCOPE] });
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
      return { tenant_id: tenant, object_id: oid, client_id: client, scopes: [SCOPE] };
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
  assert.deepEqual(metadata.scopes_supported, [`api://${audience}/Incident.Manage`, `api://${audience}/User.Manage`]);
  assert.equal(metadata.resource, profile.public_url);
  assert.deepEqual(metadata.authorization_servers, [`https://login.microsoftonline.com/${tenant}/v2.0`]);
  for (const method of ["initialize", "tools/list", "tools/call"]) {
    const denied = await rpc(method, { name: "get_incident", arguments: { number: "INC0000001" } }, {});
    assert.equal(denied.status, 401);
    assert.match(denied.headers.get("WWW-Authenticate"), /oauth-protected-resource\/mcp/);
  }
  const listed = await (await rpc("tools/list")).json();
  assert.deepEqual(listed.result.tools, tools.slice(0, 10));
  assert.equal(tools.length, 18);
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

test("opt-in tool audit logs only verified identity, catalog tool and bounded outcomes", async t => {
  const { generateKeyPair, SignJWT } = await import("jose");
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const another = "55555555-5555-4555-8555-555555555555";
  const sign = objectId => new SignJWT({ tid: tenant, oid: objectId, azp: client, ver: "2.0", scp: SCOPE })
    .setProtectedHeader({ alg: "RS256" }).setIssuer(`https://login.microsoftonline.com/${tenant}/v2.0`)
    .setAudience(audience).setIssuedAt().setNotBefore("0s").setExpirationTime("5m").sign(privateKey);
  const tokens = [await sign(oid), await sign(another)];
  const audit = [], callers = [];
  let failure, result = { status: "confirmed", record: { description: "PRIVATE_SOURCE_BODY" } };
  const server = createCoworkApp({ profile: { ...profile, writes_enabled: true, audit_enabled: true },
    backend: { handle: async (_name, _args, callerKey) => {
      callers.push(callerKey);
      if (failure) throw failure;
      return result;
    } },
    verifyAccessToken: await createEntraVerifier(profile, { key: publicKey }),
    writeAudit: line => audit.push(line),
  }).listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => { server.closeAllConnections(); server.close(); });
  const rpc = (name, token = tokens[0], method = "tools/call") => fetch(`http://127.0.0.1:${server.address().port}/mcp`, {
    method: "POST", headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json",
      "X-Private-Header": "PRIVATE_HEADER" },
    body: JSON.stringify({ jsonrpc: "2.0", id: "PRIVATE_RPC_ID", method,
      params: { name, arguments: { private_argument: "PRIVATE_ARGUMENT", caller: "SPOOFED_CALLER" } } }),
  });
  for (const token of tokens) {
    const response = await (await rpc("update_incident", token)).json();
    assert.notEqual(response.result.isError, true);
  }
  assert.deepEqual(callers, [`${tenant}:${oid}:${client}`, `${tenant}:${another}:${client}`]);
  assert.deepEqual(audit.map(JSON.parse), [oid, another].map(object_id => ({
    event: "cowork_tool_audit", tenant_id: tenant, object_id, client_id: client,
    tool: "update_incident", outcome: "success", status: "confirmed",
  })));
  failure = Object.assign(new Error("PRIVATE_RAW_ERROR"), {
    diagnostic: { detail: "PRIVATE_DIAGNOSTIC" }, outcome: { status: "uncertain", before: "PRIVATE_BEFORE" },
  });
  assert.equal((await (await rpc("update_incident")).json()).result.isError, true);
  assert.deepEqual(JSON.parse(audit.at(-1)), { event: "cowork_tool_audit", tenant_id: tenant,
    object_id: oid, client_id: client, tool: "update_incident", outcome: "error", status: "uncertain" });
  failure.outcome.status = "PRIVATE_UNTRUSTED_ERROR_STATUS";
  await rpc("update_incident");
  assert.equal(JSON.parse(audit.at(-1)).status, "failed");
  failure = undefined;
  result = { status: "PRIVATE_UNTRUSTED_RESULT_STATUS", record: "PRIVATE_SOURCE_BODY" };
  await rpc("get_incident");
  assert.equal(JSON.parse(audit.at(-1)).status, "completed");
  await rpc("PRIVATE_UNREGISTERED_TOOL");
  assert.deepEqual(JSON.parse(audit.at(-1)), { event: "cowork_tool_audit", tenant_id: tenant,
    object_id: oid, client_id: client, tool: null, outcome: "not_dispatched", status: "tool_unavailable" });
  const count = audit.length;
  await rpc("get_incident", tokens[0], "tools/list");
  assert.equal((await rpc("get_incident", "PRIVATE_INVALID_TOKEN")).status, 401);
  assert.equal(audit.length, count);
  const text = audit.join("");
  assert.doesNotMatch(text, /PRIVATE_|SPOOFED_CALLER|Bearer/);
  for (const token of tokens) assert.equal(text.includes(token), false);
  for (const line of audit) {
    assert.ok(line.endsWith("\n"));
    assert.deepEqual(Object.keys(JSON.parse(line)), ["event", "tenant_id", "object_id", "client_id", "tool", "outcome", "status"]);
  }
});

test("audit is off by default, records disabled-write rejection when enabled and preserves outcomes on output failure", async t => {
  for (const mode of ["default", "disabled", "blocked", "output_failure"]) {
    const audit = [];
    let calls = 0;
    const config = { ...profile, writes_enabled: mode !== "blocked",
      ...(mode === "default" ? {} : { audit_enabled: mode !== "disabled" }) };
    const server = createCoworkApp({ profile: config,
      backend: { handle: async () => { calls++; return { status: "confirmed", operation_id: "PRIVATE_OPERATION" }; } },
      verifyAccessToken: async () => ({ tenant_id: tenant, object_id: oid, client_id: client, scopes: [SCOPE] }),
      writeAudit: line => {
        if (mode === "output_failure") throw new Error("PRIVATE_SINK_ERROR");
        audit.push(line);
      },
    }).listen(0, "127.0.0.1");
    await once(server, "listening");
    t.after(() => { server.closeAllConnections(); server.close(); });
    const response = await fetch(`http://127.0.0.1:${server.address().port}/mcp`, {
      method: "POST", headers: { Authorization: "Bearer synthetic", "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call",
        params: { name: "update_incident", arguments: {} } }),
    });
    const rpc = await response.json();
    assert.equal(response.status, 200);
    if (mode === "blocked") {
      assert.equal(calls, 0);
      assert.equal(rpc.result.isError, true);
      assert.deepEqual(audit.map(JSON.parse), [{ event: "cowork_tool_audit",
        tenant_id: tenant, object_id: oid, client_id: client, tool: "update_incident",
        outcome: "not_dispatched", status: "writes_disabled" }]);
    } else {
      assert.equal(calls, 1);
      assert.notEqual(rpc.result.isError, true);
      assert.deepEqual(JSON.parse(rpc.result.content[0].text), { status: "confirmed", operation_id: "PRIVATE_OPERATION" });
      assert.equal(audit.length, 0);
      if (mode === "output_failure") {
        assert.equal(rpc.result.content.length, 2);
        assert.match(rpc.result.content[1].text, /audit output unavailable.*outcome is unchanged; do not retry/);
        assert.doesNotMatch(JSON.stringify(rpc), /PRIVATE_SINK_ERROR/);
      } else assert.equal(rpc.result.content.length, 1);
    }
  }
});

test("the default audit destination emits one bounded JSON line on stderr and leaves the MCP response intact", () => {
  const { spawnSync } = require("node:child_process");
  const child = spawnSync(process.execPath, ["-e", `
    const { createCoworkApp } = require(${JSON.stringify(require.resolve("../src/cowork-http.cjs"))});
    const server = createCoworkApp({
      profile: ${JSON.stringify({ ...profile, audit_enabled: true })},
      verifyAccessToken: async () => (${JSON.stringify({ tenant_id: tenant, object_id: oid, client_id: client, scopes: [SCOPE] })}),
      backend: { handle: async () => ({ record: "PRIVATE_SOURCE_BODY" }) },
    }).listen(0, "127.0.0.1", async () => {
      try {
        const response = await fetch("http://127.0.0.1:" + server.address().port + "/mcp", {
          method: "POST",
          headers: { Authorization: "Bearer PRIVATE_TOKEN", "Content-Type": "application/json" },
          body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call",
            params: { name: "get_incident", arguments: { number: "PRIVATE_ARGUMENT" } } }),
        });
        process.stdout.write(JSON.stringify(await response.json()));
      } finally { server.closeAllConnections(); server.close(); }
    });
  `], { encoding: "utf8", timeout: 10000 });
  assert.equal(child.status, 0, child.stderr);
  assert.deepEqual(child.stderr.trim().split(/\r?\n/).map(JSON.parse), [{
    event: "cowork_tool_audit", tenant_id: tenant, object_id: oid, client_id: client,
    tool: "get_incident", outcome: "success", status: "completed",
  }]);
  const rpc = JSON.parse(child.stdout);
  assert.notEqual(rpc.result.isError, true);
  assert.equal(JSON.parse(rpc.result.content[0].text).record, "PRIVATE_SOURCE_BODY");
  assert.doesNotMatch(child.stderr, /PRIVATE_|Bearer/);
});
