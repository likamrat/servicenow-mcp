const assert = require("node:assert/strict");
const { test } = require("node:test");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { randomUUID } = require("node:crypto");
const { createAdmin } = require("../src/admin/index.cjs");
const id = character => character.repeat(32);

function fixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "servicenow-users-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const rows = [];
  const requests = [];
  const mode = { lostResponse: false, missingResponseIdentity: false, deny: false, unexpectedActive: false, ruleVersion: "0" };
  const user = values => ({ sys_id: id("a"), sys_mod_count: "0", sys_class_name: "sys_user",
    user_name: "", first_name: "", last_name: "", name: "", title: "", email: "",
    active: "false", locked_out: "true", notification: "1", identity_type: "human",
    internal_integration_user: "false", web_service_access_only: "false", source: "", ldap_server: "",
    ...values });
  const operator = user({ sys_id: id("b"), user_name: "operator" });
  const fetchImpl = async (raw, options) => {
    const url = new URL(raw), [table, recordId] = url.pathname.split("/table/")[1].split("/");
    const query = url.searchParams.get("sysparm_query") || "";
    const values = options.body ? JSON.parse(options.body) : undefined;
    requests.push({ table, recordId, query, method: options.method, values });
    if (options.method !== "GET") {
      if (mode.deny) return Response.json({ error: { message: "Security constraints deny access" } }, { status: 403 });
      if (options.method === "POST") rows.push(user(Object.fromEntries(Object.entries(values).map(([key, value]) => [key, String(value)]))));
      if (options.method === "PATCH") Object.assign(rows.find(row => row.sys_id === recordId),
        Object.fromEntries(Object.entries(values).map(([key, value]) => [key, String(value)])),
        { sys_mod_count: "1" });
      if (mode.unexpectedActive) rows[0].active = "true";
      if (mode.lostResponse) throw new Error("Synthetic lost response");
      if (mode.missingResponseIdentity) return Response.json({ result: {} });
      return Response.json({ result: rows[0] });
    }
    let result = [];
    if (table === "sys_db_object") result = [{ name: "sys_user", "super_class.name": "" }];
    if (table === "sys_dictionary") {
      if (query === "name=sys_user^element=user_name") result = [{ sys_id: id("1"), sys_mod_count: "0", unique: "true" }];
      else result = ["user_name", "first_name", "last_name", "title", "email", "active", "locked_out",
        "notification", "identity_type", "internal_integration_user", "web_service_access_only"].map((field, index) => ({
        sys_id: (index + 1).toString(16).padStart(32, "0"), name: "sys_user", element: field,
        internal_type: ["active", "locked_out", "internal_integration_user", "web_service_access_only"].includes(field) ? "boolean" : "string",
        max_length: field === "user_name" ? "40" : field === "email" ? "100" : "50",
        choice: field === "title" ? "2" : "0",
        mandatory: field === "user_name" ? "true" : "false", default_value: "", reference: "",
      }));
    }
    if (table === "sys_choice") result = [{ sys_id: id("2"), name: "sys_user", element: "title",
      value: "Suggested title", label: "Suggested title", dependent_value: "" }];
    if (table === "sys_script") result = [{ sys_id: id("c"), sys_mod_count: mode.ruleVersion }];
    if (table === "sys_user") result = [...rows, operator].filter(row => query.split("^").every(part => {
      if (part.startsWith("ORDERBY")) return true;
      const split = part.indexOf("=");
      return split > 0 && String(row[part.slice(0, split)]).toLowerCase() === part.slice(split + 1).toLowerCase();
    }));
    const fields = (url.searchParams.get("sysparm_fields") || "").split(",");
    return Response.json({ result: result.map(row => Object.fromEntries(fields
      .filter(field => Object.hasOwn(row, field)).map(field => [field, row[field]]))) });
  };
  const config = { instance: "https://service.example.invalid", username: "operator", password: "synthetic-only", directory, fetchImpl };
  return { admin: createAdmin(config), directory, rows, user, requests, mode, restart: () => createAdmin(config),
    writes: () => requests.filter(row => row.method !== "GET") };
}

async function approve(f) {
  const schema = await f.admin.handle("get_user_schema", {});
  fs.writeFileSync(path.join(f.directory, "user-profile-contract.json"), JSON.stringify({
    format: 1, instance: "https://service.example.invalid", schema_sha256: schema.schema_sha256,
    rules_sha256: schema.rules_sha256, sourceEvidenceSha256: "d".repeat(64),
    protectedIds: [], protectedNames: ["admin", "guest", "system"], absence_visibility_reviewed: true,
  }));
}

test("generic user CRUD accepts internally discovered email as unverified request data and creates no-login user", async t => {
  const f = fixture(t);
  await approve(f);
  const operation_id = randomUUID();
  const created = await f.admin.handle("create_user", { user_name: "avery@example.invalid",
    profile: { first_name: "Avery", last_name: "Example", email: "avery@example.invalid" }, operation_id }, "caller-a");
  assert.equal(created.status, "confirmed");
  assert.equal(created.record.email, "avery@example.invalid");
  assert.equal(created.record.active, "false");
  assert.equal(created.record.locked_out, "true");
  assert.equal(created.directory_verified, false);
  assert.equal(created.assignee_readiness, "not_evaluated");
  assert.equal(f.writes()[0].values.user_password, undefined);
  assert.equal((await f.admin.handle("get_user", { sys_id: created.record.sys_id })).record.email, "avery@example.invalid");
  const updated = await f.admin.handle("update_user", { sys_id: created.record.sys_id,
    expected_mod_count: "0", profile: { title: "Support engineer" }, operation_id: randomUUID() }, "caller-a");
  assert.equal(updated.record.title, "Support engineer");
  assert.equal((await f.admin.handle("get_user_operation", { operation_id }, "caller-a")).status, "confirmed");
  await assert.rejects(f.admin.handle("get_user_operation", { operation_id }, "caller-b"), /not available/);
  assert.deepEqual(f.writes().map(row => row.method), ["POST", "PATCH"]);
});

test("user schema distinguishes generic record restrictions from semantic CRUD and unevaluated authorization", async t => {
  const f = fixture(t);
  await approve(f);
  const raw = await f.admin.handle("local_record_schema", { table: "sys_user" });
  const schema = await f.admin.handle("get_user_schema", {});
  assert.equal(raw.mutationAllowed, false);
  assert.equal(Object.hasOwn(schema.schema, "mutationAllowed"), false);
  assert.equal(schema.generic_record_interface.mutation_allowed, false);
  assert.equal(schema.semantic_user_interface.supported, true);
  assert.equal(schema.semantic_user_interface.policy_status, "not_evaluated");
  assert.equal(schema.semantic_user_interface.source_permission, "not_evaluated");
  assert.equal(schema.schema.fields.title.choiceMode, "2");
  assert.equal(schema.schema.fields.title.choice_semantics, "suggestions_not_restricted_picklist");
  assert.equal(schema.schema.fields.title.choices.length, 1);
  assert.equal(schema.schema_sha256, require("../src/admin/users.cjs").fingerprint(raw));
  assert.equal(f.writes().length, 0);
});

test("profile CRUD preserves policy, current-operator, retention, collisions and sensitive-field boundaries", async t => {
  const f = fixture(t);
  const args = { user_name: "avery@example.invalid", profile: { email: "avery@example.invalid" }, operation_id: randomUUID() };
  await assert.rejects(f.admin.handle("create_user", args), /Missing operator-reviewed/);
  await approve(f);
  f.rows.push(f.user({ user_name: args.user_name, email: args.profile.email }));
  await assert.rejects(f.admin.handle("create_user", args), /collision/);
  await assert.rejects(f.admin.handle("create_user", { ...args, user_name: "another" }), /email collision/);
  await assert.rejects(f.admin.handle("create_user", { ...args, user_name: "admin" }), /Reserved/);
  const update = { sys_id: id("a"), expected_mod_count: "0", profile: { title: "New title" }, operation_id: randomUUID() };
  await assert.rejects(f.admin.handle("update_user", { ...update, sys_id: id("b") }), /Current operator/);
  await assert.rejects(f.admin.handle("update_user", { ...update, expected_mod_count: "4" }), /changed/);
  for (const field of ["user_password", "active", "locked_out", "roles", "user_name", "directory_verified"])
    await assert.rejects(f.admin.handle("update_user", { ...update, profile: { [field]: "untrusted" } }), /Unexpected/);
  fs.writeFileSync(path.join(f.directory, "retained-user-ids.json"), JSON.stringify([id("a")]));
  await assert.rejects(f.admin.handle("update_user", update), /retention hold/);
  fs.writeFileSync(path.join(f.directory, "retained-user-ids.json"), "[]");
  f.rows[0].source = "managed externally";
  await assert.rejects(f.admin.handle("update_user", update), /External/);
  f.rows[0].source = "";
  f.mode.ruleVersion = "1";
  await assert.rejects(f.admin.handle("update_user", update), /differ from reviewed policy/);
  assert.equal(f.writes().length, 0);
});

test("lost or rejected user creation and unexpected lifecycle effects remain durable without replay or adoption", async t => {
  for (const mode of ["lostResponse", "missingResponseIdentity", "deny", "unexpectedActive"]) {
    const f = fixture(t);
    await approve(f);
    f.mode[mode] = true;
    const operation_id = randomUUID();
    await assert.rejects(f.admin.handle("create_user", { user_name: "avery", profile: { email: "avery@example.invalid" },
      operation_id }, "caller-a"), error => {
      assert.equal(error.outcome.status, "uncertain");
      if (mode === "lostResponse") {
        assert.equal(error.outcome.observed_user_identity, id("a"));
        assert.equal(error.outcome.retained_created_identity, null, "Readback is not proof of attribution");
      }
      if (mode === "unexpectedActive") assert.equal(error.outcome.retained_created_identity, id("a"));
      return true;
    });
    f.mode[mode] = false;
    const restarted = f.restart();
    const result = await restarted.handle("get_user_operation", { operation_id }, "caller-a");
    assert.equal(result.status, "uncertain");
    assert.equal(result.unresolved_hold, true);
    await assert.rejects(restarted.handle("get_user_operation", { operation_id }, "caller-b"), /not available/);
    await assert.rejects(restarted.handle("create_user", { user_name: "another",
      profile: { email: "another@example.invalid" }, operation_id: randomUUID() }, "caller-b"), /unresolved/);
    assert.equal(f.writes().length, 1);
  }
});

test("signed remote user CRUD requires its own scope and uses the same caller-isolated backend", async t => {
  const { createCoworkApp } = require("../src/cowork-http.cjs");
  const { createEntraVerifier } = require("../src/cowork-auth.cjs");
  const { generateKeyPair, SignJWT } = await import("jose");
  const { once } = require("node:events");
  const f = fixture(t);
  await approve(f);
  const tenant = "11111111-1111-4111-8111-111111111111", client = "33333333-3333-4333-8333-333333333333";
  const audience = "44444444-4444-4444-8444-444444444444", oid = "22222222-2222-4222-8222-222222222222";
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const sign = scope => new SignJWT({ tid: tenant, oid, azp: client, ver: "2.0", scp: scope })
    .setProtectedHeader({ alg: "RS256" }).setIssuer(`https://login.microsoftonline.com/${tenant}/v2.0`)
    .setAudience(audience).setIssuedAt().setNotBefore("0s").setExpirationTime("5m").sign(privateKey);
  const profile = { format: 1, instance: "https://service.example.invalid", public_url: "https://mcp.example.invalid/mcp",
    tenant_id: tenant, audience, client_id: client, writes_enabled: true };
  const server = createCoworkApp({ profile, backend: f.admin,
    verifyAccessToken: await createEntraVerifier(profile, { key: publicKey }),
  }).listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => { server.closeAllConnections(); server.close(); });
  const rpc = async (scope, method, params) => {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/mcp`, {
      method: "POST", headers: { Authorization: `Bearer ${await sign(scope)}`, "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    });
    assert.equal(response.status, 200);
    return response.json();
  };
  for (const [scope, count] of [["Incident.Manage", 10], ["User.Manage", 8], ["User.Access.Manage", 4],
    ["Incident.Manage User.Manage", 18], ["Incident.Manage User.Manage User.Access.Manage", 22]]) {
    const result = await rpc(scope, "tools/list");
    assert.equal(result.result.tools.length, count);
  }
  const args = { user_name: "avery", profile: { email: "avery@example.invalid" }, operation_id: randomUUID() };
  const denied = await rpc("Incident.Manage", "tools/call", { name: "create_user", arguments: args });
  assert.equal(denied.result.isError, true);
  assert.equal(f.writes().length, 0);
  const accessDenied = await rpc("User.Manage", "tools/call", { name: "apply_user_access", arguments: {} });
  assert.equal(accessDenied.result.isError, true);
  assert.equal(f.writes().length, 0);
  const created = await rpc("User.Manage", "tools/call", { name: "create_user", arguments: args });
  assert.notEqual(created.result.isError, true, created.result.content[0].text);
  assert.equal(JSON.parse(created.result.content[0].text).record.email, args.profile.email);
  const incidentDenied = await rpc("User.Manage", "tools/call", { name: "update_incident", arguments: {} });
  assert.equal(incidentDenied.result.isError, true);
  const status = await rpc("User.Manage", "tools/call", { name: "get_user_operation", arguments: { operation_id: args.operation_id } });
  assert.equal(JSON.parse(status.result.content[0].text).status, "confirmed");
  assert.equal(f.writes().length, 1);
});
