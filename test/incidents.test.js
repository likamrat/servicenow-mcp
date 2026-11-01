const assert = require("node:assert/strict");
const { test } = require("node:test");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { randomUUID } = require("node:crypto");
const { createAdmin } = require("../src/admin/index.cjs");

const id = value => value.repeat(32);
function fixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "servicenow-incidents-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const incident = { sys_id: id("a"), number: "INC0000001", short_description: "Synthetic incident",
    assigned_to: "", assignment_group: id("b"), sys_mod_count: "0" };
  const users = [
    { sys_id: id("c"), user_name: "avery@example.invalid", name: "Avery Example", first_name: "Avery",
      last_name: "Example", email: "avery@example.invalid", active: "true", sys_mod_count: "0" },
    { sys_id: id("d"), user_name: "blair@example.invalid", name: "Blair Example", first_name: "Blair",
      last_name: "Example", email: "blair@example.invalid", active: "true", sys_mod_count: "0" },
  ];
  const requests = [];
  const mode = { denied: false, responseLoss: false, groupChange: false, ignoreValues: false, failReadback: false };
  let present = true;
  let written = false;
  const fetchImpl = async (raw, options) => {
    const url = new URL(raw);
    const [table, recordId] = url.pathname.split("/table/")[1].split("/");
    const query = url.searchParams.get("sysparm_query") || "";
    const values = options.body ? JSON.parse(options.body) : undefined;
    requests.push({ table, recordId, query, method: options.method, values });
    if (options.method !== "GET" && mode.denied)
      return Response.json({ error: { message: "Security constraints deny this operation" } }, { status: 403 });
    let rows = [];
    if (table === "sys_db_object") {
      const name = query.slice(5);
      rows = [{ name, "super_class.name": name === "incident" ? "task" : "" }];
    } else if (table === "sys_dictionary") rows = [
      { sys_id: id("1"), name: "task", element: "short_description", internal_type: "string", mandatory: "true", max_length: "160" },
      { sys_id: id("2"), name: "task", element: "assigned_to", internal_type: "reference", reference: "sys_user", max_length: "32" },
      { sys_id: id("3"), name: "task", element: "assignment_group", internal_type: "reference", reference: "sys_user_group", max_length: "32" },
      { sys_id: id("4"), name: "task", element: "number", internal_type: "string", max_length: "40" },
    ];
    else if (table === "sys_user") {
      const [field, value] = query.split("=");
      rows = users.filter(user => user[field] === value);
    } else if (table === "sys_user_group") rows = [{ sys_id: id("b") }];
    else if (table === "incident") {
      if (options.method === "POST") {
        Object.assign(incident, values);
        present = true;
        written = true;
        if (mode.responseLoss) throw new Error("Synthetic response loss");
        return Response.json({ result: incident });
      }
      if (options.method === "PATCH") {
        if (!mode.ignoreValues) Object.assign(incident, values);
        incident.sys_mod_count = String(Number(incident.sys_mod_count) + 1);
        if (mode.groupChange) incident.assignment_group = id("9");
        written = true;
        if (mode.responseLoss) throw new Error("Synthetic response loss");
        return Response.json({ result: incident });
      }
      if (options.method === "DELETE") { present = false; return new Response(null, { status: 204 }); }
      if (written && mode.failReadback) return Response.json({ error: { message: "Readback unavailable" } }, { status: 503 });
      rows = present ? [incident] : [];
    }
    const fields = (url.searchParams.get("sysparm_fields") || "").split(",");
    return Response.json({ result: rows.map(row => Object.fromEntries(
      fields.filter(field => Object.hasOwn(row, field)).map(field => [field, row[field]]))) });
  };
  const config = { instance: "https://service.example.invalid", username: "operator",
    password: "synthetic-only", directory, fetchImpl };
  return { admin: createAdmin(config), restart: () => createAdmin(config), incident, users, requests, mode,
    writes: () => requests.filter(row => row.method !== "GET") };
}

test("shared backend supports incident CRUD and exact assignment, reassignment and clearing", async t => {
  const f = fixture(t);
  const resolved = await f.admin.handle("resolve_incident_assignee", { identity: "Avery" });
  assert.equal(resolved.resolution, "unique");
  assert.equal(resolved.candidates[0].sys_id, f.users[0].sys_id);
  const created = await f.admin.handle("create_incident", {
    values: { short_description: "New synthetic incident", assigned_to: resolved.candidates[0].sys_id },
    operation_id: randomUUID(),
  });

  assert.equal(created.status, "confirmed");
  assert.equal(created.record.assigned_to, f.users[0].sys_id);
  for (const assigned_to of [f.users[1].sys_id, null]) {
    const result = await f.admin.handle("update_incident", {
      number: f.incident.number, expected_mod_count: f.incident.sys_mod_count,
      values: { assigned_to }, operation_id: randomUUID(),
    });
    assert.equal(result.status, "confirmed");
    assert.equal(result.record.assigned_to, assigned_to === null ? "" : assigned_to);
    assert.equal(result.assignment_group_preserved, true);
  }
  const deleted = await f.admin.handle("delete_incident", {
    number: f.incident.number, expected_mod_count: f.incident.sys_mod_count,
    operation_id: randomUUID(), confirm: true,
  });
  assert.equal(deleted.deleted, true);
  assert.equal(deleted.cleanup_complete, false);
  assert.deepEqual(f.requests.filter(row => row.method !== "GET").map(row => row.method), ["POST", "PATCH", "PATCH", "DELETE"]);
});

test("exact identity resolution retains ambiguity and rejects missing references and stale incident versions without writes", async t => {
  const f = fixture(t);
  f.users[1].first_name = "Avery";
  assert.equal((await f.admin.handle("resolve_incident_assignee", { identity: "Avery" })).resolution, "ambiguous");
  assert.equal((await f.admin.handle("resolve_incident_assignee", { identity: "Av" })).resolution, "not_found");
  const exact = await f.admin.handle("resolve_incident_assignee", { identity: "avery@example.invalid", field: "email" });
  assert.equal(exact.resolution, "unique");
  for (const [expected_mod_count, assigned_to] of [["9", f.users[0].sys_id], ["0", id("e")], ["0", "Avery"]]) {
    await assert.rejects(f.admin.handle("update_incident", { number: f.incident.number,
      expected_mod_count, values: { assigned_to }, operation_id: randomUUID() }));
  }
  await assert.rejects(f.admin.handle("resolve_incident_assignee", { identity: "Avery^NQactive=true" }), /encoded query/);
  assert.equal(f.writes().length, 0);
});

test("denied, partial and uncertain source writes keep their evidence and block replay under any UUID", async t => {
  for (const failure of ["denied", "responseLoss", "groupChange", "ignoreValues", "failReadback"]) {
    const f = fixture(t);
    f.mode[failure] = true;
    const operation_id = randomUUID();
    const args = { number: f.incident.number, expected_mod_count: "0",
      values: { assigned_to: f.users[0].sys_id }, operation_id };
    await assert.rejects(f.admin.handle("update_incident", args, "requester-a"), error => {
      assert.equal(error.outcome.status, "uncertain", failure);
      assert.equal(error.outcome.source_write_attempted, true);
      if (failure === "denied") {
        assert.equal(error.outcome.source_rejected, true);
        assert.equal(error.diagnostic.status, 403);
        assert.match(error.diagnostic.message, /Security constraints/);
      }
      if (failure === "ignoreValues") assert.equal(error.outcome.observed.assigned_to, "");
      return true;
    });
    f.mode.failReadback = false;
    const status = await f.admin.handle("get_incident_operation", { operation_id }, "requester-a");
    assert.equal(status.status, "uncertain", failure);
    assert.equal(status.unresolved_hold, true);
    await assert.rejects(f.admin.handle("get_incident_operation", { operation_id }, "requester-b"), /not available/);
    for (const retryId of [operation_id, randomUUID()]) await assert.rejects(f.admin.handle("update_incident", {
      ...args, expected_mod_count: f.incident.sys_mod_count, operation_id: retryId,
    }, "requester-a"), /already|unresolved/);
    assert.equal(f.writes().length, 1, failure);
  }
});

test("signed Cowork HTTP calls use the same guarded backend for recent reads and full incident CRUD", async t => {
  const { createCoworkApp } = require("../src/cowork-http.cjs");
  const { createEntraVerifier } = require("../src/cowork-auth.cjs");
  const { once } = require("node:events");
  const { generateKeyPair, SignJWT } = await import("jose");
  const f = fixture(t);
  const tenant = "11111111-1111-4111-8111-111111111111";
  const client = "33333333-3333-4333-8333-333333333333";
  const audience = "44444444-4444-4444-8444-444444444444";
  const profile = { format: 1, tenant_id: tenant, client_id: client, audience, writes_enabled: true,
    instance: "https://service.example.invalid", public_url: "https://mcp.example.invalid/mcp" };
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const token = await new SignJWT({ tid: tenant, oid: "22222222-2222-4222-8222-222222222222",
    azp: client, ver: "2.0", scp: "Incident.Manage" }).setProtectedHeader({ alg: "RS256" })
    .setIssuer(`https://login.microsoftonline.com/${tenant}/v2.0`).setAudience(audience)
    .setIssuedAt().setNotBefore("0s").setExpirationTime("5m").sign(privateKey);
  const server = createCoworkApp({ profile, backend: f.admin,
    verifyAccessToken: await createEntraVerifier(profile, { key: publicKey }),
  }).listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => { server.closeAllConnections(); server.close(); });
  const call = async (name, args) => {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/mcp`, {
      method: "POST", headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }),
    });
    assert.equal(response.status, 200);
    const rpc = await response.json();
    assert.notEqual(rpc.result.isError, true, rpc.result.content[0].text);
    return JSON.parse(rpc.result.content[0].text);
  };
  const incident = await call("get_incident", { number: f.incident.number });
  assert.equal(incident.sys_mod_count, "0");
  assert.ok(f.requests.at(-1).query.startsWith("sys_updated_on>javascript:gs.monthsAgo(6)^"));
  const candidate = await call("resolve_incident_assignee", { identity: "Avery" });
  assert.equal(candidate.resolution, "unique");
  const created = await call("create_incident", {
    values: { short_description: "Cowork synthetic incident" }, operation_id: randomUUID(),
  });
  assert.equal(created.status, "confirmed");
  for (const assigned_to of [candidate.candidates[0].sys_id, f.users[1].sys_id, null]) {
    const operation_id = randomUUID();
    const result = await call("update_incident", { number: incident.number, expected_mod_count: f.incident.sys_mod_count,
      values: { assigned_to }, operation_id });
    assert.equal(result.status, "confirmed");
    assert.equal(result.assignment_group_preserved, true);
    assert.equal((await call("get_incident_operation", { operation_id })).unresolved_hold, false);
  }
  assert.equal((await call("delete_incident", { number: incident.number, expected_mod_count: f.incident.sys_mod_count,
    operation_id: randomUUID(), confirm: true })).deleted, true);
  assert.deepEqual(f.writes().map(row => row.method), ["POST", "PATCH", "PATCH", "PATCH", "DELETE"]);
});

test("uncertain creation survives restart and blocks both semantic and generic writes to the returned identity", async t => {
  const f = fixture(t);
  f.mode.failReadback = true;
  const operation_id = randomUUID();
  await assert.rejects(f.admin.handle("create_incident", {
    values: { short_description: "Retained uncertain incident" }, operation_id,
  }, "requester-a"), error => error.outcome.status === "uncertain" && error.outcome.sys_id === f.incident.sys_id);
  f.mode.failReadback = false;
  const restarted = f.restart();
  const status = await restarted.handle("get_incident_operation", { operation_id }, "requester-a");
  assert.equal(status.status, "uncertain");
  assert.equal(status.current.record.sys_id, f.incident.sys_id);
  assert.equal(status.unresolved_hold, true);
  await assert.rejects(restarted.handle("update_incident", { number: f.incident.number,
    expected_mod_count: f.incident.sys_mod_count, values: { assigned_to: f.users[0].sys_id },
    operation_id: randomUUID() }, "requester-a"), /unresolved/);
  await assert.rejects(restarted.handle("local_record_update", { table: "incident", sys_id: f.incident.sys_id,
    expected_mod_count: f.incident.sys_mod_count, values: { short_description: "Must not replay" },
    operation_id: randomUUID() }), /unresolved/);
  assert.equal(f.writes().length, 1);
});
