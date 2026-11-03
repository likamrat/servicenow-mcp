const assert = require("node:assert/strict");
const { test } = require("node:test");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { randomUUID } = require("node:crypto");
const { createAdmin } = require("../src/admin/index.cjs");

const id = value => value.repeat(32);
function fixture(t, { beforeRead } = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "servicenow-incidents-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const incident = { sys_id: id("a"), number: "INC0000001", short_description: "Synthetic incident",
    description: "Preserve the investigation context.", work_notes: "",
    assigned_to: "", assignment_group: id("b"), sys_mod_count: "0" };
  const users = [
    { sys_id: id("c"), user_name: "avery@example.invalid", name: "Avery Example", first_name: "Avery",
      last_name: "Example", email: "avery@example.invalid", active: "true", sys_mod_count: "0" },
    { sys_id: id("d"), user_name: "blair@example.invalid", name: "Blair Example", first_name: "Blair",
      last_name: "Example", email: "blair@example.invalid", active: "true", sys_mod_count: "0" },
  ];
  const requests = [];
  const notes = [];
  const mode = { denied: false, responseLoss: false, groupChange: false, ignoreValues: false, failReadback: false,
    suppressNote: false, denyJournal: false, failJournalReadback: false };
  let present = true;
  let written = false;
  const fetchImpl = async (raw, options) => {
    const url = new URL(raw);
    const [table, recordId] = url.pathname.split("/table/")[1].split("/");
    const query = url.searchParams.get("sysparm_query") || "";
    const values = options.body ? JSON.parse(options.body) : undefined;
    requests.push({ table, recordId, query, method: options.method, values });
    if (options.method === "GET" && beforeRead) await beforeRead(table);
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
      { sys_id: id("5"), name: "task", element: "work_notes", internal_type: "journal_input", max_length: "4000" },
      { sys_id: id("6"), name: "task", element: "description", internal_type: "string", max_length: "4000" },
    ];
    else if (table === "sys_user") {
      const [field, value] = query.split("=");
      rows = users.filter(user => user[field] === value);
    } else if (table === "sys_user_group") rows = [{ sys_id: id("b") }];
    else if (table === "sys_journal_field") {
      if (mode.denyJournal || written && mode.failJournalReadback)
        return Response.json({ error: { message: "Journal visibility denied" } }, { status: 403 });
      rows = notes.filter(row => query.includes(`element_id=${row.element_id}`) &&
        query.includes(`element=${row.element}`) && (!query.includes("^sys_id=") || query.includes(`^sys_id=${row.sys_id}`)))
        .sort((a, b) => b.sys_created_on.localeCompare(a.sys_created_on) || b.sys_id.localeCompare(a.sys_id))
        .slice(0, Number(url.searchParams.get("sysparm_limit")));
    }
    else if (table === "incident") {
      if (options.method === "POST") {
        Object.assign(incident, values);
        present = true;
        written = true;
        if (mode.responseLoss) throw new Error("Synthetic response loss");
        return Response.json({ result: incident });
      }
      if (options.method === "PATCH") {
        if (!mode.ignoreValues) Object.assign(incident, Object.fromEntries(Object.entries(values).filter(([field]) => field !== "work_notes")));
        if (values.work_notes && !mode.suppressNote) notes.push({ sys_id: (notes.length + 1).toString(16).padStart(32, "0"),
          name: "incident", element: "work_notes", element_id: incident.sys_id, value: values.work_notes,
          sys_created_on: "2026-01-02 12:00:00" });
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
  return { admin: createAdmin(config), restart: () => createAdmin(config), incident, users, requests, notes, mode,
    writes: () => requests.filter(row => row.method !== "GET") };
}

test("incident handoff appends a work note and independently reads only that new entry without overwriting description", async t => {
  const f = fixture(t);
  const operation_id = randomUUID();
  const value = "Observed delays; routing remains a hypothesis.\nNext: check the service path.";
  f.notes.push({ sys_id: id("e"), name: "task", element: "work_notes", element_id: f.incident.sys_id,
    value, sys_created_on: "2026-01-01 12:00:00" });
  const result = await f.admin.handle("update_incident", { number: f.incident.number,
    expected_mod_count: "0", values: { assigned_to: f.users[0].sys_id, work_notes: value }, operation_id }, "requester-a");
  assert.equal(result.status, "confirmed");
  assert.equal(result.record.assigned_to, f.users[0].sys_id);
  assert.equal(result.assignment_group_preserved, true);
  assert.equal(result.work_note.status, "observed");
  assert.equal(result.work_note.entry.value, value);
  assert.notEqual(result.work_note.entry.sys_id, id("e"), "An existing identical note is not append evidence");
  assert.equal(f.incident.description, "Preserve the investigation context.");
  assert.equal(f.notes.length, 2);
  assert.deepEqual(f.writes().map(row => [row.table, row.method, row.values]), [
    ["incident", "PATCH", { assigned_to: f.users[0].sys_id, work_notes: value }],
  ]);
  for (let i = 0; i < 25; i++) f.notes.push({ sys_id: (100 + i).toString(16).padStart(32, "0"),
    name: "incident", element: "work_notes", element_id: f.incident.sys_id,
    value: "Unrelated later note", sys_created_on: "2026-01-03 12:00:00" });
  const recovery = await f.restart().handle("get_incident_operation", { operation_id }, "requester-a");
  assert.deepEqual(recovery.work_note.entry, result.work_note.entry);
  assert.equal(recovery.unresolved_hold, false);
  const reads = f.requests.length;
  await assert.rejects(f.admin.handle("get_incident_operation", { operation_id }, "requester-b"), /not available/);
  assert.equal(f.requests.length, reads);
});

test("lost handoff response and failed record readback retain the original error and recover notes without replay", async t => {
  const f = fixture(t);
  f.mode.responseLoss = true;
  f.mode.failReadback = true;
  const args = { number: f.incident.number, expected_mod_count: "0",
    values: { assigned_to: f.users[0].sys_id, work_notes: "Retain this exact finding." }, operation_id: randomUUID() };
  await assert.rejects(f.admin.handle("update_incident", args, "requester-a"), error => {
    assert.equal(error.outcome.status, "uncertain");
    assert.equal(error.outcome.work_note.status, "observed");
    assert.equal(error.outcome.record_fields.status, "unknown");
    assert.match(error.outcome.original_error.message, /transport failed/);
    return true;
  });
  f.mode.failReadback = false;
  const restarted = f.restart();
  const result = await restarted.handle("get_incident_operation", { operation_id: args.operation_id }, "requester-a");
  assert.equal(result.status, "uncertain");
  assert.equal(result.work_note.entry.value, args.values.work_notes);
  assert.equal(result.current.record.assigned_to, f.users[0].sys_id);
  assert.equal(result.unresolved_hold, true);
  for (const operation_id of [args.operation_id, randomUUID()]) await assert.rejects(restarted.handle("update_incident",
    { ...args, expected_mod_count: "1", operation_id }, "requester-a"), /already|unresolved/);
  assert.equal(f.writes().length, 1);
});

test("partial handoffs distinguish assignment and note observations, and journal denial never causes a fallback write", async t => {
  for (const [mode, fields, note] of [
    ["suppressNote", "observed", "not_observed"],
    ["ignoreValues", "not_observed", "observed"],
    ["failJournalReadback", "observed", "unknown"],
    ["denyJournal", "not_sent", "not_sent"],
  ]) {
    const f = fixture(t);
    f.mode[mode] = true;
    const work_notes = "The original note is not new append evidence.";
    f.notes.push({ sys_id: id("e"), name: "incident", element: "work_notes", element_id: f.incident.sys_id,
      value: work_notes, sys_created_on: "2026-01-01 12:00:00" });
    const operation_id = randomUUID();
    await assert.rejects(f.admin.handle("update_incident", { number: f.incident.number, expected_mod_count: "0",
      values: { assigned_to: f.users[0].sys_id, work_notes }, operation_id }, "requester-a"), error => {
      assert.equal(error.outcome.record_fields.status, fields, mode);
      assert.equal(error.outcome.work_note.status, note, mode);
      assert.equal(error.outcome.status, mode === "denyJournal" ? "not_sent" : "uncertain", mode);
      if (mode === "failJournalReadback") assert.equal(error.outcome.work_note.diagnostic.status, 403);
      return true;
    });
    const result = await f.admin.handle("get_incident_operation", { operation_id }, "requester-a");
    assert.equal(result.unresolved_hold, mode !== "denyJournal");
    assert.equal(f.writes().length, mode === "denyJournal" ? 0 : 1);
    assert.equal(f.incident.description, "Preserve the investigation context.");
  }
});

test("work-note input and visibility bounds fail closed without scalar or description fallbacks", async t => {
  const f = fixture(t);
  for (const work_notes of ["", " \n ", null, 123, "x".repeat(4001)]) await assert.rejects(f.admin.handle("update_incident", {
    number: f.incident.number, expected_mod_count: "0", values: { work_notes }, operation_id: randomUUID(),
  }), /nonempty|length/);
  await assert.rejects(f.admin.handle("local_record_update", { table: "incident", sys_id: f.incident.sys_id,
    expected_mod_count: "0", values: { work_notes: "Cannot use scalar confirmation" }, operation_id: randomUUID() }), /append\/readback/);
  await assert.rejects(f.admin.handle("create_incident", {
    values: { short_description: "Not a supported journal creation path", work_notes: "No scalar confirmation" },
    operation_id: randomUUID(),
  }), /append\/readback/);
  assert.equal(f.writes().length, 0);
  const noteOnly = await f.admin.handle("update_incident", { number: f.incident.number, expected_mod_count: "0",
    values: { work_notes: "A standalone work note." }, operation_id: randomUUID() });
  assert.equal(noteOnly.status, "confirmed");
  assert.equal(noteOnly.work_note.entry.value, "A standalone work note.");
  assert.equal(noteOnly.record_fields.status, "not_requested");
  assert.equal(noteOnly.assignment_group_preserved, true);
  assert.equal(f.incident.assigned_to, "");

  let noteReads = 0;
  const crowded = fixture(t, { beforeRead: async table => {
    if (table !== "sys_journal_field" || ++noteReads !== 2) return;
    for (let i = 0; i < 21; i++) crowded.notes.push({ sys_id: (100 + i).toString(16).padStart(32, "0"),
      name: "incident", element: "work_notes", element_id: crowded.incident.sys_id,
      value: "Concurrent unrelated note", sys_created_on: "2026-01-03 12:00:00" });
  } });
  await assert.rejects(crowded.admin.handle("update_incident", { number: crowded.incident.number, expected_mod_count: "0",
    values: { work_notes: "Do not infer absence from a bounded window" }, operation_id: randomUUID() }), error => {
    assert.equal(error.outcome.status, "uncertain");
    assert.equal(error.outcome.work_note.status, "unknown");
    assert.equal(error.outcome.work_note.limit, 20);
    assert.equal(error.outcome.work_note.limitReached, true);
    assert.equal(error.outcome.work_note.entry, undefined);
    return true;
  });
  assert.equal(crowded.writes().length, 1);
});

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
  const signCaller = oid => new SignJWT({ tid: tenant, oid,
    azp: client, ver: "2.0", scp: "Incident.Manage" }).setProtectedHeader({ alg: "RS256" })
    .setIssuer(`https://login.microsoftonline.com/${tenant}/v2.0`).setAudience(audience)
    .setIssuedAt().setNotBefore("0s").setExpirationTime("5m").sign(privateKey);
  const token = await signCaller("22222222-2222-4222-8222-222222222222");
  const secondToken = await signCaller("55555555-5555-4555-8555-555555555555");
  const server = createCoworkApp({ profile, backend: f.admin,
    verifyAccessToken: await createEntraVerifier(profile, { key: publicKey }),
  }).listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => { server.closeAllConnections(); server.close(); });
  const call = async (name, args, accessToken = token, expectError = false) => {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/mcp`, {
      method: "POST", headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }),
    });
    assert.equal(response.status, 200);
    const rpc = await response.json();
    assert.equal(rpc.result.isError === true, expectError, rpc.result.content[0].text);
    return JSON.parse(rpc.result.content[0].text);
  };
  const incident = await call("get_incident", { number: f.incident.number });
  assert.equal(incident.sys_mod_count, "0");
  assert.ok(f.requests.at(-1).query.startsWith("sys_updated_on>javascript:gs.monthsAgo(6)^"));
  const candidate = await call("resolve_incident_assignee", { identity: "Avery" });
  assert.equal(candidate.resolution, "unique");
  const createId = randomUUID();
  const created = await call("create_incident", {
    values: { short_description: "Cowork synthetic incident" }, operation_id: createId,
  });
  assert.equal(created.status, "confirmed");
  assert.equal((await call("get_incident", { number: f.incident.number }, secondToken)).number, f.incident.number);
  const requestCount = f.requests.length;
  const unavailable = await call("get_incident_operation", { operation_id: createId }, secondToken, true);
  assert.deepEqual(Object.keys(unavailable), ["error"]);
  assert.match(unavailable.error, /not available to this requester/);
  assert.equal(f.requests.length, requestCount, "Another caller's receipt must not cause source observation");
  const replay = await call("update_incident", { number: incident.number, expected_mod_count: f.incident.sys_mod_count,
    values: { assigned_to: f.users[0].sys_id }, operation_id: createId }, secondToken, true);
  assert.match(replay.error, /already attempted/);
  assert.equal(f.requests.length, requestCount, "Changing callers must not bypass a consumed UUID");
  assert.equal((await call("get_incident_operation", { operation_id: createId })).status, "confirmed");
  for (const assigned_to of [candidate.candidates[0].sys_id, f.users[1].sys_id, null]) {
    const operation_id = randomUUID();
    const ownerToken = assigned_to === f.users[1].sys_id ? secondToken : token;
    const values = { assigned_to, ...(assigned_to === candidate.candidates[0].sys_id ?
      { work_notes: "Cowork handoff findings; confirm this append independently." } : {}) };
    const result = await call("update_incident", { number: incident.number, expected_mod_count: f.incident.sys_mod_count,
      values, operation_id }, ownerToken);
    assert.equal(result.status, "confirmed");
    assert.equal(result.assignment_group_preserved, true);
    const recovered = await call("get_incident_operation", { operation_id }, ownerToken);
    assert.equal(recovered.unresolved_hold, false);
    if (values.work_notes) {
      assert.equal(result.work_note.entry.value, values.work_notes);
      assert.deepEqual(recovered.work_note.entry, result.work_note.entry);
      const count = f.requests.length;
      await call("get_incident_operation", { operation_id }, secondToken, true);
      assert.equal(f.requests.length, count, "Another caller cannot read this work note through operation recovery");
    }
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

test("parallel Cowork schema and assignee calls serialize on their shared backend instead of failing ownership", { timeout: 10000 }, async t => {
  const { createCoworkApp } = require("../src/cowork-http.cjs");
  const { once } = require("node:events");
  const entered = Promise.withResolvers(), release = Promise.withResolvers();
  const resolverDispatched = Promise.withResolvers();
  let paused = false;
  const f = fixture(t, { beforeRead: async table => {
    if (table === "sys_db_object" && !paused) {
      paused = true;
      entered.resolve();
      await release.promise;
    }
  } });
  const caller = { tenant_id: "11111111-1111-4111-8111-111111111111",
    object_id: "22222222-2222-4222-8222-222222222222", client_id: "33333333-3333-4333-8333-333333333333", scopes: ["Incident.Manage"] };
  const server = createCoworkApp({
    profile: { format: 1, tenant_id: caller.tenant_id, client_id: caller.client_id,
      audience: "44444444-4444-4444-8444-444444444444", writes_enabled: false,
      instance: "https://service.example.invalid", public_url: "https://mcp.example.invalid/mcp" },
    backend: { handle: (name, ...args) => {
      const result = f.admin.handle(name, ...args);
      if (name === "resolve_incident_assignee") resolverDispatched.resolve();
      return result;
    } },
    verifyAccessToken: async () => caller,
  }).listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => { release.resolve(); server.closeAllConnections(); server.close(); });
  const call = async (name, args) => {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/mcp`, {
      method: "POST", headers: { Authorization: "Bearer synthetic", "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: name, method: "tools/call", params: { name, arguments: args } }),
    });
    assert.equal(response.status, 200);
    return response.json();
  };
  const schema = call("get_incident_schema", {});
  await entered.promise;
  const resolver = call("resolve_incident_assignee", { identity: "Avery", field: "first_name" });
  await resolverDispatched.promise;
  const read = await call("get_incident", { number: f.incident.number });
  assert.notEqual(read.result.isError, true);
  release.resolve();
  const results = await Promise.all([schema, resolver]);
  for (const result of results) assert.notEqual(result.result.isError, true, result.result.content[0].text);
  assert.equal(JSON.parse(results[1].result.content[0].text).resolution, "unique");
  assert.equal(f.writes().length, 0);
});
