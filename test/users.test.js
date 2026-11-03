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
  const mode = { lostResponse: false, missingResponseIdentity: false, deny: false, unexpectedActive: false, ruleVersion: "0",
    beforeRequest: null };
  const user = values => ({ sys_id: id("a"), sys_mod_count: "0", sys_class_name: "sys_user",
    user_name: "", first_name: "", last_name: "", name: "", title: "", email: "",
    active: "false", locked_out: "true", notification: "1", identity_type: "human",
    internal_integration_user: "false", web_service_access_only: "false", source: "", ldap_server: "", failed_attempts: "0",
    ...values });
  const operator = user({ sys_id: id("b"), user_name: "operator" });
  const fetchImpl = async (raw, options) => {
    const url = new URL(raw), [table, recordId] = url.pathname.split("/table/")[1].split("/");
    const query = url.searchParams.get("sysparm_query") || "";
    const values = options.body ? JSON.parse(options.body) : undefined;
    requests.push({ table, recordId, query, method: options.method, values });
    if (mode.beforeRequest) {
      const response = await mode.beforeRequest({ table, recordId, query, method: options.method, values });
      if (response) return response;
    }
    if (options.method !== "GET") {
      if (mode.deny) return Response.json({ error: { message: "Security constraints deny access" } }, { status: 403 });
      let changed;
      if (options.method === "POST") {
        changed = user({ sys_id: rows.length ? (rows.length + 10).toString(16).padStart(32, "0") : id("a"),
          ...Object.fromEntries(Object.entries(values).map(([key, value]) => [key, String(value)])) });
        rows.push(changed);
      }
      if (options.method === "PATCH") {
        changed = rows.find(row => row.sys_id === recordId);
        Object.assign(changed, Object.fromEntries(Object.entries(values).map(([key, value]) => [key, String(value)])),
          { sys_mod_count: String(Number(changed.sys_mod_count) + 1) });
        if (values.locked_out === false) changed.failed_attempts = "0";
      }
      changed.name = [changed.first_name, changed.last_name].filter(Boolean).join(" ");
      if (mode.unexpectedActive) rows[0].active = "true";
      if (mode.lostResponse) throw new Error("Synthetic lost response");
      if (mode.missingResponseIdentity) return Response.json({ result: {} });
      return Response.json({ result: changed });
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
    if (table === "sys_script") result = [{ sys_id: id("c"), sys_mod_count: mode.ruleVersion,
      collection: "sys_user", active: "true", name: "Synthetic account rule", when: "before", order: "100",
      action_insert: "true", action_update: "true", action_delete: "false", action_query: "false",
      filter_condition: "", condition: "", script: "Synthetic lifecycle fixture", template: "", sys_overrides: "",
      role_conditions: "", abort_action: "false", sys_scope: "global", sys_domain: "global" }];
    if (table === "sys_user") result = [...rows, operator].filter(row => query.split("^").every(part => {
      if (part.startsWith("ORDERBY")) return true;
      if (part.endsWith("ISEMPTY")) return row[part.slice(0, -"ISEMPTY".length)] === "";
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

async function approveAccount(f) {
  const evidence = await f.admin.handle("inspect_user_account_policy", {});
  fs.writeFileSync(path.join(f.directory, "account-contract.json"), JSON.stringify({
    format: 2, instance: "https://service.example.invalid", sourceEvidenceSha256: "d".repeat(64),
    protectedIds: [], protectedNames: ["admin", "guest", "system"],
    businessRuleVersions: evidence.businessRuleVersions, schema_sha256: evidence.schema_sha256,
    rules_sha256: evidence.rules_sha256, reviewedAccessPolicies: [],
  }));
}

async function waitBatch(admin, batch_id, caller = "caller-a") {
  for (let attempt = 0; attempt < 1000; attempt++) {
    const result = await admin.handle("get_user_bulk_create", { batch_id }, caller);
    if (!["accepted", "assessing", "queued", "running"].includes(result.phase)) return result;
    await new Promise(resolve => setTimeout(resolve, 5));
  }
  throw new Error("Synthetic creation batch did not settle.");
}

test("bulk creation keeps safe source rejection provenance in its existing durable target error", async t => {
  const f = fixture(t);
  let denied = false;
  f.mode.beforeRequest = ({ table, method }) => {
    assert.equal(denied, false, "No request may follow an ACL denial.");
    assert.equal(method, "GET");
    if (table !== "sys_user") return;
    denied = true;
    return Response.json({ error: {
      message: "User Not Authorized", detail: "Failed API level ACL Validation",
      private_body: "PRIVATE_BODY",
    } }, { status: 403, headers: { "x-debug": "PRIVATE_HEADER" } });
  };
  const batch_id = randomUUID();
  await f.admin.handle("assess_user_bulk_create", { batch_id,
    targets: [{ user_name: "private-person@example.invalid", profile: { first_name: "PRIVATE_PROFILE" } }],
  }, "caller-a");
  const result = await waitBatch(f.admin, batch_id);
  assert.equal(denied, true);
  assert.equal(result.phase, "blocked");
  assert.equal(result.targets[0].error, "ServiceNow API returned HTTP 403.");
  assert.deepEqual(result.targets[0].diagnostic, {
    status: 403, message: "User Not Authorized", detail: "Failed API level ACL Validation",
    request: { method: "GET", table: "sys_user" },
  });
  const saved = JSON.parse(fs.readFileSync(path.join(f.directory, "user-create-batches", batch_id + ".json"), "utf8"));
  assert.deepEqual(saved.items[0].diagnostic, result.targets[0].diagnostic);
  assert.doesNotMatch(JSON.stringify(saved.items[0].diagnostic), /private|sysparm_|user_name=|Authorization|synthetic-only/i);
  assert.equal(result.assessment_sha256, undefined);
  assert.equal(result.eligible, false);
  assert.equal(f.writes().length, 0);
  assert.equal(fs.existsSync(path.join(f.directory, "operations.jsonl")), false);
});

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

test("bulk creation assesses the whole supplied roster without writes and preserves exact existing identities", async t => {
  const f = fixture(t);
  await approve(f);
  await approveAccount(f);
  f.rows.push(f.user({ user_name: "legacy.avery", first_name: "Avery", last_name: "Example", name: "Avery Example",
    active: "true", locked_out: "false" }));
  const targets = [
    { user_name: "legacy.avery", existing: { sys_id: id("a"), expected_mod_count: "0" },
      profile: { first_name: "Avery", last_name: "Example", email: "avery@example.invalid" } },
    { user_name: "jordan@example.invalid", profile: { first_name: "Jordan", last_name: "Sample", email: "jordan@example.invalid" } },
  ];
  const batch_id = randomUUID();
  await f.admin.handle("assess_user_bulk_create", { batch_id, targets }, "caller-a");
  const result = await waitBatch(f.admin, batch_id);
  assert.equal(result.eligible, true);
  assert.deepEqual(result.targets.map(target => target.disposition), ["correct", "create"]);
  assert.equal(result.targets[0].before.sys_id, id("a"));
  assert.equal(result.targets[0].before.user_name, "legacy.avery");
  assert.equal(result.final_state, null);
  assert.deepEqual(result.creation_defaults, { active: false, locked_out: true });
  assert.equal(result.directory_verified, false);
  assert.equal(f.writes().length, 0);
  await f.admin.handle("start_user_bulk_create", { batch_id, expected_assessment_sha256: result.assessment_sha256,
    confirm: true, acknowledged_native_effects: result.native_effects }, "caller-a");
  const completed = await waitBatch(f.admin, batch_id);
  assert.equal(completed.phase, "completed", JSON.stringify(completed));
  assert.equal(completed.roster_readback_complete, true);
  assert.equal(f.rows[0].active, "true");
  assert.equal(f.rows[0].locked_out, "false");
  assert.equal(f.rows[1].active, "false");
  assert.equal(f.rows[1].locked_out, "true");
  assert.deepEqual(f.writes().map(row => row.method), ["PATCH", "POST"]);
});

test("native bulk creation preserves five existing IDs and reaches explicit active/unlocked state for thirty supplied profiles", async t => {
  const f = fixture(t);
  await approve(f);
  await approveAccount(f);
  const targets = Array.from({ length: 30 }, (_, index) => {
    const user_name = index < 5 ? `legacy.staff.${index}` : `staff.${index}@example.invalid`;
    const input = { user_name, profile: { first_name: "Synthetic", last_name: `Staff${index}`, email: `staff.${index}@example.invalid` } };
    if (index < 5) {
      const sys_id = (index + 200).toString(16).padStart(32, "0");
      f.rows.push(f.user({ sys_id, user_name, name: `Synthetic Staff${index}`, first_name: "Synthetic",
        last_name: `Staff${index}`, email: index === 0 ? input.profile.email : "",
        active: index === 0 ? "true" : "false", locked_out: index === 0 ? "false" : "true", notification: "2" }));
      input.existing = { sys_id, expected_mod_count: "0" };
    }
    return input;
  });
  const batch_id = randomUUID();
  await f.admin.handle("assess_user_bulk_create", { batch_id, targets, final_state: { active: true, locked_out: false } }, "caller-a");
  const assessment = await waitBatch(f.admin, batch_id);
  assert.equal(assessment.phase, "assessed", JSON.stringify(assessment));
  assert.equal(f.writes().length, 0);
  await assert.rejects(f.admin.handle("start_user_bulk_create", { batch_id, expected_assessment_sha256: assessment.assessment_sha256,
    confirm: true, acknowledged_native_effects: [] }, "caller-a"), /exact creation assessment/);
  await f.admin.handle("start_user_bulk_create", { batch_id, expected_assessment_sha256: assessment.assessment_sha256,
    confirm: true, acknowledged_native_effects: assessment.native_effects }, "caller-a");
  const result = await waitBatch(f.admin, batch_id);
  assert.equal(result.phase, "completed", JSON.stringify(result));
  assert.equal(result.counts.created, 25);
  assert.equal(result.counts.corrected, 4);
  assert.equal(result.counts.already_matching, 1);
  const journal = await f.admin.handle("local_operation_status", { operation_id: batch_id }, "caller-a");
  assert.equal(journal.entries.at(-1).status, "confirmed");
  assert.equal(journal.entries.at(-1).batch_phase, "completed");
  assert.deepEqual(journal.entries.at(-1).counts, result.counts);
  assert.equal(f.rows.length, 30);
  assert.equal(f.writes().filter(row => row.method === "POST").length, 25);
  assert.ok(f.rows.every(row => row.active === "true" && row.locked_out === "false"));
  for (const input of targets.slice(0, 5))
    assert.equal(f.rows.find(row => row.sys_id === input.existing.sys_id).user_name, input.user_name);
  assert.ok(f.writes().every(row => row.table === "sys_user" && !Object.hasOwn(row.values, "user_password")));
  const restarted = f.restart();
  assert.equal((await restarted.handle("get_user_bulk_create", { batch_id }, "caller-a")).phase, "completed");
  await assert.rejects(restarted.handle("get_user_bulk_create", { batch_id }, "caller-b"));
  await assert.rejects(restarted.handle("start_user_bulk_create", { batch_id, expected_assessment_sha256: assessment.assessment_sha256,
    confirm: true, acknowledged_native_effects: assessment.native_effects }, "caller-a"), /unstarted/);
});

test("bulk creation blocks case collisions, ambiguous name-only identities and source drift without writes", async t => {
  const f = fixture(t);
  await approve(f);
  await approveAccount(f);
  const input = { user_name: "avery@example.invalid", profile: { first_name: "Avery", last_name: "Example", email: "avery@example.invalid" } };
  await assert.rejects(f.admin.handle("assess_user_bulk_create", { batch_id: randomUUID(),
    targets: [input, { ...input, user_name: "AVERY@example.invalid" }] }), /case-colliding/);
  f.rows.push(f.user({ user_name: "legacy.avery", first_name: "Avery", last_name: "Example", name: "Avery Example" }));
  const collisionId = randomUUID();
  await f.admin.handle("assess_user_bulk_create", { batch_id: collisionId, targets: [input] }, "caller-a");
  const collision = await waitBatch(f.admin, collisionId);
  assert.equal(collision.phase, "blocked");
  assert.equal(collision.targets[0].candidates[0].sys_id, id("a"));
  const batch_id = randomUUID();
  await f.admin.handle("assess_user_bulk_create", { batch_id, targets: [{
    ...input, user_name: "legacy.avery", existing: { sys_id: id("a"), expected_mod_count: "0" },
  }] }, "caller-a");
  const plan = await waitBatch(f.admin, batch_id);
  assert.equal(plan.phase, "assessed");
  f.rows[0].sys_mod_count = "1";
  await f.admin.handle("start_user_bulk_create", { batch_id, expected_assessment_sha256: plan.assessment_sha256,
    confirm: true, acknowledged_native_effects: plan.native_effects }, "caller-a");
  const result = await waitBatch(f.admin, batch_id);
  assert.equal(result.phase, "blocked");
  assert.match(result.targets[0].error, /version changed/);
  assert.equal(f.writes().length, 0);
});

test("a lost bulk create response stops remaining targets and survives restart without attribution upgrade or new-job replay", async t => {
  const f = fixture(t);
  await approve(f);
  const targets = ["avery", "jordan"].map(user_name => ({ user_name, profile: { email: `${user_name}@example.invalid` } }));
  const batch_id = randomUUID();
  await f.admin.handle("assess_user_bulk_create", { batch_id, targets }, "caller-a");
  const plan = await waitBatch(f.admin, batch_id);
  const operationIds = plan.targets.map(target => target.operation_ids);
  f.mode.lostResponse = true;
  await f.admin.handle("start_user_bulk_create", { batch_id, expected_assessment_sha256: plan.assessment_sha256,
    confirm: true, acknowledged_native_effects: plan.native_effects }, "caller-a");
  const result = await waitBatch(f.admin, batch_id);
  assert.equal(result.phase, "uncertain");
  assert.equal(result.counts.uncertain, 1);
  assert.equal(result.counts.assessed, 1);
  assert.equal(result.targets[0].evidence.failure.outcome.retained_created_identity, null);
  assert.equal(result.targets[0].evidence.failure.outcome.observed_user_identity, id("a"));
  assert.equal(f.writes().length, 1);
  const journal = await f.admin.handle("local_operation_status", { operation_id: batch_id }, "caller-a");
  assert.equal(journal.entries.at(-1).status, "uncertain");
  f.mode.lostResponse = false;
  const restarted = f.restart();
  const recovered = await restarted.handle("get_user_bulk_create", { batch_id }, "caller-a");
  assert.equal(recovered.phase, "uncertain");
  assert.deepEqual(recovered.targets.map(target => target.operation_ids), operationIds);
  await assert.rejects(restarted.handle("start_user_bulk_create", { batch_id, expected_assessment_sha256: plan.assessment_sha256,
    confirm: true, acknowledged_native_effects: plan.native_effects }, "caller-a"), /unstarted/);
  const replacementId = randomUUID();
  await restarted.handle("assess_user_bulk_create", { batch_id: replacementId, targets: [targets[1]] }, "caller-a");
  const replacement = await waitBatch(restarted, replacementId);
  assert.equal(replacement.phase, "blocked");
  assert.match(replacement.targets[0].error, /unresolved/);
  assert.equal(f.writes().length, 1);
});

test("bulk status and cancellation remain responsive while a semantic create owns the shared source lock", async t => {
  const f = fixture(t);
  await approve(f);
  await approveAccount(f);
  const batch_id = randomUUID();
  await f.admin.handle("assess_user_bulk_create", { batch_id, final_state: { active: true, locked_out: false },
    targets: [{ user_name: "avery", profile: { email: "avery@example.invalid" } }] }, "caller-a");
  const plan = await waitBatch(f.admin, batch_id);
  let release, reached;
  const entered = new Promise(resolve => { reached = resolve; });
  const gate = new Promise(resolve => { release = resolve; });
  f.mode.beforeRequest = async request => { if (request.method === "POST") { reached(); await gate; } };
  await f.admin.handle("start_user_bulk_create", { batch_id, expected_assessment_sha256: plan.assessment_sha256,
    confirm: true, acknowledged_native_effects: plan.native_effects }, "caller-a");
  await entered;
  try {
    const running = await f.admin.handle("get_user_bulk_create", { batch_id }, "caller-a");
    assert.equal(running.phase, "running");
    const otherProcess = f.restart();
    await assert.rejects(otherProcess.handle("create_user", { user_name: "unrelated",
      profile: { email: "unrelated@example.invalid" }, operation_id: randomUUID() }), /owned by another operation/);
    const cancelled = await f.admin.handle("cancel_user_bulk_create", { batch_id }, "caller-a");
    assert.equal(cancelled.stop_requested, true);
  } finally { release(); }
  const stopped = await waitBatch(f.admin, batch_id);
  assert.equal(stopped.phase, "stopped");
  assert.equal(stopped.targets[0].evidence.stages[0].status, "confirmed");
  assert.equal(f.rows[0].active, "false");
  assert.equal(f.rows[0].locked_out, "true");
  assert.equal(f.writes().length, 1);
  const journal = await f.admin.handle("local_operation_status", { operation_id: batch_id }, "caller-a");
  assert.equal(journal.entries.at(-1).status, "confirmed");
  assert.equal(journal.entries.at(-1).batch_phase, "stopped");
  assert.equal(journal.entries.at(-1).counts.stopped, 1);
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
