const assert = require("node:assert/strict");
const { test } = require("node:test");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { randomUUID } = require("node:crypto");
const { setImmediate } = require("node:timers/promises");
const { createAdmin } = require("../src/admin/index.cjs");
const { effects } = require("../src/admin/administrative-impact.cjs");

function fixture(t, count = 3) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "servicenow-user-batch-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const users = new Map(Array.from({ length: count }, (_, index) => {
    const sys_id = (index + 1).toString(16).padStart(32, "0");
    return [sys_id, { sys_id, user_name: index === 1 ? "admin" : `sample.${index}`,
      first_name: "Sample", last_name: String(index), title: "", active: "true", locked_out: "false",
      notification: "2", sys_class_name: "sys_user", identity_type: "human",
      internal_integration_user: "false", web_service_access_only: "false", sys_mod_count: "4" }];
  }));
  const writes = [];
  let inFlight = 0, maximumInFlight = 0;
  const controls = { beforeRead: null, beforeDelete: null, loseResponse: false, userCascade: null,
    dictionary: [], related: new Map() };
  const config = { instance: "https://service.example.invalid", username: "operator", password: "synthetic-only",
    directory, fetchImpl: async (raw, options) => {
      const url = new URL(raw);
      const table = url.pathname.split("/")[4];
      const query = url.searchParams.get("sysparm_query") || "";
      if (options.method === "DELETE") {
        const sys_id = url.pathname.split("/")[5];
        writes.push(sys_id);
        maximumInFlight = Math.max(maximumInFlight, ++inFlight);
        try {
          if (controls.beforeDelete) await controls.beforeDelete(sys_id);
          users.delete(sys_id);
          const removed = [{ table: "sys_user", sys_id }];
          while (removed.length) {
            const parent = removed.pop();
            for (const definition of controls.dictionary.filter(row => row.reference === parent.table)) {
              const records = controls.related.get(definition.name) || [];
              const children = records.filter(row => row[definition.element] === parent.sys_id);
              controls.related.set(definition.name, records.filter(row => !children.includes(row)));
              removed.push(...children.map(row => ({ table: definition.name, sys_id: row.sys_id })));
            }
          }
          if (controls.loseResponse) throw new Error("Synthetic lost deletion response");
          return new Response(null, { status: 204 });
        } finally { inFlight--; }
      }
      if (controls.beforeRead) {
        const response = await controls.beforeRead(table, query);
        if (response) return response;
      }
      let rows = [];
      if (table === "sys_user" && query === "user_name=operator")
        rows = [{ sys_id: "f".repeat(32), user_name: "operator" }];
      else if (table === "sys_user" && /^sys_id=[a-f0-9]{32}$/.test(query))
        rows = users.has(query.slice(7)) ? [users.get(query.slice(7))] : [];
      else if (table === "sys_user" && query.endsWith("^sourceISEMPTY^ldap_serverISEMPTY"))
        rows = users.has(query.slice(7, 39)) ? [{ sys_id: query.slice(7, 39) }] : [];
      else if (controls.userCascade && table === "sys_user" && query.startsWith(`manager=${controls.userCascade.parent}^`)) {
        const cursor = query.match(/\^sys_id>([a-f0-9]+)/)?.[1] || "";
        if (controls.userCascade.child > cursor)
          rows = [{ ...users.get(controls.userCascade.child), manager: controls.userCascade.parent }];
      } else if (controls.userCascade && table === "sys_dictionary" && query === "name=sys_user^element=manager")
        rows = [{ sys_id: "e".repeat(32), sys_mod_count: "0", reference_cascade_rule: "cascade" }];
      else if (table === "sys_dictionary" && query.startsWith("reference=")) {
        const reference = query.match(/^reference=([a-zA-Z0-9_]+)/)[1];
        const cursor = query.match(/\^sys_id>([a-f0-9]+)/)?.[1] || "";
        rows = controls.dictionary.filter(row => row.reference === reference && row.sys_id > cursor)
          .sort((a, b) => a.sys_id.localeCompare(b.sys_id)).slice(0, 100);
      } else if (controls.related.has(table)) {
        const [field, value] = query.split("^")[0].split("=");
        const cursor = query.match(/\^sys_id>([a-f0-9]+)/)?.[1] || "";
        rows = controls.related.get(table).filter(row => row[field] === value && row.sys_id > cursor).slice(0, 100);
      }
      return Response.json({ result: rows });
    } };
  return { config, directory, users, writes, controls, maxWrites: () => maximumInFlight, admin: createAdmin(config) };
}
async function settled(admin, batch_id, phases, caller = "local:operator") {
  for (let attempt = 0; attempt < 1000; attempt++) {
    const result = await admin.handle("local_admin_user_delete_batch_status", { batch_id, offset: 0, limit: 100 }, caller);
    if (phases.includes(result.phase)) return result;
    await setImmediate();
  }
  assert.fail("Batch did not reach the expected terminal phase.");
}
async function assess(f) {
  const batch_id = randomUUID();
  const started = await f.admin.handle("local_admin_user_delete_batch_assess", {
    batch_id, targets: [...f.users.values()].map(({ sys_id, user_name }) => ({ sys_id, expected_user_name: user_name })),
    preserve_user_ids: [],
  });
  assert.equal(started.batch_id, batch_id);
  return settled(f.admin, batch_id, ["ready", "assessment_failed"]);
}
function executeArgs(plan) {
  return { batch_id: plan.batch_id, operation_id: randomUUID(), expected_plan_sha256: plan.plan_sha256,
    confirm: true, acknowledged_native_effects: effects };
}

test("native bulk deletion reviews a complete supplied set and preserves per-user guards and receipts", async t => {
  const f = fixture(t);
  const plan = await assess(f);
  assert.equal(plan.phase, "ready");
  assert.deepEqual(plan.counts, { eligible: 2, blocked: 1 });
  assert.equal(plan.total, 3);
  const args = executeArgs(plan);
  await f.admin.handle("local_admin_user_delete_batch", args);
  const result = await settled(f.admin, plan.batch_id, ["completed", "stopped"]);
  assert.equal(result.phase, "completed");
  assert.deepEqual(result.counts, { confirmed: 2, blocked: 1 });
  assert.equal(result.cleanup_complete, false);
  assert.equal(f.writes.length, 2);
  assert.equal(f.maxWrites(), 1);
  assert.equal([...f.users.values()][0].user_name, "admin");
  assert.ok(result.items.filter(row => row.status === "confirmed").every(row => row.parent_absent === true && row.operation_id));
  const evidence = await f.admin.handle("local_admin_user_delete_batch_status", {
    batch_id: plan.batch_id, offset: 0, limit: 1, include_evidence: true,
  });
  assert.equal(evidence.items[0].evidence.outcome.status, "confirmed");
  assert.equal(evidence.items[0].evidence.outcome.impact_before.target.sys_mod_count, "4");
  const journal = await f.admin.handle("local_operation_status", { operation_id: args.operation_id });
  assert.equal(journal.entries.at(-1).status, "confirmed",
    "A completed batch must not leave the existing restart guard with an unresolved parent attempt");
  assert.equal(journal.entries.at(-1).batch_phase, "completed");
  assert.deepEqual(journal.entries.at(-1).counts, { confirmed: 2, blocked: 1 });
  await assert.rejects(f.admin.handle("local_admin_user_delete_batch", args), /already|executed/);
  assert.equal(f.writes.length, 2);
});

test("lost native response stops the whole batch and retains uncertainty without replay", async t => {
  const f = fixture(t);
  const plan = await assess(f);
  f.controls.loseResponse = true;
  const args = executeArgs(plan);
  await f.admin.handle("local_admin_user_delete_batch", args);
  const result = await settled(f.admin, plan.batch_id, ["stopped"]);
  assert.deepEqual(result.counts, { uncertain: 1, blocked: 1, eligible: 1 });
  assert.equal(result.error.outcome.parent_absent, true);
  assert.equal(result.error.outcome.status, "uncertain");
  assert.equal(f.writes.length, 1);
  const journal = await f.admin.handle("local_operation_status", { operation_id: args.operation_id });
  assert.equal(journal.entries.at(-1).status, "stopped");
  await assert.rejects(f.admin.handle("local_admin_user_delete_batch", { ...args, operation_id: randomUUID() }), /already/);
  const fresh = createAdmin(f.config);
  assert.equal((await fresh.handle("local_admin_user_delete_batch_status", {
    batch_id: plan.batch_id, offset: 0, limit: 3,
  })).phase, "stopped");
  assert.equal(f.writes.length, 1);
});

test("status and cancellation remain responsive while the source lock is held", async t => {
  const f = fixture(t);
  const plan = await assess(f);
  let release, entered;
  const gate = new Promise(resolve => { release = resolve; });
  const started = new Promise(resolve => { entered = resolve; });
  f.controls.beforeDelete = async () => { entered(); await gate; };
  const args = executeArgs(plan);
  await f.admin.handle("local_admin_user_delete_batch", args);
  await started;
  try {
    const status = await f.admin.handle("local_admin_user_delete_batch_status", {
      batch_id: plan.batch_id, offset: 0, limit: 3,
    });
    assert.equal(status.phase, "deleting");
    assert.equal(status.counts.attempting, 1);
    const otherProcess = createAdmin(f.config);
    const observed = await otherProcess.handle("local_admin_user_delete_batch_status", {
      batch_id: plan.batch_id, offset: 0, limit: 3,
    });
    assert.equal(observed.execution_observation, "another_process_or_interrupted_do_not_replay");
    await assert.rejects(otherProcess.handle("local_admin_user_get", { sys_id: plan.items[2].sys_id }), /owned by another/);
    const cancel = await otherProcess.handle("local_admin_user_delete_batch_cancel", { batch_id: plan.batch_id });
    assert.equal(cancel.stop_requested, true);
    assert.equal(f.writes.length, 1);
  } finally { release(); }
  const result = await settled(f.admin, plan.batch_id, ["cancelled"]);
  assert.deepEqual(result.counts, { confirmed: 1, blocked: 1, eligible: 1 });
  assert.equal(f.writes.length, 1);
  const journal = await f.admin.handle("local_operation_status", { operation_id: args.operation_id });
  assert.equal(journal.entries.at(-1).status, "confirmed");
  assert.equal(journal.entries.at(-1).batch_phase, "cancelled");
  assert.deepEqual(journal.entries.at(-1).counts, result.counts);
});

test("bulk plans bind exact logins, preservation IDs and source versions without weakening integration protections", async t => {
  const f = fixture(t, 6);
  const ids = [...f.users.keys()];
  f.users.get(ids[2]).internal_integration_user = "true";
  const batch_id = randomUUID();
  await f.admin.handle("local_admin_user_delete_batch_assess", {
    batch_id, targets: [...f.users.values()].map(({ sys_id, user_name }) => ({
      sys_id, expected_user_name: sys_id === ids[3] ? "wrong.login" : user_name,
    })), preserve_user_ids: [ids[4]],
  });
  const plan = await settled(f.admin, batch_id, ["ready"]);
  assert.deepEqual(plan.counts, { eligible: 2, blocked: 4 });
  assert.ok(plan.items[2].assessment.blocked.includes("integration_or_nonhuman_identity"));
  assert.ok(plan.items[3].assessment.blocked.includes("supplied_login_mismatch"));
  assert.ok(plan.items[4].assessment.blocked.includes("batch_preserved_identity"));
  f.users.get(ids[0]).sys_mod_count = "5";
  await assert.rejects(f.admin.handle("local_admin_user_delete_batch", {
    ...executeArgs(plan), expected_plan_sha256: "0".repeat(64),
  }), /plan\/hash/);
  await f.admin.handle("local_admin_user_delete_batch", executeArgs(plan));
  const result = await settled(f.admin, batch_id, ["completed", "stopped"]);
  assert.deepEqual(result.counts, { drifted: 1, blocked: 4, confirmed: 1 });
  assert.deepEqual(f.writes, [ids[5]]);
});

test("bulk refuses user cascades even when the child is in the supplied set", async t => {
  const f = fixture(t);
  const ids = [...f.users.keys()];
  f.controls.userCascade = { parent: ids[0], child: ids[2] };
  f.users.get(ids[2]).internal_integration_user = "true";
  const plan = await assess(f);
  assert.ok(plan.items[0].assessment.blocked.includes("native_user_cascade_requires_individual_review"));
  await f.admin.handle("local_admin_user_delete_batch", executeArgs(plan));
  const result = await settled(f.admin, plan.batch_id, ["completed", "stopped"]);
  assert.deepEqual(result.counts, { blocked: 3 });
  assert.equal(f.writes.length, 0);
});

test("native dependency assessment discovers expense/entitlement cascades and follows their children", async t => {
  const f = fixture(t);
  const [user] = f.users.keys();
  const expense = "a".repeat(32), entitlement = "b".repeat(32), detail = "c".repeat(32);
  f.controls.dictionary = [
    { sys_id: "1".repeat(32), sys_mod_count: "0", name: "fm_expense_line", element: "user", reference: "sys_user",
      reference_cascade_rule: "delete", internal_type: "reference" },
    { sys_id: "2".repeat(32), sys_mod_count: "0", name: "alm_entitlement", element: "assigned_to", reference: "sys_user",
      reference_cascade_rule: "delete", internal_type: "reference" },
    { sys_id: "3".repeat(32), sys_mod_count: "0", name: "expense_detail", element: "expense", reference: "fm_expense_line",
      reference_cascade_rule: "delete", internal_type: "reference" },
  ];
  f.controls.related.set("fm_expense_line", [{ sys_id: expense, sys_mod_count: "2", user }]);
  f.controls.related.set("alm_entitlement", [{ sys_id: entitlement, sys_mod_count: "", assigned_to: user }]);
  f.controls.related.set("expense_detail", [{ sys_id: detail, sys_mod_count: "1", expense,
    password: "PRIVATE_VALUE_MUST_NOT_RETURN" }]);
  const plan = await assess(f);
  const before = await f.admin.handle("local_admin_user_delete_batch_status", {
    batch_id: plan.batch_id, offset: 0, limit: 1, include_evidence: true,
  });
  const relationships = before.items[0].evidence.impact.relationships;
  for (const table of ["fm_expense_line", "alm_entitlement", "expense_detail"])
    assert.equal(relationships.find(row => row.table === table)?.records.length, 1, table);
  assert.doesNotMatch(JSON.stringify(before), /PRIVATE_VALUE|password/);
  await f.admin.handle("local_admin_user_delete_batch", executeArgs(plan));
  await settled(f.admin, plan.batch_id, ["completed", "stopped"]);
  const after = await f.admin.handle("local_admin_user_delete_batch_status", {
    batch_id: plan.batch_id, offset: 0, limit: 1, include_evidence: true,
  });
  assert.deepEqual(after.items[0].evidence.outcome.native_observations.map(row => row.outcome), ["deleted", "deleted", "deleted"]);
  assert.equal(after.cleanup_complete, false);
  assert.equal(f.writes.length, 2);
});

test("bulk counts and pagination cover more than100 supplied users", async t => {
  const f = fixture(t, 101);
  const plan = await assess(f);
  assert.equal(plan.total, 101);
  assert.equal(plan.items.length, 100);
  assert.equal(plan.next_offset, 100);
  assert.deepEqual(plan.counts, { eligible: 100, blocked: 1 });
  const tail = await f.admin.handle("local_admin_user_delete_batch_status", {
    batch_id: plan.batch_id, offset: 100, limit: 100,
  });
  assert.equal(tail.items.length, 1);
  assert.equal(tail.next_offset, null);
  await f.admin.handle("local_admin_user_delete_batch", executeArgs(plan));
  const result = await settled(f.admin, plan.batch_id, ["completed", "stopped"]);
  assert.deepEqual(result.counts, { confirmed: 100, blocked: 1 });
  assert.equal(f.writes.length, 100);
});

test("batch validation and caller ownership reject unsafe requests without writes", async t => {
  const f = fixture(t);
  const target = { sys_id: [...f.users.keys()][0], expected_user_name: "sample.0" };
  await assert.rejects(f.admin.handle("local_admin_user_delete_batch_assess", {
    batch_id: randomUUID(), targets: [target, target], preserve_user_ids: [],
  }), /distinct/);
  await assert.rejects(f.admin.handle("local_admin_user_delete_batch_assess", {
    batch_id: randomUUID(), targets: Array(1001).fill(target), preserve_user_ids: [],
  }), /item count/);
  const plan = await assess(f);
  for (const [name, args] of [
    ["local_admin_user_delete_batch_status", { batch_id: plan.batch_id, offset: 0, limit: 1 }],
    ["local_admin_user_delete_batch_cancel", { batch_id: plan.batch_id }],
    ["local_admin_user_delete_batch", executeArgs(plan)],
  ]) await assert.rejects(f.admin.handle(name, args, "another-caller"), /not available/);
  await assert.rejects(f.admin.handle("local_admin_user_delete_batch_status", {
    batch_id: plan.batch_id, offset: 0, limit: 11, include_evidence: true,
  }), /limited to10/);
  await assert.rejects(f.admin.handle("local_admin_user_delete_batch", {
    ...executeArgs(plan), acknowledged_native_effects: effects.slice(1),
  }), /item count/);
  assert.equal(f.writes.length, 0);
});

test("unreadable cascade metadata fails assessment and never permits a partial plan", async t => {
  const f = fixture(t);
  f.controls.beforeRead = async (table, query) => {
    if (table === "sys_dictionary" && query.startsWith("reference=")) throw new Error("Synthetic metadata transport failure");
  };
  const plan = await assess(f);
  assert.equal(plan.phase, "assessment_failed");
  assert.equal(plan.plan_sha256, undefined);
  assert.match(plan.error.message, /transport failed/);
  await assert.rejects(f.admin.handle("local_admin_user_delete_batch", {
    ...executeArgs(plan), expected_plan_sha256: "0".repeat(64),
  }), /plan\/hash/);
  assert.equal(f.writes.length, 0);
});

test("native bulk assessment preserves the denied read provenance without retrying or disclosing request data", async t => {
  for (const [table, stage, prefix] of [
    ["sys_user", "operator_identity", "user_name="],
    ["sys_user", "target_identity", "sys_id="],
    ["sys_user_has_role", "role_grants", "user="],
    ["task", "known_relationship", "assigned_to="],
    ["sys_dictionary", "cascade_metadata", "reference="],
    ["fm_expense_line", "cascade_relationship", "user="],
  ]) await t.test(stage, async t => {
    const f = fixture(t);
    f.controls.dictionary = [{ sys_id: "1".repeat(32), sys_mod_count: "0",
      name: "fm_expense_line", element: "user", reference: "sys_user",
      reference_cascade_rule: "delete", internal_type: "reference" }];
    let denied = false;
    f.controls.beforeRead = async (requestedTable, query) => {
      assert.equal(denied, false, "No request may follow an ACL denial.");
      if (requestedTable !== table || !query.startsWith(prefix)) return;
      denied = true;
      return Response.json({ error: {
        message: "User Not Authorized", detail: "Failed API level ACL Validation",
        private_body: "PRIVATE_RESPONSE_BODY",
      } }, { status: 403, headers: { "set-cookie": "PRIVATE_COOKIE", "x-debug": "PRIVATE_HEADER" } });
    };
    const plan = await assess(f);
    assert.equal(denied, true);
    assert.equal(plan.phase, "assessment_failed");
    assert.deepEqual(plan.error, {
      message: "ServiceNow API returned HTTP 403.",
      diagnostic: { status: 403, message: "User Not Authorized", detail: "Failed API level ACL Validation",
        request: { method: "GET", table }, assessment_stage: stage },
    });
    const saved = JSON.parse(fs.readFileSync(path.join(f.directory, "user-delete-batches", plan.batch_id + ".json"), "utf8"));
    assert.deepEqual(saved.error, plan.error);
    const { assessment_stage, ...sourceDiagnostic } = saved.error.diagnostic;
    assert.doesNotMatch(JSON.stringify(sourceDiagnostic), /PRIVATE_|Authorization|sysparm_|user=|synthetic-only|cookie/i);
    assert.equal(assessment_stage, stage);
    assert.deepEqual(plan.counts, { unassessed: 3 });
    assert.equal(plan.plan_sha256, undefined);
    assert.equal(f.writes.length, 0);
    assert.equal(fs.existsSync(path.join(f.directory, "operations.jsonl")), false);
  });
});

test("cancelling a ready assessment reports a terminal stop without starting deletion", async t => {
  const f = fixture(t);
  const plan = await assess(f);
  await f.admin.handle("local_admin_user_delete_batch_cancel", { batch_id: plan.batch_id });
  const status = await f.admin.handle("local_admin_user_delete_batch_status", {
    batch_id: plan.batch_id, offset: 0, limit: 3,
  });
  assert.equal(status.phase, "cancelled");
  assert.equal(status.stop_requested, true);
  await assert.rejects(f.admin.handle("local_admin_user_delete_batch", executeArgs(plan)), /cancelled/);
  assert.equal(f.writes.length, 0);
});
