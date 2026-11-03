const assert = require("node:assert/strict");
const { test } = require("node:test");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { randomUUID } = require("node:crypto");
const { createAdmin } = require("../src/admin/index.cjs");
const id = number => number.toString(16).padStart(32, "0");

function fixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "servicenow-user-access-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const user = (number, login, active = "false") => ({
    sys_id: id(number), sys_mod_count: "0", user_name: login, name: login, first_name: "", last_name: "", title: "", email: "",
    active, locked_out: "true", notification: "1", identity_type: "human", sys_class_name: "sys_user",
    internal_integration_user: "false", web_service_access_only: "false", source: "", ldap_server: "", failed_attempts: "0",
  });
  const role = (number, name) => ({ sys_id: id(number), sys_mod_count: "0", name, sys_scope: "global",
    elevated_privilege: "false", scoped_admin: "false", can_delegate: "false", assignable_by: "", includes_roles: "", grantable: "true" });
  const group = { sys_id: id(20), sys_mod_count: "0", name: "Support team", active: "true",
    parent: "", source: "", manager: "", default_assignee: "", roles: "", include_members: "false", exclude_manager: "false" };
  const tables = {
    sys_user: [user(1, "operator", "true")], sys_user_group: [group],
    sys_user_role: [role(30, "case_editor"), role(31, "case_reader")],
    sys_user_role_contains: [{ sys_id: id(40), sys_mod_count: "0", role: id(30), contains: id(31) }],
    sys_group_has_role: [], sys_user_grmember: [], sys_user_has_role: [], provider_user_map: [],
    sys_security_acl_role: [{ sys_id: id(50), sys_mod_count: "0", sys_user_role: id(31), sys_security_acl: id(51) }],
    sys_security_acl: [{ sys_id: id(51), sys_mod_count: "0", name: "incident.read", operation: "read", type: "record",
      active: "true", admin_overrides: "true", decision_type: "allow", applies_to: "", security_attribute: "",
      advanced: "true", condition: "PRIVATE_CONDITION", script: "PRIVATE_ACL_SCRIPT", sys_class_name: "sys_security_acl" }],
    incident: [{ sys_id: id(60), sys_mod_count: "0", number: "INC0000001", short_description: "Synthetic case",
      assigned_to: "", assignment_group: group.sys_id }],
  };
  const mode = { denyTable: null, loseTable: null, omitExpansion: false, unexpectedRole: false, activateSideEffect: false,
    hiddenAcl: null, contradictoryJoin: false, omitJoinField: false, corruptJoinVersion: false };
  const requests = [];
  let sequence = 100;
  function matches(row, query) {
    return query.split("^").every(part => {
      if (part.startsWith("ORDERBY")) return true;
      if (part === "sys_updated_on>javascript:gs.monthsAgo(6)") return true;
      if (part === "sys_security_acl.sys_idISEMPTY" || part === "sys_security_acl.sys_idISNOTEMPTY") {
        const resolved = tables.sys_security_acl.some(acl => acl.sys_id === row.sys_security_acl);
        return mode.contradictoryJoin || (part.endsWith("ISNOTEMPTY") ? resolved : !resolved);
      }
      if (part.includes("ISNOTEMPTY")) return Boolean(row[part.replace("ISNOTEMPTY", "")]);
      if (part.endsWith("ISEMPTY")) return row[part.replace("ISEMPTY", "")] === "";
      const match = /^([\w.]+)(IN|=|>)(.*)$/.exec(part);
      if (!match) throw new Error(`Unhandled synthetic filter ${part}`);
      const [, field, operator, value] = match;
      if (operator === "IN") return value.split(",").includes(String(row[field]));
      if (operator === ">") return String(row[field]) > value;
      return String(row[field]).toLowerCase() === value.toLowerCase();
    });
  }
  function schema(table) {
    const exemplar = ({
      sys_user_grmember: { user: "", group: "" }, sys_user_has_role: { user: "", role: "", inherited: "", granted_by: "", state: "" },
      sys_group_has_role: { group: "", role: "", inherits: "", granted_by: "" },
    })[table] || tables[table]?.[0] || {};
    return Object.keys(exemplar).filter(field => !field.startsWith("sys_")).map((field, index) => ({
      sys_id: id(1000 + Object.keys(tables).indexOf(table) * 100 + index), name: table, element: field,
      internal_type: ["active", "locked_out", "internal_integration_user", "web_service_access_only"].includes(field) ? "boolean" :
        ["assigned_to", "assignment_group"].includes(field) ? "reference" : "string",
      reference: field === "assigned_to" ? "sys_user" : field === "assignment_group" ? "sys_user_group" : "",
      read_only: ["inherited"].includes(field) ? "true" : "false", mandatory: field === "user_name" ? "true" : "false",
      default_value: "", max_length: "255", unique: field === "user_name" ? "true" : "false", choice: "0",
    }));
  }
  const fetchImpl = async (raw, options) => {
    const url = new URL(raw), [table, recordId] = url.pathname.split("/table/")[1].split("/");
    const query = url.searchParams.get("sysparm_query") || "";
    const values = options.body ? JSON.parse(options.body) : undefined;
    requests.push({ table, method: options.method, query, recordId, values });
    if (mode.denyNative && table === "sys_security_acl_role" && query.includes("^sys_security_acl.sys_id"))
      return Response.json({ error: { message: "Native reference visibility denied" } }, { status: 403 });
    if (options.method !== "GET") {
      if (mode.denyTable === table) return Response.json({ error: { message: "Security constraints deny the requested change" } }, { status: 403 });
      let row;
      if (options.method === "POST") {
        row = table === "sys_user" ? user(sequence++, values.user_name) :
          { sys_id: id(sequence++), sys_mod_count: "0", ...(table === "sys_user_has_role" ?
            { inherited: "false", granted_by: "not-applicable", state: "active" } : {}) };
        Object.assign(row, Object.fromEntries(Object.entries(values).map(([key, value]) => [key, String(value)])));
        if (table === "sys_user") row.name = [row.first_name, row.last_name].filter(Boolean).join(" ");
        tables[table].push(row);
        if (table === "sys_user_has_role" && !mode.omitExpansion) {
          for (const edge of tables.sys_user_role_contains.filter(edge => edge.role === row.role))
            tables.sys_user_has_role.push({ sys_id: id(sequence++), sys_mod_count: "", user: row.user, role: edge.contains,
              state: "active", inherited: "true", granted_by: row.role });
        }
        if (mode.unexpectedRole) tables.sys_user_has_role.push({
          sys_id: id(sequence++), sys_mod_count: "0", user: row.user, role: id(999), state: "active",
          inherited: "true", granted_by: "",
        });
      } else {
        row = tables[table].find(item => item.sys_id === recordId);
        Object.assign(row, Object.fromEntries(Object.entries(values).map(([key, value]) => [key, String(value)])));
        row.sys_mod_count = String(Number(row.sys_mod_count) + 1);
        if (mode.activateSideEffect && table === "sys_user") row.locked_out = "false";
      }
      if (mode.loseTable === table) throw new Error("Synthetic response lost");
      if (mode.afterWrite) mode.afterWrite(table);
      return Response.json({ result: row });
    }
    let rows;
    if (table === "sys_db_object") rows = [{ name: query.slice(5), "super_class.name": "" }];
    else if (table === "sys_dictionary") {
      const tableName = /^name(?:IN|=)([a-z_]+)/.exec(query)?.[1];
      rows = schema(tableName).map(row => ({ ...row, sys_mod_count: "0" })).filter(row => matches(row, query));
    } else if (table === "sys_script") {
      const name = /^collection=([a-z_]+)/.exec(query)?.[1];
      rows = [{ sys_id: id(3000 + Object.keys(tables).indexOf(name)), sys_mod_count: "0", collection: name, active: "true",
        name: "Synthetic policy", when: "after", order: "100", action_insert: "true", action_update: "true",
        action_delete: "false", action_query: "false", filter_condition: "", condition: "", script: "PRIVATE_RULE_BODY",
        template: "", sys_overrides: "", role_conditions: "", abort_action: "false", sys_scope: "global", sys_domain: "global" }]
        .filter(row => matches(row, query));
    } else {
      rows = (tables[table] || []).filter(row => matches(row, query));
      if (table === "sys_security_acl" && mode.hiddenAcl) rows = rows.filter(row => row.sys_id !== mode.hiddenAcl);
      if (table === "sys_security_acl_role" && url.searchParams.get("sysparm_fields").includes("sys_security_acl.name"))
        rows = rows.map(row => {
          const acl = tables.sys_security_acl.find(acl => acl.sys_id === row.sys_security_acl);
          return { ...row, ...(mode.corruptJoinVersion ? { sys_mod_count: "999" } : {}),
            "sys_security_acl.sys_id": row.sys_security_acl,
            "sys_security_acl.name": acl?.name || "",
            ...(!mode.omitJoinField ? { "sys_security_acl.sys_class_name": acl?.sys_class_name || "" } : {}),
          };
        });
    }
    const fields = (url.searchParams.get("sysparm_fields") || "").split(",");
    return Response.json({ result: rows.slice(0, Number(url.searchParams.get("sysparm_limit") || 100)).map(row =>
      Object.fromEntries(fields.filter(field => Object.hasOwn(row, field)).map(field => [field, row[field]]))) });
  };
  const config = { instance: "https://service.example.invalid", username: "operator", password: "synthetic-only", directory, fetchImpl };
  return { admin: createAdmin(config), restart: () => createAdmin(config), directory, tables, user, mode, requests,
    writes: () => requests.filter(row => row.method !== "GET") };
}

async function reviewedPolicy(f, { activate = false } = {}) {
  const review = await f.admin.handle("inspect_user_access_policy", { group_id: id(20), role_id: id(30), activate });
  fs.writeFileSync(path.join(f.directory, "user-access-contract.json"), JSON.stringify({
    format: 1, instance: "https://service.example.invalid", sourceEvidenceSha256: "a".repeat(64),
    protectedIds: [], protectedNames: ["admin", "guest", "system"],
    policies: [{ key: "support-assignee", group_id: id(20), role_id: id(30), activate, enabled: true,
      allow_role_delegation: false,
      allow_unresolved_acl_references: false,
      evidence_sha256: review.evidence_sha256, native_effects: review.native_effects,
      direct_origin_values: ["", "not-applicable"] }],
  }));
  return review;
}

test("reviewed generic access policy applies to unseen users, reuses access and preserves the source account lock", async t => {
  const f = fixture(t);
  const review = await reviewedPolicy(f);
  assert.equal(review.roles.length, 2);
  assert.equal(review.acls.length, 1);
  assert.doesNotMatch(JSON.stringify(review), /PRIVATE_ACL_SCRIPT|PRIVATE_RULE_BODY|PRIVATE_CONDITION/);
  assert.equal((await f.admin.handle("inspect_user_access_policy", { policy: "support-assignee" })).policy_available, true);
  for (const [number, name] of [[2, "future-person-one"], [3, "future-person-two"]]) {
    f.tables.sys_user.push(f.user(number, name));
    const assessment = await f.admin.handle("assess_user_access", { sys_id: id(number), policy: "support-assignee" }, "caller-a");
    const operation_id = randomUUID();
    const result = await f.admin.handle("apply_user_access", { sys_id: id(number), assessment_id: assessment.assessment_id,
      operation_id, acknowledged_native_effects: assessment.native_effects }, "caller-a");
    assert.equal(result.status, "confirmed");
    assert.equal(result.after.user.locked_out, "true");
    assert.equal(result.after.user.active, "false");
    assert.equal(result.after.roles.length, 2);
    assert.equal(result.after.memberships.length, 1);
    assert.equal((await f.admin.handle("get_user_access_operation", { operation_id }, "caller-a")).status, "confirmed");
    const again = await f.admin.handle("assess_user_access", { sys_id: id(number), policy: "support-assignee" }, "caller-a");
    const unchanged = await f.admin.handle("apply_user_access", { sys_id: id(number), assessment_id: again.assessment_id,
      operation_id: randomUUID(), acknowledged_native_effects: again.native_effects }, "caller-a");
    assert.equal(unchanged.status, "no_change");
  }
  assert.deepEqual(f.writes().map(row => row.table), ["sys_user_grmember", "sys_user_has_role", "sys_user_grmember", "sys_user_has_role"]);
  assert.ok(f.writes().every(row => !Object.hasOwn(row.values, "inherited")), "Read-only native inheritance is never fabricated");
});

async function lifecycleFixture(t, activate = true) {
  const f = fixture(t);
  f.tables.sys_user.push(f.user(2, "existing-support-user"));
  f.tables.sys_user_grmember.push({ sys_id: id(70), sys_mod_count: "", user: id(2), group: id(20) });
  f.tables.sys_user_has_role.push(
    { sys_id: id(71), sys_mod_count: "0", user: id(2), role: id(30), state: "active", inherited: "false", granted_by: "" },
    { sys_id: id(72), sys_mod_count: "", user: id(2), role: id(31), state: "active", inherited: "true", granted_by: id(30) });
  f.tables.task = [{ sys_id: id(73), sys_mod_count: "1", assigned_to: id(2), active: "true" }];
  await reviewedPolicy(f, { activate });
  const evidence = await f.admin.handle("inspect_user_account_policy", {});
  const policy = { format: 2, instance: "https://service.example.invalid", sourceEvidenceSha256: "a".repeat(64),
    protectedIds: [], protectedNames: [], businessRuleVersions: evidence.businessRuleVersions,
    schema_sha256: evidence.schema_sha256, rules_sha256: evidence.rules_sha256,
    reviewedAccessPolicies: ["support-assignee"] };
  fs.writeFileSync(path.join(f.directory, "account-contract.json"), JSON.stringify(policy));
  return { ...f, policy };
}

test("native lifecycle supports reviewed existing access without treating business assignments as activation denial", async t => {
  const f = await lifecycleFixture(t);
  const before = structuredClone({ roles: f.tables.sys_user_has_role, groups: f.tables.sys_user_grmember });
  let assessment = await f.admin.handle("local_admin_user_assess", { sys_id: id(2) });
  assert.equal(assessment.eligibility.activate, true);
  assert.equal(assessment.eligibility.lock, false);
  assert.equal(assessment.eligibility.deactivate, false);
  assert.deepEqual(assessment.responsibility_tables, ["active_tasks"]);
  const activated = await f.admin.handle("local_admin_user_activate", {
    sys_id: id(2), expected_mod_count: "0", assessment_id: assessment.assessment_id, operation_id: randomUUID(),
    acknowledged_native_effects: assessment.required_native_effects.activate,
  });
  assert.equal(activated.record.active, "true");
  assert.equal(activated.record.locked_out, "true");
  assessment = await f.admin.handle("local_admin_user_assess", { sys_id: id(2) });
  assert.equal(assessment.eligibility.unlock, true);
  const unlocked = await f.admin.handle("local_admin_user_unlock", {
    sys_id: id(2), expected_mod_count: "1", assessment_id: assessment.assessment_id, operation_id: randomUUID(),
    acknowledged_native_effects: assessment.required_native_effects.unlock,
  });
  assert.equal(unlocked.record.locked_out, "false");
  assert.equal(unlocked.record.notification, "1");
  assert.deepEqual({ roles: f.tables.sys_user_has_role, groups: f.tables.sys_user_grmember }, before);
  assert.deepEqual(f.writes().map(row => [row.method, row.table, row.values]),
    [["PATCH", "sys_user", { active: true }], ["PATCH", "sys_user", { locked_out: false }]]);
});

test("existing-access lifecycle requires explicit policy coverage and stops on privilege, policy or relationship drift", async t => {
  const f = await lifecycleFixture(t);
  const assess = () => f.admin.handle("local_admin_user_assess", { sys_id: id(2) });
  f.policy.reviewedAccessPolicies = [];
  fs.writeFileSync(path.join(f.directory, "account-contract.json"), JSON.stringify(f.policy));
  assert.equal((await assess()).eligibility.activate, false);
  f.policy.reviewedAccessPolicies = ["support-assignee"];
  fs.writeFileSync(path.join(f.directory, "account-contract.json"), JSON.stringify(f.policy));
  const assessment = await assess();
  const args = { sys_id: id(2), expected_mod_count: "0", assessment_id: assessment.assessment_id,
    operation_id: randomUUID(), acknowledged_native_effects: assessment.required_native_effects.activate };
  f.tables.sys_user_grmember[0].sys_mod_count = "1";
  await assert.rejects(f.admin.handle("local_admin_user_activate", args), /evidence changed/);
  f.tables.sys_user_grmember[0].sys_mod_count = "";
  f.tables.sys_user_role[0].scoped_admin = "true";
  await assert.rejects(assess(), /administrative/);
  f.tables.sys_user_role[0].scoped_admin = "false";
  f.tables.sys_security_acl[0].script = "CHANGED";
  await assert.rejects(assess(), /policy changed/);
  assert.equal(f.writes().length, 0);
});

test("nonactivation access policies never qualify restoring login access", async t => {
  const f = await lifecycleFixture(t, false);
  const assessment = await f.admin.handle("local_admin_user_assess", { sys_id: id(2) });
  assert.equal(assessment.eligibility.profile, true);
  assert.equal(assessment.eligibility.activate, false);
  assert.equal(assessment.eligibility.unlock, false);
  assert.equal(f.writes().length, 0);
});

test("native lifecycle response loss remains uncertain even when the requested state is visible", async t => {
  const f = await lifecycleFixture(t);
  const assessment = await f.admin.handle("local_admin_user_assess", { sys_id: id(2) });
  const args = { sys_id: id(2), expected_mod_count: "0", assessment_id: assessment.assessment_id,
    operation_id: randomUUID(), acknowledged_native_effects: assessment.required_native_effects.activate };
  f.mode.loseTable = "sys_user";
  await assert.rejects(f.admin.handle("local_admin_user_activate", args), error => {
    assert.equal(error.outcome.status, "uncertain");
    assert.equal(error.outcome.source_write_confirmed, false);
    assert.equal(error.outcome.requested_state_observed, true);
    return true;
  });
  await assert.rejects(f.restart().handle("local_admin_user_activate", { ...args, operation_id: randomUUID() }), /unresolved/);
  assert.equal(f.writes().length, 1);
});

test("unexpected native access changes remain uncertain instead of claiming lifecycle success", async t => {
  const f = await lifecycleFixture(t);
  const assessment = await f.admin.handle("local_admin_user_assess", { sys_id: id(2) });
  f.mode.afterWrite = () => { f.tables.sys_user_grmember[0].sys_mod_count = "1"; };
  await assert.rejects(f.admin.handle("local_admin_user_activate", {
    sys_id: id(2), expected_mod_count: "0", assessment_id: assessment.assessment_id, operation_id: randomUUID(),
    acknowledged_native_effects: assessment.required_native_effects.activate,
  }), error => error.outcome.status === "uncertain" && /changed existing access/.test(error.message));
  assert.equal(f.writes().length, 1);
});

test("native access creation on a previously roleless account is not silently accepted", async t => {
  const f = await lifecycleFixture(t);
  f.tables.sys_user_has_role.length = 0;
  f.tables.sys_user_grmember.length = 0;
  const assessment = await f.admin.handle("local_admin_user_assess", { sys_id: id(2) });
  f.mode.afterWrite = () => {
    f.tables.sys_user_grmember.push({ sys_id: id(70), sys_mod_count: "", user: id(2), group: id(20) });
  };
  await assert.rejects(f.admin.handle("local_admin_user_activate", {
    sys_id: id(2), expected_mod_count: "0", assessment_id: assessment.assessment_id, operation_id: randomUUID(),
    acknowledged_native_effects: assessment.required_native_effects.activate,
  }), error => error.outcome.status === "uncertain" && /changed existing access/.test(error.message));
  assert.equal(f.writes().length, 1);
});

test("policy listing distinguishes unevaluated readiness from disabled policy without qualifying it", async t => {
  const f = fixture(t);
  await reviewedPolicy(f);
  const requestCount = f.requests.length;
  const listing = await f.admin.handle("inspect_user_access_policy", {});
  assert.equal(listing.policies[0].enabled, true);
  assert.equal(listing.policy_available, null);
  assert.equal(listing.qualification, "not_evaluated");
  assert.equal(listing.policies[0].qualification, "not_evaluated");
  assert.equal(f.requests.length, requestCount, "Listing must not perform policy qualification");
  const checked = await f.admin.handle("inspect_user_access_policy", { policy: listing.policies[0].key });
  assert.equal(checked.policy_available, true);
  assert.equal(checked.qualification, "matched_reviewed_evidence");
  assert.equal(f.writes().length, 0);
});

test("access policy is closed before user creation and detects closure, ACL, caller and target drift", async t => {
  const f = fixture(t);
  await assert.rejects(f.admin.handle("inspect_user_access_policy", {}), /Missing operator-reviewed/);
  const review = await reviewedPolicy(f);
  f.tables.sys_user.push(f.user(2, "another-future-person"));
  const assess = () => f.admin.handle("assess_user_access", { sys_id: id(2), policy: "support-assignee" }, "caller-a");
  const saved = await assess();
  const args = { sys_id: id(2), assessment_id: saved.assessment_id, operation_id: randomUUID(),
    acknowledged_native_effects: review.native_effects };
  await assert.rejects(f.admin.handle("apply_user_access", args, "caller-b"), /caller/);
  await assert.rejects(f.admin.handle("apply_user_access", { ...args, acknowledged_native_effects: [] }, "caller-a"), /exact reviewed/);
  f.tables.sys_user[1].sys_mod_count = "1";
  await assert.rejects(f.admin.handle("apply_user_access", args, "caller-a"), /changed since assessment/);
  f.tables.sys_user[1].sys_mod_count = "0";
  for (const [row, field, value] of [
    [f.tables.sys_user_role[1], "name", "new_application_reader"],
    [f.tables.sys_security_acl[0], "script", "changed access logic"],
    [f.tables.sys_security_acl[0], "decision_type", "deny"],
    [f.tables.sys_user_role_contains[0], "sys_mod_count", "1"],
  ]) {
    const before = row[field]; row[field] = value;
    await assert.rejects(assess(), /policy changed/);
    row[field] = before;
  }
  f.tables.sys_user_role[1].elevated_privilege = "true";
  await assert.rejects(assess(), /Elevated/);
  f.tables.sys_user_role[1].elevated_privilege = "false";
  f.tables.sys_user_group[0].parent = id(22);
  await assert.rejects(assess(), /Parented/);
  f.tables.sys_user_group[0].parent = "";
  fs.writeFileSync(path.join(f.directory, "retained-user-ids.json"), JSON.stringify([id(2)]));
  await assert.rejects(assess(), /retention hold/);
  await assert.rejects(f.admin.handle("assess_user_access", { sys_id: id(1), policy: "support-assignee" }), /Current operator/);
  const contractPath = path.join(f.directory, "user-access-contract.json");
  const contract = JSON.parse(fs.readFileSync(contractPath, "utf8"));
  contract.policies[0].enabled = false;
  fs.writeFileSync(contractPath, JSON.stringify(contract));
  await assert.rejects(f.admin.handle("inspect_user_access_policy", { policy: "support-assignee" }), /disabled/);
  assert.equal(f.writes().length, 0);
});

test("missing linked ACLs remain a hard failure with bounded reference-only diagnostics", async t => {
  for (const missingCount of [1, 12]) {
    const f = fixture(t);
    f.tables.sys_security_acl = [];
    f.tables.sys_security_acl_role = Array.from({ length: missingCount }, (_, index) => ({
      sys_id: id(200 + index), sys_mod_count: "0", sys_user_role: id(31), sys_security_acl: id(500 + index),
    }));
    await assert.rejects(f.admin.handle("inspect_user_access_policy", { group_id: id(20), role_id: id(30) }), error => {
      assert.equal(error.message, "Linked ACL definition is absent or unreadable.");
      assert.equal(error.diagnostic?.code, "linked_acl_definition_incomplete");
      assert.equal(error.diagnostic.table, "sys_security_acl");
      assert.equal(error.diagnostic.expected_count, missingCount);
      assert.equal(error.diagnostic.returned_count, 0);
      assert.deepEqual(error.diagnostic.missing_acl_ids, Array.from({ length: Math.min(10, missingCount) }, (_, index) => id(500 + index)));
      assert.equal(error.diagnostic.references[0].link_id, id(200));
      assert.equal(error.diagnostic.references[0].role_id, id(31));
      assert.equal(error.diagnostic.truncated, missingCount > 10);
      assert.doesNotMatch(JSON.stringify(error.diagnostic), /PRIVATE_|script|condition|password|token|principal/i);
      return true;
    });

    assert.equal(f.writes().length, 0);
    assert.equal(fs.existsSync(path.join(f.directory, "user-access-contract.json")), false);
  }
});

test("native unresolved ACL references require exact complementary evidence, a visible control and private opt-in", async t => {
  const f = fixture(t);
  const unresolved = { sys_id: id(52), sys_mod_count: "0", sys_user_role: id(31), sys_security_acl: id(53) };
  f.tables.sys_security_acl_role.push(unresolved);
  const review = await f.admin.handle("inspect_user_access_policy", { group_id: id(20), role_id: id(30) });
  assert.equal(review.policy_requirements.allow_unresolved_acl_references, true);
  assert.equal(review.unresolved_acl_references.references.length, 1);
  assert.deepEqual(review.unresolved_acl_references.references[0], unresolved);
  assert.equal(review.unresolved_acl_references.positive_control.link.sys_id, id(50));
  assert.equal(review.unresolved_acl_references.positive_control.definition.sys_id, id(51));
  assert.equal(review.unresolved_acl_references.native_empty.length, 1);
  assert.equal(review.unresolved_acl_references.native_not_empty.length, 0);
  assert.equal(review.acls.length, 1, "Do not invent the missing definition");
  await reviewedPolicy(f);
  await assert.rejects(f.admin.handle("inspect_user_access_policy", { policy: "support-assignee" }), /unresolved.*explicit reviewed/);
  const file = path.join(f.directory, "user-access-contract.json"), policy = JSON.parse(fs.readFileSync(file, "utf8"));
  policy.policies[0].allow_unresolved_acl_references = true;
  fs.writeFileSync(file, JSON.stringify(policy));
  assert.equal((await f.admin.handle("inspect_user_access_policy", { policy: "support-assignee" })).policy_available, true);
  for (const failure of ["contradictoryJoin", "omitJoinField", "corruptJoinVersion", "denyNative"]) {
    f.mode[failure] = true;
    await assert.rejects(f.admin.handle("inspect_user_access_policy", { policy: "support-assignee" }));
    f.mode[failure] = false;
  }
  for (const [row, field, value] of [
    [unresolved, "sys_mod_count", "1"],
    [f.tables.sys_security_acl[0], "name", "changed.control.name"],
  ]) {
    const before = row[field]; row[field] = value;
    await assert.rejects(f.admin.handle("inspect_user_access_policy", { policy: "support-assignee" }), /policy changed/);
    row[field] = before;
  }
  f.tables.sys_security_acl.push({ ...f.tables.sys_security_acl[0], sys_id: id(53), name: "different.acl" });
  await assert.rejects(f.admin.handle("inspect_user_access_policy", { policy: "support-assignee" }), /policy changed/);
  f.mode.hiddenAcl = id(53);
  await assert.rejects(f.admin.handle("inspect_user_access_policy", { policy: "support-assignee" }), /absent or unreadable|reference/);
  assert.equal(f.writes().length, 0);
});

test("accepted unresolved-reference policy is rechecked between mutation stages", async t => {
  for (const drift of [false, true]) {
    const f = fixture(t);
    const unresolved = { sys_id: id(52), sys_mod_count: "0", sys_user_role: id(31), sys_security_acl: id(53) };
    f.tables.sys_security_acl_role.push(unresolved);
    await reviewedPolicy(f);
    const file = path.join(f.directory, "user-access-contract.json"), policy = JSON.parse(fs.readFileSync(file, "utf8"));
    policy.policies[0].allow_unresolved_acl_references = true;
    fs.writeFileSync(file, JSON.stringify(policy));
    f.tables.sys_user.push(f.user(2, "runtime-new-person"));
    const assessment = await f.admin.handle("assess_user_access", { sys_id: id(2), policy: "support-assignee" }, "caller-a");
    if (drift) f.mode.afterWrite = table => { if (table === "sys_user_grmember") unresolved.sys_mod_count = "1"; };
    const operation_id = randomUUID();
    const operation = f.admin.handle("apply_user_access", { sys_id: id(2), assessment_id: assessment.assessment_id,
      operation_id, acknowledged_native_effects: assessment.native_effects }, "caller-a");
    if (drift) {
      await assert.rejects(operation, error => error.outcome.status === "uncertain" && error.outcome.partial === true);
      assert.deepEqual(f.writes().map(row => row.table), ["sys_user_grmember"]);
      const result = await f.restart().handle("get_user_access_operation", { operation_id }, "caller-a");
      assert.equal(result.unresolved_hold, true);
      assert.equal(result.outcome.stages[0].status, "confirmed");
    } else {
      assert.equal((await operation).status, "confirmed");
      assert.deepEqual(f.writes().map(row => row.table), ["sys_user_grmember", "sys_user_has_role"]);
    }
  }
});

test("delegation-capable closure is disclosed but denied unless the private policy explicitly permits it", async t => {
  const f = fixture(t);
  f.tables.sys_user_role[0].can_delegate = "true";
  const review = await reviewedPolicy(f);
  assert.equal(review.policy_requirements.allow_role_delegation, true);
  assert.ok(review.native_effects.includes("reviewed-role-delegation-eligibility"));
  await assert.rejects(f.admin.handle("inspect_user_access_policy", { policy: "support-assignee" }), /delegation eligibility/);
  const file = path.join(f.directory, "user-access-contract.json"), policy = JSON.parse(fs.readFileSync(file, "utf8"));
  policy.policies[0].allow_role_delegation = true;
  fs.writeFileSync(file, JSON.stringify(policy));
  assert.equal((await f.admin.handle("inspect_user_access_policy", { policy: "support-assignee" })).policy_available, true);
  f.tables.sys_user_role[1].name = "role_delegator";
  await assert.rejects(f.admin.handle("inspect_user_access_policy", { group_id: id(20), role_id: id(30) }), /administrative/);
  assert.equal(f.writes().length, 0);
});

test("partial, denied and uncertain access effects survive restart and stop cross-caller or incident replay", async t => {
  for (const failure of ["deny", "lost", "expansion", "unexpected"]) {
    const f = fixture(t);
    await reviewedPolicy(f);
    f.tables.sys_user.push(f.user(2, "future-user"));
    const saved = await f.admin.handle("assess_user_access", { sys_id: id(2), policy: "support-assignee" }, "caller-a");
    if (failure === "deny") f.mode.denyTable = "sys_user_has_role";
    if (failure === "lost") f.mode.loseTable = "sys_user_has_role";
    if (failure === "expansion") f.mode.omitExpansion = true;
    if (failure === "unexpected") f.mode.unexpectedRole = true;
    const operation_id = randomUUID();
    await assert.rejects(f.admin.handle("apply_user_access", {
      sys_id: id(2), assessment_id: saved.assessment_id, operation_id,
      acknowledged_native_effects: saved.native_effects,
    }, "caller-a"), error => {
      assert.equal(error.outcome.status, "uncertain");
      assert.equal(error.outcome.retained_user, id(2));
      if (failure !== "unexpected") assert.equal(error.outcome.partial, true);
      if (failure === "deny") assert.equal(error.outcome.diagnostic.status, 403);
      return true;
    });
    const writes = f.writes().length, restarted = f.restart();
    const status = await restarted.handle("get_user_access_operation", { operation_id }, "caller-a");
    assert.equal(status.status, "uncertain");
    assert.equal(status.unresolved_hold, true);
    assert.equal(status.outcome.stages[0].response_sys_id !== undefined, true);
    await assert.rejects(restarted.handle("get_user_access_operation", { operation_id }, "caller-b"), /not available/);
    await assert.rejects(restarted.handle("assess_user_access", { sys_id: id(2), policy: "support-assignee" }, "caller-b"), /unresolved/);
    await assert.rejects(restarted.handle("update_incident", { number: "INC0000001", expected_mod_count: "0",
      values: { assigned_to: id(2) }, operation_id: randomUUID() }), /unresolved/);
    await assert.rejects(restarted.handle("local_admin_user_role_add", { user: id(2), role: id(30), operation_id: randomUUID() }),
      /unresolved/);
    assert.equal(f.writes().length, writes);
  }
});

test("activation is opt-in and preserves lock; unrequested native status changes stop later grants", async t => {
  for (const unexpected of [false, true]) {
    const f = fixture(t);
    await reviewedPolicy(f, { activate: true });
    f.tables.sys_user.push(f.user(2, "new-human"));
    const assessment = await f.admin.handle("assess_user_access", { sys_id: id(2), policy: "support-assignee" });
    assert.deepEqual(assessment.missing_stages, ["activate", "membership", "role"]);
    f.mode.activateSideEffect = unexpected;
    const call = f.admin.handle("apply_user_access", { sys_id: id(2), assessment_id: assessment.assessment_id,
      operation_id: randomUUID(), acknowledged_native_effects: assessment.native_effects });
    if (unexpected) {
      await assert.rejects(call, error => error.outcome.status === "uncertain");
      assert.deepEqual(f.writes().map(row => row.table), ["sys_user"]);
    } else {
      const result = await call;
      assert.equal(result.after.user.active, "true");
      assert.equal(result.after.user.locked_out, "true");
      assert.deepEqual(f.writes()[0].values, { active: true });
      assert.equal(result.status, "confirmed");
    }
  }
});

test("signed MCP composes dynamic names into user creation, reviewed access and assignment with no preloaded people", async t => {
  const { createCoworkApp } = require("../src/cowork-http.cjs");
  const { createEntraVerifier } = require("../src/cowork-auth.cjs");
  const { generateKeyPair, SignJWT } = await import("jose");
  const { once } = require("node:events");
  const f = fixture(t);
  await reviewedPolicy(f);
  const userSchema = await f.admin.handle("get_user_schema", {});
  fs.writeFileSync(path.join(f.directory, "user-profile-contract.json"), JSON.stringify({
    format: 1, instance: "https://service.example.invalid", schema_sha256: userSchema.schema_sha256,
    rules_sha256: userSchema.rules_sha256, sourceEvidenceSha256: "b".repeat(64),
    protectedIds: [], protectedNames: ["admin", "guest", "system"], absence_visibility_reviewed: true,
  }));
  const tenant = "11111111-1111-4111-8111-111111111111", client = "33333333-3333-4333-8333-333333333333";
  const audience = "44444444-4444-4444-8444-444444444444", oid = "22222222-2222-4222-8222-222222222222";
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const sign = scopes => new SignJWT({ tid: tenant, oid, azp: client, ver: "2.0", scp: scopes })
    .setProtectedHeader({ alg: "RS256" }).setIssuer(`https://login.microsoftonline.com/${tenant}/v2.0`)
    .setAudience(audience).setIssuedAt().setNotBefore("0s").setExpirationTime("5m").sign(privateKey);
  const token = await sign("Incident.Manage User.Manage User.Access.Manage");
  const withoutAccess = await sign("Incident.Manage User.Manage");
  const audit = [];
  const profile = { format: 1, tenant_id: tenant, client_id: client, audience, writes_enabled: true, audit_enabled: true,
    instance: "https://service.example.invalid", public_url: "https://mcp.example.invalid/mcp" };
  const server = createCoworkApp({ profile, backend: f.admin,
    verifyAccessToken: await createEntraVerifier(profile, { key: publicKey }), writeAudit: line => audit.push(JSON.parse(line)),
  }).listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => { server.closeAllConnections(); server.close(); });
  const call = async (name, args, accessToken = token, error = false) => {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/mcp`, {
      method: "POST", headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }),
    });
    assert.equal(response.status, 200);
    const rpc = await response.json();
    assert.equal(rpc.result.isError === true, error, rpc.result.content[0].text);
    return JSON.parse(rpc.result.content[0].text);
  };
  await call("inspect_user_access_policy", { policy: "support-assignee" }, withoutAccess, true);
  assert.equal(f.writes().length, 0);
  const names = Array.from({ length: 2 }, () => `New Person ${randomUUID().slice(0, 8)}`);
  for (const name of names) {
    assert.equal((await call("inspect_user_access_policy", { policy: "support-assignee" })).policy_available, true);
    assert.equal((await call("lookup_users", { identity: name, field: "name" })).resolution, "not_found");
    const createArgs = { user_name: name.replaceAll(" ", ".").toLowerCase(), profile: { first_name: name, email: `${name.replaceAll(" ", ".")}@example.invalid` },
      operation_id: randomUUID() };
    const created = await call("create_user", createArgs);
    const sys_id = created.record.sys_id;
    assert.equal(created.directory_verified, false);
    assert.equal(created.record.locked_out, "true");
    assert.equal((await call("lookup_users", { identity: name, field: "name" })).candidates[0].sys_id, sys_id);
    const collision = await call("create_user", { ...createArgs, operation_id: randomUUID() }, token, true);
    assert.match(collision.error, /collision/);
    const assessment = await call("assess_user_access", { sys_id, policy: "support-assignee" });
    const operation_id = randomUUID();
    const access = await call("apply_user_access", { sys_id, assessment_id: assessment.assessment_id, operation_id,
      acknowledged_native_effects: assessment.native_effects });
    assert.equal(access.status, "confirmed");
    assert.equal((await call("get_user_access_operation", { operation_id })).unresolved_hold, false);
    const incident = await call("get_incident", { number: "INC0000001" });
    const assigned = await call("update_incident", { number: incident.number, expected_mod_count: incident.sys_mod_count,
      values: { assigned_to: sys_id }, operation_id: randomUUID() });
    assert.equal(assigned.status, "confirmed");
    assert.equal(assigned.assignment_group_preserved, true);
    assert.equal((await call("get_incident", { number: incident.number })).assigned_to, sys_id);
  }
  assert.equal(f.writes().filter(row => row.table === "sys_user" && row.method === "POST").length, 2);
  assert.equal(f.writes().filter(row => row.table === "sys_user" && row.method === "PATCH").length, 0);
  assert.equal(audit.filter(row => row.tool === "create_user" && row.status === "confirmed").length, 2);
  assert.equal(audit.filter(row => row.tool === "apply_user_access" && row.status === "confirmed").length, 2);
  assert.ok(audit.every(row => row.object_id === oid && !JSON.stringify(row).includes("New Person")));
});
