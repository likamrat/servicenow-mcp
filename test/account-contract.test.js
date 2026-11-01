const assert = require("node:assert/strict");
const { test } = require("node:test");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { randomUUID } = require("node:crypto");
const { createAdmin } = require("../src/admin/index.cjs");

test("account lifecycle requires reviewed metadata and rejects live rule drift before writes", async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "servicenow-account-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const instance = "https://service.example.invalid", id = "a".repeat(32);
  const rule = { sys_id: "b".repeat(32), sys_mod_count: "0" };
  const user = { sys_id: id, sys_mod_count: "0", user_name: "sample", first_name: "Example", last_name: "",
    title: "Before", active: "true", locked_out: "false", notification: "2", sys_class_name: "sys_user",
    identity_type: "human", internal_integration_user: "false", web_service_access_only: "false", failed_attempts: "0" };
  let requests = 0, writes = 0;
  const fetchImpl = async (raw, options) => {
    requests++;
    const url = new URL(raw), table = url.pathname.split("/")[4];
    if (options.method === "PATCH") {
      writes++;
      Object.assign(user, JSON.parse(options.body), { sys_mod_count: String(Number(user.sys_mod_count) + 1) });
      return Response.json({ result: { sys_id: id } });
    }
    let rows = [];
    if (table === "sys_script") rows = [rule];
    if (table === "sys_user" && url.searchParams.get("sysparm_query").startsWith(`sys_id=${id}`)) rows = [user];
    const fields = url.searchParams.get("sysparm_fields").split(",");
    return Response.json({ result: rows.map(row => Object.fromEntries(fields.filter(key => Object.hasOwn(row, key)).map(key => [key, row[key]]))) });
  };
  const admin = createAdmin({ instance, username: "operator", password: "synthetic-only", directory, fetchImpl });
  await assert.rejects(admin.handle("local_admin_user_assess", { sys_id: id }), /Missing operator-reviewed account/);
  assert.equal(requests, 0);
  const contract = { format: 2, instance, sourceEvidenceSha256: "c".repeat(64), protectedIds: [], protectedNames: [],
    businessRuleVersions: [structuredClone(rule)] };
  fs.writeFileSync(path.join(directory, "account-contract.json"), JSON.stringify(contract));
  const assessment = await admin.handle("local_admin_user_assess", { sys_id: id });
  assert.equal(assessment.eligibility.profile, true);
  const args = { sys_id: id, expected_mod_count: "0", assessment_id: assessment.assessment_id,
    operation_id: randomUUID(), acknowledged_native_effects: [], profile: { title: "After" } };
  rule.sys_mod_count = "1";
  await assert.rejects(admin.handle("local_admin_user_update_profile", args), /policy changed/);
  assert.equal(writes, 0);
  rule.sys_mod_count = "0";
  const result = await admin.handle("local_admin_user_update_profile", args);
  assert.equal(result.record.title, "After");
  assert.equal(result.record.notification, "2");
  assert.equal(writes, 1);
  const fresh = await admin.handle("local_admin_user_assess", { sys_id: id });
  const deactivate = { sys_id: id, expected_mod_count: "1", assessment_id: fresh.assessment_id,
    operation_id: randomUUID(), acknowledged_native_effects: [] };
  await assert.rejects(admin.handle("local_admin_user_deactivate_and_lock", deactivate), /native-effect acknowledgment/);
  assert.equal(writes, 1);
  deactivate.acknowledged_native_effects = ["conditional_native_lockout_event", "contextual_writer_membership_recompute",
    "provider_mapping_deactivation", "session_lockout_and_oauth_revocation"];
  const locked = await admin.handle("local_admin_user_deactivate_and_lock", deactivate);
  assert.equal(locked.record.active, false);
  assert.equal(locked.record.locked_out, true);
  assert.equal(locked.record.notification, "2");
});

test("disabled creation, activation and unlock preserve separate effects and native child observations", async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "servicenow-user-lifecycle-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const instance = "https://service.example.invalid", id = "a".repeat(32);
  const rule = { sys_id: "b".repeat(32), sys_mod_count: "0" };
  fs.writeFileSync(path.join(directory, "account-contract.json"), JSON.stringify({
    format: 2, instance, sourceEvidenceSha256: "c".repeat(64), protectedIds: [], protectedNames: [], businessRuleVersions: [rule],
  }));
  let user;
  const methods = [];
  const fetchImpl = async (raw, options) => {
    const url = new URL(raw), table = url.pathname.split("/")[4], query = url.searchParams.get("sysparm_query") || "";
    if (options.method === "POST") {
      methods.push(options.method);
      user = { sys_id: id, sys_mod_count: "0", first_name: "", last_name: "", title: "",
        sys_class_name: "sys_user", internal_integration_user: "false", web_service_access_only: "false", failed_attempts: "0",
        ...JSON.parse(options.body) };
      return Response.json({ result: { sys_id: id } });
    }
    if (options.method === "PATCH") {
      methods.push(options.method);
      Object.assign(user, JSON.parse(options.body), { sys_mod_count: String(Number(user.sys_mod_count) + 1), failed_attempts: "0" });
      return Response.json({ result: { sys_id: id } });
    }
    let rows = [];
    if (table === "sys_script") rows = [rule];
    if (table === "sys_user" && user && (query.startsWith(`sys_id=${id}`) || query === "user_name=sample")) rows = [user];
    if (table === "cmn_notif_device" && user) rows = [{
      sys_id: "d".repeat(32), user: id, active: "true", primary_email: "true", type: "Email",
    }];
    const fields = url.searchParams.get("sysparm_fields").split(",");
    return Response.json({ result: rows.map(row => Object.fromEntries(fields.filter(key => Object.hasOwn(row, key)).map(key => [key, row[key]]))) });
  };
  const admin = createAdmin({ instance, username: "operator", password: "synthetic-only", directory, fetchImpl });
  const created = await admin.handle("local_admin_user_create_disabled", {
    operation_id: randomUUID(), user_name: "sample", profile: { first_name: "Example" },
    active: false, locked_out: true, notification: "1", identity_type: "human",
  });
  assert.equal(created.record.active, false);
  assert.equal(created.record.locked_out, true);
  assert.equal(created.native_effects.primary_device_observation, "active_primary_observed");
  let assessment = await admin.handle("local_admin_user_assess", { sys_id: id });
  const active = await admin.handle("local_admin_user_activate", {
    sys_id: id, expected_mod_count: "0", assessment_id: assessment.assessment_id, operation_id: randomUUID(),
    acknowledged_native_effects: ["contextual_writer_membership_recompute", "local_account_activation", "session_lockout_and_oauth_revocation"],
  });
  assert.equal(active.record.active, true);
  assert.equal(active.record.locked_out, true);
  assessment = await admin.handle("local_admin_user_assess", { sys_id: id });
  const unlocked = await admin.handle("local_admin_user_unlock", {
    sys_id: id, expected_mod_count: "1", assessment_id: assessment.assessment_id, operation_id: randomUUID(),
    acknowledged_native_effects: ["local_account_unlock_and_failed_attempt_reset"],
  });
  assert.equal(unlocked.record.locked_out, false);
  assert.equal(unlocked.record.notification, "1");
  assert.deepEqual(methods, ["POST", "PATCH", "PATCH"]);
});
