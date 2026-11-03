const assert = require("node:assert/strict");
const { test } = require("node:test");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { createAdmin } = require("../src/admin/index.cjs");

function fixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "servicenow-account-policy-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const instance = "https://service.example.invalid";
  const rule = { sys_id: "a".repeat(32), sys_mod_count: "0", collection: "sys_user", active: "true",
    name: "Synthetic native account rule", when: "before", order: "100", action_insert: "true",
    action_update: "true", action_delete: "false", action_query: "false", filter_condition: "",
    condition: "", script: "PRIVATE_REVIEW_SCRIPT", template: "locked_out=true", sys_overrides: "",
    role_conditions: "", abort_action: "false", sys_scope: "global", sys_domain: "global" };
  const requests = [];
  let unique = "true";
  const fetchImpl = async (raw, options) => {
    requests.push(options.method);
    const url = new URL(raw), table = url.pathname.split("/")[4];
    const query = url.searchParams.get("sysparm_query") || "";
    let rows = [];
    if (table === "sys_db_object") rows = [{ name: "sys_user", "super_class.name": "" }];
    if (table === "sys_script") rows = [rule];
    if (table === "sys_dictionary") rows = query === "name=sys_user^element=user_name" ?
      [{ sys_id: "b".repeat(32), sys_mod_count: "0", unique }] :
      [{ sys_id: "b".repeat(32), name: "sys_user", element: "user_name", internal_type: "string",
        mandatory: "true", read_only: "false", default_value: "", reference: "", max_length: "40",
        display: "false", choice: "0" }];
    const fields = url.searchParams.get("sysparm_fields").split(",");
    return Response.json({ result: rows.map(row =>
      Object.fromEntries(fields.filter(key => Object.hasOwn(row, key)).map(key => [key, row[key]]))) });
  };
  return { directory, instance, rule, requests, nonunique: () => { unique = "false"; },
    admin: createAdmin({ instance, username: "operator", password: "synthetic-only", directory, fetchImpl }) };
}

test("native account qualification is discoverable without a contract and never approves itself", async t => {
  const f = fixture(t);
  const tool = f.admin.tools.find(tool => tool.name === "inspect_user_account_policy");
  assert.ok(tool, "Native clients need a supported route from the missing-contract error to qualification");
  assert.equal(tool.annotations.readOnlyHint, true);
  const evidence = await f.admin.handle(tool.name, {});
  assert.equal(evidence.policy_status, "missing");
  assert.equal(evidence.source_permission, "not_evaluated");
  assert.equal(evidence.review_required, true);
  assert.equal(evidence.native_user_name_unique, true);
  assert.deepEqual(evidence.businessRuleVersions, [{ sys_id: f.rule.sys_id, sys_mod_count: "0" }]);
  assert.match(evidence.rules_sha256, /^[a-f0-9]{64}$/);
  assert.match(evidence.schema_sha256, /^[a-f0-9]{64}$/);
  assert.match(evidence.rules[0].template_sha256, /^[a-f0-9]{64}$/);
  assert.doesNotMatch(JSON.stringify(evidence), /PRIVATE_REVIEW_SCRIPT/);
  assert.equal(fs.existsSync(path.join(f.directory, "account-contract.json")), false);
  await assert.rejects(f.admin.handle("local_admin_user_assess", { sys_id: "c".repeat(32) }),
    /Missing operator-reviewed account.*inspect_user_account_policy/);
  assert.ok(f.requests.every(method => method === "GET"));
});

test("account readiness compares reviewed schema, full rule content and native uniqueness, not discovery alone", async t => {
  const f = fixture(t);
  const evidence = await f.admin.handle("inspect_user_account_policy", {});
  fs.writeFileSync(path.join(f.directory, "account-contract.json"), JSON.stringify({
    format: 2, instance: f.instance, sourceEvidenceSha256: "d".repeat(64), protectedIds: [],
    protectedNames: ["admin", "guest", "system"], businessRuleVersions: evidence.businessRuleVersions,
    schema_sha256: evidence.schema_sha256, rules_sha256: evidence.rules_sha256,
  }));
  assert.equal((await f.admin.handle("inspect_user_account_policy", {})).policy_status, "matching");
  f.rule.template = "locked_out=false";
  assert.equal((await f.admin.handle("inspect_user_account_policy", {})).policy_status, "drifted");
  await assert.rejects(f.admin.handle("local_admin_user_assess", { sys_id: "c".repeat(32) }), /policy changed/);
  f.rule.template = "locked_out=true";
  f.nonunique();
  assert.equal((await f.admin.handle("inspect_user_account_policy", {})).policy_status, "drifted");
  assert.ok(f.requests.every(method => method === "GET"));
});
