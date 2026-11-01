const assert = require("node:assert/strict");
const { test } = require("node:test");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { randomUUID } = require("node:crypto");
const { createAdmin } = require("../src/admin/index.cjs");

function fixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "servicenow-delete-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const id = "a".repeat(32), operator = "b".repeat(32);
  const user = { sys_id: id, user_name: "existing-active-user", first_name: "Example", last_name: "", title: "",
    active: "true", locked_out: "false", notification: "2", sys_class_name: "sys_user", identity_type: "human",
    internal_integration_user: "false", web_service_access_only: "false", sys_mod_count: "4" };
  let present = true, deny = false, writes = 0;
  const children = Array.from({ length: 101 }, (_, index) => ({
    sys_id: (index + 1).toString(16).padStart(32, "0"), sys_mod_count: "", user: id,
  }));
  const fetchImpl = async (raw, options) => {
    const url = new URL(raw);
    const table = url.pathname.split("/")[4];
    const query = url.searchParams.get("sysparm_query") || "";
    if (options.method === "DELETE") {
      writes++;
      if (deny) return Response.json({ error: { message: "ACL denied" } }, { status: 403 });
      present = false;
      return new Response(null, { status: 204 });
    }
    let rows = [];
    if (table === "sys_user" && query === "user_name=operator") rows = [{ sys_id: operator, user_name: "operator" }];
    else if (table === "sys_user" && query === `sys_id=${operator}`) rows = [{ ...user, sys_id: operator, user_name: "operator" }];
    else if (table === "sys_user" && query === `sys_id=${id}`) rows = present ? [user] : [];
    else if (table === "sys_user_grmember") {
      if (query.startsWith(`user=${id}^`)) {
        const cursor = query.match(/\^sys_id>([a-f0-9]+)/)?.[1] || "";
        rows = present ? children.filter(row => row.sys_id > cursor).slice(0, 100) : [];
      } else if (query.startsWith("sys_id=")) rows = present ? children.filter(row => row.sys_id === query.slice(7)) : [];
    } else if (table === "sys_dictionary" && query === "name=sys_user_grmember^element=user")
      rows = [{ sys_id: "c".repeat(32), sys_mod_count: "0", reference_cascade_rule: "cascade" }];
    return Response.json({ result: rows });
  };
  return { directory, id, operator, user, children, deny: () => { deny = true; }, writes: () => writes,
    admin: createAdmin({ instance: "https://service.example.invalid", username: "operator", password: "synthetic-only", directory, fetchImpl }) };
}
test("administrative deletion pages beyond100, preserves blank child versions and confirms parent separately", async (t) => {
  const f = fixture(t);
  const impact = await f.admin.handle("local_admin_user_delete_assess", { sys_id: f.id });
  assert.deepEqual(impact.blocked, []);
  const members = impact.relationships.find(row => row.table === "sys_user_grmember");
  assert.equal(members.records.length, 101);
  assert.equal(members.records[0].sys_mod_count, "");
  const args = { sys_id: f.id, expected_mod_count: "4", expected_impact_sha256: impact.impact_sha256,
    operation_id: randomUUID(), confirm: true, acknowledged_native_effects: impact.native_effects_declared };
  const result = await f.admin.handle("local_admin_user_delete_administrative", args);
  assert.equal(result.parent_absent, true);
  assert.equal(result.cleanup_complete, false);
  assert.equal(result.native_observations.length, 101);
  assert.ok(result.native_observations.every(row => row.outcome === "deleted"));
  await assert.rejects(f.admin.handle("local_admin_user_delete_administrative", args), /already attempted/);
  assert.equal(f.writes(), 1);
});
test("operator, retained users and stale impact are rejected before deletion", async (t) => {
  const f = fixture(t);
  const self = await f.admin.handle("local_admin_user_delete_assess", { sys_id: f.operator });
  assert.ok(self.blocked.includes("current_authenticated_operator"));
  fs.writeFileSync(path.join(f.directory, "retained-user-ids.json"), JSON.stringify([f.id]));
  const held = await f.admin.handle("local_admin_user_delete_assess", { sys_id: f.id });
  assert.ok(held.blocked.includes("explicit_user_retention_hold"));
  fs.writeFileSync(path.join(f.directory, "retained-user-ids.json"), "[]");
  const impact = await f.admin.handle("local_admin_user_delete_assess", { sys_id: f.id });
  await assert.rejects(f.admin.handle("local_admin_user_delete_administrative", {
    sys_id: f.id, expected_mod_count: "4", expected_impact_sha256: "0".repeat(64), operation_id: randomUUID(),
    confirm: true, acknowledged_native_effects: impact.native_effects_declared,
  }), /impact changed/);
  assert.equal(f.writes(), 0);
});
test("source denial retains uncertainty and blocks a different-UUID deletion replay", async (t) => {
  const f = fixture(t);
  const impact = await f.admin.handle("local_admin_user_delete_assess", { sys_id: f.id });
  f.deny();
  const args = { sys_id: f.id, expected_mod_count: "4", expected_impact_sha256: impact.impact_sha256,
    operation_id: randomUUID(), confirm: true, acknowledged_native_effects: impact.native_effects_declared };
  await assert.rejects(f.admin.handle("local_admin_user_delete_administrative", args), error => error.outcome.status === "uncertain");
  await assert.rejects(f.admin.handle("local_admin_user_delete_administrative", { ...args, operation_id: randomUUID() }), /unresolved/);
  assert.equal(f.writes(), 1);
});
