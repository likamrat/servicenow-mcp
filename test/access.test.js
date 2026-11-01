const assert = require("node:assert/strict");
const { test } = require("node:test");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { randomUUID } = require("node:crypto");
const { createAdmin } = require("../src/admin/index.cjs");

test("managed access retains neutral scope, exact relationships, ownership receipts and hook drift guards", async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "servicenow-access-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const instance = "https://service.example.invalid", userId = "a".repeat(32);
  const account = { format: 2, instance, sourceEvidenceSha256: "b".repeat(64), protectedNames: [], protectedIds: [],
    businessRuleVersions: [{ sys_id: "c".repeat(32), sys_mod_count: "0" }] };
  fs.writeFileSync(path.join(directory, "account-contract.json"), JSON.stringify(account));
  const tables = ["sys_user_group", "sys_user_role", "sys_user_has_role", "sys_group_has_role", "sys_user_role_contains", "sys_user_grmember"];
  const access = { format: 1, instance, sourceEvidenceSha256: "d".repeat(64),
    tables: Object.fromEntries(tables.map(table => [table, { rules: [], dictionary: [] }])), directOriginDefaults: ["", "0"] };
  const db = new Map([["sys_user", [{
    sys_id: userId, user_name: "sample", active: "false", locked_out: "true", identity_type: "human",
    internal_integration_user: "false", web_service_access_only: "false", manager: "", sys_mod_count: "0",
    sys_class_name: "sys_user", source: "", ldap_server: "",
  }]]]);
  const writes = [];
  let next = 1, drift = false;
  const fetchImpl = async (raw, options) => {
    const url = new URL(raw), [, , , , table, id] = url.pathname.split("/");
    const query = url.searchParams.get("sysparm_query") || "";
    if (options.method !== "GET") {
      writes.push({ method: options.method, table });
      if (options.method === "DELETE") {
        db.set(table, (db.get(table) || []).filter(row => row.sys_id !== id));
        return new Response(null, { status: 204 });
      }
      if (options.method === "PATCH") {
        const row = db.get(table).find(row => row.sys_id === id);
        Object.assign(row, JSON.parse(options.body), { sys_mod_count: String(Number(row.sys_mod_count) + 1) });
        return Response.json({ result: row });
      }
      const row = { ...JSON.parse(options.body), sys_id: (next++).toString(16).padStart(32, "0"),
        sys_mod_count: "0", sys_created_by: "operator" };
      if (table === "sys_user_role") Object.assign(row, { assignable_by: "", includes_roles: "" });
      if (table === "sys_user_has_role") row.state = "active";
      if (!db.has(table)) db.set(table, []);
      db.get(table).push(row);
      return Response.json({ result: row });
    }
    let rows = db.get(table) || [];
    if (table === "sys_script" && drift) rows = [{
      sys_id: "e".repeat(32), sys_mod_count: "1", collection: "sys_user_group", active: "true",
    }];
    rows = rows.filter(row => query.split("^").every(term => {
      if (term.endsWith("ISEMPTY")) return !row[term.slice(0, -7)];
      const separator = term.indexOf("=");
      return separator > 0 && String(row[term.slice(0, separator)]) === term.slice(separator + 1);
    }));
    const fields = url.searchParams.get("sysparm_fields").split(",");
    return Response.json({ result: rows.map(row => Object.fromEntries(fields.filter(key => Object.hasOwn(row, key)).map(key => [key, row[key]]))) });
  };
  const admin = createAdmin({ instance, username: "operator", password: "synthetic-only", directory, fetchImpl });
  const createGroup = { operation_id: randomUUID(), name: "u_copilot_team", description: "Supplied group" };
  await assert.rejects(admin.handle("local_admin_group_create", createGroup), /Missing operator-reviewed access/);
  assert.equal(writes.length, 0);
  fs.writeFileSync(path.join(directory, "access-contract.json"), JSON.stringify(access));
  const group = await admin.handle("local_admin_group_create", createGroup);
  assert.equal(group.managed_access_authority, true);
  const role = await admin.handle("local_admin_role_create", {
    operation_id: randomUUID(), name: "u_copilot_reader", description: "Supplied role",
  });
  assert.equal(role.managed_access_authority, true);
  await admin.handle("local_admin_role_update", {
    operation_id: randomUUID(), sys_id: role.sys_id, expected_mod_count: "0", description: "Updated",
  });
  const grant = await admin.handle("local_admin_user_role_add", { operation_id: randomUUID(), user: userId, role: role.sys_id });
  assert.equal(grant.access.roles.length, 1);
  const removed = await admin.handle("local_admin_user_role_remove", {
    operation_id: randomUUID(), user: userId, role: role.sys_id, relationship_id: grant.sys_id, expected_mod_count: "0",
  });
  assert.equal(removed.exact_relationship_absent, true);
  assert.deepEqual(removed.access.roles, []);
  const deleted = await admin.handle("local_admin_group_delete", {
    operation_id: randomUUID(), sys_id: group.sys_id, expected_mod_count: "0", confirm: true,
  });
  assert.equal(deleted.absent, true);
  await assert.rejects(admin.handle("local_admin_role_delete", {
    operation_id: randomUUID(), sys_id: role.sys_id, expected_mod_count: "1", confirm: true,
  }), /not available/);
  const before = writes.length;
  drift = true;
  await assert.rejects(admin.handle("local_admin_group_create", {
    operation_id: randomUUID(), name: "u_copilot_next", description: "Not sent",
  }), /policy drift/);
  assert.equal(writes.length, before);
});
