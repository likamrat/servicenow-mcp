const assert = require("node:assert/strict");
const { test } = require("node:test");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { randomUUID } = require("node:crypto");
const { createAdmin } = require("../src/admin/index.cjs");

function fixture(t, { omitBoolean = false, protectedParent = false } = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "servicenow-records-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const records = new Map(), writes = [];
  const fetchImpl = async (raw, options) => {
    const url = new URL(raw), [, , , , table, id] = url.pathname.split("/");
    const query = url.searchParams.get("sysparm_query") || "";
    let rows = [];
    if (table === "sys_db_object") {
      const name = query.slice(5);
      rows = [{ name, "super_class.name": protectedParent && name !== "sys_user" ? "sys_user" : "" }];
    } else if (table === "sys_dictionary") {
      const name = query.match(/^nameIN([^,^]+)/)[1];
      const title = name === "kb_knowledge_base" ? "title" : "short_description";
      rows = [{ sys_id: "1".repeat(32), name, element: title, internal_type: "string", mandatory: "true",
        default_value: "", max_length: "160", display: "true" },
      { sys_id: "2".repeat(32), name, element: "active", internal_type: "boolean", mandatory: "false",
        default_value: "", max_length: "", display: "false" }];
    } else if (["sys_choice", "sys_data_policy2"].includes(table)) rows = [];
    else if (options.method === "GET") rows = records.has(table) ? [records.get(table)] : [];
    else {
      writes.push({ method: options.method, table, values: options.body ? JSON.parse(options.body) : undefined });
      if (options.method === "POST") {
        const row = { ...JSON.parse(options.body), sys_id: "a".repeat(32), sys_mod_count: "0" };
        if (omitBoolean) delete row.active;
        records.set(table, row);
        return Response.json({ result: row });
      }
      if (options.method === "PATCH") {
        Object.assign(records.get(table), JSON.parse(options.body), { sys_mod_count: "1" });
        return Response.json({ result: records.get(table) });
      }
      assert.equal(id, "a".repeat(32));
      records.delete(table);
      return new Response(null, { status: 204 });
    }
    return Response.json({ result: rows });
  };
  return { writes, admin: createAdmin({ instance: "https://service.example.invalid",
    username: "operator", password: "synthetic-only", directory, fetchImpl }) };
}
test("incident, knowledge base and article writes follow discovered fields without injecting business defaults", async (t) => {
  const { admin, writes } = fixture(t);
  for (const [table, field] of [["incident", "short_description"], ["kb_knowledge_base", "title"], ["kb_knowledge", "short_description"]]) {
    const values = { [field]: "Supplied title" };
    const created = await admin.handle("local_record_create", { table, values, operation_id: randomUUID() });
    assert.deepEqual(writes.at(-1).values, values);
    const updated = await admin.handle("local_record_update", { table, sys_id: created.sys_id,
      values: { [field]: "Changed title" }, expected_mod_count: "0", operation_id: randomUUID() });
    assert.equal(updated.record[field], "Changed title");
    const deleted = await admin.handle("local_record_delete", { table, sys_id: created.sys_id,
      expected_mod_count: "1", operation_id: randomUUID(), confirm: true });
    assert.equal(deleted.absent, true);
    assert.equal(deleted.cleanup_complete, false);
  }
});
test("missing false readback remains uncertain and a new UUID cannot replay creation", async (t) => {
  const { admin, writes } = fixture(t, { omitBoolean: true });
  const args = { table: "incident", values: { short_description: "Supplied", active: false }, operation_id: randomUUID() };
  await assert.rejects(admin.handle("local_record_create", args), /not confirmed/);
  await assert.rejects(admin.handle("local_record_create", { ...args, operation_id: randomUUID() }), /unresolved/);
  assert.equal(writes.length, 1);
});
test("generic writes cannot bypass account protection through a custom inherited table", async (t) => {
  const { admin, writes } = fixture(t, { protectedParent: true });
  await assert.rejects(admin.handle("local_record_create", {
    table: "u_extended_user", values: { short_description: "Attempt" }, operation_id: randomUUID(),
  }), /semantic administration/);
  assert.equal(writes.length, 0);
});
