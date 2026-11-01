const assert = require("node:assert/strict");
const { test } = require("node:test");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { randomUUID } = require("node:crypto");
const { createAdmin } = require("../src/admin/index.cjs");

test("business CRUD uses source schema, guards versions and retains consumed operations across restart", async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "servicenow-admin-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const records = new Map();
  const id = "a".repeat(32);
  const requests = [];
  const fetchImpl = async (url, options) => {
    const parsed = new URL(url);
    const [, table, recordId] = parsed.pathname.split("/table/");
    const tableName = table.split("/")[0];
    requests.push({ table: tableName, method: options.method });
    let result;
    if (tableName === "sys_db_object") result = [{ name: "incident", label: "Incident", "super_class.name": "" }];
    else if (tableName === "sys_dictionary") result = ["short_description", "number"].map((element, index) => ({
      sys_id: String(index + 1).repeat(32), name: "incident", element, internal_type: "string",
      mandatory: element === "short_description" ? "true" : "false", read_only: "false",
      default_value: "", reference: "", max_length: "160", display: "true", choice: "0",
    }));
    else if (["sys_choice", "sys_data_policy2"].includes(tableName)) result = [];
    else if (tableName === "incident" && options.method === "POST") {
      result = { ...JSON.parse(options.body), sys_id: id, sys_mod_count: "0" };
      records.set(id, result);
    } else if (tableName === "incident" && options.method === "PATCH") {
      result = { ...records.get(id), ...JSON.parse(options.body), sys_mod_count: "1" };
      records.set(id, result);
    } else if (tableName === "incident" && options.method === "DELETE") {
      records.delete(id);
      return new Response(null, { status: 204 });
    } else if (tableName === "incident") result = [...records.values()];
    else throw new Error("Unexpected synthetic request");
    return Response.json({ result });
  };
  const config = { instance: "https://service.example.invalid", username: "operator", password: "synthetic-only", directory, fetchImpl };
  let admin = createAdmin(config);
  const operation_id = randomUUID();
  const created = await admin.handle("local_record_create", {
    table: "incident", values: { short_description: "Synthetic" }, operation_id,
  });
  assert.equal(created.record.short_description, "Synthetic");
  assert.equal(created.record.sys_mod_count, "0");
  assert.equal(created.source_url, `https://service.example.invalid/incident.do?sys_id=${id}`);
  admin = createAdmin(config);
  await assert.rejects(admin.handle("local_record_create", {
    table: "incident", values: { short_description: "Synthetic" }, operation_id,
  }), /already attempted/);
  await assert.rejects(admin.handle("local_record_update", {
    table: "incident", sys_id: id, values: { short_description: "Changed" },
    operation_id: randomUUID(), expected_mod_count: "9",
  }), /changed/);
  assert.equal(requests.filter(r => r.method === "PATCH").length, 0);
  const updated = await admin.handle("local_record_update", {
    table: "incident", sys_id: id, values: { short_description: "Changed" },
    operation_id: randomUUID(), expected_mod_count: "0",
  });
  assert.equal(updated.record.short_description, "Changed");
  const deleted = await admin.handle("local_record_delete", {
    table: "incident", sys_id: id, operation_id: randomUUID(), expected_mod_count: "1", confirm: true,
  });
  assert.equal(deleted.absent, true);
  assert.equal(requests.filter(r => r.method === "POST").length, 1);
});
