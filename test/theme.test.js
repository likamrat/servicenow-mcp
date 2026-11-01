const assert = require("node:assert/strict");
const { test } = require("node:test");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { randomUUID, createHash } = require("node:crypto");
const { createAdmin } = require("../src/admin/index.cjs");
const sha = value => createHash("sha256").update(value).digest("hex");

test("paired style partial writes retain originals and restore exactly without replay or unrelated edits", async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "servicenow-theme-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const theme = "a".repeat(32), colors = "b".repeat(32), shape = "c".repeat(32);
  const originalColors = '{ "base": {"--now-color--primary":"1, 2, 3"},\n "properties":{"--now-color_brand--primary":"1, 2, 3","untouched":true} }\n';
  const originalShape = '{ "properties": { "--now-actionable--border-radius": "2px", "untouched": 42 } }\n';
  const meta = { sys_scope: "global", sys_created_by: "operator", sys_mod_count: "0" };
  const styles = new Map([
    [colors, { ...meta, sys_id: colors, type: "core", style: originalColors }],
    [shape, { ...meta, sys_id: shape, type: "core", style: originalShape }],
  ]);
  let denyShape = true, writes = 0;
  const fetchImpl = async (raw, options) => {
    const url = new URL(raw);
    const [, , , , table, id] = url.pathname.split("/");
    const query = url.searchParams.get("sysparm_query");
    if (options.method === "PATCH") {
      writes++;
      if (id === shape && denyShape) return Response.json({ error: { message: "Policy denied" } }, { status: 403 });
      const current = styles.get(id);
      Object.assign(current, JSON.parse(options.body), { sys_mod_count: String(Number(current.sys_mod_count) + 1) });
      return Response.json({ result: current });
    }
    let rows = [];
    if (table === "sys_ux_theme") rows = [{ ...meta, sys_id: theme }];
    if (table === "sys_ux_style") rows = [styles.get(query.slice(7))];
    if (table === "m2m_theme_style") rows = [{ sys_id: "d".repeat(32), theme, style: query.slice(6) }];
    return Response.json({ result: rows });
  };
  const admin = createAdmin({ instance: "https://service.example.invalid", username: "operator", password: "synthetic-only", directory, fetchImpl });
  const operation_id = randomUUID();
  const args = { theme_id: theme, expected_theme_mod_count: "0", operation_id,
    colors: { style_id: colors, expected_mod_count: "0", expected_sha256: sha(originalColors),
      expected_primary: "1, 2, 3", expected_brand_primary: "1, 2, 3", primary_rgb: "4, 5, 6" },
    shape: { style_id: shape, expected_mod_count: "0", expected_sha256: sha(originalShape), expected_radius: "2px", radius: "8px" } };
  await assert.rejects(admin.handle("local_admin_patch_theme_style_pair", args), error => {
    assert.equal(error.outcome.status, "partial_or_uncertain");
    assert.equal(error.outcome.snapshot_id, operation_id);
    assert.equal(error.outcome.steps[0].status, "confirmed");
    return true;
  });
  assert.equal(writes, 2);
  await assert.rejects(admin.handle("local_admin_patch_theme_style_pair", { ...args, operation_id: randomUUID() }), /unresolved/);
  denyShape = false;
  const result = await admin.handle("local_admin_restore_theme_style_pair", {
    snapshot_id: operation_id, operation_id: randomUUID(), expected_theme_mod_count: "0",
    colors: { expected_mod_count: "1", expected_sha256: sha(styles.get(colors).style) },
    shape: { expected_mod_count: "0", expected_sha256: sha(styles.get(shape).style) },
  });
  assert.equal(result.rawRestorationExact, true);
  assert.equal(styles.get(colors).style, originalColors);
  assert.equal(styles.get(shape).style, originalShape);
  assert.equal(writes, 3);
  const receipt = await admin.handle("local_operation_status", { operation_id });
  assert.equal(receipt.entries.at(-1).status, "resolved_by_restore");
  await assert.rejects(admin.handle("local_admin_patch_theme_style_pair", args), /already attempted/);
});
