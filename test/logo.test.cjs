const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { randomUUID, createHash } = require("node:crypto");
const { deflateSync, crc32 } = require("node:zlib");
const { createLogoRestoreOperations, tools, applyTools } = require("../src/admin/logo-restore.cjs");
const hash = (value) => createHash("sha256").update(value).digest("hex");
function png() {
  const chunk = (type, bytes) => {
    const header = Buffer.alloc(8); header.writeUInt32BE(bytes.length); header.write(type, 4);
    const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(Buffer.concat([Buffer.from(type), bytes])));
    return Buffer.concat([header, bytes, crc]);
  };
  const header = Buffer.alloc(13); header.writeUInt32BE(2); header.writeUInt32BE(1, 4); header[8] = 8; header[9] = 6;
  return Buffer.concat([Buffer.from([137,80,78,71,13,10,26,10]), chunk("IHDR", header),
    chunk("IDAT", deflateSync(Buffer.alloc(9))), chunk("IEND", Buffer.alloc(0))]);
}
function fixture(t, { afterCreate } = {}) {
  const directory = fs.mkdtempSync(path.join(require("node:os").tmpdir(), "modern-logo-test-"));
  t.after(() => fs.rmSync(directory, { recursive: true }));
  const ids = Object.fromEntries(["theme","customization","style","link","asset","attachment","fontStyle"].map((key, i) => [key, (i + 1).toString(16).repeat(32)]));
  const meta = { sys_scope: "global", sys_created_by: "unit-principal", sys_mod_count: "0" };
  const styleRaw = '{\n  "properties": { "unrelated": "exact original" }\n}';
  const props = '{\n  "position": "header_logo"\n}';
  const bytes = png();
  const rows = new Map([
    ["sys_ux_theme", [{ ...meta, sys_id: ids.theme }]],
    ["sys_ux_theme_customization", [{ ...meta, sys_id: ids.customization, theme: ids.theme }]],
    ["sys_ux_style", [{ ...meta, sys_id: ids.style, type: "core", style: styleRaw }]],
    ["sys_ux_theme_asset", [{ ...meta, sys_id: ids.asset, category: "image" }]],
    ["sys_attachment", [{ sys_id: ids.attachment, table_name: "sys_ux_theme_asset", table_sys_id: ids.asset,
      content_type: "image/png", state: "available", size_bytes: String(bytes.length), image_width: "2", image_height: "1", hash: hash(bytes), sys_mod_count: "2" }]],
    ["m2m_theme_style", [
      { sys_id: "a".repeat(32), theme: ids.theme, style: ids.style, sys_mod_count: "0" },
      { sys_id: "b".repeat(32), theme: ids.theme, style: ids.fontStyle, sys_mod_count: "0" },
    ]],
    ["m2m_style_asset", [
      { ...meta, sys_id: ids.link, style: ids.style, asset: ids.asset, properties: props, sys_overrides: "" },
      ...Array.from({ length: 17 }, (_, i) => ({ ...meta, sys_id: (100 + i).toString(16).padStart(32, "0"), style: ids.fontStyle,
        asset: (200 + i).toString(16).padStart(32, "0"), properties: JSON.stringify({ font: i }), sys_overrides: "" })),
    ]],
  ]);
  const writes = [], events = [], attempted = new Set();
  let denial = false, lose = false, destroyAsset = false;
  let activeLinkId = ids.link;
  const list = async (table, query, fields, limit) => (rows.get(table) || []).filter((row) => query.split("^").every((condition) => {
    const match = condition.match(/^(\w+?)(IN|=)(.*)$/);
    return match && (match[2] === "IN" ? match[3].split(",").includes(row[match[1]]) : String(row[match[1]] ?? "") === match[3]);
  })).slice(0, limit).map((row) => Object.fromEntries(fields.split(",").filter((key) => Object.hasOwn(row, key)).map((key) => [key, row[key]])));
  const module = createLogoRestoreOperations({ instance: "https://service.example.invalid", list, principal: "unit-principal", directory,
    request: async (method, table, params, values, id) => {
      writes.push({ method, table, values, id });
      assert.equal(table, "m2m_style_asset");
      if (denial) { const error = new Error("Source denied"); error.diagnostic = { status: 403, detail: "ACL denied" }; throw error; }
      if (method === "POST") {
        assert.deepEqual(Object.keys(values).sort(), ["asset", "properties", "style"]);
        assert.equal(values.style, ids.style); assert.equal(values.asset, ids.asset);
        assert.deepEqual(JSON.parse(values.properties), { position: "header_logo" });
        activeLinkId = "8".repeat(32);
        rows.get(table).push({ ...meta, sys_id: activeLinkId, style: ids.style, asset: ids.asset, properties: values.properties, sys_overrides: "" });
        if (afterCreate) afterCreate(rows.get(table).at(-1), rows);
        if (lose) throw new Error("Response lost after creation");
        return { result: { sys_id: activeLinkId, sys_mod_count: "0" } };
      }
      assert.equal(method, "DELETE"); assert.equal(id, activeLinkId); assert.equal(values, undefined);
      rows.set(table, rows.get(table).filter((row) => row.sys_id !== id));
      if (destroyAsset) rows.set("sys_ux_theme_asset", []);
      if (lose) throw new Error("Response lost after deletion");
      return null;
    },
    downloadAttachment: async (id, max) => { assert.equal(id, ids.attachment); assert.equal(max, 120000); return bytes; },
    record: (entry) => events.push(entry), isAttempted: (id) => attempted.has(id),
    claim: (id, entry) => { assert.ok(!attempted.has(id)); attempted.add(id); events.push({ ...entry, operation_id: id, status: "attempt" }); },
  });
  const identity = (key, version = "0") => ({ sys_id: ids[key], expected_mod_count: version });
  const args = { operation_id: randomUUID(), confirm: true, theme: identity("theme"), customization: identity("customization"),
    style: { ...identity("style"), expected_sha256: hash(styleRaw) }, link: { ...identity("link"), expected_properties_sha256: hash(props) },
    asset: identity("asset"), attachment: { ...identity("attachment", "2"), expected_sha256: hash(bytes) } };
  return { module, args, ids, rows, writes, events, deny: () => { denial = true; }, lose: () => { lose = true; }, destroy: () => { destroyAsset = true; } };
}
test("modern unlink adopts source/UI link and retains PNG, asset, raw style and seventeen unrelated font links", async (t) => {
  const f = fixture(t);
  const result = await f.module.handle(tools[0].name, f.args);
  assert.equal(result.status, "confirmed");
  assert.equal(result.linkAbsent, true);
  assert.equal(result.retainedAssetAndBinary, true);
  assert.equal(result.unrelatedBindingCount, 17);
  assert.match(result.association_origin, /not claimed MCP-created/);
  assert.equal(f.writes.length, 1);
  assert.equal(f.rows.get("sys_ux_theme_asset").length, 1);
  assert.equal(f.rows.get("sys_attachment").length, 1);
  await assert.rejects(f.module.handle(tools[0].name, f.args), /already attempted/);
});
test("stale hashes, shared assets and override references prevent unlink before source write", async (t) => {
  const f = fixture(t);
  const stale = structuredClone(f.args); stale.link.expected_properties_sha256 = "a".repeat(64);
  await assert.rejects(f.module.handle(tools[0].name, stale), /raw selector/);
  f.rows.get("m2m_style_asset").push({ sys_id: "c".repeat(32), style: f.ids.fontStyle, asset: f.ids.asset, sys_mod_count: "0" });
  await assert.rejects(f.module.handle(tools[0].name, f.args), /no longer exclusive/);
  f.rows.get("m2m_style_asset").pop();
  f.rows.get("m2m_style_asset").push({ sys_id: "d".repeat(32), style: f.ids.fontStyle, asset: "e".repeat(32), sys_overrides: f.ids.link });
  await assert.rejects(f.module.handle(tools[0].name, f.args), /overrides/);
  assert.equal(f.writes.length, 0);
});
test("source403 is terminal for the unlink and never falls back to asset/file deletion", async (t) => {
  const f = fixture(t); f.deny();
  await assert.rejects(f.module.handle(tools[0].name, f.args), (error) => error.outcome.status === "rejected" && error.diagnostic.status === 403);
  assert.equal(f.writes.length, 1);
  await assert.rejects(f.module.handle(tools[0].name, f.args), /already attempted/);
  assert.equal(f.writes.length, 1);
  assert.equal(f.rows.get("m2m_style_asset").length, 18);
});
test("lost response reconciles only through reads, while unexpected retained-asset loss remains explicit", async (t) => {
  const f = fixture(t); f.lose();
  const result = await f.module.handle(tools[0].name, f.args);
  assert.equal(result.reconciledAfterError, true);
  assert.equal(f.writes.length, 1);
  const g = fixture(t); g.destroy();
  await assert.rejects(g.module.handle(tools[0].name, g.args), (error) => error.outcome.status === "partial_or_uncertain" && error.outcome.linkAbsent);
  assert.equal(g.writes.length, 1);
});
test("modern apply creates only one native link and its removal identifies actual MCP provenance", async (t) => {
  const f = fixture(t);
  f.rows.set("m2m_style_asset", f.rows.get("m2m_style_asset").filter((row) => row.sys_id !== f.ids.link));
  const args = structuredClone(f.args); delete args.link;
  const created = await f.module.handle(applyTools[0].name, args);
  assert.equal(created.status, "confirmed");
  assert.match(created.association_origin, /MCP-created/);
  assert.equal(created.unrelatedBindingCount, 17);
  assert.equal(f.writes.length, 1);
  assert.equal(f.writes[0].method, "POST");
  const removed = await f.module.handle(tools[0].name, { ...f.args, operation_id: randomUUID(),
    link: { sys_id: created.link_id, expected_mod_count: created.link_mod_count, expected_properties_sha256: created.link_properties_sha256 } });
  assert.equal(removed.status, "confirmed");
  assert.equal(removed.apply_operation_id, args.operation_id);
  assert.match(removed.association_origin, /MCP-created/);
  assert.equal(f.rows.get("m2m_style_asset").length, 17);
  assert.equal(f.rows.get("sys_attachment").length, 1);
  assert.equal(f.rows.get("sys_ux_theme_asset").length, 1);
});
test("modern apply refuses existing bindings and preserves source denial without uploading or recreating", async (t) => {
  const f = fixture(t);
  const args = structuredClone(f.args); delete args.link;
  await assert.rejects(f.module.handle(applyTools[0].name, args), /already has an association/);
  assert.equal(f.writes.length, 0);
  f.rows.set("m2m_style_asset", f.rows.get("m2m_style_asset").filter((row) => row.sys_id !== f.ids.link));
  f.deny();
  await assert.rejects(f.module.handle(applyTools[0].name, args), (error) => error.outcome.status === "rejected" && error.diagnostic.status === 403);
  assert.equal(f.writes.length, 1);
  await assert.rejects(f.module.handle(applyTools[0].name, args), /already attempted/);
});
test("lost apply response uses read-only reconciliation and never claims returned-ID provenance", async (t) => {
  const f = fixture(t);
  f.rows.set("m2m_style_asset", f.rows.get("m2m_style_asset").filter((row) => row.sys_id !== f.ids.link));
  const args = structuredClone(f.args); delete args.link;
  f.lose();
  const result = await f.module.handle(applyTools[0].name, args);
  assert.equal(result.status, "confirmed");
  assert.equal(result.reconciledAfterError, true);
  assert.equal(result.returnedLinkId, undefined);
  assert.match(result.association_origin, /response ID unavailable/);
  assert.equal(result.unrelatedBindingCount, 17);
  await assert.rejects(f.module.handle(applyTools[0].name, args), /already attempted/);
  assert.equal(f.writes.length, 1);
});
test("a denied apply cannot become confirmed from matching observed state or be repeated under another UUID", async (t) => {
  const f = fixture(t, { afterCreate() {
    const error = new Error("Source rejected; matching state has uncertain attribution");
    error.diagnostic = { status: 403, detail: "ACL denied" };
    throw error;
  } });
  f.rows.set("m2m_style_asset", f.rows.get("m2m_style_asset").filter((row) => row.sys_id !== f.ids.link));
  const args = structuredClone(f.args); delete args.link;
  await assert.rejects(f.module.handle(applyTools[0].name, args), (error) => {
    assert.equal(error.outcome.status, "partial_or_uncertain");
    assert.deepEqual(error.outcome.observedLinkIds, ["8".repeat(32)]);
    assert.equal(error.diagnostic.status, 403);
    return true;
  });
  await assert.rejects(f.module.handle(applyTools[0].name, { ...args, operation_id: randomUUID() }), /unresolved/);
  assert.equal(f.writes.length, 1);
});
test("missing returned-link guards or changed unrelated bindings stay partial with no automatic cleanup", async (t) => {
  for (const change of [
    (link) => { delete link.sys_overrides; },
    (link) => { delete link.sys_mod_count; },
    (_link, rows) => { rows.get("m2m_style_asset")[0].properties = '{"font":"changed"}'; },
  ]) {
    const f = fixture(t, { afterCreate: change });
    f.rows.set("m2m_style_asset", f.rows.get("m2m_style_asset").filter((row) => row.sys_id !== f.ids.link));
    const args = structuredClone(f.args); delete args.link;
    await assert.rejects(f.module.handle(applyTools[0].name, args), (error) => {
      assert.equal(error.outcome.status, "partial_or_uncertain");
      assert.equal(error.outcome.returnedLinkId, "8".repeat(32));
      return true;
    });
    await assert.rejects(f.module.handle(applyTools[0].name, { ...args, operation_id: randomUUID() }), /unresolved/);
    assert.equal(f.writes.length, 1);
    assert.equal(f.rows.get("sys_ux_theme_asset").length, 1);
    assert.equal(f.rows.get("sys_attachment").length, 1);
  }
});
test("the unpublished target can be guarded before creating a new image asset", async (t) => {
  const f = fixture(t);
  f.rows.set("sys_ux_theme_asset", []);
  const target = await f.module.guards.target(f.args);
  assert.deepEqual(target, {
    theme_mod_count: "0", customization_mod_count: "0",
    style_mod_count: "0", style_sha256: f.args.style.expected_sha256,
  });
  f.rows.get("sys_ux_theme_customization")[0].sys_mod_count = "1";
  await assert.rejects(f.module.guards.target(f.args), /current owned\/global version/);
  assert.equal(f.writes.length, 0);
});
