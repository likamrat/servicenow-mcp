const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { randomUUID, createHash } = require("node:crypto");
const { deflateSync, crc32 } = require("node:zlib");
const { createLogoStaging } = require("../src/admin/staging.cjs");
const { inspectPng } = require("../src/admin/png.cjs");
const { createLogoImportOperations, createLogoImportPolicy, tools } = require("../src/admin/logo-import.cjs");
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const canonical = value => Array.isArray(value) ? value.map(canonical) : value && typeof value === "object"
  ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;
function png() {
  const chunk = (type, data) => {
    const header = Buffer.alloc(8); header.writeUInt32BE(data.length); header.write(type, 4);
    const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(Buffer.concat([Buffer.from(type), data])));
    return Buffer.concat([header, data, crc]);
  };
  const header = Buffer.alloc(13); header.writeUInt32BE(2); header.writeUInt32BE(1, 4); header[8] = 8; header[9] = 6;
  return Buffer.concat([Buffer.from([137,80,78,71,13,10,26,10]), chunk("IHDR", header),
    chunk("IDAT", deflateSync(Buffer.alloc(9))), chunk("IEND", Buffer.alloc(0))]);
}
function fixture(t) {
  const directory = fs.mkdtempSync(path.join(require("node:os").tmpdir(), "import-test-"));
  t.after(() => fs.rmSync(directory, { recursive: true }));
  const bytes = png(), sourcePath = path.join(directory, "original.png");
  fs.writeFileSync(sourcePath, bytes);
  const staging = createLogoStaging(path.join(directory, "staged"));
  const manifest = staging.stage({ sourcePath, expected_sha256: hash(bytes), file_name: "original.png" });
  const ids = { theme: "1".repeat(32), customization: "2".repeat(32), style: "3".repeat(32),
    asset: "4".repeat(32), attachment: "5".repeat(32) };
  const identity = (sys_id) => ({ sys_id, expected_mod_count: "0" });
  const args = { operation_id: randomUUID(), confirm: true, theme: identity(ids.theme),
    customization: identity(ids.customization), style: { ...identity(ids.style), expected_sha256: hash("{}") },
    staging: { staging_id: manifest.staging_id, expected_sha256: manifest.sha256 } };
  args.asset_name = `qualified-logo-${args.operation_id}`;
  const rows = new Map(), writes = [], events = [], attempted = new Set();
  const snapshot = { theme_mod_count: "0", customization_mod_count: "0", style_mod_count: "0", style_sha256: args.style.expected_sha256 };
  const bindings = { themeStyles: [{ sys_id: "6".repeat(32), theme: ids.theme, style: ids.style, sys_mod_count: "0" }], styleAssets: [] };
  const options = {
    instance: "https://service.example.invalid", directory, principal: "unit-principal", staging,
    checkPolicy: async () => ({ status: "qualified", fingerprint: "a".repeat(64), assetNameMaxLength: 80 }),
    list: async (table, query, fields, limit) => (rows.get(table) || []).filter(row =>
      query.split("^").every(term => { const i = term.indexOf("="); return i > 0 && String(row[term.slice(0, i)] ?? "") === term.slice(i + 1); })
    ).slice(0, limit).map(row => Object.fromEntries(fields.split(",").filter(key => Object.hasOwn(row, key)).map(key => [key, row[key]]))),
    request: async (method, table, _params, values) => {
      writes.push({ method, table, values });
      assert.equal(method, "POST"); assert.equal(table, "sys_ux_theme_asset");
      rows.set(table, [{ ...values, sys_id: ids.asset, sys_scope: "global", sys_domain: "global",
        sys_class_name: "sys_ux_theme_asset", sys_overrides: "", sys_created_by: "unit-principal", sys_mod_count: "0" }]);
      return { result: { sys_id: ids.asset } };
    },
    uploadAttachment: async prepared => {
      const url = new URL(prepared.url);
      assert.equal(url.origin, "https://service.example.invalid");
      assert.equal(url.pathname, "/api/now/attachment/file");
      assert.equal(url.searchParams.get("table_name"), "sys_ux_theme_asset");
      assert.equal(url.searchParams.get("table_sys_id"), ids.asset);
      assert.equal(url.searchParams.get("file_name"), `${args.asset_name}.png`);
      assert.deepEqual(prepared.body, bytes);
      writes.push({ method: "POST", table: "Attachment API" });
      rows.set("sys_attachment", [{ sys_id: ids.attachment, table_name: "sys_ux_theme_asset", table_sys_id: ids.asset,
        file_name: `${args.asset_name}.png`, state: "available", content_type: "image/png", size_bytes: String(bytes.length),
        image_width: "2", image_height: "1", hash: hash(bytes), sys_mod_count: "0" }]);
      return { result: { sys_id: ids.attachment } };
    },
    guards: {
      target: async () => structuredClone(snapshot),
      bindings: async () => structuredClone(bindings),
      parents: async input => {
        assert.equal(input.asset.sys_id, ids.asset);
        assert.equal(input.asset.expected_mod_count, "0");
        return { ...snapshot, asset_mod_count: "0" };
      },
      attachment: async input => {
        assert.equal(input.attachment.sys_id, ids.attachment);
        assert.equal(input.attachment.expected_sha256, hash(bytes));
        const image = inspectPng(bytes);
        return { sys_id: ids.attachment, sys_mod_count: "0", sha256: image.sha256,
          bytes: image.bytes, width: image.width, height: image.height };
      },
    },
    record: event => events.push(event),
    claim: (id, meta) => { assert.ok(!attempted.has(id)); attempted.add(id); events.push({ ...meta, operation_id: id, status: "attempt" }); },
    isAttempted: id => attempted.has(id),
  };
  return { options, args, ids, rows, writes, events, snapshot, bindings, directory, bytes };
}
test("fresh import creates a distinct image parent and uploads the exact staged PNG once without applying it", async (t) => {
  const f = fixture(t);
  const module = createLogoImportOperations(f.options);
  const result = await module.handle(tools[0].name, f.args);
  assert.equal(result.status, "confirmed");
  assert.equal(result.source_write_confirmed, true);
  assert.equal(result.asset.sys_id, f.ids.asset);
  assert.equal(result.attachment.sys_id, f.ids.attachment);
  assert.equal(result.attachment.expected_sha256, hash(f.bytes));
  assert.equal(result.applied, false);
  assert.equal(f.writes.length, 2);
  assert.equal(f.writes[0].values.name, f.args.asset_name);
  assert.equal(f.writes[0].values.category, "image");
  assert.equal(f.writes[0].values.sys_scope, "global");
  assert.equal(result.stages.asset.status, "confirmed");
  assert.equal(result.stages.attachment.status, "confirmed");
  await assert.rejects(module.handle(tools[0].name, f.args), /already attempted/);
  assert.equal(f.writes.length, 2);
});
test("changed native schema or insert rules block the import before creating any source record", async (t) => {
  const f = fixture(t);
  const schema = { table: "sys_ux_theme_asset", lineage: ["sys_ux_theme_asset", "sys_metadata"],
    fields: {
      name: { type: "string", mandatory: true, readOnlyMetadata: false, maxLength: 400 },
      category: { type: "string", mandatory: true, readOnlyMetadata: false, choices: [{ value: "image" }] },
      sys_scope: { type: "reference", reference: "sys_scope", readOnlyMetadata: false },
    }, conditionalPolicies: [] };
  const current = structuredClone(schema);
  let rules = [];
  f.options.checkPolicy = createLogoImportPolicy({ qualified: {
    schema_sha256: hash(JSON.stringify(canonical(schema))), rules_sha256: hash("[]"),
  },
    discover: async () => current, list: async () => rules });
  assert.equal((await f.options.checkPolicy()).status, "qualified");
  current.fields.name.maxLength = 399;
  await assert.rejects(createLogoImportOperations(f.options).handle(tools[0].name, f.args), /schema.*changed/i);
  current.fields.name.maxLength = 400;
  rules = [{ sys_id: "f".repeat(32) }];
  await assert.rejects(createLogoImportOperations(f.options).handle(tools[0].name, f.args), /rule/i);
  assert.equal(f.writes.length, 0);
});
test("policy drift after the new asset retains its confirmed ID and never sends the binary", async (t) => {
  const f = fixture(t);
  const check = f.options.checkPolicy;
  let checks = 0;
  f.options.checkPolicy = async () => ({ ...await check(), fingerprint: (++checks === 1 ? "a" : "b").repeat(64) });
  const module = createLogoImportOperations(f.options);
  await assert.rejects(module.handle(tools[0].name, f.args), error => {
    assert.equal(error.outcome.asset.sys_id, f.ids.asset);
    assert.equal(error.outcome.stages.asset.status, "confirmed");
    assert.equal(error.outcome.stages.attachment.status, "not_attempted");
    assert.equal(error.outcome.status, "partial_or_uncertain");
    return true;
  });
  assert.equal(f.writes.length, 1);
});
test("authentication or access rejection stays explicit at either stage, even when matching source state exists", async (t) => {
  for (const stage of ["asset", "attachment"]) for (const status of [401, 403]) {
    const f = fixture(t);
    const key = stage === "asset" ? "request" : "uploadAttachment", send = f.options[key], list = f.options.list;
    let failed = false, readsAfterFailure = 0;
    f.options[key] = async (...args) => {
      await send(...args);
      failed = true;
      const error = new Error("Source rejected the request");
      error.diagnostic = { status };
      throw error;
    };
    f.options.list = async (...args) => { if (failed) readsAfterFailure++; return list(...args); };
    const module = createLogoImportOperations(f.options);
    await assert.rejects(module.handle(tools[0].name, f.args), error => {
      assert.equal(error.outcome.source_write_confirmed, false);
      assert.equal(error.outcome.stages[stage].status, "request_rejected");
      assert.equal(error.diagnostic.status, status);
      if (stage === "attachment") assert.equal(error.outcome.stages.asset.status, "confirmed");
      else assert.equal(error.outcome.stages.attachment.status, "not_attempted");
      return true;
    });
    assert.equal(readsAfterFailure, 0);
    await assert.rejects(module.handle(tools[0].name, f.args), /already attempted/);
    const next = randomUUID();
    await assert.rejects(createLogoImportOperations({ ...f.options, isAttempted: () => false }).handle(tools[0].name,
      { ...f.args, operation_id: next, asset_name: `qualified-logo-${next}` }), /unresolved/);
    assert.equal(f.writes.length, stage === "asset" ? 1 : 2);
  }
});
test("lost responses retain read-only observations, never advance or replay, and preserve a later authentication denial", async (t) => {
  for (const stage of ["asset", "attachment"]) for (const denyRead of [false, true]) {
    const f = fixture(t), key = stage === "asset" ? "request" : "uploadAttachment";
    const send = f.options[key], list = f.options.list;
    let failed = false, reconciliations = 0;
    f.options[key] = async (...args) => {
      await send(...args); failed = true;
      const error = new Error("Source response lost"); error.diagnostic = { status: 500 }; throw error;
    };
    f.options.list = async (...args) => {
      if (failed) {
        reconciliations++;
        if (denyRead) { const error = new Error("Authentication required"); error.diagnostic = { status: 401 }; throw error; }
      }
      return list(...args);
    };
    const module = createLogoImportOperations(f.options);
    await assert.rejects(module.handle(tools[0].name, f.args), error => {
      assert.equal(error.outcome.source_write_confirmed, false);
      assert.equal(error.outcome.status, "partial_or_uncertain");
      if (denyRead) {
        assert.deepEqual(error.outcome.diagnostics.map(d => d.status), [500, 401]);
        assert.equal(error.diagnostic.status, 401);
      } else {
        assert.equal(error.outcome.stages[stage].observed_records[0].sys_id, f.ids[stage]);
      }
      return true;
    });
    assert.equal(reconciliations, 1);
    await assert.rejects(module.handle(tools[0].name, f.args), /already attempted/);
    assert.equal(f.writes.length, stage === "asset" ? 1 : 2);
  }
});
test("wrong ownership, attachment identity or changed target stops with returned IDs and no compensating writes", async (t) => {
  for (const change of ["owner", "parent", "hash", "target", "binary"]) {
    const f = fixture(t), key = change === "owner" ? "request" : "uploadAttachment", send = f.options[key];
    f.options[key] = async (...args) => {
      const response = await send(...args);
      if (change === "owner") f.rows.get("sys_ux_theme_asset")[0].sys_created_by = "someone-else";
      if (change === "parent") f.rows.get("sys_attachment")[0].table_sys_id = "f".repeat(32);
      if (change === "hash") f.rows.get("sys_attachment")[0].hash = "f".repeat(64);
      if (change === "target") f.snapshot.style_mod_count = "1";
      return response;
    };
    if (change === "binary") f.options.guards.attachment = async () => { throw new Error("Downloaded PNG does not match"); };
    await assert.rejects(createLogoImportOperations(f.options).handle(tools[0].name, f.args), error => {
      assert.equal(error.outcome.source_write_confirmed, false);
      assert.equal(error.outcome.stages.asset.returned_id, f.ids.asset);
      if (change !== "owner") assert.equal(error.outcome.stages.attachment.returned_id, f.ids.attachment);
      return true;
    });
    assert.equal(f.writes.length, change === "owner" ? 1 : 2);
    assert.equal(f.rows.get("sys_ux_theme_asset").length, 1);
  }
});
test("each transport observes its durable attempt and attachment transport has the verified returned parent", async (t) => {
  const f = fixture(t);
  for (const [key, stage] of [["request", "asset"], ["uploadAttachment", "attachment"]]) {
    const send = f.options[key];
    f.options[key] = async (...args) => {
      const receipt = JSON.parse(fs.readFileSync(path.join(f.directory, "logo-import-receipts", `${f.args.operation_id}.json`), "utf8"));
      assert.equal(receipt.stages[stage].status, "attempt");
      assert.equal(receipt.stages[stage].request_state, "attempt");
      assert.equal(receipt.staging_sha256, hash(f.bytes));
      if (stage === "attachment") {
        assert.equal(receipt.stages.asset.status, "confirmed");
        assert.equal(receipt.stages.asset.returned_id, f.ids.asset);
        assert.equal(receipt.stages.attachment.parent_id, f.ids.asset);
      }
      return send(...args);
    };
  }
  assert.equal((await createLogoImportOperations(f.options).handle(tools[0].name, f.args)).status, "confirmed");
});
test("unexpected Global-domain or override defaults prevent upload; native linking prevents an unapplied success claim", async (t) => {
  for (const change of ["domain", "override", "binding"]) {
    const f = fixture(t), key = change === "binding" ? "uploadAttachment" : "request", send = f.options[key];
    f.options[key] = async (...args) => {
      const result = await send(...args);
      if (change === "domain") f.rows.get("sys_ux_theme_asset")[0].sys_domain = "f".repeat(32);
      if (change === "override") f.rows.get("sys_ux_theme_asset")[0].sys_overrides = "e".repeat(32);
      if (change === "binding") f.rows.set("m2m_style_asset", [{ sys_id: "f".repeat(32), asset: f.ids.asset, style: "e".repeat(32) }]);
      return result;
    };
    await assert.rejects(createLogoImportOperations(f.options).handle(tools[0].name, f.args), error => {
      assert.equal(error.outcome.status, "partial_or_uncertain");
      assert.equal(error.outcome.stages.asset.returned_id, f.ids.asset);
      return true;
    });
    assert.equal(f.writes.length, change === "binding" ? 2 : 1);
  }
});
