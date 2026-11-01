const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { isDeepStrictEqual } = require("node:util");
const ID = /^[a-f0-9]{32}$/;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const HASH = /^[a-f0-9]{64}$/;
const PRIMARY = ["base", "--now-color--primary"];
const BRAND = ["properties", "--now-color_brand--primary"];
const RADIUS = ["properties", "--now-actionable--border-radius"];
const objectSchema = (properties, required = Object.keys(properties)) => ({ type: "object", properties, required, additionalProperties: false });
const id = { type: "string", pattern: ID.source };
const uuid = { type: "string", pattern: UUID.source };
const version = { type: "string", pattern: "^\\d+$" };
const hash = { type: "string", pattern: HASH.source };
const rgb = { type: "string", maxLength: 32, description: "Comma-separated decimal RGB channels, each 0 through 255. No CSS expression." };
const radius = { type: "string", maxLength: 32, description: "Nonnegative numeric CSS px string, such as 0px or 12px." };
const expected = { expected_mod_count: version, expected_sha256: hash };
const tools = [
  { name: "local_admin_patch_theme_style_pair",
    description: "BACKEND ADMIN: change a coherent primary color and actionable corner radius on two distinct, unshared core/global styles of an owned unpublished theme. Validates both raw hashes/versions and selected values before any write. Changes only existing base primary, matching brand primary, and actionable radius entries; all other raw JSON bytes are preserved. Saves exact originals for guarded restoration. Two source writes are not atomic: partial/uncertain errors include a snapshot reference and per-style outcomes. Does not publish or alter defaults/preferences.",
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false },
    inputSchema: objectSchema({ theme_id: id, expected_theme_mod_count: version, operation_id: uuid,
      colors: objectSchema({ style_id: id, ...expected, expected_primary: rgb, expected_brand_primary: rgb, primary_rgb: rgb }),
      shape: objectSchema({ style_id: id, ...expected, expected_radius: radius, radius }) }) },
  { name: "local_admin_restore_theme_style_pair",
    description: "BACKEND ADMIN: restore the exact raw originals from a prior paired-style snapshot. Requires actual latest theme/style versions and raw hashes. Rechecks ownership, unshared unpublished mapping and that current content is either original or this snapshot's intended patch; refuses unrelated drift. Does not blindly retry, publish, or change defaults/preferences. Partial outcomes are explicit.",
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false },
    inputSchema: objectSchema({ snapshot_id: uuid, operation_id: uuid, expected_theme_mod_count: version,
      colors: objectSchema(expected), shape: objectSchema(expected) }) },
];
const sha = (raw) => crypto.createHash("sha256").update(raw, "utf8").digest("hex");
function checkObject(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      Object.keys(value).some((key) => !fields.includes(key)) || fields.some((key) => value[key] === undefined))
    throw new Error("Missing or unexpected paired-style argument.");
}
function checkVersion(value) { if (typeof value !== "string" || !/^\d+$/.test(value)) throw new Error("A current source version string is required."); }
function checkHash(value) { if (typeof value !== "string" || !HASH.test(value)) throw new Error("A current raw SHA256 is required."); }
function checkRgb(value) {
  if (typeof value !== "string" || value.length > 32 || !/^\d{1,3}, *\d{1,3}, *\d{1,3}$/.test(value) ||
      value.split(",").some((v) => Number(v) > 255)) throw new Error("Primary color must be a literal comma-separated RGB value.");
}
function checkRadius(value) {
  if (typeof value !== "string" || value.length > 32 || !/^\d+(?:\.\d+)?px$/.test(value) ||
      !Number.isFinite(Number(value.slice(0, -2)))) throw new Error("Radius must be a nonnegative literal px value.");
}
function selected(raw, role) {
  const parsed = JSON.parse(raw);
  const paths = role === "colors" ? [PRIMARY, BRAND] : [RADIUS];
  return paths.map(([section, key]) => {
    if (!parsed || typeof parsed !== "object" || !parsed[section] || typeof parsed[section] !== "object" ||
        !Object.hasOwn(parsed[section], key) || typeof parsed[section][key] !== "string")
      throw new Error("A required existing style key is missing or not a string.");
    return parsed[section][key];
  });
}
function patchRaw(raw, changes) {
  JSON.parse(raw);
  let at = 0;
  const ranges = [];
  const skip = () => { while (/\s/.test(raw[at] || "") && at < raw.length) at++; };
  function stringToken() {
    const start = at++;
    while (at < raw.length) {
      if (raw[at] === "\\") { at += 2; continue; }
      if (raw[at++] === '"') return { start, end: at, value: JSON.parse(raw.slice(start, at)) };
    }
    throw new Error("Unterminated source JSON string.");
  }
  function visit(keys, depth = 0) {
    if (depth > 100) throw new Error("Source style JSON nesting is unsupported.");
    skip();
    if (raw[at] === "{") {
      at++; skip();
      while (raw[at] !== "}") {
        const key = stringToken(); skip(); at++;
        visit([...keys, key.value], depth + 1); skip();
        if (raw[at] !== ",") break;
        at++; skip();
      }
      at++;
    } else if (raw[at] === "[") {
      at++; skip(); let index = 0;
      while (raw[at] !== "]") {
        visit([...keys, index++], depth + 1); skip();
        if (raw[at] !== ",") break;
        at++; skip();
      }
      at++;
    } else if (raw[at] === '"') {
      const token = stringToken();
      const change = changes.find((item) => isDeepStrictEqual(item.path, keys));
      if (change) ranges.push({ ...token, replacement: JSON.stringify(change.value), key: JSON.stringify(keys) });
    } else {
      while (at < raw.length && !/[\s,\]}]/.test(raw[at])) at++;
    }
  }
  visit([]);
  for (const change of changes) if (ranges.filter((r) => r.key === JSON.stringify(change.path)).length !== 1)
    throw new Error("Selected style key is absent or duplicated; no patch built.");
  for (const range of ranges.sort((a, b) => b.start - a.start)) raw = raw.slice(0, range.start) + range.replacement + raw.slice(range.end);
  JSON.parse(raw);
  return raw;
}

function createThemeStyleOperations({ instance: INSTANCE, list, request, record, claim, isAttempted, principal, directory }) {
  const folder = path.join(directory, "theme-style-receipts");
  function save(file, value, exclusive = false) {
    fs.mkdirSync(folder, { recursive: true });
    const fd = fs.openSync(path.join(folder, file), exclusive ? "wx" : "w");
    try { fs.writeSync(fd, JSON.stringify(value)); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  }
  const scalar = (v) => v && typeof v === "object" ? v.value : v;
  async function getStyle(styleId) {
    if (!ID.test(styleId)) throw new Error("Invalid style sys_id.");
    const rows = await list("sys_ux_style", `sys_id=${styleId}`, "sys_id,name,type,sys_scope,sys_created_by,sys_mod_count,style", 2);
    if (rows.length !== 1 || rows[0].sys_id !== styleId || rows[0].type !== "core" ||
        scalar(rows[0].sys_scope) !== "global" || rows[0].sys_created_by !== principal || typeof rows[0].style !== "string")
      throw new Error("Style is not a uniquely readable, current-principal-owned core/global record.");
    return { id: styleId, version: rows[0].sys_mod_count, hash: sha(rows[0].style), raw: rows[0].style };
  }
  async function isolation(themeId, styleIds, expectedVersion) {
    if (!ID.test(themeId) || styleIds.length !== 2 || new Set(styleIds).size !== 2 || styleIds.some((v) => !ID.test(v)))
      throw new Error("Supply one theme and two distinct source style IDs.");
    const roots = await list("sys_ux_theme", `sys_id=${themeId}`, "sys_id,sys_scope,sys_created_by,sys_mod_count", 2);
    if (roots.length !== 1 || roots[0].sys_created_by !== principal || scalar(roots[0].sys_scope) !== "global")
      throw new Error("Theme is not a current-principal-owned global draft.");
    if (expectedVersion !== undefined && roots[0].sys_mod_count !== expectedVersion) throw new Error("Theme version changed.");
    for (const table of ["m2m_app_theme", "m2m_app_config_theme"]) {
      if ((await list(table, `theme=${themeId}`, "sys_id", 1)).length) throw new Error("Theme has a publication/application mapping; patching is not allowed.");
    }
    for (const styleId of styleIds) {
      const links = await list("m2m_theme_style", `style=${styleId}`, "sys_id,theme,style", 2);
      if (links.length !== 1 || scalar(links[0].theme) !== themeId || scalar(links[0].style) !== styleId)
        throw new Error("Selected style is not exclusively linked to this theme.");
    }
    return roots[0].sys_mod_count;
  }
  function verifyCurrent(current, expected) {
    checkVersion(expected.expected_mod_count); checkHash(expected.expected_sha256);
    if (current.version !== expected.expected_mod_count || current.hash !== expected.expected_sha256)
      throw new Error("Style version or raw hash changed; refresh before writing.");
  }
  const intended = (snapshot, role) => role === "colors"
    ? patchRaw(snapshot.styles.colors.raw, [{ path: PRIMARY, value: snapshot.primaryRgb }, { path: BRAND, value: snapshot.primaryRgb }])
    : patchRaw(snapshot.styles.shape.raw, [{ path: RADIUS, value: snapshot.radius }]);
  function summary(style, role) {
    const result = { style_id: style.id, sys_mod_count: style.version, raw_sha256: style.hash,
      source_url: `${INSTANCE}/sys_ux_style.do?sys_id=${style.id}` };
    try { result.selected_values = selected(style.raw, role); }
    catch { result.selected_values_unavailable = true; }
    return result;
  }
  async function handle(name, args) {
    const restore = name === "local_admin_restore_theme_style_pair";
    checkObject(args, restore ? ["snapshot_id", "operation_id", "expected_theme_mod_count", "colors", "shape"]
      : ["theme_id", "operation_id", "expected_theme_mod_count", "colors", "shape"]);
    if (!UUID.test(args.operation_id) || (restore && !UUID.test(args.snapshot_id))) throw new Error("A valid operation/snapshot UUID is required.");
    if (isAttempted(args.operation_id)) throw new Error("This paired-style operation was already attempted; inspect its receipt and do not replay writes.");
    checkVersion(args.expected_theme_mod_count);
    checkObject(args.colors, restore ? ["expected_mod_count", "expected_sha256"]
      : ["style_id", "expected_mod_count", "expected_sha256", "expected_primary", "expected_brand_primary", "primary_rgb"]);
    checkObject(args.shape, restore ? ["expected_mod_count", "expected_sha256"]
      : ["style_id", "expected_mod_count", "expected_sha256", "expected_radius", "radius"]);
    let snapshot;
    if (restore) {
      snapshot = JSON.parse(fs.readFileSync(path.join(folder, `${args.snapshot_id}.snapshot.json`), "utf8"));
      if (snapshot.instance !== INSTANCE || snapshot.snapshotId !== args.snapshot_id || snapshot.format !== 1) throw new Error("Snapshot identity mismatch.");
      checkRgb(snapshot.primaryRgb); checkRadius(snapshot.radius);
      for (const role of ["colors", "shape"]) if (sha(snapshot.styles[role].raw) !== snapshot.styles[role].hash) throw new Error("Preserved raw snapshot integrity mismatch.");
    } else {
      for (const value of [args.colors.expected_primary, args.colors.expected_brand_primary, args.colors.primary_rgb]) checkRgb(value);
      for (const value of [args.shape.expected_radius, args.shape.radius]) checkRadius(value);
      snapshot = { format: 1, instance: INSTANCE, snapshotId: args.operation_id, themeId: args.theme_id,
        primaryRgb: args.colors.primary_rgb, radius: args.shape.radius,
        styles: { colors: { id: args.colors.style_id }, shape: { id: args.shape.style_id } } };
    }
    const ids = [snapshot.styles.colors.id, snapshot.styles.shape.id];
    await isolation(snapshot.themeId, ids, args.expected_theme_mod_count);
    const current = { colors: await getStyle(ids[0]), shape: await getStyle(ids[1]) };
    for (const role of ["colors", "shape"]) verifyCurrent(current[role], args[role]);
    if (!restore) {
      if (!isDeepStrictEqual(selected(current.colors.raw, "colors"), [args.colors.expected_primary, args.colors.expected_brand_primary]) ||
          !isDeepStrictEqual(selected(current.shape.raw, "shape"), [args.shape.expected_radius]))
        throw new Error("Selected current style values changed.");
      snapshot.styles = current;
      save(`${snapshot.snapshotId}.snapshot.json`, snapshot, true);
    } else {
      for (const role of ["colors", "shape"]) {
        const parsed = JSON.parse(current[role].raw);
        if (!isDeepStrictEqual(parsed, JSON.parse(snapshot.styles[role].raw)) && !isDeepStrictEqual(parsed, JSON.parse(intended(snapshot, role))))
          throw new Error("Style has unrelated drift; original snapshot will not overwrite it.");
      }
    }
    const targets = Object.fromEntries(["colors", "shape"].map((role) => [role, restore ? snapshot.styles[role].raw : intended(snapshot, role)]));
    const outcome = { operation_id: args.operation_id, action: restore ? "restore" : "patch", snapshot_id: snapshot.snapshotId,
      theme_id: snapshot.themeId, status: "pending", steps: ["colors", "shape"].map((role) => ({ role, status: "not_attempted", before: summary(current[role], role) })) };
    claim(args.operation_id, { action: "admin_theme_style_pair", mode: outcome.action, snapshot_id: snapshot.snapshotId,
      theme_id: snapshot.themeId, style_ids: ids });
    const operationFile = `${args.operation_id}.operation.json`;
    save(operationFile, outcome, true);
    try {
      for (const step of outcome.steps) {
        const role = step.role;
        await isolation(snapshot.themeId, ids, args.expected_theme_mod_count);
        verifyCurrent(await getStyle(current[role].id), args[role]);
        const wanted = targets[role];
        step.intended_sha256 = sha(wanted);
        if (current[role].raw === wanted) {
          step.status = "unchanged";
          step.after = summary(current[role], role);
          save(operationFile, outcome);
          continue;
        }
        step.status = "write_pending";
        save(operationFile, outcome);
        record({ action: "admin_theme_style_step", operation_id: args.operation_id, snapshot_id: snapshot.snapshotId,
          role, sys_id: current[role].id, status: "attempt", before_sha256: current[role].hash, intended_sha256: step.intended_sha256 });
        let failure;
        try { await request("PATCH", "sys_ux_style", { sysparm_fields: "sys_id,sys_mod_count" }, { style: wanted }, current[role].id); }
        catch (error) { failure = error; }
        let after;
        try { after = await getStyle(current[role].id); }
        catch (error) {
          step.status = "uncertain"; step.error = error.message; step.diagnostic = failure?.diagnostic;
          throw new Error("Style write outcome is uncertain; remaining writes were not attempted.");
        }
        step.after = summary(after, role);
        step.reconciledAfterError = Boolean(failure);
        let matches = false;
        try { matches = isDeepStrictEqual(JSON.parse(after.raw), JSON.parse(wanted)); }
        catch { step.error = "Source style JSON after the attempted write is invalid."; }
        if (!matches) {
          step.status = failure?.diagnostic?.status && failure.diagnostic.status < 500 ? "rejected" : "uncertain_or_not_applied";
          step.error = failure?.message || step.error || "Source content differs from the intended style.";
          step.diagnostic = failure?.diagnostic;
          throw new Error("Style update was not confirmed; remaining writes were not attempted.");
        }
        step.rawMatchesIntended = after.hash === step.intended_sha256;
        step.status = step.rawMatchesIntended ? "confirmed" : "confirmed_semantics_raw_normalized";
        record({ action: "admin_theme_style_step", operation_id: args.operation_id, snapshot_id: snapshot.snapshotId,
          role, sys_id: after.id, status: "confirmed", after_sha256: after.hash, after_mod_count: after.version,
          rawMatchesIntended: step.rawMatchesIntended, reconciledAfterError: Boolean(failure) });
        save(operationFile, outcome);
      }
      outcome.theme_mod_count = await isolation(snapshot.themeId, ids);
      outcome.status = "confirmed";
      outcome.rawRestorationExact = restore ? outcome.steps.every((step) => ["unchanged", "confirmed"].includes(step.status)) : undefined;
      if (restore && !outcome.rawRestorationExact) throw new Error("Source restored equivalent style values but not the exact raw originals; inspect the explicit hashes.");
      save(operationFile, outcome);
      record({ action: "admin_theme_style_pair", operation_id: args.operation_id, snapshot_id: snapshot.snapshotId, status: "confirmed", mode: outcome.action });
      return outcome;
    } catch (error) {
      outcome.status = "partial_or_uncertain";
      outcome.error = error.message;
      error.outcome = outcome;
      try {
        save(operationFile, outcome);
        record({ action: "admin_theme_style_pair", operation_id: args.operation_id, snapshot_id: snapshot.snapshotId,
          status: "partial_or_uncertain", mode: outcome.action, reason: error.message });
      } catch (receiptError) {
        outcome.receipt_error = receiptError.message;
      }
      throw error;
    }
  }
  return { handle };
}
module.exports = { tools, createThemeStyleOperations, patchRaw };
