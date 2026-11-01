const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { inspectPng } = require("./png.cjs");
const TABLE = "m2m_style_asset";
const ID = /^[a-f0-9]{32}$/;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const HASH = /^[a-f0-9]{64}$/;
const object = (properties) => ({ type: "object", properties, required: Object.keys(properties), additionalProperties: false });
const identity = { sys_id: { type: "string", pattern: ID.source }, expected_mod_count: { type: "string", pattern: "^\\d+$" } };
const withHash = object({ ...identity, expected_sha256: { type: "string", pattern: HASH.source } });
const tools = [{
  name: "local_admin_remove_theme_logo_link",
  description: "BACKEND ADMIN DESTRUCTIVE: remove only a supplied, explicitly authorized modern m2m_style_asset header_logo link from an owned unpublished theme's exclusive core/global imagery style. Adopts the existing source/UI-created association honestly; it need not have been MCP-created. Checks current identities/versions/raw hashes, reverse sharing/override references and actual approved PNG bytes. Deletes only the link, then verifies original asset/file, unrelated bindings and parent/style state remain. No upload, relink, legacy-table write, asset deletion, publication/default/preference changes or automatic retry. Actual UI restoration must be checked separately.",
  annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false },
  inputSchema: object({
    operation_id: { type: "string", pattern: UUID.source }, confirm: { type: "boolean", const: true },
    theme: object(identity), customization: object(identity), style: withHash,
    link: object({ ...identity, expected_properties_sha256: { type: "string", pattern: HASH.source } }),
    asset: object(identity), attachment: withHash,
  }),
}];
const applyTools = [{
  name: "local_admin_apply_theme_logo",
  description: "BACKEND ADMIN: create one native m2m_style_asset header_logo association between a supplied exclusive imagery style and an existing retained approved PNG asset, within an owned unpublished theme. Requires current parent/style/asset/file versions and raw/binary hashes, no existing imagery asset binding, and no sharing. Creates only the modern link; no binary upload, asset creation, legacy association, style/customization/default/selection or publication writes. Preserves all prior bindings and journals the returned new link for separately authorized removal. Source linkage is not visual proof.",
  annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false },
  inputSchema: object({
    operation_id: { type: "string", pattern: UUID.source }, confirm: { type: "boolean", const: true },
    theme: object(identity), customization: object(identity), style: withHash,
    asset: object(identity), attachment: withHash,
  }),
}];
const scalar = (value) => value && typeof value === "object" ? value.value : value;
const sha = (value) => crypto.createHash("sha256").update(value, "utf8").digest("hex");
function exact(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      fields.some((field) => !Object.hasOwn(value, field)) || Object.keys(value).some((field) => !fields.includes(field)))
    throw new Error("Missing or unexpected modern-logo restore argument.");
}
function validate(args, apply = false) {
  exact(args, ["operation_id", "confirm", "theme", "customization", "style", ...(apply ? [] : ["link"]), "asset", "attachment"]);
  if (typeof args.operation_id !== "string" || !UUID.test(args.operation_id) || args.confirm !== true)
    throw new Error("An explicit restore confirmation and unique operation UUID are required.");
  for (const key of ["theme", "customization", "style", ...(apply ? [] : ["link"]), "asset", "attachment"]) {
    const hashField = key === "link" ? "expected_properties_sha256" : ["style", "attachment"].includes(key) ? "expected_sha256" : null;
    exact(args[key], ["sys_id", "expected_mod_count", ...(hashField ? [hashField] : [])]);
    if (typeof args[key].sys_id !== "string" || !ID.test(args[key].sys_id) ||
        typeof args[key].expected_mod_count !== "string" || !/^\d+$/.test(args[key].expected_mod_count) ||
        (hashField && (typeof args[key][hashField] !== "string" || !HASH.test(args[key][hashField]))))
      throw new Error(`Invalid ${key} identity, version or hash.`);
  }
}
function createLogoRestoreOperations({ instance: INSTANCE, list, request, downloadAttachment, record, claim, isAttempted, principal, directory }) {
  const folder = path.join(directory, "modern-logo-restore-receipts");
  function save(id, value, exclusive = false) {
    fs.mkdirSync(folder, { recursive: true });
    const fd = fs.openSync(path.join(folder, `${id}.json`), exclusive ? "wx" : "w");
    try { fs.writeSync(fd, JSON.stringify(value)); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  }
  async function one(table, id, fields) {
    const rows = await list(table, `sys_id=${id}`, fields, 2);
    if (rows.length !== 1 || rows[0].sys_id !== id) throw new Error(`Exact ${table} identity is missing or ambiguous.`);
    return rows[0];
  }
  function owned(row, expected, label) {
    if (row.sys_created_by !== principal || scalar(row.sys_scope) !== "global" || row.sys_mod_count !== expected.expected_mod_count)
      throw new Error(`${label} is not the current owned/global version.`);
  }
  async function target(args) {
    const fields = "sys_id,sys_scope,sys_created_by,sys_mod_count";
    const theme = await one("sys_ux_theme", args.theme.sys_id, fields);
    const customization = await one("sys_ux_theme_customization", args.customization.sys_id, fields + ",theme");
    const style = await one("sys_ux_style", args.style.sys_id, fields + ",type,style");
    for (const [label, row] of Object.entries({ theme, customization, style })) owned(row, args[label], label);
    if (scalar(customization.theme) !== theme.sys_id || style.type !== "core" ||
        typeof style.style !== "string" || sha(style.style) !== args.style.expected_sha256)
      throw new Error("Theme/customization/style relationship or raw style hash changed.");
    for (const table of ["m2m_app_theme", "m2m_app_config_theme"])
      if ((await list(table, `theme=${theme.sys_id}`, "sys_id", 1)).length) throw new Error("Theme has a publication mapping.");
    const reverse = await list("m2m_theme_style", `style=${style.sys_id}`, "sys_id,theme,style", 2);
    if (reverse.length !== 1 || scalar(reverse[0].theme) !== theme.sys_id || scalar(reverse[0].style) !== style.sys_id)
      throw new Error("Imagery style is not exclusive to the supplied theme.");
    return { theme_mod_count: theme.sys_mod_count, customization_mod_count: customization.sys_mod_count,
      style_mod_count: style.sys_mod_count, style_sha256: sha(style.style) };
  }
  async function parents(args) {
    const snapshot = await target(args);
    const asset = await one("sys_ux_theme_asset", args.asset.sys_id, "sys_id,sys_scope,sys_created_by,sys_mod_count,category");
    owned(asset, args.asset, "asset");
    if (asset.category !== "image") throw new Error("Theme image-asset category changed.");
    return { ...snapshot, asset_mod_count: asset.sys_mod_count };
  }
  async function attachment(args) {
    const row = await one("sys_attachment", args.attachment.sys_id,
      "sys_id,table_name,table_sys_id,content_type,size_bytes,image_width,image_height,hash,state,sys_mod_count");
    if (row.table_name !== "sys_ux_theme_asset" || scalar(row.table_sys_id) !== args.asset.sys_id ||
        row.content_type !== "image/png" || row.state !== "available" || row.hash !== args.attachment.expected_sha256 ||
        row.sys_mod_count !== args.attachment.expected_mod_count) throw new Error("Retained attachment identity, state, hash or version changed.");
    const png = inspectPng(await downloadAttachment(row.sys_id, 120000));
    if (png.sha256 !== args.attachment.expected_sha256 || png.bytes !== Number(row.size_bytes) ||
        png.width !== Number(row.image_width) || png.height !== Number(row.image_height))
      throw new Error("Retained source PNG bytes or dimensions do not match.");
    return { sys_id: row.sys_id, sys_mod_count: row.sys_mod_count, sha256: png.sha256,
      bytes: png.bytes, width: png.width, height: png.height };
  }
  async function bindings(args) {
    const styles = await list("m2m_theme_style", `theme=${args.theme.sys_id}`, "sys_id,theme,style,sys_mod_count", 100);
    if (!styles.length || styles.length >= 100 || styles.some((row) => !ID.test(scalar(row.style)) || scalar(row.theme) !== args.theme.sys_id))
      throw new Error("Bounded theme-style membership is incomplete.");
    const ids = [...new Set(styles.map((row) => scalar(row.style)))];
    const rows = await list(TABLE, `styleIN${ids.join(",")}`, "sys_id,style,asset,properties,sys_mod_count", 100);
    if (rows.length >= 100 || rows.some((row) => !ID.test(row.sys_id) || !ids.includes(scalar(row.style))))
      throw new Error("Bounded style-asset membership is incomplete.");
    const stable = (values) => values.map((row) => Object.fromEntries(Object.keys(row).sort().map((key) => [key,
      ["theme", "style", "asset"].includes(key) ? scalar(row[key]) : row[key]])))
      .sort((a, b) => a.sys_id.localeCompare(b.sys_id));
    return { themeStyles: stable(styles), styleAssets: stable(rows) };
  }
  async function applyLogo(args) {
    validate(args, true);
    if (isAttempted(args.operation_id)) throw new Error("Apply UUID already attempted; no replay.");
    if (fs.existsSync(folder)) for (const file of fs.readdirSync(folder).filter((name) => name.endsWith(".json"))) {
      const previous = JSON.parse(fs.readFileSync(path.join(folder, file), "utf8"));
      if (previous.action === "apply_existing_asset_by_creating_modern_style_link" && previous.style_id === args.style.sys_id &&
          !["confirmed", "rejected"].includes(previous.status))
        throw new Error("Previous modern apply outcome is unresolved; a new UUID cannot replay it.");
    }
    const beforeParents = await parents(args);
    const beforeAttachment = await attachment(args);
    if ((await list(TABLE, `style=${args.style.sys_id}`, "sys_id", 1)).length ||
        (await list(TABLE, `asset=${args.asset.sys_id}`, "sys_id", 1)).length)
      throw new Error("Imagery style or asset already has an association; no duplicate/replacement is created.");
    const beforeBindings = await bindings(args);
    const rawProperties = JSON.stringify({ position: "header_logo" }, null, 2);
    const outcome = { format: 1, instance: INSTANCE, operation_id: args.operation_id,
      action: "apply_existing_asset_by_creating_modern_style_link", association_origin: "MCP create requested; attribution requires source confirmation",
      status: "prepared", theme_id: args.theme.sys_id, style_id: args.style.sys_id, asset_id: args.asset.sys_id,
      attachment_id: args.attachment.sys_id, beforeParents, beforeAttachment, beforeBindings, rawProperties,
      sourceScope: "One modern association only; existing asset and original PNG reused, not uploaded." };
    save(args.operation_id, outcome, true);
    claim(args.operation_id, { action: outcome.action, table: TABLE, theme_id: args.theme.sys_id,
      style_id: args.style.sys_id, asset_id: args.asset.sys_id, attachment_id: args.attachment.sys_id });
    outcome.status = "attempt"; save(args.operation_id, outcome);
    let failure;
    try {
      const response = await request("POST", TABLE, { sysparm_fields: "sys_id,sys_mod_count", sysparm_display_value: "false" },
        { style: args.style.sys_id, asset: args.asset.sys_id, properties: rawProperties });
      if (typeof response?.result?.sys_id === "string" && ID.test(response.result.sys_id)) {
        outcome.returnedLinkId = response.result.sys_id; save(args.operation_id, outcome);
      }
    } catch (error) { failure = error; }
    if (failure?.diagnostic?.status === 401) {
      outcome.status = "uncertain_authentication_rejected"; outcome.diagnostic = failure.diagnostic;
      save(args.operation_id, outcome); record(outcome); failure.outcome = outcome; throw failure;
    }
    try {
      const rows = await list(TABLE, `style=${args.style.sys_id}`, "sys_id,style,asset,properties,sys_scope,sys_created_by,sys_overrides,sys_mod_count", 2);
      outcome.observedLinkIds = rows.map((row) => row.sys_id);
      if (failure?.diagnostic?.status >= 400 && failure.diagnostic.status < 500)
        throw new Error("Source rejected association creation; observed state cannot establish successful attribution.");
      if (rows.length !== 1) throw new Error("Exactly one modern association was not confirmed.");
      const link = rows[0];
      if (!ID.test(link.sys_id) || scalar(link.style) !== args.style.sys_id || scalar(link.asset) !== args.asset.sys_id ||
          typeof link.sys_mod_count !== "string" || !/^\d+$/.test(link.sys_mod_count) ||
          scalar(link.sys_scope) !== "global" || link.sys_created_by !== principal ||
          !Object.hasOwn(link, "sys_overrides") || scalar(link.sys_overrides) ||
          (outcome.returnedLinkId && outcome.returnedLinkId !== link.sys_id))
        throw new Error("Created modern association identity/ownership/scope is not confirmed.");
      const props = typeof link.properties === "string" ? JSON.parse(link.properties) : null;
      if (!props || props.position !== "header_logo" || Object.keys(props).length !== 1)
        throw new Error("Created selector differs from the actual native header_logo contract.");
      outcome.link_id = link.sys_id;
      outcome.link_mod_count = link.sys_mod_count;
      outcome.link_properties_sha256 = sha(link.properties);
      outcome.afterParents = await parents(args);
      outcome.afterAttachment = await attachment(args);
      const after = await bindings(args);
      const retained = { themeStyles: after.themeStyles, styleAssets: after.styleAssets.filter((row) => row.sys_id !== link.sys_id) };
      if (JSON.stringify(retained) !== JSON.stringify(beforeBindings) || after.styleAssets.length !== beforeBindings.styleAssets.length + 1)
        throw new Error("Unrelated bindings changed; no automatic repair or cleanup performed.");
      outcome.status = "confirmed";
      outcome.association_origin = outcome.returnedLinkId ? "MCP-created link confirmed by response and independent readback" : "Uniquely matching source state after MCP apply; response ID unavailable and no stronger attribution claimed";
      outcome.reconciledAfterError = Boolean(failure);
      outcome.unrelatedBindingCount = retained.styleAssets.length;
      outcome.source_url = `${INSTANCE}/${TABLE}.do?sys_id=${link.sys_id}`;
      outcome.visualVerification = "Required in actual Editor/workspace; this is not binary-upload proof.";
      save(args.operation_id, outcome);
      record({ action: outcome.action, operation_id: args.operation_id, status: "confirmed", table: TABLE, sys_id: link.sys_id,
        style_id: args.style.sys_id, asset_id: args.asset.sys_id, attachment_id: args.attachment.sys_id,
        responseIdentityConfirmed: Boolean(outcome.returnedLinkId), properties_sha256: outcome.link_properties_sha256 });
      return outcome;
    } catch (error) {
      outcome.status = failure?.diagnostic?.status >= 400 && failure.diagnostic.status < 500 &&
        !outcome.returnedLinkId && outcome.observedLinkIds?.length === 0 ? "rejected" : "partial_or_uncertain";
      outcome.error = error.message; outcome.diagnostic = failure?.diagnostic || error.diagnostic;
      const stopped = new Error(`${outcome.status}: ${error.message} No repeat create, relink or compensating action.`);
      stopped.outcome = outcome; stopped.diagnostic = outcome.diagnostic;
      try { save(args.operation_id, outcome); record(outcome); }
      catch (receiptError) { outcome.receipt_error = receiptError.message; }
      throw stopped;
    }
  }
  async function handle(name, args) {
    if (name === applyTools[0].name) return await applyLogo(args);
    if (name !== tools[0].name) throw new Error("Unknown modern-logo operation.");
    validate(args);
    if (isAttempted(args.operation_id)) throw new Error("Restore operation UUID was already attempted; reconcile rather than replay.");
    if (fs.existsSync(folder)) for (const file of fs.readdirSync(folder).filter((name) => name.endsWith(".json"))) {
      const previous = JSON.parse(fs.readFileSync(path.join(folder, file), "utf8"));
      if (previous.link_id === args.link.sys_id && !["confirmed", "rejected"].includes(previous.status))
        throw new Error("Earlier unlink outcome is unresolved; a new UUID cannot bypass reconciliation.");
    }
    const beforeParents = await parents(args);
    const beforeAttachment = await attachment(args);
    const link = await one(TABLE, args.link.sys_id, "sys_id,style,asset,properties,sys_scope,sys_created_by,sys_overrides,sys_mod_count");
    owned(link, args.link, "Modern logo link");
    if (scalar(link.style) !== args.style.sys_id || scalar(link.asset) !== args.asset.sys_id ||
        typeof link.properties !== "string" || sha(link.properties) !== args.link.expected_properties_sha256 ||
        !Object.hasOwn(link, "sys_overrides") || scalar(link.sys_overrides))
      throw new Error("Modern link endpoints, raw selector or override state changed.");
    const props = JSON.parse(link.properties);
    if (!props || props.position !== "header_logo" || Object.keys(props).length !== 1) throw new Error("Only the exact native header_logo selector is supported.");
    const styleLinks = await list(TABLE, `style=${args.style.sys_id}`, "sys_id,style,asset", 2);
    const assetLinks = await list(TABLE, `asset=${args.asset.sys_id}`, "sys_id,style,asset", 2);
    if (styleLinks.length !== 1 || styleLinks[0].sys_id !== link.sys_id || assetLinks.length !== 1 || assetLinks[0].sys_id !== link.sys_id)
      throw new Error("Imagery/asset association is no longer exclusive.");
    if ((await list(TABLE, `sys_overrides=${link.sys_id}`, "sys_id", 1)).length) throw new Error("Another association overrides this link.");
    if ((await list("sys_script", `collectionIN${TABLE},sys_metadata^active=true^action_delete=true`, "sys_id", 1)).length)
      throw new Error("Declared exact/inherited delete behavior changed; review the source rule before unlinking.");
    if ((await list("sys_attachment", `table_name=${TABLE}^table_sys_id=${link.sys_id}`, "sys_id", 1)).length)
      throw new Error("The association itself has unexpected attachments.");
    const beforeBindings = await bindings(args);
    if (beforeBindings.styleAssets.filter((row) => row.sys_id === link.sys_id).length !== 1)
      throw new Error("Approved link is not in the exact bounded theme membership.");
    const outcome = { format: 1, instance: INSTANCE, operation_id: args.operation_id,
      action: "restore_by_removing_authorized_existing_source_logo_link", association_origin: "adopted source/UI-created link; not claimed MCP-created",
      status: "prepared", theme_id: args.theme.sys_id, style_id: args.style.sys_id, link_id: args.link.sys_id,
      asset_id: args.asset.sys_id, attachment_id: args.attachment.sys_id, beforeParents, beforeAttachment,
      rawSelector: link.properties, beforeBindings,
      coverage: "Exact link, reverse sharing/override, bounded theme bindings and declared exact/inherited delete rules; not a global graph inventory. Native asset/file retention is verified after the write." };
    if (fs.existsSync(folder)) for (const file of fs.readdirSync(folder).filter((name) => name.endsWith(".json"))) {
      const applied = JSON.parse(fs.readFileSync(path.join(folder, file), "utf8"));
      if (applied.status === "confirmed" && applied.action === "apply_existing_asset_by_creating_modern_style_link" &&
          applied.link_id === link.sys_id && applied.style_id === args.style.sys_id && applied.asset_id === args.asset.sys_id) {
        outcome.association_origin = applied.association_origin;
        outcome.apply_operation_id = applied.operation_id;
      }
    }
    save(args.operation_id, outcome, true);
    claim(args.operation_id, { action: outcome.action, table: TABLE, sys_id: link.sys_id,
      theme_id: args.theme.sys_id, asset_id: args.asset.sys_id, attachment_id: args.attachment.sys_id });
    outcome.status = "attempt"; save(args.operation_id, outcome);
    let failure;
    try { await request("DELETE", TABLE, {}, undefined, link.sys_id); } catch (error) { failure = error; }
    if (failure?.diagnostic?.status === 401) {
      outcome.status = "uncertain_authentication_rejected"; outcome.diagnostic = failure.diagnostic;
      save(args.operation_id, outcome); record(outcome); failure.outcome = outcome; throw failure;
    }
    try {
      const remains = await list(TABLE, `sys_id=${link.sys_id}`, "sys_id", 1);
      outcome.linkAbsent = remains.length === 0;
      if (remains.length) throw new Error("Source link remains present; no retry sent.");
      if (failure?.diagnostic?.status >= 400 && failure.diagnostic.status < 500)
        throw new Error("Source rejected DELETE; observed absence does not establish attribution to the denied request.");
      outcome.afterParents = await parents(args);
      outcome.afterAttachment = await attachment(args);
      const afterBindings = await bindings(args);
      const expectedBindings = { themeStyles: beforeBindings.themeStyles,
        styleAssets: beforeBindings.styleAssets.filter((row) => row.sys_id !== link.sys_id) };
      if (JSON.stringify(afterBindings) !== JSON.stringify(expectedBindings))
        throw new Error("Unrelated theme/style-asset membership changed; no compensating action performed.");
      outcome.unrelatedBindingCount = afterBindings.styleAssets.length;
      outcome.retainedAssetAndBinary = true;
      outcome.status = "confirmed";
      outcome.reconciledAfterError = Boolean(failure);
      outcome.source_url = `${INSTANCE}/${TABLE}.do?sys_id=${link.sys_id}`;
      outcome.visualVerification = "Required separately in fresh Editor/workspace; source absence alone is not visual proof.";
      save(args.operation_id, outcome);
      record({ action: outcome.action, operation_id: args.operation_id, table: TABLE, sys_id: link.sys_id,
        status: "confirmed", linkAbsent: true, assetRetained: true, binaryRetained: true,
        unrelatedBindingCount: outcome.unrelatedBindingCount, source_sha256: outcome.afterAttachment.sha256 });
      return outcome;
    } catch (error) {
      outcome.status = failure?.diagnostic?.status >= 400 && failure.diagnostic.status < 500 && !outcome.linkAbsent ? "rejected" : "partial_or_uncertain";
      outcome.error = error.message; outcome.diagnostic = failure?.diagnostic || error.diagnostic;
      const stopped = new Error(`${outcome.status}: ${error.message} No automatic retry or compensating write.`);
      stopped.outcome = outcome; stopped.diagnostic = outcome.diagnostic;
      try {
        save(args.operation_id, outcome);
        record({ action: outcome.action, operation_id: args.operation_id, status: outcome.status, table: TABLE,
          sys_id: link.sys_id, linkAbsent: outcome.linkAbsent, reason: error.message, diagnostic: outcome.diagnostic });
      } catch (receiptError) { outcome.receipt_error = receiptError.message; }
      throw stopped;
    }
  }
  return { tools: [...tools, ...applyTools], handle, guards: { target, parents, attachment, bindings } };
}
module.exports = { tools, applyTools, createLogoRestoreOperations };
