const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { prepareAttachmentRequest } = require("./staging.cjs");
const TABLE = "sys_ux_theme_asset";
const ID = /^[a-f0-9]{32}$/;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const SHA = /^[a-f0-9]{64}$/;
const object = properties => ({ type: "object", properties, required: Object.keys(properties), additionalProperties: false });
const identity = { sys_id: { type: "string", pattern: ID.source }, expected_mod_count: { type: "string", pattern: "^\\d+$" } };
const tools = [{
  name: "local_admin_import_theme_logo",
  description: "BACKEND ADMIN: import the exact approved locally staged PNG into a NEW owned Global image asset with a supplied unique name ending in the operation UUID, followed by one documented Attachment API binary POST using that name plus .png. Requires qualified current image-asset schema/insert policies and an unchanged owned unpublished theme target. These two source writes are not atomic. Journals each stage/returned ID, retains all asset/file/partial effects and never retries or deduplicates to an existing asset. Does not apply the image; use separately authorized existing modern apply and returned-link-only removal. No arbitrary media, private GraphQL, publication or cleanup.",
  annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false },
  inputSchema: object({
    operation_id: { type: "string", pattern: UUID.source }, confirm: { type: "boolean", const: true },
    asset_name: { type: "string", pattern: "^[A-Za-z0-9][A-Za-z0-9_-]{0,100}$" },
    theme: object(identity), customization: object(identity),
    style: object({ ...identity, expected_sha256: { type: "string", pattern: SHA.source } }),
    staging: object({ staging_id: { type: "string", pattern: UUID.source }, expected_sha256: { type: "string", pattern: SHA.source } }),
  }),
}];
const scalar = value => value && typeof value === "object" ? value.value : value;
const canonical = value => Array.isArray(value) ? value.map(canonical) :
  value && typeof value === "object" ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;
const fingerprint = value => crypto.createHash("sha256").update(JSON.stringify(canonical(value))).digest("hex");
const RULE_FIELDS = ["sys_id", "collection", "name", "active", "action_insert", "when", "order", "sys_mod_count",
  "condition", "filter_condition", "role_conditions", "script"];
function ruleSnapshot(rows) {
  if (!Array.isArray(rows) || rows.length >= 100) throw new Error("Bounded native insert-rule coverage is incomplete.");
  return rows.map(row => {
    if (!ID.test(row.sys_id) || RULE_FIELDS.some(field => typeof row[field] !== "string"))
      throw new Error("Native insert-rule fields are missing; review coverage before importing.");
    return Object.fromEntries(RULE_FIELDS.map(field => [field, row[field]]));
  }).sort((a, b) => a.sys_id.localeCompare(b.sys_id));
}
function createLogoImportPolicy({ discover, list, qualified }) {
  if (!qualified || !SHA.test(qualified.schema_sha256) || !SHA.test(qualified.rules_sha256))
    throw new Error("Reviewed image-asset schema and insert-rule fingerprints are required.");
  const expectedSchema = qualified.schema_sha256, expectedRules = qualified.rules_sha256;
  return async () => {
    const schema = await discover(TABLE, true);
    if (fingerprint(schema) !== expectedSchema) throw new Error("Qualified image-asset schema changed; review before importing.");
    if (JSON.stringify(schema.lineage) !== JSON.stringify([TABLE, "sys_metadata"]))
      throw new Error("Unsupported image-asset inheritance.");
    const fields = schema.fields;
    if (fields.name?.type !== "string" || fields.name.readOnlyMetadata || !Number.isInteger(fields.name.maxLength) ||
        fields.category?.type !== "string" || fields.category.readOnlyMetadata || !fields.category.choices.some(c => c.value === "image") ||
        fields.sys_scope?.reference !== "sys_scope" || fields.sys_scope.readOnlyMetadata || Object.hasOwn(fields, "suffix") ||
        JSON.stringify(Object.keys(fields).filter(key => fields[key].mandatory).sort()) !== JSON.stringify(["category", "name"]) ||
        !Array.isArray(schema.conditionalPolicies) || schema.conditionalPolicies.length)
      throw new Error("The qualified name/category/Global-scope insert assumptions no longer hold.");
    const rows = await list("sys_script", `collectionIN${TABLE},sys_metadata^active=true^action_insert=true`, RULE_FIELDS.join(","), 100);
    if (fingerprint(ruleSnapshot(rows)) !== expectedRules) throw new Error("Qualified exact/inherited insert rules changed; review before importing.");
    return { status: "qualified", fingerprint: fingerprint({ schema: expectedSchema, rules: expectedRules }),
      assetNameMaxLength: fields.name.maxLength };
  };
}
function exact(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      fields.some(key => !Object.hasOwn(value, key)) || Object.keys(value).some(key => !fields.includes(key)))
    throw new Error("Missing or unexpected PNG-import argument.");
}
function validate(args) {
  exact(args, ["operation_id", "confirm", "asset_name", "theme", "customization", "style", "staging"]);
  if (typeof args.operation_id !== "string" || !UUID.test(args.operation_id) || args.confirm !== true)
    throw new Error("PNG import requires explicit confirmation and a unique operation UUID.");
  if (typeof args.asset_name !== "string" || !/^[A-Za-z0-9][A-Za-z0-9_-]{0,100}$/.test(args.asset_name) ||
      !args.asset_name.endsWith(`-${args.operation_id}`))
    throw new Error("Asset name must end in this exact operation UUID and use a safe PNG filename.");
  for (const key of ["theme", "customization", "style"]) {
    exact(args[key], ["sys_id", "expected_mod_count", ...(key === "style" ? ["expected_sha256"] : [])]);
    if (typeof args[key].sys_id !== "string" || !ID.test(args[key].sys_id) ||
        typeof args[key].expected_mod_count !== "string" || !/^\d+$/.test(args[key].expected_mod_count) ||
        (key === "style" && (typeof args.style.expected_sha256 !== "string" || !SHA.test(args.style.expected_sha256))))
      throw new Error("Invalid PNG-import target identity, version or hash.");
  }
  exact(args.staging, ["staging_id", "expected_sha256"]);
  if (typeof args.staging.staging_id !== "string" || !UUID.test(args.staging.staging_id) ||
      typeof args.staging.expected_sha256 !== "string" || !SHA.test(args.staging.expected_sha256))
    throw new Error("Invalid staged-PNG identity or hash.");
}
function createLogoImportOperations({ instance: INSTANCE, directory, principal, staging, checkPolicy, list, request, uploadAttachment,
  guards, record, claim, isAttempted }) {
  const folder = path.join(directory, "logo-import-receipts");
  function save(outcome, exclusive = false) {
    fs.mkdirSync(folder, { recursive: true });
    const fd = fs.openSync(path.join(folder, `${outcome.operation_id}.json`), exclusive ? "wx" : "w");
    try { fs.writeSync(fd, JSON.stringify(outcome)); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  }
  async function one(table, id, fields) {
    const rows = await list(table, `sys_id=${id}`, fields, 2);
    if (rows.length !== 1 || rows[0].sys_id !== id) throw new Error(`Created ${table} record is missing or ambiguous.`);
    return rows[0];
  }
  async function unchangedTarget(args, before) {
    const current = { target: await guards.target(args), bindings: await guards.bindings(args) };
    if (JSON.stringify(current) !== JSON.stringify(before)) throw new Error("Theme target or existing bindings changed during import.");
  }
  async function handle(name, args) {
    if (name !== tools[0].name) throw new Error("Unknown PNG-import operation.");
    validate(args);
    if (isAttempted(args.operation_id)) throw new Error("Import UUID already attempted; no replay.");
    const assetName = args.asset_name, fileName = `${assetName}.png`;
    if (fs.existsSync(folder)) for (const file of fs.readdirSync(folder).filter(file => file.endsWith(".json"))) {
      const previous = JSON.parse(fs.readFileSync(path.join(folder, file), "utf8"));
      if (previous.status !== "confirmed" &&
          (previous.asset_name === assetName || (previous.style_id === args.style.sys_id &&
            previous.staging_sha256 === args.staging.expected_sha256)))
        throw new Error("Earlier matching import is unresolved; a new UUID cannot bypass reconciliation.");
    }
    const { manifest } = staging.readVerified(args.staging);
    const policy = await checkPolicy();
    if (policy?.status !== "qualified" || typeof policy.fingerprint !== "string" || !SHA.test(policy.fingerprint) ||
        !Number.isInteger(policy.assetNameMaxLength) || assetName.length > policy.assetNameMaxLength)
      throw new Error("Actual image-asset schema and insert policy are not qualified for this import.");
    const before = { target: await guards.target(args), bindings: await guards.bindings(args) };
    if ((await list("m2m_style_asset", `style=${args.style.sys_id}`, "sys_id", 1)).length)
      throw new Error("Imagery already has an association; fresh import will not replace it.");
    if ((await list(TABLE, `name=${assetName}`, "sys_id", 2)).length)
      throw new Error("Unique import asset name already exists; no reuse, upload or deduplication performed.");
    const outcome = {
      format: 1, instance: INSTANCE, operation_id: args.operation_id, action: "import_fresh_staged_png",
      status: "prepared", source_write_confirmed: false, theme_id: args.theme.sys_id, style_id: args.style.sys_id,
      staging_id: manifest.staging_id, staging_sha256: manifest.sha256, staged: manifest, asset_name: assetName, file_name: fileName,
      policyFingerprint: policy.fingerprint, before, applied: false,
      stages: { asset: { status: "not_attempted", request_state: "not_sent" },
        attachment: { status: "not_attempted", request_state: "not_sent" } },
      retention: "New image asset, attachment/native storage and any partial effects are retained; no automatic deletion or compensation.",
    };
    save(outcome, true);
    claim(args.operation_id, { action: outcome.action, table: TABLE, asset_name: assetName, staging_sha256: manifest.sha256 });
    let activeStage = "asset", phase = "asset_write_ahead";
    try {
      outcome.status = "attempt";
      outcome.stages.asset.status = "attempt";
      outcome.stages.asset.request_state = "attempt";
      save(outcome);
      record({ action: outcome.action, operation_id: args.operation_id, stage: "asset", status: "stage_attempt", asset_name: assetName });
      phase = "asset_transport";
      const response = await request("POST", TABLE, { sysparm_fields: "sys_id", sysparm_display_value: "false" },
        { name: assetName, category: "image", sys_scope: "global" });
      phase = "asset_readback";
      outcome.stages.asset.request_state = "response_received";
      if (typeof response?.result?.sys_id !== "string" || !ID.test(response.result.sys_id))
        throw new Error("Image create response has no usable returned ID; no binary upload will follow.");
      outcome.stages.asset.returned_id = response.result.sys_id;
      save(outcome);
      const asset = await one(TABLE, response.result.sys_id,
        "sys_id,name,category,sys_scope,sys_domain,sys_class_name,sys_overrides,sys_created_by,sys_mod_count");
      if (asset.name !== assetName || asset.category !== "image" || scalar(asset.sys_scope) !== "global" ||
          scalar(asset.sys_domain) !== "global" || asset.sys_class_name !== TABLE ||
          !Object.hasOwn(asset, "sys_overrides") || scalar(asset.sys_overrides) ||
          asset.sys_created_by !== principal || typeof asset.sys_mod_count !== "string" || !/^\d+$/.test(asset.sys_mod_count))
        throw new Error("Created image asset does not match the approved owned Global name/category/class/override/version.");
      outcome.asset = { sys_id: asset.sys_id, expected_mod_count: asset.sys_mod_count };
      outcome.stages.asset.status = "confirmed";
      save(outcome);
      record({ action: outcome.action, operation_id: args.operation_id, stage: "asset", status: "stage_confirmed", sys_id: asset.sys_id });
      phase = "before_attachment";
      await unchangedTarget(args, before);
      const currentPolicy = await checkPolicy();
      if (JSON.stringify(currentPolicy) !== JSON.stringify(policy)) throw new Error("Source import policy changed after asset creation.");
      await guards.parents({ ...args, asset: outcome.asset });
      if ((await list("sys_attachment", `table_name=${TABLE}^table_sys_id=${asset.sys_id}`, "sys_id", 1)).length ||
          (await list("m2m_style_asset", `asset=${asset.sys_id}`, "sys_id", 1)).length)
        throw new Error("Fresh asset already has an attachment or binding; no upload or reuse performed.");
      const prepared = prepareAttachmentRequest({ instance: INSTANCE, staging, ...args.staging, target_table: TABLE,
        target_sys_id: asset.sys_id, file_name: fileName, qualifiedTargetTables: [TABLE] });
      if (prepared.staged.file_name !== manifest.file_name) throw new Error("Staged filename changed after import preflight.");
      activeStage = "attachment";
      outcome.stages.attachment.status = "attempt";
      outcome.stages.attachment.request_state = "attempt";
      outcome.stages.attachment.parent_id = asset.sys_id;
      save(outcome);
      record({ action: outcome.action, operation_id: args.operation_id, stage: "attachment", status: "stage_attempt",
        parent_id: asset.sys_id, staging_sha256: manifest.sha256 });
      phase = "attachment_transport";
      const uploaded = await uploadAttachment(prepared);
      phase = "attachment_readback";
      outcome.stages.attachment.request_state = "response_received";
      if (typeof uploaded?.result?.sys_id !== "string" || !ID.test(uploaded.result.sys_id))
        throw new Error("Attachment response has no usable returned ID; import needs read-only reconciliation.");
      outcome.stages.attachment.returned_id = uploaded.result.sys_id;
      save(outcome);
      const file = await one("sys_attachment", uploaded.result.sys_id,
        "sys_id,table_name,table_sys_id,file_name,content_type,hash,state,sys_mod_count");
      if (file.table_name !== TABLE || scalar(file.table_sys_id) !== asset.sys_id || file.file_name !== fileName ||
          file.content_type !== "image/png" || file.hash !== manifest.sha256 || file.state !== "available" ||
          typeof file.sys_mod_count !== "string" || !/^\d+$/.test(file.sys_mod_count))
        throw new Error("Imported attachment parent/name/type/hash/state/version is not confirmed.");
      outcome.attachment = { sys_id: file.sys_id, expected_mod_count: file.sys_mod_count, expected_sha256: manifest.sha256 };
      const related = await list("sys_attachment", `table_name=${TABLE}^table_sys_id=${asset.sys_id}`, "sys_id", 2);
      if (related.length !== 1 || related[0].sys_id !== file.sys_id)
        throw new Error("Exactly one attachment on the new image asset was not confirmed.");
      outcome.verifiedBinary = await guards.attachment({ ...args, asset: outcome.asset, attachment: outcome.attachment });
      await guards.parents({ ...args, asset: outcome.asset });
      await unchangedTarget(args, before);
      if ((await list("m2m_style_asset", `asset=${asset.sys_id}`, "sys_id", 1)).length)
        throw new Error("New image acquired an unrequested binding; retain and investigate without automatic cleanup.");
      outcome.stages.attachment.status = "confirmed";
      outcome.status = "confirmed";
      outcome.source_write_confirmed = true;
      outcome.source_url = `${INSTANCE}/${TABLE}.do?sys_id=${asset.sys_id}`;
      save(outcome);
      record({ action: outcome.action, operation_id: args.operation_id, stage: "attachment", status: "stage_confirmed", sys_id: file.sys_id });
      record({ action: outcome.action, operation_id: args.operation_id, status: "confirmed",
        asset_id: asset.sys_id, attachment_id: file.sys_id, source_sha256: manifest.sha256, applied: false });
      return outcome;
    } catch (error) {
      const stage = outcome.stages[activeStage];
      if (stage.status !== "confirmed") {
        stage.status = phase.endsWith("_transport") && error.diagnostic?.status >= 400 && error.diagnostic.status < 500
          ? "request_rejected" : "partial_or_uncertain";
        stage.error = error.message;
      }
      outcome.failure_phase = phase;
      outcome.error = error.message;
      if (error.diagnostic) stage.diagnostic = error.diagnostic;
      outcome.status = "partial_or_uncertain";
      outcome.source_write_confirmed = false;
      outcome.diagnostics = error.diagnostic ? [error.diagnostic] : [];
      if (![401, 403].includes(error.diagnostic?.status)) {
        try {
          const observed = activeStage === "asset"
            ? await list(TABLE, `name=${assetName}`, "sys_id,name,category,sys_mod_count", 2)
            : await list("sys_attachment", `table_name=${TABLE}^table_sys_id=${outcome.asset.sys_id}`,
              "sys_id,table_name,table_sys_id,file_name,content_type,state,sys_mod_count", 2);
          stage.observed_records = observed;
          stage.observation_limit_reached = observed.length >= 2;
        } catch (readError) {
          stage.reconciliation_error = readError.message;
          if (readError.diagnostic) outcome.diagnostics.push(readError.diagnostic);
        }
      } else {
        stage.reconciliation = "Not attempted after authentication/access rejection.";
      }
      const stopped = new Error(`PNG import stopped during ${phase}: ${error.message} Retain known effects; no retry, apply or cleanup was sent.`);
      stopped.outcome = outcome;
      stopped.diagnostic = outcome.diagnostics.find(d => d.status === 401 || d.status === 403) || outcome.diagnostics[0];
      try { save(outcome); record(outcome); }
      catch (receiptError) { outcome.receipt_error = receiptError.message; stopped.message += " Final receipt persistence also failed; returned outcome retains known IDs."; }
      throw stopped;
    }
  }
  return { tools, handle };
}
module.exports = { createLogoImportOperations, createLogoImportPolicy, tools };
