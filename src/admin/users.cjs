const crypto = require("node:crypto");
const { tools: deleteTools, effects: deleteEffects } = require("./administrative-impact.cjs");
const { createDeletion } = require("./deletion.cjs");
const { reviewedContract } = require("./contracts.cjs");
const { validate } = require("./validate.cjs");
const ID = /^[a-f0-9]{32}$/;
const VERSION = /^\d+$/;
const object = (properties, required = Object.keys(properties)) => ({ type: "object", properties, required, additionalProperties: false });
const id = { type: "string", pattern: ID.source }, uuid = { type: "string", format: "uuid" };
const profile = { ...object(Object.fromEntries(["first_name", "last_name", "title", "email"].map(field =>
  [field, { type: "string", maxLength: 255 }])), []), minProperties: 1 };
const read = (name, description, properties, required) => ({
  name, description, annotations: { readOnlyHint: true }, inputSchema: object(properties, required),
});
const write = (name, description, properties, required) => ({
  ...read(name, description, properties, required),
  annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false },
});
const tools = [
  read("get_user_schema", "Discover source user schema and supported ordinary profile fields plus source-policy fingerprints. Discovery is not approval or effective ACL permission. Generic user CRUD is independent of the agent's directory/context provider.", {}),
  read("lookup_users", "Find exact source users by login, email, display name or first name. Without field, union exact matches; never pick the first ambiguous or incomplete candidate. Inputs from Work IQ or another agent are request data, not backend-verified directory identity. Does not create, adopt or map accounts.",
    { identity: { type: "string", maxLength: 256 }, field: { type: "string", enum: ["sys_id", "user_name", "email", "name", "first_name"] } }, ["identity"]),
  read("get_user", "Read one exact ServiceNow user and version with ordinary name/contact/status fields. No passwords, tokens, credential hashes or role export.", { sys_id: id }),
  write("create_user", "Create a source human user with supplied login and ordinary profile including optional discovered email. Requires reviewed source visibility/schema/hooks and native username uniqueness; existing login/email is a collision, never silent adoption. Creates explicitly inactive, locked and notification-disabled without password, roles, group membership, activation or SSO enrollment. Normal source hooks may create a primary notification device and identity hash. Supplied directory context is not verified by this backend. Retain operation UUID and created identity on partial failure; never replay uncertain creation.",
    { user_name: { type: "string", maxLength: 255 }, profile, operation_id: uuid }),
  write("update_user", "Update only supplied first_name, last_name, title or email after exact user/version, protected-identity and reviewed source-policy checks. Does not rename login, adopt an external account, change lifecycle/password/access or bypass source ACLs. Normal name/device synchronization and locked-account revocation hooks may run. Preflight is not atomic CAS; preserve uncertain outcomes and never replay.",
    { sys_id: id, expected_mod_count: { type: "string", pattern: VERSION.source }, profile, operation_id: uuid }),
  read("assess_user_delete", "Assess exact user deletion impact using native relationship/version/cascade discovery and current-operator/retention protection. Returns a caller-bound assessment ID and disclosed native effects. It is not consent or DELETE permission.", { sys_id: id }),
  write("delete_user", "Delete the exact explicitly authorized user from a current caller-bound impact assessment. Rechecks target version, relationships and native effects; protects current operator and retention holds. No role stripping, direct child cleanup or force. Parent absence is separate from cleanup_complete=false and retained/unknown effects. Never replay an uncertain operation.",
    { ...deleteTools[1].inputSchema.properties, assessment_id: uuid }),
  read("get_user_operation", "Read only this authenticated caller's original user-operation receipt and current source observation when available. Retains created identity and partial/uncertain evidence without replay, attribution upgrade or hold removal.", { operation_id: uuid }),
];
const PUBLIC = ["sys_id", "sys_mod_count", "user_name", "name", "first_name", "last_name", "title", "email", "active", "locked_out", "notification"];
const GUARDED = [...PUBLIC, "sys_class_name", "identity_type", "internal_integration_user", "web_service_access_only", "source", "ldap_server"];
const creationEffects = ["native-primary-email-device-insert", "native-identity-hash-generation", "conditional-source-hooks"];
const updateEffects = ["native-name-and-email-device-synchronization", "locked-user-session-and-provider-hooks", "conditional-source-hooks"];
function fingerprint(value) {
  const canonical = item => Array.isArray(item) ? item.map(canonical) : item && typeof item === "object" ?
    Object.fromEntries(Object.keys(item).sort().map(key => [key, canonical(item[key])])) : item;
  return crypto.createHash("sha256").update(JSON.stringify(canonical(value))).digest("hex");
}
function literal(value, label) {
  if (typeof value !== "string" || !value.trim() || value !== value.trim() ||
      /[\u0000-\u001f\u007f^]|javascript:/i.test(value)) throw new Error(`Invalid literal ${label}.`);
  return value;
}

function createUsers({ source, state, records, incidents, principal }) {
  const deletion = createDeletion({ source, principal, state: { ...state, record: entry =>
    state.record(entry.status === "confirmed" ? { ...entry, status: "user_delete_observed" } : entry) } });
  async function list(table, query, fields, limit = 100) {
    const rows = await source.list(table, query, fields.join(","), limit);
    if (rows.length >= limit || new Set(rows.map(row => row.sys_id)).size !== rows.length ||
        rows.some(row => !ID.test(row.sys_id) || fields.some(field => !Object.hasOwn(row, field))))
      throw new Error(`Incomplete or inconsistent user-operation evidence: ${table}.`);
    return rows.map(row => Object.fromEntries(fields.map(field => [field, row[field]])));
  }
  async function get(sysId) {
    const rows = await list("sys_user", `sys_id=${sysId}`, GUARDED, 2);
    if (rows.length && (rows[0].sys_id !== sysId || typeof rows[0].sys_mod_count !== "string" || !VERSION.test(rows[0].sys_mod_count)))
      throw new Error("Exact user identity or version changed.");
    return rows[0] || null;
  }
  function project(row) {
    return row ? { ...Object.fromEntries(PUBLIC.map(field => [field, row[field]])),
      source_url: `${source.instance}/sys_user.do?sys_id=${row.sys_id}` } : null;
  }
  async function schemaEvidence() {
    const schema = await records.discover("sys_user");
    const rules = [];
    for (const table of schema.lineage) rules.push(...await list("sys_script", `collection=${table}^active=true`, ["sys_id", "sys_mod_count"]));
    const unique = await list("sys_dictionary", "name=sys_user^element=user_name", ["sys_id", "sys_mod_count", "unique"], 2);
    return { schema, schema_sha256: fingerprint(schema),
      rules_sha256: fingerprint(rules.sort((a, b) => a.sys_id.localeCompare(b.sys_id))),
      native_user_name_unique: unique.length === 1 && ["true", true, "1"].includes(unique[0].unique),
      writable_profile_fields: ["first_name", "last_name", "title", "email"],
      directory_verified: false, meaning: "Fingerprints are review inputs, not permission or an automatically approved policy." };
  }
  async function policy() {
    const approved = reviewedContract("user-profile", state.directory, source.instance);
    const observed = await schemaEvidence();
    if (approved.schema_sha256 !== observed.schema_sha256 || approved.rules_sha256 !== observed.rules_sha256 ||
        !observed.native_user_name_unique)
      throw new Error("User schema/hooks/username uniqueness differ from reviewed policy; no write sent.");
    return { ...observed, approved };
  }
  function validateProfile(schema, input) {
    for (const [field, value] of Object.entries(input)) {
      const spec = schema.fields[field];
      if (!spec || spec.readOnlyMetadata || typeof value !== "string" ||
          value.length > Math.min(spec.maxLength || 255, 255) || /[\u0000-\u001f\u007f]/.test(value))
        throw new Error(`Unsupported source profile value: ${field}.`);
      if (field === "email" && value !== "" && (!/^[^\s@^]+@[^\s@^]+\.[^\s@^]+$/.test(value) || /javascript:/i.test(value)))
        throw new Error("Email must be a plain address or empty.");
    }
  }
  async function guardUser(row, approved) {
    if (!row) throw new Error("User is absent or unreadable.");
    if (typeof row.user_name !== "string" || !row.user_name) throw new Error("User login identity is unreadable.");
    const operators = await list("sys_user", `user_name=${literal(principal, "source operator")}`, ["sys_id", "user_name"], 2);
    if (operators.length !== 1 || operators[0].user_name.toLowerCase() !== principal.toLowerCase())
      throw new Error("Current source operator identity is not uniquely readable.");
    if (row.sys_id === operators[0].sys_id || row.user_name.toLowerCase() === principal.toLowerCase() ||
        [...approved.protectedNames.map(name => name.toLowerCase()), "admin", "guest", "system"].includes(row.user_name.toLowerCase()) ||
        approved.protectedIds.includes(row.sys_id) || state.retainedIds().includes(row.sys_id))
      throw new Error("Current operator, protected identity or retention hold prevents this user change.");
    if (row.sys_class_name !== "sys_user" || row.identity_type !== "human" ||
        !["false", false, "0"].includes(row.internal_integration_user) ||
        !["false", false, "0"].includes(row.web_service_access_only) || row.source !== "" || row.ldap_server !== "")
      throw new Error("External, service or unknown identity is not an ordinary profile-update target.");
    if ((await list("provider_user_map", `user=${row.sys_id}`, ["sys_id", "user"], 2)).length)
      throw new Error("Provider-linked identity requires its authoritative identity-management path.");
  }
  async function collision(field, value, exceptId) {
    if (!value) return;
    const rows = await list("sys_user", `${field}=${literal(value, field)}`, ["sys_id", field], 3);
    if (rows.some(row => String(row[field]).toLowerCase() !== value.toLowerCase()))
      throw new Error("Exact user collision query returned inconsistent identity.");
    if (rows.some(row => row.sys_id !== exceptId)) throw new Error(`Existing ${field} collision; no account created, adopted or changed.`);
  }
  async function mutate(name, args, callerKey) {
    if (state.events(args.operation_id).length) throw new Error("Operation UUID already used; no replay.");
    const creating = name === "create_user";
    if (state.unresolved("sys_user") || args.sys_id && state.unresolved("sys_user", args.sys_id))
      throw new Error("Earlier user outcome unresolved; a new UUID cannot replay it.");
    const evidence = await policy();
    validateProfile(evidence.schema, args.profile);
    const before = creating ? null : await get(args.sys_id);
    let values;
    if (creating) {
      literal(args.user_name, "user_name");
      const spec = evidence.schema.fields.user_name;
      if (!spec || spec.readOnlyMetadata || args.user_name.length > (spec.maxLength || 255) ||
          [...evidence.approved.protectedNames.map(name => name.toLowerCase()), principal.toLowerCase(), "admin", "guest", "system"].includes(args.user_name.toLowerCase()))
        throw new Error("Reserved or invalid source username.");
      values = { user_name: args.user_name, ...args.profile, active: false, locked_out: true,
        notification: "1", identity_type: "human", internal_integration_user: false, web_service_access_only: false };
      for (const [field, value] of Object.entries(values)) {
        const sourceField = evidence.schema.fields[field];
        if (!sourceField || sourceField.readOnlyMetadata ||
            typeof value === "string" && value.length > (sourceField.maxLength || 255) ||
            ["1", "3"].includes(sourceField.choiceMode) && sourceField.choices.length &&
              !sourceField.choices.some(choice => choice.value === String(value)))
          throw new Error(`Source does not permit the explicit creation field: ${field}.`);
      }
      for (const field of Object.values(evidence.schema.fields))
        if (field.mandatory && !field.defaultValue && !field.name.startsWith("sys_") && !Object.hasOwn(values, field.name))
          throw new Error(`Source requires ${field.name}; user creation does not invent a default.`);
    } else {
      await guardUser(before, evidence.approved);
      if (before.sys_mod_count !== args.expected_mod_count) throw new Error("User changed since your read; no write sent.");
      values = { ...args.profile };
    }
    await collision("user_name", creating ? args.user_name : before.user_name, before?.sys_id);
    if (Object.hasOwn(values, "email")) await collision("email", values.email, before?.sys_id);
    const intent = { action: "user_crud", caller_key: callerKey, operation_id: args.operation_id, table: "sys_user",
      sys_id: before?.sys_id, user_name: creating ? args.user_name : before.user_name, values, before: project(before),
      directory_verified: false, native_effects: creating ? creationEffects : updateEffects, status: "prepared" };
    state.record(intent);
    let response, row;
    try {
      if (!creating) {
        const current = await get(before.sys_id);
        await guardUser(current, evidence.approved);
        if (fingerprint(current) !== fingerprint(before)) throw new Error("User context changed during preflight; no write sent.");
      }
      state.claim(args.operation_id, intent);
      let failure;
      try { response = await source.request(creating ? "POST" : "PATCH", "sys_user",
        { sysparm_fields: "sys_id", sysparm_display_value: "false" }, values, before?.sys_id); }
      catch (error) { failure = error; }
      if (response?.result?.sys_id) {
        if (!ID.test(response.result.sys_id)) throw new Error("Invalid source response identity.");
        state.record({ ...intent, status: "response", sys_id: response.result.sys_id });
      }
      if (failure?.diagnostic?.status === 401) throw failure;
      if (creating) {
        const matches = await list("sys_user", `user_name=${args.user_name}`, GUARDED, 2);
        row = matches[0] || null;
      } else row = await get(before.sys_id);
      if (row) state.record({ ...intent, status: "observed", sys_id: row.sys_id, observed: project(row) });
      if (failure) throw failure;
      if (!row || response?.result?.sys_id && response.result.sys_id !== row.sys_id ||
          !VERSION.test(row.sys_mod_count) || Object.entries(values).some(([field, value]) => String(row[field]) !== String(value)))
        throw new Error("Requested user fields or response/correlation identity not confirmed.");
      await guardUser(row, evidence.approved);
      if (creating) {
        for (const table of ["sys_user_has_role", "sys_user_grmember"])
          if ((await list(table, `user=${row.sys_id}`, ["sys_id", "user"])).length)
            throw new Error("Source created access relationships during user creation; retain the identity and review native effects.");
      }
      if (!creating && (BigInt(row.sys_mod_count) <= BigInt(before.sys_mod_count) ||
          GUARDED.some(field => !["sys_mod_count", "name"].includes(field) && !Object.hasOwn(values, field) && row[field] !== before[field])))
        throw new Error("Source changed an unrequested identity/status field or did not advance the version.");
      if (creating && (row.active !== "false" || row.locked_out !== "true" || row.notification !== "1"))
        throw new Error("No-login creation state was not confirmed.");
      const result = { status: "confirmed", operation_id: args.operation_id, sys_id: row.sys_id, record: project(row),
        source_write_attempted: true, directory_verified: false, atomic_compare_and_swap: false,
        native_effects: intent.native_effects, cleanup_complete: false,
        ...(creating ? { assignee_readiness: "not_evaluated",
          continuation: "Account creation grants no role, membership or activation. Qualify source assignee requirements through a separately authorized supported access/lifecycle path before claiming readiness." } : {}) };
      state.record({ ...intent, ...result });
      return result;
    } catch (error) {
      const outcome = { operation_id: args.operation_id, status: state.isAttempted(args.operation_id) ? "uncertain" : "not_sent",
        source_write_attempted: state.isAttempted(args.operation_id), sys_id: row?.sys_id || response?.result?.sys_id || before?.sys_id,
        observed: project(row), error: error.message, diagnostic: error.diagnostic, directory_verified: false,
        retained_created_identity: creating ? response?.result?.sys_id || null : null,
        observed_user_identity: row?.sys_id || null,
        source_rejected: error.diagnostic?.status >= 400 && error.diagnostic.status < 500 };
      error.outcome = outcome;
      try { state.record({ ...intent, ...outcome }); } catch (receiptError) { outcome.receipt_error = receiptError.message; }
      throw error;
    }
  }
  async function remove(args, callerKey) {
    if (state.events(args.operation_id).length) throw new Error("Operation UUID already used; no replay.");
    const saved = state.events(args.assessment_id).find(row => row.action === "user_delete_assessment" && row.caller_key === callerKey);
    if (!saved || saved.sys_id !== args.sys_id || saved.impact.target.sys_mod_count !== args.expected_mod_count ||
        saved.impact.impact_sha256 !== args.expected_impact_sha256)
      throw new Error("User deletion assessment identity, caller or version mismatch.");
    const intent = { action: "user_crud", caller_key: callerKey, table: "sys_user", sys_id: args.sys_id,
      operation_id: args.operation_id, assessment_id: args.assessment_id, status: "prepared" };
    state.record(intent);
    try {
      const { assessment_id, ...nativeArgs } = args;
      const result = await deletion.handle("local_admin_user_delete_administrative", nativeArgs);
      if (result.reconciled_after_error) throw Object.assign(new Error("Deletion response lost; preserve later absence without attributing success."), { outcome: result });
      state.record({ ...intent, status: "confirmed", result });
      return result;
    } catch (error) {
      const outcome = { ...(error.outcome || {}), status: state.isAttempted(args.operation_id) ? "uncertain" : "not_sent",
        operation_id: args.operation_id, sys_id: args.sys_id, error: error.message };
      error.outcome = outcome;
      try { state.record({ ...intent, ...outcome, action: "user_crud", caller_key: callerKey }); }
      catch (receiptError) { outcome.receipt_error = receiptError.message; }
      throw error;
    }
  }
  async function handle(name, args, callerKey) {
    const tool = tools.find(item => item.name === name);
    if (!tool) throw new Error("User operation unavailable.");
    validate(tool.inputSchema, args);
    if (name === "get_user_schema") {
      const evidence = await schemaEvidence();
      return { ...evidence, schema: { ...evidence.schema,
        fields: Object.fromEntries(Object.entries(evidence.schema.fields).filter(([field]) => GUARDED.includes(field))),
      } };
    }
    if (name === "lookup_users") return incidents.handle("resolve_incident_assignee", args, callerKey);
    if (name === "get_user") { const row = await get(args.sys_id); return { found: Boolean(row), record: project(row) }; }
    if (name === "create_user" || name === "update_user") return mutate(name, args, callerKey);
    if (name === "assess_user_delete") {
      const impact = await deletion.handle("local_admin_user_delete_assess", args);
      const assessment_id = crypto.randomUUID();
      state.record({ action: "user_delete_assessment", operation_id: assessment_id, caller_key: callerKey,
        status: "assessed", sys_id: args.sys_id, impact });
      return { ...impact, assessment_id, acknowledged_native_effects: deleteEffects };
    }
    if (name === "delete_user") return remove(args, callerKey);
    const entries = state.events(args.operation_id);
    const own = entries.filter(row => row.action === "user_crud" && row.caller_key === callerKey);
    if (!own.length) throw new Error("User operation is not available to this requester.");
    const { caller_key, ...outcome } = own.at(-1);
    if (!["confirmed", "uncertain", "not_sent"].includes(outcome.status))
      outcome.status = state.isAttempted(args.operation_id) ? "uncertain" : "not_sent";
    const sysId = outcome.sys_id || entries.findLast(row => ID.test(row.sys_id))?.sys_id;
    let current, observationError;
    if (sysId) { try { current = project(await get(sysId)); } catch (error) { observationError = error.message; } }
    return { operation_id: args.operation_id, status: outcome.status, outcome, current, observation_error: observationError,
      unresolved_hold: state.unresolved("sys_user") || Boolean(sysId && state.unresolved("sys_user", sysId)),
      meaning: "Read-only observation; no replay, attribution upgrade, adoption or hold removal." };
  }
  return { tools, handle };
}
module.exports = { tools, createUsers, fingerprint };
