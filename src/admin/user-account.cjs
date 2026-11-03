const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const ID = /^[a-f0-9]{32}$/;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const USERNAME = /^[a-z0-9][a-z0-9._-]{0,39}$/;
const HASH = /^[a-f0-9]{64}$/;
const PROFILE = { first_name: 50, last_name: 50, title: 60 };
const PUBLIC = ["sys_id", "sys_mod_count", "user_name", ...Object.keys(PROFILE), "active", "locked_out", "notification"];
const GUARDED = [...PUBLIC, "sys_class_name", "identity_type", "internal_integration_user", "web_service_access_only", "failed_attempts"];
const EFFECTS = ["live_profile_name_sync", "session_lockout_and_oauth_revocation", "provider_mapping_deactivation",
  "contextual_writer_membership_recompute", "conditional_native_lockout_event"];
const STATUS_EFFECTS = [...EFFECTS, "local_account_activation", "local_account_unlock_and_failed_attempt_reset"];
const CREATE_EFFECTS = ["active_primary_email_device_insert_attempt", "native_identity_hash_generation"];
const object = (properties, required = Object.keys(properties)) => ({ type: "object", properties, required, additionalProperties: false });
const id = { type: "string", pattern: ID.source };
const uuid = { type: "string", pattern: UUID.source };
const version = { type: "string", pattern: "^\\d+$" };
const profileSchema = { ...object(Object.fromEntries(Object.entries(PROFILE).map(([field, maxLength]) =>
  [field, { type: "string", maxLength }])), []), minProperties: 1 };
const target = { operation_id: uuid, sys_id: id, expected_mod_count: version, assessment_id: uuid,
  acknowledged_native_effects: { type: "array", uniqueItems: true, items: { type: "string", enum: EFFECTS } } };
const statusTarget = { ...target,
  acknowledged_native_effects: { type: "array", uniqueItems: true, items: { type: "string", enum: STATUS_EFFECTS } } };
const tools = [
  { name: "local_admin_user_get", annotations: { readOnlyHint: true },
    description: "BACKEND ACCOUNT ADMIN: read one supplied user ID with a fixed minimal profile/status projection. No bulk users, contact, password/hash/token, Federated ID, role or credential values.",
    inputSchema: object({ sys_id: id }) },
  { name: "local_admin_user_assess", annotations: { readOnlyHint: true },
    description: "BACKEND ACCOUNT ADMIN: assess one supplied root sys_user for profile, activation, deactivation, lock and unlock. Returns per-action eligibility and exact status native-effect acknowledgments. Protects self/system/service/external identities; existing roles/groups need explicit current reviewed-access policy coverage. Business responsibilities block lock/deactivation, not activation/unlock. Saves a local versioned assessment, not approval or effective source permission. Unknown/truncated/hidden coverage is not permission.",
    inputSchema: object({ sys_id: id }) },
  { name: "local_admin_user_create_disabled", annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false },
    description: "BACKEND ACCOUNT ADMIN: create a supplied native human username/profile explicitly inactive, locked and notification-disabled; no credentials/contact/access fields. Source unconditionally attempts an active primary-email-device child even without email; account for it, never silently delete it. Retains receipts and reconciles once without replay. Requires separately scoped account-creation approval.",
    inputSchema: object({ operation_id: uuid, user_name: { type: "string", pattern: USERNAME.source }, profile: profileSchema,
      active: { type: "boolean", const: false }, locked_out: { type: "boolean", const: true },
      notification: { type: "string", const: "1" }, identity_type: { type: "string", const: "human" } }) },
  { name: "local_admin_user_update_profile", annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false },
    description: "BACKEND ACCOUNT ADMIN: change first_name/last_name/title on an eligible supplied local user, including pre-existing users; not fixture-owned only. Revalidates exact assessment/version and protected/service/external/role/group guards. Names may update live_profile. ANY source update while locked may revoke sessions/OAuth; acknowledge actual declared native effects. No status/access/identity changes. Preflight guard is not atomic CAS.",
    inputSchema: object({ ...target, profile: profileSchema }) },
  { name: "local_admin_user_deactivate_and_lock", annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false },
    description: "BACKEND ACCOUNT ADMIN: explicitly set active=false and locked_out=true on an eligible supplied local user and retain the record/history. Requires current assessment/version and native-effect acknowledgment. Blocks observed active business responsibilities; no reassignment, deletion, activation, credentials, direct token/device/group writes or notification preference changes. Source native session/OAuth/provider/group logic may run.",
    inputSchema: object(target) },
  { name: "local_admin_user_lock", annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false },
    description: "BACKEND ACCOUNT ADMIN: explicitly set locked_out=true only on an eligible supplied local user after current assessment/version and native-effect acknowledgment. Active and notification settings remain unchanged. Source sessions/OAuth/provider links may be revoked; conditional native lockout events may be created. No unlock, activation, direct credential/token/group/device operations.",
    inputSchema: object(target) },
  { name: "local_admin_user_activate", annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false },
    description: "BACKEND ACCOUNT ADMIN: explicitly set active=true only on an eligible supplied native human after current assessment/version and native-effect acknowledgment. Lock and notification preference remain unchanged; activation does not unlock or set a password. Existing access requires explicit reviewed activation-policy coverage; no role or membership writes. Protects self/system/service/external/provider identities. Source group/cache/session hooks remain enabled and unexpected access changes leave an uncertain receipt.",
    inputSchema: object(statusTarget) },
  { name: "local_admin_user_unlock", annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false },
    description: "BACKEND ACCOUNT ADMIN: explicitly set locked_out=false on an eligible supplied ACTIVE native human after current assessment/version and native-effect acknowledgment. Source clears failed attempts. Does not activate, change notifications/password/MFA/roles, or restore revoked tokens/provider links. Inactive-user unlock is not supported because source policy warns/retains lock.",
    inputSchema: object(statusTarget) },
];
const unsupportedOperations = { delete: "Use the separate local_admin_user_delete_assess/local_admin_user_delete_administrative tools with current impact/version guards; lifecycle eligibility is not deletion permission.",
  access: "Explicit eligible activation/unlock only; no password/reset/MFA, provider/identity conversion, roles or groups." };
function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object")
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
  return value;
}
const hash = (value) => crypto.createHash("sha256").update(JSON.stringify(canonical(value))).digest("hex");
function exact(value, required, optional = []) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      Object.keys(value).some((field) => !required.includes(field) && !optional.includes(field)) ||
      required.some((field) => !Object.hasOwn(value, field))) throw new Error("Missing or unexpected account argument.");
}
function string(value, pattern, label) {
  if (typeof value !== "string" || !pattern.test(value)) throw new Error(`Invalid ${label}.`);
}
function checkProfile(profile) {
  exact(profile, [], Object.keys(PROFILE));
  if (!Object.keys(profile).length) throw new Error("Provide a supported profile field.");
  for (const [field, value] of Object.entries(profile))
    if (typeof value !== "string" || value.length > PROFILE[field] || /[\u0000-\u001f\u007f]/.test(value))
      throw new Error(`Invalid plain profile value: ${field}.`);
}
function validate(name, args) {
  if (["local_admin_user_get", "local_admin_user_assess"].includes(name)) {
    exact(args, ["sys_id"]); string(args.sys_id, ID, "sys_id"); return;
  }
  if (name === "local_admin_user_create_disabled") {
    exact(args, ["operation_id", "user_name", "profile", "active", "locked_out", "notification", "identity_type"]);
    string(args.user_name, USERNAME, "user_name"); checkProfile(args.profile);
    if (args.active !== false || args.locked_out !== true || args.notification !== "1" || args.identity_type !== "human")
      throw new Error("Creation requires inactive, locked, notification-disabled human intent.");
    if ([args.user_name, [args.profile.first_name, args.profile.last_name].filter(Boolean).join(" ")].some((value) => value.trim().toLowerCase() === "system"))
      throw new Error("SYSTEM identity is source-protected.");
  } else if (["local_admin_user_update_profile", "local_admin_user_deactivate_and_lock", "local_admin_user_lock",
    "local_admin_user_activate", "local_admin_user_unlock"].includes(name)) {
    exact(args, [...Object.keys(target), ...(name === "local_admin_user_update_profile" ? ["profile"] : [])]);
    string(args.sys_id, ID, "sys_id"); string(args.expected_mod_count, /^\d+$/, "expected_mod_count");
    string(args.assessment_id, UUID, "assessment_id");
    const permittedEffects = ["local_admin_user_activate", "local_admin_user_unlock"].includes(name) ? STATUS_EFFECTS : EFFECTS;
    if (!Array.isArray(args.acknowledged_native_effects) ||
        new Set(args.acknowledged_native_effects).size !== args.acknowledged_native_effects.length ||
        args.acknowledged_native_effects.some((value) => !permittedEffects.includes(value))) throw new Error("Invalid native-effect acknowledgment.");
    if (name === "local_admin_user_update_profile") checkProfile(args.profile);
  } else throw new Error("Unsupported account operation; delete/credentials/access grants are not implemented.");
  string(args.operation_id, UUID, "operation_id");
}
function bool(value) {
  if (![true, false, "true", "false", "0", "1"].includes(value)) throw new Error("A guarded source boolean is missing/invalid.");
  return value === true || value === "true" || value === "1";
}
function projectAccount(row, instance) {
  if (!row) return null;
  string(row.sys_id, ID, "source sys_id"); string(row.sys_mod_count, /^\d+$/, "source version");
  if (PUBLIC.some((field) => !Object.hasOwn(row, field))) throw new Error("Source omitted a selected account field.");
  return { ...Object.fromEntries(PUBLIC.map((field) => [field, row[field]])),
    source_url: `${instance}/sys_user.do?sys_id=${row.sys_id}` };
}
function matches(row, values) {
  return Boolean(row) && Object.entries(values).every(([field, value]) =>
    typeof value === "boolean" ? bool(row[field]) === value : row[field] === value);
}
function effectList(name, before, values) {
  if (Object.entries(values).every(([field, value]) => typeof value === "boolean" ? bool(before[field]) === value : before[field] === value)) return [];
  const effects = [];
  if (name === "local_admin_user_update_profile" && ["first_name", "last_name"].some((field) => Object.hasOwn(values, field) && values[field] !== before[field]))
    effects.push("live_profile_name_sync");
  const afterLocked = Object.hasOwn(values, "locked_out") ? values.locked_out : bool(before.locked_out);
  if (afterLocked) effects.push("session_lockout_and_oauth_revocation");
  if ((!bool(before.locked_out) && afterLocked) || (bool(before.active) && values.active === false))
    effects.push("provider_mapping_deactivation");
  if (bool(before.active) && values.active === false) effects.push("contextual_writer_membership_recompute");
  if (!bool(before.locked_out) && afterLocked) effects.push("conditional_native_lockout_event");
  if (!bool(before.active) && values.active === true) effects.push("local_account_activation", "contextual_writer_membership_recompute");
  if (bool(before.locked_out) && values.locked_out === false) effects.push("local_account_unlock_and_failed_attempt_reset");
  return effects.sort();
}
function classifyFailure(failure, observed, knownId) {
  if (failure?.diagnostic?.status === 401) return "authentication_rejected";
  const diagnostic = failure?.diagnostic;
  const detail = `${diagnostic?.code || ""} ${diagnostic?.message || ""} ${diagnostic?.detail || ""}`;
  if (diagnostic?.status === 403 && !observed && !knownId &&
      /access.?denied|acl.*denied|user not authorized|security constraints prevent access/i.test(detail))
    return "rejected_source_acl";
  return "uncertain";
}
function createUserAccountOperations({ instance: INSTANCE, policy, list, request, record, claim, isAttempted, principal, directory,
  checkSourcePolicy, reviewExistingAccess }) {
  const project = row => projectAccount(row, INSTANCE);
  if (typeof principal !== "string" || !principal || typeof directory !== "string" || policy.format !== 2 || policy.instance !== INSTANCE)
    throw new Error("Existing principal, private directory and matching source policy snapshot are required.");
  const folder = path.join(directory, "user-account-v2-receipts");
  let writing = false;
  function save(file, value, exclusive = false) {
    fs.mkdirSync(folder, { recursive: true });
    const fd = fs.openSync(path.join(folder, file), exclusive ? "wx" : "w");
    try { fs.writeSync(fd, JSON.stringify(value)); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  }
  const load = (file) => JSON.parse(fs.readFileSync(path.join(folder, file), "utf8"));
  async function bounded(table, query, fields, limit = 100) {
    const rows = await list(table, query, fields, limit);
    if (!Array.isArray(rows) || rows.length >= limit) throw new Error(`Incomplete bounded ${table} evidence; no mutation permitted.`);
    const identities = new Set();
    for (const row of rows) {
      string(row.sys_id, ID, `${table} identity`);
      if (identities.has(row.sys_id)) throw new Error(`Duplicate ${table} identities.`);
      identities.add(row.sys_id);
      for (const field of fields.split(",")) if (!Object.hasOwn(row, field)) throw new Error(`Source omitted ${table}.${field}; coverage unknown.`);
    }
    return rows;
  }
  async function get(sysId, guarded = false) {
    const rows = await bounded("sys_user", `sys_id=${sysId}`, (guarded ? GUARDED : PUBLIC).join(","), 2);
    if (rows[0] && rows[0].sys_id !== sysId) throw new Error("Source returned a wrong user identity.");
    if (rows[0]) project(rows[0]);
    return rows[0] || null;
  }
  async function checkPolicy() {
    if (policy.schema_sha256) return checkSourcePolicy(policy);
    const rows = await bounded("sys_script", "collection=sys_user^active=true", "sys_id,sys_mod_count");
    const versions = rows.map(({ sys_id, sys_mod_count }) => ({ sys_id, sys_mod_count })).sort((a, b) => a.sys_id.localeCompare(b.sys_id));
    if (hash(versions) !== hash(policy.businessRuleVersions)) throw new Error("Source user business-rule policy changed or is not fully readable; refresh qualification.");
  }
  async function accessEvidence(sysId) {
    const observed = {};
    for (const [key, table] of [["roles", "sys_user_has_role"], ["groups", "sys_user_grmember"], ["providers", "provider_user_map"]])
      observed[key] = (await bounded(table, `user=${sysId}`, "sys_id,sys_mod_count")).sort((a, b) => a.sys_id.localeCompare(b.sys_id));
    return observed;
  }
  async function assess(sysId) {
    const row = await get(sysId, true);
    if (!row) throw new Error("User is absent or not readable; no eligibility inferred.");
    const blocked = [];
    if (row.sys_class_name !== "sys_user") blocked.push("specialized_or_unknown_user_class");
    if (typeof row.user_name !== "string" || !row.user_name.trim() ||
        row.user_name.toLowerCase() === principal.toLowerCase() || policy.protectedNames.includes(String(row.user_name).toLowerCase()) ||
        policy.protectedIds.includes(sysId)) blocked.push("current_or_source_protected_identity");
    if (row.identity_type !== "human" ||
        bool(row.internal_integration_user) || bool(row.web_service_access_only)) blocked.push("service_ai_or_unclassified_identity_type");
    bool(row.active); bool(row.locked_out);
    if (blocked.length) return { row, fingerprint: hash({ row, blocked, scope: "protected_identity_short_circuit" }),
      summary: { sys_id: sysId, sys_mod_count: row.sys_mod_count, eligibility: { profile: false, lock: false, deactivate: false, activate: false, unlock: false },
        blocked, responsibility_tables: null, observed_counts: null,
        classification: "Protected or non-human identity; downstream association reads were not needed and were not performed.",
        coverage: "Remaining role/group/provider/business references not evaluated; never interpreted as zero.",
        policy_evidence_sha256: policy.sourceEvidenceSha256 } };
    const local = await bounded("sys_user", `sys_id=${sysId}^sourceISEMPTY^ldap_serverISEMPTY`, "sys_id", 2);
    if (!local.length || local[0].sys_id !== sysId) blocked.push("external_source_or_ldap_marker_or_omitted_evidence");
    const observed = await accessEvidence(sysId);
    const accessFingerprint = hash(observed);
    for (const [key, table, query] of [
      ["active_tasks", "task", `assigned_to=${sysId}^active=true`],
      ["owned_bases", "kb_knowledge_base", `owner=${sysId}`], ["managed_groups", "sys_user_group", `manager=${sysId}`],
      ["direct_reports", "sys_user", `manager=${sysId}`], ["delegations_from", "sys_user_delegate", `user=${sysId}`],
      ["delegations_to", "sys_user_delegate", `delegate=${sysId}`],
    ]) observed[key] = await bounded(table, query, "sys_id,sys_mod_count");
    let reviewedAccess = null;
    if ((observed.roles.length || observed.groups.length) && policy.reviewedAccessPolicies?.length) {
      reviewedAccess = await reviewExistingAccess(sysId, policy.reviewedAccessPolicies);
    } else {
      if (observed.roles.length) blocked.push("roles_present_requiring_separate_privilege_review");
      if (observed.groups.length) blocked.push("memberships_present_requiring_separate_access_review");
    }
    if (observed.providers.length) blocked.push("provider_linked_identity");
    const responsibilities = ["active_tasks", "owned_bases", "managed_groups", "direct_reports", "delegations_from", "delegations_to"]
      .filter((key) => observed[key].length);
    const eligibility = { profile: blocked.length === 0, lock: blocked.length === 0 && responsibilities.length === 0,
      deactivate: blocked.length === 0 && responsibilities.length === 0,
      activate: blocked.length === 0 && (!reviewedAccess || reviewedAccess.activation_reviewed),
      unlock: blocked.length === 0 && bool(row.active) && (!reviewedAccess || reviewedAccess.activation_reviewed) };
    const requiredEffects = Object.fromEntries([
      ["profile", null], ["lock", { locked_out: true }], ["deactivate", { active: false, locked_out: true }],
      ["activate", { active: true }], ["unlock", { locked_out: false }],
    ].map(([kind, values]) => [kind, values ? effectList({
      lock: "local_admin_user_lock", deactivate: "local_admin_user_deactivate_and_lock",
      activate: "local_admin_user_activate", unlock: "local_admin_user_unlock",
    }[kind], row, values) : "Depends on the supplied profile fields; name changes synchronize live_profile and any update while locked can revoke sessions/OAuth."]));
    const fingerprint = hash({ row, sourceMarkersEmpty: local.length === 1,
      observed: Object.fromEntries(Object.entries(observed).map(([key, rows]) => [key, rows.sort((a, b) => a.sys_id.localeCompare(b.sys_id))])),
      blocked, responsibilities, reviewedAccess, policy: hash(policy) });
    return { row, fingerprint, accessFingerprint, reviewedAccess, summary: { sys_id: sysId, sys_mod_count: row.sys_mod_count, eligibility, blocked,
      required_native_effects: requiredEffects, reviewed_access: reviewedAccess,
      responsibility_tables: responsibilities, observed_counts: Object.fromEntries(Object.entries(observed).map(([key, rows]) => [key, rows.length])),
      classification: "Native-root account with no observed external/service/access markers; not proof of all identity-provider governance.",
      coverage: "Bounded read-visible rows only; not universal dependency absence, effective permission, or user consent.",
      policy_evidence_sha256: policy.sourceEvidenceSha256 } };
  }
  function pendingConflict(args, creating) {
    if (!fs.existsSync(folder)) return;
    for (const file of fs.readdirSync(folder).filter((file) => file.endsWith(".operation.json"))) {
      const prior = load(file);
      if (["confirmed", "no_change", "rejected_source_acl"].includes(prior.status)) continue;
      if ((creating && prior.user_name === args.user_name) || (!creating && prior.sys_id === args.sys_id))
        throw new Error("Earlier account outcome is unresolved; reconcile read-only, not by a new-UUID replay.");
    }
  }
  async function observeCreateNative(sysId, native) {
    try {
      const devices = await bounded("cmn_notif_device", `user=${sysId}`, "sys_id,user,active,primary_email,type");
      if (devices.some((device) => device.user !== sysId)) throw new Error("Notification-device read returned another user's relationship.");
      native.observed_notification_devices = devices;
      native.primary_device_observation = devices.some((device) => bool(device.active) && bool(device.primary_email))
        ? "active_primary_observed" : "active_primary_not_observed";
      native.verification = "Notification-device rows observed; no email addresses or generated identity hashes selected. Delivery/session effects not verified.";
    } catch (error) {
      native.verification = "Parent state observed; native notification-device verification unavailable.";
      native.verification_error = error.message; native.diagnostic = error.diagnostic;
    }
  }
  async function mutate(name, args) {
    if (isAttempted(args.operation_id)) throw new Error("Operation UUID already consumed; no replay.");
    const creating = name === "local_admin_user_create_disabled";
    pendingConflict(args, creating);
    await checkPolicy();
    let before;
    let beforeAccess;
    let beforeAccessFingerprint;
    let values;
    let effects = creating ? [...CREATE_EFFECTS] : [];
    if (creating) {
      if (args.user_name === principal.toLowerCase() || policy.protectedNames.includes(args.user_name)) throw new Error("Reserved/current-principal username.");
      if ((await bounded("sys_user", `user_name=${args.user_name}`, "sys_id", 2)).length) throw new Error("Username already exists; no create sent.");
      values = { user_name: args.user_name, ...args.profile, active: false, locked_out: true, notification: "1", identity_type: "human",
        internal_integration_user: false, web_service_access_only: false };
    } else {
      const saved = load(`${args.assessment_id}.assessment.json`);
      string(saved.fingerprint, HASH, "assessment fingerprint");
      if (saved.instance !== INSTANCE || saved.sys_id !== args.sys_id || saved.sys_mod_count !== args.expected_mod_count)
        throw new Error("Assessment identity/version mismatch.");
      const fresh = await assess(args.sys_id);
      if (fresh.fingerprint !== saved.fingerprint || fresh.row.sys_mod_count !== args.expected_mod_count)
        throw new Error("Account/identity/access/responsibility evidence changed; reassess before mutation.");
      const kind = { local_admin_user_update_profile: "profile", local_admin_user_lock: "lock",
        local_admin_user_activate: "activate", local_admin_user_unlock: "unlock", local_admin_user_deactivate_and_lock: "deactivate" }[name];
      if (!fresh.summary.eligibility[kind]) throw new Error("Account is outside this bounded local-account operation; inspect assessment blockers.");
      before = fresh.row;
      beforeAccess = fresh.reviewedAccess;
      beforeAccessFingerprint = fresh.accessFingerprint;
      values = kind === "profile" ? { ...args.profile } : kind === "lock" ? { locked_out: true }
        : kind === "activate" ? { active: true } : kind === "unlock" ? { locked_out: false } : { active: false, locked_out: true };
      effects = effectList(name, before, values);
      if (JSON.stringify([...args.acknowledged_native_effects].sort()) !== JSON.stringify(effects))
        throw new Error(`Explicit native-effect acknowledgment required: ${effects.join(", ") || "none"}. This is not a substitute for user approval.`);
    }
    const outcome = { format: 2, instance: INSTANCE, operation_id: args.operation_id, action: name,
      status: "prepared", ...(creating ? { user_name: args.user_name } : { sys_id: args.sys_id, assessment_id: args.assessment_id }),
      intended_fields: Object.keys(values).sort(), intended_sha256: hash(values), native_effects_declared: effects,
      native_effects: { declared: [...effects], verification: "Not observed; source write not yet attempted.",
        ...(creating ? { primary_device_observation: "not_read", identity_hash_observation: "not_read_by_design" } : {}) },
      source_write_sent: false };
    const file = `${args.operation_id}.operation.json`;
    save(file, outcome, true);
    claim(args.operation_id, { action: name, table: "sys_user", sys_id: args.sys_id, intended_sha256: outcome.intended_sha256, receipt: file });
    if (!creating && matches(before, values)) {
      outcome.status = "no_change"; save(file, outcome); record(outcome);
      return { status: "no_change", changed: false, record: project(before), operation_id: args.operation_id, native_effects_executed_by_this_call: [] };
    }
    outcome.status = "attempt"; outcome.source_write_sent = true;
    outcome.native_effects.verification = "Unknown after write attempt; native effects not independently observed.";
    save(file, outcome);
    let response;
    let failure;
    try { response = await request(creating ? "POST" : "PATCH", "sys_user", {
      sysparm_fields: "sys_id,sys_mod_count", sysparm_display_value: "false", sysparm_exclude_reference_link: "true",
    }, values, args.sys_id); } catch (error) { failure = error; }
    const sourceRejected = failure?.diagnostic?.status >= 400 && failure.diagnostic.status < 500;
    if (creating && typeof response?.result?.sys_id === "string" && ID.test(response.result.sys_id)) {
      outcome.sys_id = response.result.sys_id; outcome.response_sys_id = response.result.sys_id; save(file, outcome);
    }
    let after;
    let reconciliationFailure;
    let requestedFieldsObserved = false;
    if (failure?.diagnostic?.status !== 401) {
      try {
        if (creating) {
          const rows = await bounded("sys_user", `user_name=${args.user_name}`, GUARDED.join(","), 2);
          after = rows[0] || null;
          if (after) {
            outcome.sys_id = after.sys_id; project(after);
            if (after.user_name !== args.user_name || (response?.result?.sys_id && response.result.sys_id !== after.sys_id))
              throw new Error("Create correlation/response identity mismatch.");
          }
        } else after = await get(args.sys_id, true);
        if (!after || !matches(after, values)) throw new Error("Requested source fields were not all confirmed.");
        requestedFieldsObserved = true;
        if (creating && !failure && response?.result?.sys_id !== after.sys_id)
          throw new Error("Create response identity was not confirmed; matching state is not write attribution.");
        if (after.sys_class_name !== "sys_user" || bool(after.internal_integration_user) || bool(after.web_service_access_only) ||
            after.identity_type !== "human") throw new Error("Source identity/service guard changed.");
        if (creating && !sourceRejected && (await assess(after.sys_id)).summary.blocked.length)
          throw new Error("Created parent exists but local/external/access eligibility was not confirmed; no compensating mutation.");
        if (name === "local_admin_user_unlock" && after.failed_attempts !== "0")
          throw new Error("Unlock source failed-attempt reset was not confirmed.");
        if (!creating && (after.sys_mod_count === before.sys_mod_count || GUARDED.some((field) =>
          field !== "sys_mod_count" && !(field === "failed_attempts" && name === "local_admin_user_unlock") &&
          !Object.hasOwn(values, field) && after[field] !== before[field])))
          throw new Error("Source changed an unrequested status/identity or did not advance version.");
        if (beforeAccess) {
          const currentAccess = await reviewExistingAccess(args.sys_id, policy.reviewedAccessPolicies);
          if (currentAccess.fingerprint !== beforeAccess.fingerprint)
            throw new Error("Source changed existing access during lifecycle mutation; retain and review native effects without replay.");
        }
        if (!creating && hash(await accessEvidence(args.sys_id)) !== beforeAccessFingerprint)
          throw new Error("Source changed existing access during lifecycle mutation; retain and review native effects without replay.");
      } catch (error) { reconciliationFailure = error; }
    }
    if (failure || reconciliationFailure) {
      const accessFailure = [401, 403].includes(reconciliationFailure?.diagnostic?.status) ? reconciliationFailure : null;
      const diagnosticFailure = accessFailure || failure || reconciliationFailure;
      outcome.status = classifyFailure(diagnosticFailure, after, outcome.sys_id);
      outcome.reason = diagnosticFailure?.diagnostic?.status === 401 ? "Saved login rejected; no further source requests."
        : sourceRejected ? `Source request rejected HTTP ${failure.diagnostic.status}; matching observed state cannot establish successful write attribution.`
          : reconciliationFailure?.message || "Source response was lost; observed fields do not establish write attribution.";
      outcome.diagnostic = diagnosticFailure?.diagnostic;
      outcome.write_diagnostic = failure?.diagnostic;
      outcome.reconciliation_diagnostic = reconciliationFailure?.diagnostic;
      outcome.source_request_rejected = sourceRejected;
      outcome.source_write_confirmed = false;
      outcome.requested_state_observed = requestedFieldsObserved;
      outcome.observed_parent = after ? Object.fromEntries(PUBLIC.filter((field) => Object.hasOwn(after, field))
        .map((field) => [field, after[field]])) : null;
      outcome.rejection_is_request_outcome_only = outcome.status === "rejected_source_acl";
      outcome.reconciliation = outcome.status === "rejected_source_acl"
        ? "Source explicitly rejected ACL access and no account was visible by the unique correlation. Not a universal absence proof; stop this action. No automatic retry."
        : "Effects remain unresolved; read-only reconciliation/credential repair through coordinator, never replay.";
      const accessGate = [401, 403].includes(outcome.diagnostic?.status);
      const safeCreatedIdentity = creating && after && typeof after.sys_id === "string" && ID.test(after.sys_id) &&
        after.user_name === args.user_name && (!response?.result?.sys_id || response.result.sys_id === after.sys_id);
      if (safeCreatedIdentity && !accessGate) await observeCreateNative(after.sys_id, outcome.native_effects);
      else if (creating) outcome.native_effects.verification = accessGate
        ? "Unknown; native child reads not attempted after source authentication/access rejection."
        : "Unknown; no safely correlated created parent available for native child reads.";
      save(file, outcome); record(outcome);
      const error = new Error(`${outcome.status}: ${outcome.reason} No automatic retry or compensating write.`);
      error.diagnostic = outcome.diagnostic; error.outcome = outcome; throw error;
    }
    outcome.status = "confirmed"; outcome.sys_id = after.sys_id; outcome.after_mod_count = after.sys_mod_count;
    outcome.reconciled_after_error = Boolean(failure); outcome.diagnostic = failure?.diagnostic;
    outcome.source_write_confirmed = true;
    save(file, outcome);
    const native = outcome.native_effects;
    native.verification = "Source parent fields confirmed; native effects are not independently proved by this readback.";
    if (creating) await observeCreateNative(after.sys_id, native);
    save(file, outcome); record(outcome);
    return { status: "confirmed", changed: true, operation_id: args.operation_id, record: project(after),
      reconciled_after_error: Boolean(failure), ...(failure ? { diagnostic: failure.diagnostic } : {}), native_effects: native };
  }
  async function handle(name, args) {
    validate(name, args);
    if (name === "local_admin_user_get") {
      const row = await get(args.sys_id); return { found: Boolean(row), record: project(row) };
    }
    if (name === "local_admin_user_assess") {
      await checkPolicy();
      const assessment = await assess(args.sys_id);
      const assessmentId = crypto.randomUUID();
      save(`${assessmentId}.assessment.json`, { instance: INSTANCE, assessment_id: assessmentId,
        ...assessment.summary, fingerprint: assessment.fingerprint }, true);
      return { ...assessment.summary, assessment_id: assessmentId };
    }
    if (writing) throw new Error("Another account write is in progress; parent shared-write lock is also required.");
    writing = true;
    try { return await mutate(name, args); }
    catch (error) {
      if (!error.outcome && isAttempted(args.operation_id)) {
        const declared = name === "local_admin_user_create_disabled" ? [...CREATE_EFFECTS] : [...args.acknowledged_native_effects];
        error.outcome = { operation_id: args.operation_id, status: "uncertain_adapter_failure",
          receipt: `${args.operation_id}.operation.json`, noReplay: true, source_write_confirmed: false,
          native_effects_declared: declared, native_effects: { declared, verification: "Unknown after adapter failure; inspect the durable receipt read-only.",
            ...(name === "local_admin_user_create_disabled" ? { primary_device_observation: "not_read", identity_hash_observation: "not_read_by_design" } : {}) } };
      }
      throw error;
    } finally { writing = false; }
  }
  return { tools, handle };
}
module.exports = { tools, unsupportedOperations, createUserAccountOperations, effectList, classifyFailure };
