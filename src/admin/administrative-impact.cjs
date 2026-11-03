const crypto = require("node:crypto");
const ID = /^[a-f0-9]{32}$/;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const deletesReference = rule => ["delete", "delete_no_workflow", "cascade"].includes(rule);
const effects = ["primary-device-cascade-and-parent-hook", "exact-user-profile/channel/filter/preference-cleanup",
  "exact-user-session-invalidation", "native-reference-delete-clear-retain-or-restrict",
  "conditional-native-hooks-and-unenumerated-effects"];
const id = { type: "string", pattern: ID.source };
const tools = [
  { name: "local_admin_user_delete_assess", annotations: { readOnlyHint: true },
    description: "Read administrative deletion impact for one supplied user ID. Active/status/contact/provider/ordinary role/group/business links are not universal DELETE denials. Protects current operator, retained/configured identities, built-in system accounts and administrative/elevated role closure, including observed user cascades. Follows ordered native pages for known target-scoped relationships and root delete rules; returns versions, cascade metadata and an impact hash. Unreadable/omitted/inconsistent evidence stops assessment; hidden/dynamic effects remain unknown. No mutation or approval.",
    inputSchema: { type: "object", properties: { sys_id: id }, required: ["sys_id"], additionalProperties: false } },
  { name: "local_admin_user_delete_administrative", annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false },
    description: "Delete one explicitly authorized supplied user through native sys_user DELETE after exact identity/version/impact recheck. No fixture, profile-cohort, inactive/locked, blank-email or no-ordinary-role/group/business prerequisite. Never deletes current operator, protected administrator/system identities or overrides retention. Acknowledge disclosed native effects; source ACLs/rules/hooks govern deletion. No role removal, reassignment, child deletion or forced policy change. Parent absence is separate from known related effects and unknown cleanup; response loss stays uncertain. Shared runtime serialization required; no replay after ambiguity.",
    inputSchema: { type: "object", properties: { sys_id: id,
      expected_mod_count: { type: "string", pattern: "^\\d+$" },
      expected_impact_sha256: { type: "string", pattern: "^[a-f0-9]{64}$" },
      operation_id: { type: "string", pattern: UUID.source }, confirm: { type: "boolean", const: true },
      acknowledged_native_effects: { type: "array", uniqueItems: true, minItems: effects.length, maxItems: effects.length,
        items: { type: "string", enum: effects } } },
    required: ["sys_id", "expected_mod_count", "expected_impact_sha256", "operation_id", "confirm", "acknowledged_native_effects"],
    additionalProperties: false } },
];
function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") return Object.fromEntries(Object.keys(value).sort().map(k => [k, canonical(value[k])]));
  return value;
}
function digest(value) { return crypto.createHash("sha256").update(JSON.stringify(canonical(value))).digest("hex"); }
function createAdministrativeImpact({ rows, principal, retainedIds, references, protectedIds = [], protectedNames = [] }) {
  async function allRows(table, query, fields, { checkRecord, allowEmptyChildVersion = false } = {}) {
    const records = [];
    let cursor = "";
    for (;;) {
      const page = await rows(table, `${query}${cursor ? "^sys_id>" + cursor : ""}^ORDERBYsys_id`, fields, 100,
        { allowFullPage: true, allowEmptyChildVersion });
      if (!page.length) return records;
      for (const record of page) {
        if (record.sys_id <= cursor) throw new Error("Administrative page IDs unordered or non-progressing:" + table);
        if (checkRecord) checkRecord(record);
        cursor = record.sys_id;
        records.push(record);
      }
    }
  }
  async function exactUser(query, fields) {
    const found = await rows("sys_user", query, fields, 2);
    if (found.length !== 1) throw new Error("Administrative identity absent, ambiguous or not readable.");
    return found[0];
  }
  function systemIdentity(user) {
    return protectedIds.includes(user.sys_id) ||
      protectedNames.includes(user.user_name.trim().toLowerCase()) ||
      [user.first_name, user.last_name].filter(Boolean).join(" ").trim().toLowerCase() === "system";
  }
  async function administratorEvidence(userId) {
    const grants = await allRows("sys_user_has_role", `user=${userId}`, "sys_id,sys_mod_count,user,role", {
      allowEmptyChildVersion: true,
      checkRecord: row => {
        if (row.user !== userId || !ID.test(row.role)) throw new Error("Administrator-role evidence is incomplete.");
      },
    });
    const definitions = new Map(), contains = [];
    const pending = grants.map(row => row.role);
    while (pending.length) {
      const roleId = pending.pop();
      if (definitions.has(roleId)) continue;
      if (definitions.size >= 500) throw new Error("Administrator-role closure exceeds bounded review.");
      const found = await rows("sys_user_role", `sys_id=${roleId}`,
        "sys_id,sys_mod_count,name,elevated_privilege,scoped_admin", 2);
      if (found.length !== 1 || found[0].sys_id !== roleId || !found[0].name ||
          !["true", "false"].includes(found[0].elevated_privilege) || !["true", "false"].includes(found[0].scoped_admin))
        throw new Error("Administrator-role definition is absent or unreadable.");
      definitions.set(roleId, found[0]);
      const edges = await allRows("sys_user_role_contains", `role=${roleId}`, "sys_id,sys_mod_count,role,contains", {
        checkRecord: row => {
          if (row.role !== roleId || !ID.test(row.contains)) throw new Error("Administrator-role closure is incomplete.");
        },
      });
      contains.push(...edges);
      pending.push(...edges.map(row => row.contains));
    }
    const roles = [...definitions.values()].sort((a, b) => a.sys_id.localeCompare(b.sys_id));
    return { grants, roles, contains: contains.sort((a, b) => a.sys_id.localeCompare(b.sys_id)),
      protected: roles.some(role => role.elevated_privilege === "true" || role.scoped_admin === "true" ||
        /(?:^|[_.])(admin|security_admin|maint|impersonator|role_delegator)(?:$|[_.])/i.test(role.name)) };
  }
  async function relation(table, field, target, operator = "=") {
    const matches = value => typeof value === "string" && (operator === "LIKE" ? value.split(",").includes(target) : value === target);
    const records = await allRows(table, `${field}${operator}${target}`, `sys_id,sys_mod_count,${field}`, {
      allowEmptyChildVersion: true,
      checkRecord: record => {
        if (!matches(record[field])) throw new Error("Administrative impact relationship identity/version mismatch:" + table + "." + field);
      },
    });
    const metadata = records.length ? await rows("sys_dictionary", `name=${table}^element=${field}`,
      "sys_id,sys_mod_count,reference_cascade_rule", 2) : [];
    return { table, field, target, operator, records: records.sort((a, b) => a.sys_id.localeCompare(b.sys_id)),
      cascade_rule: metadata[0]?.reference_cascade_rule || "unspecified",
      dictionary: metadata[0] || null };
  }
  async function assess(args) {
    if (!args || typeof args !== "object" || Array.isArray(args) || Object.keys(args).length !== 1 || !Object.hasOwn(args, "sys_id") ||
        typeof args.sys_id !== "string" || !ID.test(args.sys_id)) throw new Error("Exact administrative assessment sys_id required.");
    if (typeof principal !== "string" || !principal || /[\u0000-\u001f^]/.test(principal))
      throw new Error("Saved operator cannot be safely resolved.");
    const operator = await exactUser(`user_name=${principal}`, "sys_id,user_name");
    if (operator.user_name.toLowerCase() !== principal.toLowerCase()) throw new Error("Saved operator identity mismatch.");
    const target = await exactUser(`sys_id=${args.sys_id}`,
      "sys_id,user_name,first_name,last_name,title,active,locked_out,notification,sys_class_name,identity_type,internal_integration_user,web_service_access_only,sys_mod_count");
    if (target.sys_id !== args.sys_id || typeof target.user_name !== "string" || !/^\d+$/.test(target.sys_mod_count))
      throw new Error("Administrative target identity/version mismatch.");
    const blocked = [];
    if (target.sys_id === operator.sys_id || target.user_name.toLowerCase() === principal.toLowerCase()) blocked.push("current_authenticated_operator");
    if (retainedIds.includes(target.sys_id)) blocked.push("explicit_user_retention_hold");
    if (systemIdentity(target)) blocked.push("protected_system_identity");
    const impact = { target, operator_sys_id: operator.sys_id, blocked,
      ...(blocked.includes("explicit_user_retention_hold") ? { retention_conflict: { sys_id: target.sys_id,
        source: "trusted runtime retainedIds", resolution: "Resolve the exact prior user retention hold with the coordinator; not a source ACL and not caller-overridable." } } : {}),
      native_effects_declared: [...effects],
      coverage: "Known target-scoped read-visible user/device relationships and root sys_user delete rules collected through ordered pages until an empty page. Empty related sys_mod_count is preserved literally as unversioned evidence, never normalized to0. Not hidden/inherited/dynamic references, a source snapshot or atomic CAS, effective DELETE permission, or independently verified session/notification effects." };
    if (!blocked.length) {
      impact.administrator_evidence = await administratorEvidence(target.sys_id);
      if (impact.administrator_evidence.protected) blocked.push("protected_administrator_role");
    }
    if (!blocked.length) {
      const contact = await rows("sys_user", `sys_id=${target.sys_id}^emailISEMPTY`, "sys_id", 2);
      const local = await rows("sys_user", `sys_id=${target.sys_id}^sourceISEMPTY^ldap_serverISEMPTY`, "sys_id", 2);
      if ([...contact, ...local].some(r => r.sys_id !== target.sys_id)) throw new Error("Administrative marker identity mismatch.");
      impact.email_present = contact.length === 0;
      impact.external_marker_present = local.length === 0;
      impact.native_policy = (await allRows("sys_script", "collection=sys_user^active=true^action_delete=true", "sys_id,sys_mod_count,name,when"))
        .sort((a, b) => a.sys_id.localeCompare(b.sys_id));
      impact.relationships = [];
      for (const [table, field] of references) impact.relationships.push(await relation(table, field, target.sys_id));
      for (const field of ["watch_list", "work_notes_list", "additional_assignee_list"])
        impact.relationships.push(await relation("task", field, target.sys_id, "LIKE"));
      const devices = await relation("cmn_notif_device", "user", target.sys_id);
      impact.relationships.push(devices);
      for (const device of devices.records) for (const [table, field, op] of [
        ["pwd_device", "device", "="], ["sys_notif_subscription", "devices", "LIKE"],
        ["cmn_notif_device_variable", "device", "="], ["cmn_notif_message", "device", "="],
      ]) impact.relationships.push(await relation(table, field, device.sys_id, op));
      const cascadingUsers = impact.relationships.filter(r => r.table === "sys_user" && deletesReference(r.cascade_rule))
        .flatMap(r => r.records.map(record => record.sys_id));
      if (cascadingUsers.includes(operator.sys_id)) blocked.push("native_cascade_to_current_operator");
      impact.retained_related_ids = [...new Set(cascadingUsers.filter(id => retainedIds.includes(id)))].sort();
      if (impact.retained_related_ids.length) blocked.push("native_cascade_conflicts_with_user_retention_hold");
      impact.cascading_user_protection = [];
      for (const sysId of [...new Set(cascadingUsers)].sort()) {
        const user = await exactUser(`sys_id=${sysId}`, "sys_id,sys_mod_count,user_name,first_name,last_name");
        if (user.sys_id !== sysId || typeof user.user_name !== "string")
          throw new Error("Cascading user identity is unreadable.");
        const privileged = await administratorEvidence(sysId);
        impact.cascading_user_protection.push({ user, administrator_evidence: privileged });
        if (systemIdentity(user) || privileged.protected) blocked.push("native_cascade_to_protected_identity");
      }
    }
    return { ...impact, impact_sha256: digest(impact) };
  }
  async function verify(impact, observations) {
    for (const rel of impact.relationships) for (const before of rel.records) {
      const after = await rows(rel.table, `sys_id=${before.sys_id}`, `sys_id,sys_mod_count,${rel.field}`, 2,
        { allowEmptyChildVersion: true });
      if (after[0] && after[0].sys_id !== before.sys_id) throw new Error("Administrative related readback identity mismatch.");
      const stillLinked = after.length && (rel.operator === "LIKE" ? after[0][rel.field].split(",").includes(rel.target) : after[0][rel.field] === rel.target);
      const expectedDelete = deletesReference(rel.cascade_rule);
      observations.push({ table: rel.table, field: rel.field, sys_id: before.sys_id,
        outcome: !after.length ? "deleted" : stillLinked ? "retained_reference" : "reference_cleared_or_changed",
        cascade_rule: rel.cascade_rule, expected_effect_confirmed: expectedDelete ? !after.length :
          rel.cascade_rule === "clear" ? !stillLinked : null,
        ...(after.length ? { after_mod_count: after[0].sys_mod_count } : {}) });
    }
    return observations;
  }
  return { assess, verify };
}
module.exports = { tools, effects, createAdministrativeImpact };
