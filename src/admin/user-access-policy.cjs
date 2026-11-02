const { fingerprint } = require("./users.cjs");
const ID = /^[a-f0-9]{32}$/;
const VERSION = /^\d+$/;
const ROLE_FIELDS = ["sys_id", "sys_mod_count", "name", "sys_scope", "elevated_privilege",
  "scoped_admin", "can_delegate", "assignable_by", "includes_roles", "grantable"];
const GROUP_FIELDS = ["sys_id", "sys_mod_count", "name", "active", "parent", "source", "manager", "default_assignee",
  "roles", "include_members", "exclude_manager"];
const TABLES = ["sys_user", "sys_user_group", "sys_user_role", "sys_user_grmember",
  "sys_user_has_role", "sys_group_has_role", "sys_user_role_contains"];
const EFFECTS = ["native-membership-and-cache-effects", "native-direct-and-contained-role-grants",
  "reviewed-acl-and-application-access", "conditional-source-hooks",
  "account-activation-with-lock-preserved", "reviewed-role-delegation-eligibility"];

function boolean(value) {
  if (![true, false, "true", "false", "1", "0"].includes(value)) throw new Error("Source boolean evidence is missing or invalid.");
  return [true, "true", "1"].includes(value);
}
function roleSafety(role) {
  if (typeof role.name !== "string" || !role.name ||
      /(?:^|[_.])(admin|security_admin|maint|impersonator|role_delegator|snc_internal|snc_external)(?:$|[_.])/i.test(role.name) ||
      boolean(role.elevated_privilege) || boolean(role.scoped_admin) || role.assignable_by)
    throw new Error("Elevated, administrative or restricted-grantor role is outside this access continuation.");
  boolean(role.can_delegate);
  boolean(role.grantable);
}
function createUserAccessInspection({ source, records }) {
  async function rows(table, query, fields, { optionalVersion = false } = {}) {
    const selected = [...new Set(["sys_id", ...fields])];
    const result = [];
    let cursor = "";
    for (let page = 0; page < 20; page++) {
      const found = await source.list(table, `${query}${cursor ? `^sys_id>${cursor}` : ""}^ORDERBYsys_id`, selected.join(","), 100);
      for (const row of found) {
        if (!row || typeof row.sys_id !== "string" || !ID.test(row.sys_id) || row.sys_id <= cursor ||
            selected.some(field => !Object.hasOwn(row, field)) ||
            selected.includes("sys_mod_count") && (typeof row.sys_mod_count !== "string" ||
              !VERSION.test(row.sys_mod_count) && !(optionalVersion && row.sys_mod_count === "")))
          throw new Error(`Incomplete or non-progressing access evidence: ${table}.`);
        const equalities = query.split("^").map(part => /^([a-z_]+)=([^^]*)$/.exec(part)).filter(Boolean);
        if (equalities.some(([, field, value]) => selected.includes(field) && String(row[field]) !== value))
          throw new Error(`Access evidence query identity mismatch: ${table}.`);
        result.push(Object.fromEntries(selected.map(field => [field, row[field]])));
        cursor = row.sys_id;
      }
      if (found.length < 100) return result;
    }
    throw new Error(`Access evidence exceeds bounded discovery: ${table}.`);
  }
  async function one(table, id, fields) {
    const found = await rows(table, `sys_id=${id}`, fields);
    if (found.length !== 1 || found[0].sys_id !== id) throw new Error(`Exact access definition unavailable: ${table}.`);
    return found[0];
  }
  async function selectedRows(table, field, ids, fields) {
    const result = [];
    const unique = [...new Set(ids)].sort();
    for (let start = 0; start < unique.length; start += 50) {
      const batch = unique.slice(start, start + 50);
      if (batch.some(id => !ID.test(id))) throw new Error("Invalid bounded access-query identity.");
      const found = await rows(table, `${field}IN${batch.join(",")}`, [...new Set([...fields, field])]);
      if (found.some(row => !batch.includes(row[field]))) throw new Error("Source returned access evidence outside requested identities.");
      result.push(...found);
    }
    return result;
  }
  async function inspect({ group_id = null, role_id = null, activate = false }) {
    if (!group_id && !role_id && !activate) throw new Error("Select an existing group, role or explicit activation for review.");
    for (const id of [group_id, role_id]) if (id !== null && !ID.test(id)) throw new Error("Invalid access definition identity.");
    let group = null, groupRoles = [];
    if (group_id) {
      group = await one("sys_user_group", group_id, GROUP_FIELDS);
      boolean(group.active);
      if (group.parent || group.source) throw new Error("Parented or externally managed groups require an additional reviewed integration; no grant supported.");
      groupRoles = await rows("sys_group_has_role", `group=${group_id}`, ["sys_mod_count", "group", "role", "inherits", "granted_by"]);
      if (new Set(groupRoles.map(row => row.role)).size !== groupRoles.length ||
          groupRoles.some(row => !ID.test(row.role))) throw new Error("Ambiguous group-role definition.");
      groupRoles.forEach(row => boolean(row.inherits));
    }
    const definitions = new Map(), edges = [];
    const pending = [...new Set([role_id, ...groupRoles.map(row => row.role)].filter(Boolean))];
    while (pending.length) {
      const batch = [...new Set(pending.splice(0).filter(id => !definitions.has(id)))];
      if (!batch.length) continue;
      if (definitions.size + batch.length > 500) throw new Error("Role closure exceeds bounded review.");
      const found = await selectedRows("sys_user_role", "sys_id", batch, ROLE_FIELDS);
      if (found.length !== batch.length) throw new Error("Role closure definition is absent or unreadable.");
      for (const role of found) { roleSafety(role); definitions.set(role.sys_id, role); }
      const contained = await selectedRows("sys_user_role_contains", "role", batch, ["sys_mod_count", "role", "contains"]);
      if (new Set(contained.map(row => `${row.role}:${row.contains}`)).size !== contained.length ||
          contained.some(row => !ID.test(row.contains) || row.contains === row.role))
        throw new Error("Ambiguous or self-containing role closure.");
      if (edges.length + contained.length > 5000) throw new Error("Role-edge closure exceeds bounded review.");
      edges.push(...contained);
      pending.push(...contained.map(row => row.contains));
    }
    if (role_id && !boolean(definitions.get(role_id).grantable))
      throw new Error("The selected direct role is not source-grantable; no direct grant supported.");
    const closures = new Map();
    function closure(root, ancestors = new Set()) {
      if (ancestors.has(root)) throw new Error("Cyclic contained-role graph is not supported.");
      if (closures.has(root)) return closures.get(root);
      const next = new Set([...ancestors, root]);
      const result = [...new Set([root, ...edges.filter(edge => edge.role === root).flatMap(edge => closure(edge.contains, next))])];
      closures.set(root, result);
      return result;
    }
    const directRoles = role_id ? closure(role_id) : [];
    const inheritedRoles = [...new Set(groupRoles.filter(row => boolean(row.inherits)).flatMap(row => closure(row.role)))].sort();
    const aclLinks = [], acls = new Map();
    aclLinks.push(...await selectedRows("sys_security_acl_role", "sys_user_role", [...definitions.keys()],
      ["sys_mod_count", "sys_user_role", "sys_security_acl"]));
    const aclIds = [...new Set(aclLinks.map(link => link.sys_security_acl))];
    const aclSchema = await records.discover("sys_security_acl");
    const aclRows = await selectedRows("sys_security_acl", "sys_id", aclIds,
      ["sys_id", "sys_mod_count", "name", "operation", "type", "active", "admin_overrides",
        "decision_type", "applies_to", "security_attribute", "advanced", "condition", "script"]);
    if (aclRows.length !== aclIds.length) throw new Error("Linked ACL definition is absent or unreadable.");
    for (const acl of aclRows) {
      boolean(acl.active); boolean(acl.admin_overrides); boolean(acl.advanced);
      const { script, condition, applies_to, ...metadata } = acl;
      acls.set(acl.sys_id, { ...metadata, script_sha256: fingerprint(script),
        condition_sha256: fingerprint(condition), applies_to_sha256: fingerprint(applies_to) });
    }
    const attributeIds = [...new Set(aclRows.map(row => row.security_attribute).filter(Boolean))];
    let securityAttributes = [];
    if (attributeIds.length) {
      const reference = aclSchema.fields.security_attribute?.reference;
      if (!reference) throw new Error("ACL security-attribute reference metadata is unavailable.");
      securityAttributes = await selectedRows(reference, "sys_id", attributeIds, ["sys_id", "sys_mod_count"]);
      if (securityAttributes.length !== attributeIds.length) throw new Error("Referenced ACL security-attribute versions are incomplete.");
      securityAttributes = securityAttributes.map(row => ({ table: reference, ...row }));
    }
    const sourcePolicy = [];
    for (const table of TABLES) {
      const schema = await records.discover(table);
      const rules = [];
      for (const ancestor of schema.lineage) {
        const current = await rows("sys_script", `collection=${ancestor}^active=true`,
          ["sys_mod_count", "collection", "active", "name", "when", "order", "action_insert", "action_update",
            "action_delete", "action_query", "filter_condition", "condition", "script", "sys_overrides",
            "role_conditions", "abort_action", "sys_scope", "sys_domain"]);
        rules.push(...current.map(({ script, condition, filter_condition, role_conditions, ...metadata }) => ({
          ...metadata, script_sha256: fingerprint(script), condition_sha256: fingerprint(condition),
          filter_sha256: fingerprint(filter_condition), role_conditions_sha256: fingerprint(role_conditions),
        })));
      }
      sourcePolicy.push({ table, schema_sha256: fingerprint(schema), rules: rules.sort((a, b) => a.sys_id.localeCompare(b.sys_id)) });
    }
    const native_effects = EFFECTS.filter(effect =>
      effect === "account-activation-with-lock-preserved" ? activate :
        effect === "reviewed-role-delegation-eligibility" ? [...definitions.values()].some(role => boolean(role.can_delegate)) :
        effect === "native-membership-and-cache-effects" ? Boolean(group_id) :
          effect === "native-direct-and-contained-role-grants" || effect === "reviewed-acl-and-application-access" ?
            definitions.size > 0 : true);
    const evidence = { group, group_roles: groupRoles, roles: [...definitions.values()].sort((a, b) => a.sys_id.localeCompare(b.sys_id)),
      contains: edges.sort((a, b) => a.sys_id.localeCompare(b.sys_id)),
      acl_links: aclLinks.sort((a, b) => a.sys_id.localeCompare(b.sys_id)),
      acls: [...acls.values()].sort((a, b) => a.sys_id.localeCompare(b.sys_id)),
      acl_schema_sha256: fingerprint(aclSchema), security_attributes: securityAttributes, source_policy: sourcePolicy,
      desired: { group_id, role_id, activate }, direct_roles: directRoles.sort(), inherited_roles: inheritedRoles, native_effects };
    return { ...evidence, evidence_sha256: fingerprint(evidence),
      policy_requirements: { allow_role_delegation: [...definitions.values()].some(role => boolean(role.can_delegate)) },
      delegation_meaning: "allow_role_delegation accepts existing can_delegate role metadata under review; it does not grant role_delegator authority, change a source flag or create delegation.",
      review: "Read-visible closure, ACL links and executable/schema fingerprints are review evidence, not authorization. Review application role checks and native effects too; non-elevated flags alone never establish safe access.",
      coverage: "Bounded complete pages for selected definitions, downward closure and linked ACL/attribute versions, not universal hidden/dynamic privilege or effective grant-permission proof. Native Java/security-attribute implementation semantics still require operator review. No script or condition bodies are returned." };
  }
  return { inspect, rows, one, selectedRows };
}
module.exports = { createUserAccessInspection, boolean, roleSafety, ROLE_FIELDS, EFFECTS };
