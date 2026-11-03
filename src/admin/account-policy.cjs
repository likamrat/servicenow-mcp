const fs = require("node:fs");
const path = require("node:path");
const { reviewedContract } = require("./contracts.cjs");
const { fingerprint } = require("./users.cjs");
const ID = /^[a-f0-9]{32}$/;
const RULE_FIELDS = ["sys_id", "sys_mod_count", "collection", "active", "name", "when", "order",
  "action_insert", "action_update", "action_delete", "action_query", "filter_condition", "condition",
  "script", "template", "sys_overrides", "role_conditions", "abort_action", "sys_scope", "sys_domain"];
const BODY_FIELDS = ["filter_condition", "condition", "script", "template", "role_conditions"];
const tools = [{
  name: "inspect_user_account_policy",
  description: "Read native account lifecycle qualification before creating or changing an account. No contract is needed to inspect inherited schema, complete bounded active-rule metadata/content fingerprints (including native templates), username uniqueness and configured readiness. Missing/drifted policy is not a source ACL denial. Review the actual source behavior and install the private account contract separately; this tool never approves, installs, repairs or weakens a policy and never writes a source record.",
  annotations: { readOnlyHint: true },
  inputSchema: { type: "object", properties: {}, required: [], additionalProperties: false },
}];

function createAccountPolicyInspection({ source, records, directory }) {
  async function evidence() {
    const schema = await records.discover("sys_user");
    const rules = [];
    for (const table of schema.lineage) {
      const found = await source.list("sys_script", `collection=${table}^active=true`, RULE_FIELDS.join(","), 100);
      if (found.length >= 100 || found.some(row => !ID.test(row.sys_id) || !/^\d+$/.test(row.sys_mod_count) ||
          RULE_FIELDS.some(field => typeof row[field] !== "string") || row.collection !== table || row.active !== "true"))
        throw new Error("Incomplete account source-rule evidence; no qualification inferred.");
      rules.push(...found);
    }
    if (!rules.length || new Set(rules.map(row => row.sys_id)).size !== rules.length)
      throw new Error("Missing or duplicate account source-rule evidence.");
    rules.sort((a, b) => a.sys_id.localeCompare(b.sys_id));
    const unique = await source.list("sys_dictionary", "name=sys_user^element=user_name", "sys_id,sys_mod_count,unique", 2);
    if (unique.length !== 1 || !ID.test(unique[0].sys_id) || !/^\d+$/.test(unique[0].sys_mod_count) ||
        !["true", "false"].includes(unique[0].unique))
      throw new Error("Native username uniqueness metadata is incomplete.");
    return { instance: source.instance, schema, schema_sha256: fingerprint(schema),
      rules_sha256: fingerprint(rules), native_user_name_unique: unique[0].unique === "true",
      businessRuleVersions: rules.map(({ sys_id, sys_mod_count }) => ({ sys_id, sys_mod_count })),
      rules: rules.map(row => ({
        ...Object.fromEntries(RULE_FIELDS.filter(field => !BODY_FIELDS.includes(field)).map(field => [field, row[field]])),
        ...Object.fromEntries(BODY_FIELDS.map(field => [`${field}_sha256`, fingerprint(row[field])])),
        source_url: `${source.instance}/sys_script.do?sys_id=${row.sys_id}`,
      })),
      coverage: "Complete bounded read-visible active rules for the discovered user lineage; not hidden source policy, effective ACL permission or an atomic source snapshot. Rule scripts, conditions and templates require operator review." };
  }
  function matches(policy, observed) {
    return fingerprint(policy.businessRuleVersions) === fingerprint(observed.businessRuleVersions) &&
      (!policy.schema_sha256 || policy.schema_sha256 === observed.schema_sha256) &&
      (!policy.rules_sha256 || policy.rules_sha256 === observed.rules_sha256) && observed.native_user_name_unique;
  }
  async function inspect() {
    const observed = await evidence();
    const exists = fs.existsSync(path.join(directory, "account-contract.json"));
    const policy = exists ? reviewedContract("account", directory, source.instance) : null;
    return { ...observed, policy_status: !policy ? "missing" : matches(policy, observed) ? "matching" : "drifted",
      qualification: policy?.schema_sha256 ? "schema_and_rule_content" : policy ? "legacy_rule_versions_only" : "not_configured",
      review_required: true, source_permission: "not_evaluated",
      review_instructions: "Review source scripts, filters, templates, native child/access/session effects, visibility and protected identities. Store the reviewed schema/rules fingerprints and complete businessRuleVersions with a separately retained sourceEvidenceSha256 in account-contract.json under the existing private state directory. Discovery never creates that file. Do not copy fixture contracts or regenerate approvals after drift.",
      reviewed_access_policies: policy?.reviewedAccessPolicies || [] };
  }
  async function check(policy) {
    if (!matches(policy, await evidence())) throw new Error("Source account schema/rule policy changed or uniqueness is unqualified; no write sent. Inspect and review qualification.");
  }
  return { tools, inspect, check };
}

module.exports = { createAccountPolicyInspection, RULE_FIELDS };
