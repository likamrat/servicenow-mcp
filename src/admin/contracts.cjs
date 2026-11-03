const fs = require("node:fs");
const path = require("node:path");
const { validate } = require("./validate.cjs");
const id = { type: "string", pattern: "^[a-f0-9]{32}$" };
const sha = { type: "string", pattern: "^[a-f0-9]{64}$" };
const object = (properties, required = Object.keys(properties)) => ({ type: "object", properties, required, additionalProperties: false });
const versions = { type: "array", items: object({ sys_id: id, sys_mod_count: { type: "string", pattern: "^\\d+$" } }) };
const accessTables = ["sys_user_group", "sys_user_role", "sys_user_has_role", "sys_group_has_role", "sys_user_role_contains", "sys_user_grmember"];
const schemas = {
  "user-access": object({
    format: { const: 1 }, instance: { type: "string" }, sourceEvidenceSha256: sha,
    protectedIds: { type: "array", uniqueItems: true, items: id },
    protectedNames: { type: "array", uniqueItems: true, items: { type: "string", maxLength: 255 } },
    policies: { type: "array", minItems: 1, maxItems: 20, items: object({
      key: { type: "string", pattern: "^[a-z][a-z0-9_-]{0,63}$" },
      group_id: { type: ["string", "null"], pattern: "^[a-f0-9]{32}$" },
      role_id: { type: ["string", "null"], pattern: "^[a-f0-9]{32}$" },
      activate: { type: "boolean" }, enabled: { type: "boolean" }, allow_role_delegation: { type: "boolean" }, evidence_sha256: sha,
      allow_unresolved_acl_references: { type: "boolean" },
      native_effects: { type: "array", uniqueItems: true, items: { type: "string", maxLength: 100 } },
      direct_origin_values: { type: "array", minItems: 1, maxItems: 10, uniqueItems: true, items: { type: "string", maxLength: 100 } },
    }, ["key", "group_id", "role_id", "activate", "enabled", "allow_role_delegation", "evidence_sha256",
      "native_effects", "direct_origin_values"]) },
  }),
  "user-profile": object({ format: { const: 1 }, instance: { type: "string" },
    schema_sha256: sha, rules_sha256: sha, sourceEvidenceSha256: sha,
    protectedIds: { type: "array", uniqueItems: true, items: id },
    protectedNames: { type: "array", uniqueItems: true, items: { type: "string", maxLength: 255 } },
    absence_visibility_reviewed: { const: true, type: "boolean" },
  }),
  account: object({
    format: { const: 2 }, instance: { type: "string" }, sourceEvidenceSha256: sha,
    protectedIds: { type: "array", uniqueItems: true, items: id },
    protectedNames: { type: "array", uniqueItems: true, items: { type: "string", pattern: "^[a-z0-9][a-z0-9._-]{0,99}$" } },
    businessRuleVersions: { type: "array", minItems: 1, items: object({ sys_id: id, sys_mod_count: { type: "string", pattern: "^\\d+$" } }) },
    schema_sha256: sha, rules_sha256: sha,
    reviewedAccessPolicies: { type: "array", maxItems: 20, uniqueItems: true,
      items: { type: "string", pattern: "^[a-z][a-z0-9_-]{0,63}$" } },
  }, ["format", "instance", "sourceEvidenceSha256", "protectedIds", "protectedNames", "businessRuleVersions"]),
  image: object({ format: { const: 1 }, instance: { type: "string" }, schema_sha256: sha, rules_sha256: sha }),
  access: object({ format: { const: 1 }, instance: { type: "string" }, sourceEvidenceSha256: sha,
    tables: object(Object.fromEntries(accessTables.map(table => [table, object({ rules: versions, dictionary: versions })]))),
    directOriginDefaults: { type: "array", minItems: 1, uniqueItems: true, items: { type: "string", maxLength: 32 } },
  }),
};

function reviewedContract(kind, directory, instance) {
  const file = path.join(directory, `${kind}-contract.json`);
  if (!fs.existsSync(file)) throw new Error(`Missing operator-reviewed ${kind} source contract. This capability is not ready; discovery alone is not qualification.${kind === "account" ? " Use inspect_user_account_policy for read-only qualification evidence; install the reviewed account-contract.json in the existing private state directory." : ""}`);
  if (fs.lstatSync(file).isSymbolicLink() || fs.statSync(file).size > 128000)
    throw new Error("Reviewed contract must be a bounded private regular file, not a link.");
  const contract = JSON.parse(fs.readFileSync(file, "utf8"));
  validate(schemas[kind], contract, "reviewed contract");
  if (contract.instance !== instance) throw new Error("Reviewed source contract belongs to another instance.");
  if (kind === "account" && new Set(contract.businessRuleVersions.map(rule => rule.sys_id)).size !== contract.businessRuleVersions.length)
    throw new Error("Duplicate source rule identity in account contract.");
  if (kind === "account" && (Boolean(contract.schema_sha256) !== Boolean(contract.rules_sha256) ||
      contract.reviewedAccessPolicies?.length && !contract.schema_sha256))
    throw new Error("Account schema and rule-content fingerprints must be reviewed together; existing-access lifecycle requires both.");
  if (kind === "access") for (const table of Object.values(contract.tables)) for (const rows of Object.values(table))
    if (new Set(rows.map(row => row.sys_id)).size !== rows.length) throw new Error("Duplicate source identity in access contract.");
  return contract;
}

function protectedAccounts(directory, instance) {
  const protectedIds = [], protectedNames = ["admin", "guest", "system", "mms-service-account", "sharedservice.worker"];
  for (const kind of ["account", "user-profile"]) if (fs.existsSync(path.join(directory, `${kind}-contract.json`))) {
    const policy = reviewedContract(kind, directory, instance);
    protectedIds.push(...policy.protectedIds);
    protectedNames.push(...policy.protectedNames.map(name => name.toLowerCase()));
  }
  return { protectedIds: [...new Set(protectedIds)], protectedNames: [...new Set(protectedNames)] };
}

module.exports = { reviewedContract, protectedAccounts };
