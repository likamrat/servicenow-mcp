const fs = require("node:fs");
const path = require("node:path");
const { validate } = require("./validate.cjs");
const id = { type: "string", pattern: "^[a-f0-9]{32}$" };
const sha = { type: "string", pattern: "^[a-f0-9]{64}$" };
const object = properties => ({ type: "object", properties, required: Object.keys(properties), additionalProperties: false });
const versions = { type: "array", items: object({ sys_id: id, sys_mod_count: { type: "string", pattern: "^\\d+$" } }) };
const accessTables = ["sys_user_group", "sys_user_role", "sys_user_has_role", "sys_group_has_role", "sys_user_role_contains", "sys_user_grmember"];
const schemas = {
  account: object({
    format: { const: 2 }, instance: { type: "string" }, sourceEvidenceSha256: sha,
    protectedIds: { type: "array", uniqueItems: true, items: id },
    protectedNames: { type: "array", uniqueItems: true, items: { type: "string", pattern: "^[a-z0-9][a-z0-9._-]{0,99}$" } },
    businessRuleVersions: { type: "array", minItems: 1, items: object({ sys_id: id, sys_mod_count: { type: "string", pattern: "^\\d+$" } }) },
  }),
  image: object({ format: { const: 1 }, instance: { type: "string" }, schema_sha256: sha, rules_sha256: sha }),
  access: object({ format: { const: 1 }, instance: { type: "string" }, sourceEvidenceSha256: sha,
    tables: object(Object.fromEntries(accessTables.map(table => [table, object({ rules: versions, dictionary: versions })]))),
    directOriginDefaults: { type: "array", minItems: 1, uniqueItems: true, items: { type: "string", maxLength: 32 } },
  }),
};

function reviewedContract(kind, directory, instance) {
  const file = path.join(directory, `${kind}-contract.json`);
  if (!fs.existsSync(file)) throw new Error(`Missing operator-reviewed ${kind} source contract. This capability is not ready; discovery alone is not qualification.`);
  if (fs.lstatSync(file).isSymbolicLink() || fs.statSync(file).size > 128000)
    throw new Error("Reviewed contract must be a bounded private regular file, not a link.");
  const contract = JSON.parse(fs.readFileSync(file, "utf8"));
  validate(schemas[kind], contract, "reviewed contract");
  if (contract.instance !== instance) throw new Error("Reviewed source contract belongs to another instance.");
  if (kind === "account" && new Set(contract.businessRuleVersions.map(rule => rule.sys_id)).size !== contract.businessRuleVersions.length)
    throw new Error("Duplicate source rule identity in account contract.");
  if (kind === "access") for (const table of Object.values(contract.tables)) for (const rows of Object.values(table))
    if (new Set(rows.map(row => row.sys_id)).size !== rows.length) throw new Error("Duplicate source identity in access contract.");
  return contract;
}

module.exports = { reviewedContract };
