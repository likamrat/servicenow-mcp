const { tools, effects, createAdministrativeImpact } = require("./administrative-impact.cjs");
const { protectedAccounts } = require("./contracts.cjs");
const references = [
  ["sys_user_has_role", "user"], ["sys_user_grmember", "user"], ["provider_user_map", "user"],
  ["sys_user_delegate", "user"], ["sys_user_delegate", "delegate"], ["live_profile", "document"],
  ["sys_cs_channel_user_profile", "user_document"], ["sys_filter", "user"], ["sys_user_preference", "user"],
  ["sa_business_service_user_prefs", "user"], ["task", "assigned_to"], ["task", "opened_by"], ["task", "closed_by"],
  ["kb_knowledge_base", "owner"], ["sys_user_group", "manager"], ["sys_user", "manager"],
];

function createDeletion({ source, state, principal }) {
  async function rows(table, query, fields, limit = 20, options = {}) {
    const found = await source.list(table, query, fields, limit);
    if (found.length === limit && !options.allowFullPage) throw new Error("Incomplete deletion evidence:" + table);
    const seen = new Set();
    for (const row of found) {
      if (typeof row.sys_id !== "string" || !/^[a-f0-9]{32}$/.test(row.sys_id) || seen.has(row.sys_id))
        throw new Error("Invalid deletion evidence identity:" + table);
      seen.add(row.sys_id);
      for (const field of fields.split(",")) if (!Object.hasOwn(row, field)) throw new Error("Deletion evidence field omitted:" + table + "." + field);
      if (fields.split(",").includes("sys_mod_count") && (typeof row.sys_mod_count !== "string" ||
          !/^\d+$/.test(row.sys_mod_count) && !(options.allowEmptyChildVersion && row.sys_mod_count === "")))
        throw new Error("Invalid deletion evidence version:" + table);
    }
    return found.map(row => Object.fromEntries(fields.split(",").map(field => [field, row[field]])));
  }
  async function handle(name, args) {
    if (name !== "local_admin_user_delete_assess" && state.unresolved("sys_user", args.sys_id))
      throw new Error("Earlier user outcome unresolved; no new UUID replay.");
    const impact = createAdministrativeImpact({ rows, principal, retainedIds: state.retainedIds(), references,
      ...protectedAccounts(state.directory, source.instance) });
    const before = await impact.assess({ sys_id: args.sys_id });
    if (name === "local_admin_user_delete_assess") return before;
    if (before.blocked.length) throw new Error("Administrative deletion blocked:" + before.blocked.join(","));
    if (before.target.sys_mod_count !== args.expected_mod_count || before.impact_sha256 !== args.expected_impact_sha256)
      throw new Error("Target/version/impact changed; reassess before deletion.");
    const meta = { action: name, operation_id: args.operation_id, table: "sys_user", sys_id: args.sys_id };
    const outcome = { ...meta, status: "attempt", impact_before: before, native_effects_declared: effects,
      cleanup_complete: false, parent_absent: false, native_observations: [] };
    state.claim(args.operation_id, outcome);
    let failure;
    try { await source.request("DELETE", "sys_user", {}, undefined, args.sys_id); } catch (error) { failure = error; }
    try {
      if (failure?.diagnostic?.status === 401) throw failure;
      outcome.parent_absent = !(await rows("sys_user", `sys_id=${args.sys_id}`, "sys_id", 2)).length;
      await impact.verify(before, outcome.native_observations);
      outcome.retained_references = outcome.native_observations.filter(row => row.outcome === "retained_reference");
      if (failure) throw new Error("Rejected or unacknowledged source deletion cannot be attributed from later absence.");
      if (!outcome.parent_absent || outcome.native_observations.some(row => row.expected_effect_confirmed === false))
        throw new Error("Parent or declared native effect not confirmed.");
      outcome.status = "confirmed";
      outcome.reconciled_after_error = Boolean(failure);
      outcome.source_url = `${source.instance}/sys_user.do?sys_id=${args.sys_id}`;
      state.record(outcome);
      return outcome;
    } catch (error) {
      outcome.status = "uncertain";
      outcome.error = error.message;
      outcome.diagnostic = failure?.diagnostic || error.diagnostic;
      error.outcome = outcome;
      try { state.record(outcome); } catch (receiptError) { outcome.receipt_error = receiptError.message; }
      throw error;
    }
  }
  return { tools, handle };
}

module.exports = { createDeletion };
