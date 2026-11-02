const { randomUUID } = require("node:crypto");
const { isDeepStrictEqual } = require("node:util");
const { reviewedContract } = require("./contracts.cjs");
const { validate } = require("./validate.cjs");
const { fingerprint } = require("./users.cjs");
const { createUserAccessInspection, boolean, roleSafety, ROLE_FIELDS, EFFECTS } = require("./user-access-policy.cjs");
const ID = /^[a-f0-9]{32}$/;
const id = { type: "string", pattern: ID.source }, uuid = { type: "string", format: "uuid" };
const key = { type: "string", pattern: "^[a-z][a-z0-9_-]{0,63}$" };
const object = (properties, required = Object.keys(properties)) => ({ type: "object", properties, required, additionalProperties: false });
const tool = (name, description, properties, required, readOnlyHint = true) => ({
  name, description, annotations: { readOnlyHint, ...(readOnlyHint ? {} : { destructiveHint: true, idempotentHint: false }) },
  inputSchema: object(properties, required),
});
const tools = [
  tool("inspect_user_access_policy", "Preflight generic access continuation BEFORE creating a source user. With no arguments, list privately configured definition-policy keys (not user lists). With policy, verify the enabled policy's current group, full contained-role/ACL/source-hook evidence. Alternatively supply existing group_id/role_id and optional activate to produce review evidence, NOT approval. Do not mix policy and definition inputs. No grant, adoption, directory lookup or source write.",
    { policy: key, group_id: id, role_id: id, activate: { type: "boolean" } }, []),
  tool("assess_user_access", "Read one exact source user's current identity, memberships and effective roles against an enabled operator-reviewed generic definition policy. Saves a five-minute caller-bound assessment with missing stages and material native effects. Works for newly created or existing legitimate local users, not preloaded people. No source grant or approval. Protected/operator/retained/external/service identities and incomplete evidence stop the path.",
    { sys_id: id, policy: key }),
  tool("apply_user_access", "Apply only the reviewed policy's missing existing-group membership, direct role grant and activation if explicitly configured, from this caller's current assessment. Native role expansion and unrelated access/profile preservation are verified after every stage. Never writes inherited-role bookkeeping, passwords, unlock, new role/group definitions or incident assignment. Multiple stages are not atomic: retain confirmed stages and user identity on denial/partial/uncertain outcome, never replay with any UUID or caller. Acknowledgments are not user consent or a source ACL override.",
    { sys_id: id, assessment_id: uuid, operation_id: uuid,
      acknowledged_native_effects: { type: "array", uniqueItems: true, items: { type: "string", enum: EFFECTS } } }, undefined, false),
  tool("get_user_access_operation", "Read this caller's original generic access-continuation receipt and current source access when readable. Retains user identity, stage receipts, denials and uncertainty. Does not repeat grants, delete retained accounts, upgrade attribution or clear resource holds.",
    { operation_id: uuid }),
];
const USER_FIELDS = ["sys_id", "sys_mod_count", "user_name", "first_name", "last_name", "active", "locked_out",
  "notification", "sys_class_name", "identity_type", "internal_integration_user", "web_service_access_only", "source", "ldap_server"];
const MEMBERSHIP_FIELDS = ["sys_id", "sys_mod_count", "user", "group"];
const ROLE_GRANT_FIELDS = ["sys_id", "sys_mod_count", "user", "role", "state", "inherited", "granted_by"];

function createUserAccess({ source, state, records, principal, now = Date.now }) {
  const inspection = createUserAccessInspection({ source, records });
  const { rows, one } = inspection;
  function contract() {
    const policy = reviewedContract("user-access", state.directory, source.instance);
    if (new Set(policy.policies.map(item => item.key)).size !== policy.policies.length)
      throw new Error("Duplicate configured user-access policy key.");
    return policy;
  }
  async function ready(policyKey) {
    const approved = contract();
    const selected = approved.policies.find(item => item.key === policyKey);
    if (!selected || !selected.enabled) throw new Error("User access policy is absent or disabled; no grant permitted.");
    const evidence = await inspection.inspect(selected);
    if (evidence.policy_requirements.allow_unresolved_acl_references && !selected.allow_unresolved_acl_references)
      throw new Error("Source-native unresolved ACL references require explicit reviewed policy permission; no grant permitted.");
    if (evidence.policy_requirements.allow_role_delegation && !selected.allow_role_delegation)
      throw new Error("Role delegation eligibility requires explicit reviewed policy permission; no grant permitted.");
    if (evidence.evidence_sha256 !== selected.evidence_sha256 ||
        !isDeepStrictEqual([...evidence.native_effects].sort(), [...selected.native_effects].sort()))
      throw new Error("Reviewed group/role/ACL/source policy changed; no grant permitted.");
    return { approved, selected, evidence, policy_sha256: fingerprint(approved) };
  }
  function clear(userId) {
    if (state.unresolved("sys_user") || state.unresolved("sys_user", userId))
      throw new Error("User has an unresolved operation; reconcile the original receipt without replay.");
  }
  async function observe(userId, approved) {
    const user = await one("sys_user", userId, USER_FIELDS);
    if (typeof user.user_name !== "string" || !user.user_name || /[\u0000-\u001f^]/.test(principal))
      throw new Error("Source user/operator identity is not safely readable.");
    const operators = await rows("sys_user", `user_name=${principal}`, ["sys_id", "user_name"]);
    if (operators.length !== 1 || operators[0].user_name.toLowerCase() !== principal.toLowerCase())
      throw new Error("Current source operator is not uniquely identified.");
    if (userId === operators[0].sys_id || user.user_name.toLowerCase() === principal.toLowerCase() ||
        state.retainedIds().includes(userId) || approved.protectedIds.includes(userId) ||
        [...approved.protectedNames.map(name => name.toLowerCase()), "admin", "guest", "system"].includes(user.user_name.toLowerCase()))
      throw new Error("Current operator, protected user or retention hold prevents access continuation.");
    boolean(user.active); boolean(user.locked_out);
    if (user.sys_class_name !== "sys_user" || user.identity_type !== "human" ||
        boolean(user.internal_integration_user) || boolean(user.web_service_access_only) || user.source || user.ldap_server ||
        (await rows("provider_user_map", `user=${userId}`, ["sys_id", "user"])).length)
      throw new Error("External, provider-managed, service or unknown identity is not an eligible local access target.");
    const memberships = await rows("sys_user_grmember", `user=${userId}`, MEMBERSHIP_FIELDS, { optionalVersion: true });
    if (memberships.some(row => !ID.test(row.group)) || new Set(memberships.map(row => row.group)).size !== memberships.length)
      throw new Error("Ambiguous or invalid current group memberships.");
    const roles = await rows("sys_user_has_role", `user=${userId}`, ROLE_GRANT_FIELDS, { optionalVersion: true });
    for (const grant of roles) {
      if (!ID.test(grant.role) || grant.state !== "active") throw new Error("Current role state is incomplete or pending.");
      boolean(grant.inherited);
    }
    const roleIds = [...new Set(roles.map(row => row.role))];
    const definitions = await inspection.selectedRows("sys_user_role", "sys_id", roleIds, ROLE_FIELDS);
    if (definitions.length !== roleIds.length) throw new Error("Current role definitions are incomplete.");
    definitions.forEach(roleSafety);
    return { user, memberships, roles };
  }
  function stages(selected, before) {
    const result = [];
    if (selected.activate && !boolean(before.user.active)) {
      if (!boolean(before.user.locked_out)) throw new Error("Activation of an unlocked account is outside this no-unlock continuation.");
      result.push("activate");
    }
    if (selected.group_id && !before.memberships.some(row => row.group === selected.group_id)) result.push("membership");
    if (selected.role_id && !before.roles.some(row => row.role === selected.role_id)) result.push("role");
    return result;
  }
  function existingExpansion(evidence, before) {
    const expected = [
      ...(before.memberships.some(row => row.group === evidence.desired.group_id) ? evidence.inherited_roles : []),
      ...(before.roles.some(row => row.role === evidence.desired.role_id) ? evidence.direct_roles : []),
    ];
    if (expected.some(role => !before.roles.some(row => row.role === role)))
      throw new Error("Existing access lacks the reviewed native role expansion; do not replay grants to repair it.");
  }
  function verify(before, after, evidence, completedStages, stage, responseId) {
    const allowedRoles = new Set([
      ...before.roles.map(row => row.role),
      ...(completedStages.includes("membership") ? evidence.inherited_roles : []),
      ...(completedStages.includes("role") ? evidence.direct_roles : []),
    ]);
    for (const row of before.memberships) if (!after.memberships.some(current => isDeepStrictEqual(current, row)))
      throw new Error("Existing membership changed during access continuation.");
    for (const row of before.roles) if (!after.roles.some(current => isDeepStrictEqual(current, row)))
      throw new Error("Existing role origin/version changed during access continuation.");
    if (after.memberships.some(row => !before.memberships.some(old => old.sys_id === row.sys_id) &&
        !(completedStages.includes("membership") && row.group === evidence.desired.group_id)))
      throw new Error("Unrequested native membership appeared; retain and review partial effects.");
    if (after.roles.some(row => !allowedRoles.has(row.role)))
      throw new Error("Unreviewed native role appeared; retain and review partial effects.");
    const expectedRoles = [
      ...(completedStages.includes("membership") ? evidence.inherited_roles : []),
      ...(completedStages.includes("role") ? evidence.direct_roles : []),
    ];
    if (expectedRoles.some(role => !after.roles.some(row => row.role === role)))
      throw new Error("Native contained/group role expansion was not fully observed.");
    if (stage === "membership" && !after.memberships.some(row => row.sys_id === responseId &&
        row.user === before.user.sys_id && row.group === evidence.desired.group_id))
      throw new Error("Exact created membership was not confirmed.");
    if (stage === "role" && !after.roles.some(row => row.sys_id === responseId && row.user === before.user.sys_id &&
        row.role === evidence.desired.role_id && !boolean(row.inherited)))
      throw new Error("Exact native direct role grant was not confirmed.");
    for (const field of USER_FIELDS) {
      if (stage === "activate" && field === "active") {
        if (!boolean(after.user.active)) throw new Error("Requested activation was not confirmed.");
      } else if (stage === "activate" && field === "sys_mod_count") {
        if (BigInt(after.user.sys_mod_count) <= BigInt(before.user.sys_mod_count)) throw new Error("Activation version did not advance.");
      } else if (after.user[field] !== before.user[field]) throw new Error("Unrequested source user identity/status changed.");
    }
  }
  async function assess(args, callerKey) {
    clear(args.sys_id);
    const policy = await ready(args.policy);
    const before = await observe(args.sys_id, policy.approved);
    existingExpansion(policy.evidence, before);
    const missing = stages(policy.selected, before);
    const assessment_id = randomUUID(), expires_at_ms = now() + 300000;
    state.record({ action: "user_access_assessment", status: "assessed", operation_id: assessment_id, caller_key: callerKey,
      sys_id: args.sys_id, policy: args.policy, policy_sha256: policy.policy_sha256, evidence_sha256: policy.evidence.evidence_sha256,
      before, missing, expires_at_ms });
    return { assessment_id, expires_at: new Date(expires_at_ms).toISOString(), sys_id: args.sys_id,
      policy: args.policy, before, missing_stages: missing, native_effects: policy.evidence.native_effects,
      source_url: `${source.instance}/sys_user.do?sys_id=${args.sys_id}`, atomic_compare_and_swap: false,
      meaning: "Current source evidence only; assessment and policy do not replace authorization for the user or its access effects." };
  }
  async function apply(args, callerKey) {
    if (state.events(args.operation_id).length) throw new Error("Operation UUID already used; no replay.");
    clear(args.sys_id);
    const saved = state.events(args.assessment_id).find(row => row.action === "user_access_assessment");
    if (!saved || saved.caller_key !== callerKey || saved.sys_id !== args.sys_id)
      throw new Error("Access assessment identity or caller does not match.");
    if (now() >= saved.expires_at_ms) throw new Error("Access assessment expired; no source write sent.");
    const policy = await ready(saved.policy);
    let current = await observe(args.sys_id, policy.approved);
    existingExpansion(policy.evidence, current);
    if (saved.policy_sha256 !== policy.policy_sha256 || !isDeepStrictEqual(current, saved.before))
      throw new Error("User/access/policy changed since assessment; no source write sent.");
    if (!isDeepStrictEqual([...args.acknowledged_native_effects].sort(), [...policy.evidence.native_effects].sort()))
      throw new Error("Acknowledge the exact reviewed native effects; this is not user consent.");
    const pending = stages(policy.selected, current);
    const intent = { action: "user_access_operation", operation_id: args.operation_id, caller_key: callerKey,
      table: "sys_user", sys_id: args.sys_id, assessment_id: args.assessment_id, policy: saved.policy,
      policy_sha256: policy.policy_sha256, before: current, native_effects: policy.evidence.native_effects };
    const receipts = [];
    state.record({ ...intent, status: "prepared", stages: receipts });
    try {
      for (const stage of pending) {
        const freshPolicy = await ready(saved.policy);
        const fresh = await observe(args.sys_id, freshPolicy.approved);
        if (freshPolicy.policy_sha256 !== policy.policy_sha256 || !isDeepStrictEqual(fresh, current) ||
            now() >= saved.expires_at_ms)
          throw new Error("Source/policy changed or assessment expired between stages; no next stage sent.");
        const table = stage === "activate" ? "sys_user" : stage === "membership" ? "sys_user_grmember" : "sys_user_has_role";
        const values = stage === "activate" ? { active: true } : stage === "membership" ?
          { user: args.sys_id, group: policy.selected.group_id } : { user: args.sys_id, role: policy.selected.role_id };
        if (!state.isAttempted(args.operation_id)) state.claim(args.operation_id, intent);
        const receipt = { stage, table, status: "attempt", values };
        receipts.push(receipt);
        state.record({ ...intent, status: "stage_attempt", stages: structuredClone(receipts) });
        let response, failure;
        try { response = await source.request(stage === "activate" ? "PATCH" : "POST", table,
          { sysparm_fields: "sys_id", sysparm_display_value: "false", sysparm_exclude_reference_link: "true" },
          values, stage === "activate" ? args.sys_id : undefined); }
        catch (error) { failure = error; }
        if (typeof response?.result?.sys_id === "string" && ID.test(response.result.sys_id)) {
          receipt.response_sys_id = response.result.sys_id;
          state.record({ ...intent, status: "stage_response", stages: structuredClone(receipts) });
        }
        if (failure) {
          receipt.original_error = { message: failure.message, diagnostic: failure.diagnostic };
          state.record({ ...intent, status: "stage_error", stages: structuredClone(receipts) });
        }
        if (failure?.diagnostic?.status === 401) throw failure;
        const after = await observe(args.sys_id, policy.approved);
        receipt.observed = after;
        state.record({ ...intent, status: "stage_observed", stages: structuredClone(receipts) });
        if (failure) throw failure;
        if (!receipt.response_sys_id || stage === "activate" && receipt.response_sys_id !== args.sys_id)
          throw new Error("Source response identity missing or inconsistent; observation cannot establish attribution.");
        verify(current, after, policy.evidence, [stage], stage, receipt.response_sys_id);
        if (stage === "role" && !policy.selected.direct_origin_values.includes(
          after.roles.find(row => row.sys_id === receipt.response_sys_id).granted_by))
          throw new Error("Native direct role origin differs from reviewed policy.");
        receipt.status = "confirmed";
        current = after;
        state.record({ ...intent, status: "stage_confirmed", stages: structuredClone(receipts) });
      }
      if (!state.isAttempted(args.operation_id)) state.claim(args.operation_id, intent);
      const result = { status: pending.length ? "confirmed" : "no_change", operation_id: args.operation_id,
        sys_id: args.sys_id, stages: receipts, after: current, source_write_attempted: pending.length > 0,
        atomic_compare_and_swap: false, source_url: `${source.instance}/sys_user.do?sys_id=${args.sys_id}`,
        meaning: "Reviewed access continuation only, not an incident assignment or universal eligibility/permission proof." };
      state.record({ ...intent, ...result });
      return result;
    } catch (error) {
      const result = { status: state.isAttempted(args.operation_id) ? "uncertain" : "not_sent",
        operation_id: args.operation_id, sys_id: args.sys_id, stages: receipts,
        source_write_attempted: state.isAttempted(args.operation_id), partial: receipts.some(row => row.status === "confirmed"),
        retained_user: args.sys_id, error: error.message, diagnostic: error.diagnostic,
        meaning: "Retain the user and all confirmed/observed relationships. Do not retry, roll back or resume with another UUID." };
      error.outcome = result;
      try { state.record({ ...intent, ...result }); } catch (receiptError) { result.receipt_error = receiptError.message; }
      throw error;
    }
  }
  async function status(args, callerKey) {
    const own = state.events(args.operation_id).filter(row => row.action === "user_access_operation" && row.caller_key === callerKey);
    if (!own.length) throw new Error("User access operation is not available to this requester.");
    const { caller_key, ...outcome } = own.at(-1);
    if (!["confirmed", "no_change", "uncertain", "not_sent"].includes(outcome.status))
      outcome.status = state.isAttempted(args.operation_id) ? "uncertain" : "not_sent";
    let current, observationError;
    try { current = await observe(outcome.sys_id, contract()); } catch (error) { observationError = error.message; }
    return { operation_id: args.operation_id, status: outcome.status, outcome, current, observation_error: observationError,
      unresolved_hold: state.unresolved("sys_user", outcome.sys_id),
      meaning: "Read-only evidence, no replay, attribution upgrade, account deletion or hold removal." };
  }
  async function handle(name, args, callerKey) {
    const entry = tools.find(item => item.name === name);
    if (!entry) throw new Error("User access tool unavailable.");
    validate(entry.inputSchema, args);
    if (name === "inspect_user_access_policy") {
      if (args.policy) {
        if (Object.keys(args).length !== 1) throw new Error("Do not mix configured policy and definition-review inputs.");
        const result = await ready(args.policy);
        return { ...result.evidence, policy: args.policy, policy_available: true,
          qualification: "matched_reviewed_evidence",
          caller_scope_required: "User.Access.Manage", source_user_required: false };
      }
      if (!Object.keys(args).length) return { policies: contract().policies.map(({ key, group_id, role_id, activate, enabled,
        allow_role_delegation, allow_unresolved_acl_references }) =>
        ({ key, group_id, role_id, activate, enabled, allow_role_delegation, allow_unresolved_acl_references,
          qualification: "not_evaluated" })), policy_available: null, qualification: "not_evaluated",
        meaning: "This lists configured policy keys and their enabled flags only. Readiness has not been evaluated, not denied. Call inspect_user_access_policy with one policy key to verify live evidence before creating a user." };
      return { ...await inspection.inspect(args), policy_available: false, qualification: "review_required",
        caller_scope_required: "User.Access.Manage" };
    }
    if (name === "assess_user_access") return assess(args, callerKey);
    if (name === "apply_user_access") return apply(args, callerKey);
    return status(args, callerKey);
  }
  return { tools, handle };
}
module.exports = { tools, createUserAccess };
