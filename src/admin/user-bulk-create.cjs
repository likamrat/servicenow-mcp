const { randomUUID } = require("node:crypto");
const { createUserBatchJobs } = require("./user-batch-jobs.cjs");
const { tools: userTools, fingerprint, creationEffects, updateEffects } = require("./users.cjs");
const { effectList } = require("./user-account.cjs");
const { reviewedContract } = require("./contracts.cjs");
const { validate } = require("./validate.cjs");
const object = (properties, required = Object.keys(properties)) => ({ type: "object", properties, required, additionalProperties: false });
const uuid = { type: "string", format: "uuid" };
const id = { type: "string", pattern: "^[a-f0-9]{32}$" };
const profile = userTools.find(tool => tool.name === "create_user").inputSchema.properties.profile;
const target = object({ user_name: { type: "string", maxLength: 255 }, profile,
  existing: object({ sys_id: id, expected_mod_count: { type: "string", pattern: "^\\d+$" } }) }, ["user_name", "profile"]);
const finalState = object({ active: { type: "boolean", const: true }, locked_out: { type: "boolean", const: false } });
const tools = [
  { name: "assess_user_bulk_create", annotations: { readOnlyHint: true },
    description: "Start a durable native-only assessment of supplied user profiles. Returns a batch ID immediately; inspect get_user_bulk_create for completion. Explicit existing sys_id/version/login bindings preserve accounts, including blank-email accounts; name/email collisions never imply adoption. No directory discovery or source writes. Omitted final_state preserves existing lifecycle and creates missing users inactive/locked. Explicit active/unlocked intent requires reviewed lifecycle/access policy. Review the complete assessment and effects before starting.",
    inputSchema: object({ batch_id: uuid, targets: { type: "array", minItems: 1, maxItems: 500, items: target },
      final_state: finalState }, ["batch_id", "targets"]) },
  { name: "start_user_bulk_create", annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false },
    description: "Start an assessed native user-creation/reconciliation batch using its exact assessment hash and disclosed effects. Uses the shared durable batch lock and semantic create/profile/activate/unlock operations, with stable per-stage UUIDs and current source guards. No passwords, role grants/removals or login renames. Source uncertainty stops the batch; inspect retained receipts without replay. Confirmation and acknowledgments do not replace user authorization.",
    inputSchema: object({ batch_id: uuid, expected_assessment_sha256: { type: "string", pattern: "^[a-f0-9]{64}$" },
      confirm: { type: "boolean", const: true },
      acknowledged_native_effects: { type: "array", uniqueItems: true, items: { type: "string", maxLength: 100 } } }) },
  { name: "get_user_bulk_create", annotations: { readOnlyHint: true },
    description: "Read this caller's durable user-creation batch and per-target stage evidence without acquiring its source-write lock. Counts distinguish created, already-matching, corrected, blocked, failed, uncertain and unstarted targets. Interrupted jobs never resume automatically; observations do not upgrade attribution or clear source holds.",
    inputSchema: object({ batch_id: uuid, offset: { type: "integer", minimum: 0 },
      limit: { type: "integer", minimum: 1, maximum: 100 } }, ["batch_id"]) },
  { name: "cancel_user_bulk_create", annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true },
    description: "Latch a stop request for this caller's creation batch. Takes effect between targets/stages; does not abort an in-flight source call, undo confirmed work, clear uncertainty or permit replay.",
    inputSchema: object({ batch_id: uuid }) },
];
const stages = ["create", "profile", "activate", "unlock"];
const activePhases = ["accepted", "assessing", "queued", "running"];
const bool = value => {
  if (![true, false, "true", "false", "0", "1"].includes(value)) throw new Error("Missing or invalid source lifecycle boolean.");
  return value === true || value === "true" || value === "1";
};
const same = (left, right) => fingerprint(left) === fingerprint(right);
const accessEvidence = assessment => ({ reviewed_access: assessment?.reviewed_access ?? null,
  counts: Object.fromEntries(["roles", "groups", "providers"].map(key => [key, assessment ? assessment.observed_counts?.[key] : 0])) });
function literal(value) {
  if (typeof value !== "string" || !value.trim() || value !== value.trim() || /[\u0000-\u001f\u007f^]|javascript:/i.test(value))
    throw new Error("Use exact plain user identities, not encoded queries.");
  return value.toLowerCase();
}
function validateTargets(targets) {
  const seen = new Map();
  for (const [index, input] of targets.entries()) {
    const identities = [`identity:${literal(input.user_name)}`];
    if (input.profile.email) identities.push(`identity:${literal(input.profile.email)}`);
    if (input.existing) identities.push(`id:${input.existing.sys_id}`);
    if (input.profile.first_name && input.profile.last_name && !input.existing)
      identities.push(`name:${literal(`${input.profile.first_name} ${input.profile.last_name}`)}`);
    for (const key of new Set(identities)) {
      if (seen.has(key)) throw new Error(`Duplicate or case-colliding batch targets at indexes ${seen.get(key)} and ${index}.`);
      seen.set(key, index);
    }
  }
}

function createUserBulkCreate({ source, state, principal, users, runOperation }) {
  const jobs = createUserBatchJobs({ source, state, principal, kind: "create" });
  function assessmentHash(batch) {
    return fingerprint({ batch_id: batch.batch_id, final_state: batch.final_state, account_policy_sha256: batch.account_policy_sha256,
      items: batch.items.map(item => ({ item_key: item.item_key, input: item.input, operation_ids: item.operation_ids,
        evidence: jobs.readEvidence(batch.batch_id, item.item_key) })) });
  }
  async function resolve(input, caller) {
    const candidates = new Map();
    const queries = [["user_name", input.user_name]];
    if (input.user_name.includes("@")) queries.push(["email", input.user_name]);
    if (input.profile.email) {
      queries.push(["email", input.profile.email]);
      if (literal(input.profile.email) !== literal(input.user_name)) queries.push(["user_name", input.profile.email]);
    }
    if (input.profile.first_name && input.profile.last_name)
      queries.push(["name", `${input.profile.first_name} ${input.profile.last_name}`]);
    for (const [field, identity] of queries) {
      literal(identity);
      const result = await users.handle("lookup_users", { field, identity }, caller);
      if (result.limitReached || result.resolution === "incomplete") throw new Error("Identity candidate coverage is incomplete.");
      for (const row of result.candidates) {
        const prior = candidates.get(row.sys_id);
        if (prior && !same(prior, row)) throw new Error("Identity changed during bulk resolution.");
        candidates.set(row.sys_id, row);
        if (input.existing && row.sys_id !== input.existing.sys_id && field !== "name")
          throw new Error(`Another source identity has the supplied ${field}; no adoption or write permitted.`);
      }
    }
    if (!input.existing && candidates.size)
      throw Object.assign(new Error("Existing identity candidates require an explicit sys_id, current version and preserved login binding."),
        { candidates: [...candidates.values()] });
    if (input.existing) {
      const result = await users.handle("get_user", { sys_id: input.existing.sys_id }, caller);
      if (!result.found || result.record.sys_mod_count !== input.existing.expected_mod_count ||
          literal(result.record.user_name) !== literal(input.user_name))
        throw new Error("Explicit existing identity/login/version changed; do not rename, replace or recreate it.");
      const candidate = candidates.get(input.existing.sys_id);
      if (!candidate || candidate.sys_mod_count !== result.record.sys_mod_count)
        throw new Error("Exact existing login was not consistently resolved.");
      return result.record;
    }
    return null;
  }
  async function prepare(input, final_state, caller) {
    const before = await resolve(input, caller);
    const name = before ? "update_user" : "create_user";
    const args = { profile: input.profile, ...(before ? input.existing : { user_name: input.user_name }) };
    const prepared = await users.prepare(name, args);
    if (before && Object.entries(before).some(([field, value]) => field !== "source_url" && prepared.before[field] !== value))
      throw new Error("Source user changed during bulk profile qualification.");
    const profile_changes = Object.fromEntries(Object.entries(input.profile).filter(([field, value]) => !before || before[field] !== value));
    const lifecycle = [];
    let account_assessment = null;
    if (before) {
      account_assessment = await runOperation("local_admin_user_assess", { sys_id: before.sys_id }, caller);
      if (account_assessment.sys_mod_count !== before.sys_mod_count || account_assessment.blocked.length ||
          !account_assessment.eligibility.profile)
        throw new Error(`Existing account is not qualified: ${account_assessment.blocked.join(", ") || "source/access changed"}.`);
      if (final_state) {
        if (!bool(before.active) && !account_assessment.eligibility.activate ||
            bool(before.active) && bool(before.locked_out) && !account_assessment.eligibility.unlock)
          throw new Error("Existing access requires reviewed activation/unlock coverage; do not omit the user or strip roles.");
      }
    }
    if (final_state) {
      if (!before || !bool(before.active)) lifecycle.push("activate");
      if (!before || bool(before.locked_out)) lifecycle.push("unlock");
    }
    const effects = before ? Object.keys(profile_changes).length ? [...updateEffects] : [] : [...creationEffects];
    const status = before || { active: false, locked_out: true };
    for (const stage of lifecycle) effects.push(...effectList(`local_admin_user_${stage}`,
      stage === "unlock" ? { ...status, active: true } : status, stage === "activate" ? { active: true } : { locked_out: false }));
    const { assessment_id, ...account_evidence } = account_assessment || {};
    return { input, before, profile_changes, lifecycle, account_evidence,
      disposition: !before ? "create" : Object.keys(profile_changes).length || lifecycle.length ? "correct" : "already_matching",
      source_sha256: fingerprint(prepared.before),
      profile_policy_sha256: fingerprint(prepared.evidence.approved),
      native_effects: [...new Set(effects)].sort() };
  }
  async function lifecyclePolicy(caller) {
    const policy = await runOperation("inspect_user_account_policy", {}, caller);
    if (policy.policy_status !== "matching" || policy.qualification !== "schema_and_rule_content")
      throw new Error("Active/unlocked bulk creation requires matching reviewed schema and rule-content lifecycle policy.");
    return fingerprint({ schema: policy.schema_sha256, rules: policy.rules_sha256,
      approved: reviewedContract("account", state.directory, source.instance) });
  }
  async function assess(batch) {
    batch.account_policy_sha256 = batch.final_state ? await lifecyclePolicy(batch.caller_key) : null;
    for (const item of batch.items) {
      if (jobs.stopRequested(batch)) { batch.phase = "stopped"; jobs.persist(batch); return; }
      try {
        const plan = await prepare(item.input, batch.final_state, batch.caller_key);
        jobs.saveEvidence(batch.batch_id, item.item_key, { plan, stages: [] });
        item.evidence_saved = true;
        item.disposition = plan.disposition;
        item.status = "assessed";
        item.before = plan.before;
        item.native_effects = plan.native_effects;
      } catch (error) {
        item.status = "blocked";
        item.error = error.message;
        item.diagnostic = error.diagnostic;
        item.candidates = error.candidates;
        batch.phase = "blocked";
        jobs.persist(batch);
        return;
      }
      jobs.persist(batch);
    }
    batch.native_effects = [...new Set(batch.items.flatMap(item => item.native_effects))].sort();
    batch.assessment_sha256 = assessmentHash(batch);
    batch.phase = "assessed";
    jobs.persist(batch);
  }
  async function verifyFinal(plan, current, final_state, caller) {
    const final = await users.handle("get_user", { sys_id: current.sys_id }, caller);
    if (!final.found || final.record.sys_mod_count !== current.sys_mod_count ||
        final.record.user_name !== (plan.before?.user_name || plan.input.user_name) ||
        Object.entries(plan.input.profile).some(([field, value]) => final.record[field] !== value) ||
        final_state && (!bool(final.record.active) || bool(final.record.locked_out)) ||
        !final_state && (bool(final.record.active) !== (plan.before ? bool(plan.before.active) : false) ||
          bool(final.record.locked_out) !== (plan.before ? bool(plan.before.locked_out) : true)) ||
        final.record.notification !== (plan.before?.notification ?? "1"))
      throw new Error("Final profile, identity, version or requested lifecycle did not match; retain stage attribution separately.");
    let account_assessment = null;
    if (plan.before || final_state) {
      account_assessment = await runOperation("local_admin_user_assess", { sys_id: current.sys_id }, caller);
      if (account_assessment.sys_mod_count !== final.record.sys_mod_count || account_assessment.blocked.length ||
          !same(accessEvidence(account_assessment), accessEvidence(plan.before ? plan.account_evidence : null)))
        throw new Error("Account identity or existing access changed during bulk reconciliation; retain original stage receipts.");
    }
    return { record: final.record, account_assessment };
  }
  function hold(batch, item, failure) {
    if (!state.isAttempted(item.item_key)) state.claim(item.item_key, { action: "user_bulk_create_hold", table: "sys_user",
      sys_id: failure.sys_id, batch_id: batch.batch_id });
    state.record({ ...failure, operation_id: item.item_key, status: "uncertain" });
  }
  async function execute(batch) {
    if (batch.final_state && await lifecyclePolicy(batch.caller_key) !== batch.account_policy_sha256)
      throw new Error("Account lifecycle policy changed since bulk assessment.");
    for (const item of batch.items) {
      if (jobs.stopRequested(batch)) { batch.phase = "stopped"; jobs.persist(batch); return; }
      const evidence = jobs.readEvidence(batch.batch_id, item.item_key);
      const { plan } = evidence;
      let current = plan.before;
      let sent = false;
      let stage;
      let verifying = false;
      const save = () => { jobs.saveEvidence(batch.batch_id, item.item_key, evidence); jobs.persist(batch); };
      try {
        const fresh = await prepare(item.input, batch.final_state, batch.caller_key);
        if (fresh.source_sha256 !== plan.source_sha256 || fresh.profile_policy_sha256 !== plan.profile_policy_sha256 ||
            !same(fresh.native_effects, plan.native_effects) || !same(fresh.lifecycle, plan.lifecycle) ||
            !same(fresh.profile_changes, plan.profile_changes) || !same(fresh.account_evidence, plan.account_evidence))
          throw new Error("Target or policy changed since bulk assessment; no target write sent.");
        item.status = "running";
        save();
        const pending = [...(!plan.before ? ["create"] : Object.keys(plan.profile_changes).length ? ["profile"] : []), ...plan.lifecycle];
        for (stage of pending) {
          if (jobs.stopRequested(batch)) {
            item.status = "stopped"; batch.phase = "stopped"; save(); return;
          }
          let name, args;
          const operation_id = item.operation_ids[stage];
          if (stage === "create" || stage === "profile") {
            name = stage === "create" ? "create_user" : "update_user";
            args = { operation_id, profile: stage === "create" ? item.input.profile : plan.profile_changes,
              ...(stage === "create" ? { user_name: item.input.user_name } :
                { sys_id: current.sys_id, expected_mod_count: current.sys_mod_count }) };
          } else {
            const assessment = await runOperation("local_admin_user_assess", { sys_id: current.sys_id }, batch.caller_key);
            if (!same(accessEvidence(assessment), accessEvidence(plan.before ? plan.account_evidence : null)))
              throw Object.assign(new Error("Existing access changed between semantic stages; retain and review prior effects."),
                { outcome: { status: sent ? "uncertain" : "not_sent", source_write_attempted: sent, sys_id: current.sys_id } });
            if (assessment.sys_mod_count !== current.sys_mod_count || !assessment.eligibility[stage])
              throw new Error("Current lifecycle/access qualification changed; retain confirmed stages.");
            name = `local_admin_user_${stage}`;
            args = { operation_id, sys_id: current.sys_id, expected_mod_count: current.sys_mod_count,
              assessment_id: assessment.assessment_id, acknowledged_native_effects: assessment.required_native_effects[stage] };
            if (args.acknowledged_native_effects.some(effect => !batch.native_effects.includes(effect)))
              throw new Error("Lifecycle requires native effects not acknowledged for this batch.");
          }
          const receipt = { stage, operation_id, tool: name, arguments: args, status: "prepared" };
          evidence.stages.push(receipt);
          save();
          const result = await runOperation(name, args, batch.caller_key);
          sent ||= state.isAttempted(operation_id);
          if (!["confirmed", "no_change"].includes(result.status) || result.reconciled_after_error)
            throw Object.assign(new Error("Semantic stage did not confirm write attribution."), { outcome: result });
          receipt.status = result.status;
          receipt.result = result;
          current = result.record;
          item.sys_id = current.sys_id;
          save();
        }
        verifying = true;
        const final = await verifyFinal(plan, current, batch.final_state, batch.caller_key);
        evidence.final = final.record;
        evidence.final_account_assessment = final.account_assessment;
        item.sys_id = evidence.final.sys_id;
        item.status = plan.disposition === "create" ? "created" : plan.disposition === "correct" ? "corrected" : "already_matching";
        save();
      } catch (error) {
        sent ||= stages.some(key => state.isAttempted(item.operation_ids[key]));
        const unresolvedStage = evidence.stages.some(receipt => state.isAttempted(receipt.operation_id) &&
          !["confirmed", "no_change"].includes(receipt.status));
        item.status = unresolvedStage || verifying && sent || error.outcome?.status === "uncertain" ? "uncertain" : "blocked";
        item.error = error.message;
        item.diagnostic = error.diagnostic;
        evidence.failure = { stage, error: error.message, diagnostic: error.diagnostic, outcome: error.outcome,
          source_write_attempted: sent, sys_id: current?.sys_id || error.outcome?.sys_id };
        const pending = evidence.stages.at(-1);
        if (pending?.status === "prepared") {
          pending.status = state.isAttempted(pending.operation_id) ? "uncertain" : "not_sent";
          pending.error = evidence.failure;
        }
        if (item.status === "uncertain") hold(batch, item, evidence.failure);
        batch.phase = item.status;
        save();
        return;
      }
    }
    for (const item of batch.items) {
      if (jobs.stopRequested(batch)) { batch.phase = "stopped"; jobs.persist(batch); return; }
      const evidence = jobs.readEvidence(batch.batch_id, item.item_key);
      try {
        const final = await verifyFinal(evidence.plan, evidence.final, batch.final_state, batch.caller_key);
        evidence.roster_readback = final.record;
        evidence.roster_account_assessment = final.account_assessment;
        evidence.roster_readback_at = new Date().toISOString();
        jobs.saveEvidence(batch.batch_id, item.item_key, evidence);
      } catch (error) {
        evidence.roster_error = { error: error.message, diagnostic: error.diagnostic, sys_id: item.sys_id,
          source_write_attempted: evidence.stages.some(receipt => state.isAttempted(receipt.operation_id)) };
        item.status = "uncertain";
        item.error = error.message;
        hold(batch, item, evidence.roster_error);
        jobs.saveEvidence(batch.batch_id, item.item_key, evidence);
        batch.phase = "uncertain";
        jobs.persist(batch);
        return;
      }
    }
    batch.phase = "completed";
    jobs.persist(batch);
  }
  function status(batch, { offset = 0, limit = 100 } = {}) {
    const stopped = jobs.stopRequested(batch);
    const phase = batch.phase === "assessed" && stopped ? "stopped" : batch.phase;
    const counts = Object.fromEntries(["created", "already_matching", "corrected", "blocked", "failed", "uncertain", "stopped", "assessed", "pending", "running"]
      .map(value => [value, batch.items.filter(item => item.status === value).length]));
    return { ...(activePhases.includes(phase) ? jobs.observation(batch) : { execution_observation: "terminal" }),
      batch_id: batch.batch_id, phase, error: batch.error, stop_requested: stopped,
      targets: batch.items.slice(offset, offset + limit).map(item => ({ ...item,
      evidence: item.evidence_saved ? jobs.readEvidence(batch.batch_id, item.item_key) : null })),
      total: batch.items.length, offset, limit, has_more: offset + limit < batch.items.length,
      counts, eligible: phase === "assessed", roster_readback_complete: phase === "completed",
      final_state: batch.final_state, creation_defaults: { active: false, locked_out: true },
      assessment_sha256: batch.assessment_sha256, native_effects: batch.native_effects,
      directory_verified: false, atomic: false, source_observation: "Per-target final readback at its recorded stage, not an atomic roster snapshot." };
  }
  async function handle(name, args, caller) {
    const tool = tools.find(item => item.name === name);
    if (!tool) throw new Error("Bulk user creation operation unavailable.");
    validate(tool.inputSchema, args);
    if (name === "assess_user_bulk_create") {
      validateTargets(args.targets);
      const batch = await state.run(() => jobs.create(args.batch_id, caller, {
        phase: "accepted", final_state: args.final_state || null, caller_key: caller,
        items: args.targets.map(input => ({ input, item_key: randomUUID(), status: "pending",
          operation_ids: Object.fromEntries(stages.map(stage => [stage, randomUUID()])) })),
      }));
      jobs.launch(batch, "assessing", () => assess(batch), "failed");
      return status(batch);
    }
    const batch = jobs.owned(args.batch_id, caller);
    if (name === "get_user_bulk_create") return status(batch, args);
    if (name === "cancel_user_bulk_create") {
      if (activePhases.includes(batch.phase) || batch.phase === "assessed") jobs.requestStop(batch);
      return status(batch);
    }
    const accepted = await state.run(() => {
      const current = jobs.owned(args.batch_id, caller);
      if (current.phase !== "assessed" || current.execution_requested || state.isAttempted(current.batch_id) || jobs.stopRequested(current))
        throw new Error("Batch is not an unstarted, fully assessed creation request.");
      if (current.assessment_sha256 !== args.expected_assessment_sha256 ||
          assessmentHash(current) !== args.expected_assessment_sha256 ||
          !same([...args.acknowledged_native_effects].sort(), current.native_effects))
        throw new Error("Use the exact creation assessment hash and native effects; these do not replace user consent.");
      state.claim(current.batch_id, { action: "user_bulk_create", table: "user_create_batch", batch_id: current.batch_id });
      current.execution_requested = true;
      current.phase = "queued";
      jobs.persist(current);
      return current;
    });
    jobs.launch(accepted, "running", async () => {
      await execute(accepted);
      const settled = accepted.phase === "completed" || accepted.phase === "stopped" && jobs.stopRequested(accepted);
      state.record({ operation_id: accepted.batch_id, batch_id: accepted.batch_id,
        status: settled ? "confirmed" : accepted.phase, batch_phase: accepted.phase,
        counts: status(accepted, { offset: 0, limit: 1 }).counts });
    }, "failed");
    return status(accepted);
  }
  return { tools, handle };
}
module.exports = { createUserBulkCreate, tools };
