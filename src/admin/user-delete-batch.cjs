const { randomUUID } = require("node:crypto");
const { effects } = require("./administrative-impact.cjs");
const { fingerprint } = require("./users.cjs");
const { assertResourceClear } = require("./resource-guard.cjs");
const { createUserBatchJobs } = require("./user-batch-jobs.cjs");
const id = { type: "string", pattern: "^[a-f0-9]{32}$" };
const uuid = { type: "string", format: "uuid" };
const object = (properties, required = Object.keys(properties)) =>
  ({ type: "object", properties, required, additionalProperties: false });
const tools = [
  { name: "local_admin_user_delete_batch_assess", annotations: { readOnlyHint: true },
    description: "Start a durable, read-only bulk deletion assessment for up to1000 explicitly supplied user IDs and exact logins. Returns immediately; use batch_status for completion, paginated impacts and the immutable plan hash. Adds caller-supplied preservation IDs to existing operator/system/administrator/retention guards. Bulk cleanup also preserves integration/nonhuman identities and refuses cascades into other users, even within the supplied set. No source mutation, approval or automatic deletion. Unknown evidence stops assessment. Keep the installed MCP process alive; interrupted jobs never resume automatically.",
    inputSchema: object({ batch_id: uuid, targets: { type: "array", minItems: 1, maxItems: 1000,
      items: object({ sys_id: id, expected_user_name: { type: "string", maxLength: 255 } }) },
    preserve_user_ids: { type: "array", maxItems: 1000, uniqueItems: true, items: id } }) },
  { name: "local_admin_user_delete_batch", annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false },
    description: "Start ONE server-side bulk job for a fully reviewed completed batch assessment and exact plan hash. Returns immediately. Deletes eligible targets sequentially under the existing shared runtime lock with fresh per-target identity/version/impact/protection checks; no unchecked deleteMultiple or caller filter. Preserves blocked/drifted targets, stops the batch on any source failure or uncertain effect, retains original per-target operation UUIDs and full receipts. Not atomic. Confirmed parent absence never claims universal cleanup. No replay or automatic restart. Read batch_status; use batch_cancel to request a safe stop.",
    inputSchema: object({ batch_id: uuid, operation_id: uuid,
      expected_plan_sha256: { type: "string", pattern: "^[a-f0-9]{64}$" }, confirm: { type: "boolean", const: true },
      acknowledged_native_effects: { type: "array", minItems: effects.length, maxItems: effects.length,
        uniqueItems: true, items: { type: "string", enum: effects } } }) },
  { name: "local_admin_user_delete_batch_status", annotations: { readOnlyHint: true },
    description: "Read a caller/instance/principal-bound bulk job without waiting for its shared source lock. Returns phase, complete counts, coverage and a bounded page of per-user outcomes; include_evidence returns full saved impact/error/receipt for at most10 items. Does not retry, resume, clear locks or infer that another process stopped. Assessment completion is not deletion. Unattempted, blocked, drifted and uncertain remain distinct from confirmed.",
    inputSchema: object({ batch_id: uuid, offset: { type: "integer", minimum: 0, maximum: 1000 },
      limit: { type: "integer", minimum: 1, maximum: 100 }, include_evidence: { type: "boolean" } },
    ["batch_id", "offset", "limit"]) },
  { name: "local_admin_user_delete_batch_cancel", annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true },
    description: "Request a safe stop of an owned bulk assessment/deletion job. Does not interrupt or roll back an in-flight source operation. The job stops before another target; batch_status confirms when it stopped. Does not release locks, replay or resume a stopped job.",
    inputSchema: object({ batch_id: uuid }) },
];
const activePhases = new Set(["assessment_queued", "assessing", "delete_queued", "deleting"]);

function createUserDeleteBatch({ source, state, deletion, principal }) {
  const jobs = createUserBatchJobs({ source, state, principal, kind: "delete" });
  const { owned, persist, readEvidence, saveEvidence, stopRequested, launch } = jobs;
  function planHash(batch) {
    return fingerprint({ batch_id: batch.batch_id, preserve_user_ids: batch.preserve_user_ids,
      targets: batch.items.map(item => ({ sys_id: item.sys_id, expected_user_name: item.expected_user_name,
        operation_id: item.operation_id, assessment: item.assessment })) });
  }
  function extraBlocks(batch, item, impact) {
    const blocked = [...impact.blocked];
    if (impact.target.user_name !== item.expected_user_name) blocked.push("supplied_login_mismatch");
    if (!["human", "unclassified"].includes(impact.target.identity_type) ||
        impact.target.internal_integration_user !== "false" || impact.target.web_service_access_only !== "false")
      blocked.push("integration_or_nonhuman_identity");
    if (batch.preserve_user_ids.includes(item.sys_id)) blocked.push("batch_preserved_identity");
    if (impact.relationships?.some(rel => ["delete", "delete_no_workflow", "cascade"].includes(rel.cascade_rule) &&
        rel.records.some(record => batch.preserve_user_ids.includes(record.sys_id))))
      blocked.push("native_cascade_to_batch_preserved_identity");
    if (impact.cascading_user_protection?.length) blocked.push("native_user_cascade_requires_individual_review");
    const approved = new Set(batch.items.map(row => row.sys_id));
    for (const related of impact.cascading_user_protection || []) {
      if (!approved.has(related.user.sys_id)) blocked.push("native_user_cascade_outside_supplied_set");
      if (batch.preserve_user_ids.includes(related.user.sys_id)) blocked.push("native_user_cascade_to_batch_preserved_identity");
    }
    return [...new Set(blocked)];
  }
  function publicStatus(batch, args) {
    if (args.include_evidence && args.limit > 10) throw new Error("Full bulk evidence is limited to10 items per page.");
    const counts = {};
    for (const item of batch.items) counts[item.status] = (counts[item.status] || 0) + 1;
    const stopped = stopRequested(batch);
    const phase = batch.phase === "ready" && stopped ? "cancelled" : batch.phase;
    return { batch_id: batch.batch_id, operation_id: batch.operation_id, phase,
      plan_sha256: batch.plan_sha256, total: batch.items.length, counts,
      offset: args.offset, next_offset: args.offset + args.limit < batch.items.length ? args.offset + args.limit : null,
      items: batch.items.slice(args.offset, args.offset + args.limit).map(item => ({ ...item,
        ...(args.include_evidence && item.evidence_saved ? { evidence: readEvidence(batch.batch_id, item.sys_id) } : {}) })),
      stop_requested: stopped, cleanup_complete: false, error: batch.error,
      ...(activePhases.has(phase) ? jobs.observation(batch) : { execution_observation: "terminal" }),
      coverage: "Complete supplied target set, not an instance inventory or atomic transaction. Per-target native evidence is read-visible only; hidden effects/session revocation and universal cleanup remain unverified." };
  }
  async function assess(args, caller) {
    if (new Set(args.targets.map(row => row.sys_id)).size !== args.targets.length ||
        args.targets.some(row => !row.expected_user_name.trim() || /[\u0000-\u001f\u007f]/.test(row.expected_user_name)))
      throw new Error("Supply distinct user IDs and nonempty exact logins.");
    const batch = await state.run(async () => jobs.create(args.batch_id, caller, {
      phase: "assessment_queued", preserve_user_ids: [...args.preserve_user_ids].sort(),
      items: args.targets.map(target => ({ ...target, operation_id: randomUUID(), status: "unassessed" })),
    }));
    launch(batch, "assessing", async () => {
      for (const item of batch.items) {
        if (stopRequested(batch)) { batch.phase = "cancelled"; persist(batch); return; }
        const impact = await deletion.handle("local_admin_user_delete_assess", { sys_id: item.sys_id });
        const blocked = extraBlocks(batch, item, impact);
        item.assessment = { expected_mod_count: impact.target.sys_mod_count,
          expected_impact_sha256: impact.impact_sha256, blocked,
          dependencies: (impact.relationships || []).filter(rel => rel.records.length).map(rel =>
            ({ table: rel.table, field: rel.field, count: rel.records.length, cascade_rule: rel.cascade_rule })) };
        item.status = blocked.length ? "blocked" : "eligible";
        saveEvidence(batch.batch_id, item.sys_id, { impact });
        item.evidence_saved = true;
        persist(batch);
      }
      batch.plan_sha256 = planHash(batch);
      batch.phase = "ready";
      persist(batch);
    }, "assessment_failed");
    return { batch_id: batch.batch_id, phase: "assessment_queued", total: batch.items.length };
  }
  async function execute(args, caller) {
    const batch = await state.run(async () => {
      const reviewed = owned(args.batch_id, caller);
      if (reviewed.operation_id || state.isAttempted(args.operation_id)) throw new Error("Bulk operation already executed/attempted; no replay.");
      if (reviewed.phase !== "ready" || reviewed.plan_sha256 !== args.expected_plan_sha256 ||
          planHash(reviewed) !== args.expected_plan_sha256 || stopRequested(reviewed))
        throw new Error("Complete reviewed bulk plan/hash required; cancelled or changed plans cannot execute.");
      state.claim(args.operation_id, { action: "local_admin_user_delete_batch", table: "user_delete_batch",
        batch_id: args.batch_id, plan_sha256: args.expected_plan_sha256 });
      reviewed.operation_id = args.operation_id;
      reviewed.phase = "delete_queued";
      persist(reviewed);
      return reviewed;
    });
    launch(batch, "deleting", async () => {
      try {
        for (const item of batch.items) {
          if (stopRequested(batch)) { batch.phase = "cancelled"; break; }
          if (item.status !== "eligible") continue;
          assertResourceClear(state.directory, { sys_id: item.sys_id });
          if (state.isAttempted(item.operation_id) || state.unresolved("sys_user") || state.unresolved("sys_user", item.sys_id))
            throw new Error("Earlier user operation unresolved or already attempted; no batch replay.");
          const current = await deletion.handle("local_admin_user_delete_assess", { sys_id: item.sys_id });
          const blocked = extraBlocks(batch, item, current);
          const evidence = readEvidence(batch.batch_id, item.sys_id);
          evidence.preflight = current;
          if (blocked.length || current.target.sys_mod_count !== item.assessment.expected_mod_count ||
              current.impact_sha256 !== item.assessment.expected_impact_sha256) {
            item.status = blocked.length ? "blocked" : "drifted";
            item.blocked = blocked;
            saveEvidence(batch.batch_id, item.sys_id, evidence);
            persist(batch);
            continue;
          }
          if (stopRequested(batch)) { batch.phase = "cancelled"; break; }
          item.status = "attempting";
          saveEvidence(batch.batch_id, item.sys_id, evidence);
          persist(batch);
          try {
            const outcome = await deletion.handle("local_admin_user_delete_administrative", {
              sys_id: item.sys_id, operation_id: item.operation_id,
              expected_mod_count: item.assessment.expected_mod_count,
              expected_impact_sha256: item.assessment.expected_impact_sha256,
              confirm: true, acknowledged_native_effects: args.acknowledged_native_effects,
            });
            evidence.outcome = outcome;
            item.status = outcome.status;
            item.parent_absent = outcome.parent_absent;
          } catch (error) {
            item.status = error.outcome?.status || "stopped";
            evidence.error = { message: error.message, diagnostic: error.diagnostic };
            if (error.outcome) evidence.outcome = error.outcome;
            saveEvidence(batch.batch_id, item.sys_id, evidence);
            persist(batch);
            throw error;
          }
          saveEvidence(batch.batch_id, item.sys_id, evidence);
          persist(batch);
        }
        if (batch.phase === "deleting") batch.phase = "completed";
        persist(batch);
        state.record({ operation_id: batch.operation_id, batch_id: batch.batch_id, status: batch.phase,
          cleanup_complete: false, counts: publicStatus(batch, { offset: 0, limit: 1 }).counts });
      } catch (error) {
        state.record({ operation_id: batch.operation_id, batch_id: batch.batch_id, status: "stopped",
          error: error.message, diagnostic: error.diagnostic });
        throw error;
      }
    }, "stopped");
    return { batch_id: batch.batch_id, operation_id: batch.operation_id, phase: "delete_queued", total: batch.items.length };
  }
  async function handle(name, args, caller) {
    if (name === "local_admin_user_delete_batch_assess") return assess(args, caller);
    if (name === "local_admin_user_delete_batch") return execute(args, caller);
    const batch = owned(args.batch_id, caller);
    if (name === "local_admin_user_delete_batch_status") return publicStatus(batch, args);
    if (name === "local_admin_user_delete_batch_cancel") {
      if (activePhases.has(batch.phase) || batch.phase === "ready")
        jobs.requestStop(batch);
      return { batch_id: batch.batch_id, phase: batch.phase, stop_requested: stopRequested(batch),
        in_flight_operation: "Not interrupted or rolled back; inspect status for the final outcome." };
    }
    throw new Error("Unknown bulk user deletion operation.");
  }
  return { tools, handle };
}
module.exports = { createUserDeleteBatch };
