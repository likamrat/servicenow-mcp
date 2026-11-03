const { tools } = require("../../contracts/incident-tools.json");
const { createRecords } = require("./records.cjs");
const { validate } = require("./validate.cjs");
const ID = /^[a-f0-9]{32}$/;
const VERSION = /^\d+$/;
const incidentFields = ["sys_id", "number", "sys_mod_count", "assigned_to", "assignment_group"];
const userFields = ["sys_id", "user_name", "name", "first_name", "last_name", "email", "active", "sys_mod_count"];
const noteFields = ["sys_id", "name", "element", "element_id", "value", "sys_created_on"];
const NOTE_LIMIT = 20;

function createIncidents({ source, state, records }) {
  async function readWorkNotes(sysId, lineage, entryId) {
    const rows = await source.list("sys_journal_field",
      `element_id=${sysId}^element=work_notes^nameIN${lineage.join(",")}` +
      (entryId ? `^sys_id=${entryId}` : "^ORDERBYDESCsys_created_on^ORDERBYDESCsys_id"),
      noteFields.join(","), entryId ? 2 : NOTE_LIMIT + 1);
    const ids = new Set();
    for (const row of rows) {
      if (!ID.test(row.sys_id) || ids.has(row.sys_id) || entryId && row.sys_id !== entryId ||
          row.element_id !== sysId || row.element !== "work_notes" || !lineage.includes(row.name) ||
          typeof row.value !== "string" || row.value.length > 20000 ||
          typeof row.sys_created_on !== "string" || !/^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$/.test(row.sys_created_on))
        throw new Error("Incident work-note evidence is incomplete or inconsistent.");
      ids.add(row.sys_id);
    }
    if (!entryId && rows.some((row, i) => i && (row.sys_created_on > rows[i - 1].sys_created_on ||
        row.sys_created_on === rows[i - 1].sys_created_on && row.sys_id > rows[i - 1].sys_id)))
      throw new Error("Incident work-note ordering is inconsistent.");
    return rows;
  }
  async function prepareWorkNote(sysId, schema) {
    const rows = await readWorkNotes(sysId, schema.lineage);
    const latest = rows[0]?.sys_created_on ?? null;
    return { lineage: schema.lineage, ids: rows.map(row => row.sys_id), latest,
      latest_complete: rows.length <= NOTE_LIMIT || rows.at(-1).sys_created_on < latest };
  }
  async function observeWorkNote(sysId, value, baseline, entryId) {
    const rows = await readWorkNotes(sysId, baseline.lineage, entryId);
    const limitReached = !entryId && rows.length > NOTE_LIMIT;
    const visible = rows.slice(0, NOTE_LIMIT);
    const matches = visible.filter(row => row.value === value && !baseline.ids.includes(row.sys_id) &&
      (!baseline.latest || row.sys_created_on > baseline.latest ||
        baseline.latest_complete && row.sys_created_on === baseline.latest));
    const incomplete = limitReached && (!baseline.latest || rows.at(-1).sys_created_on >= baseline.latest);
    return { status: matches.length === 1 && !incomplete ? "observed" : incomplete || matches.length > 1 ? "unknown" : "not_observed",
      ...(matches.length === 1 && !incomplete ? { entry: matches[0] } : {}),
      limit: NOTE_LIMIT, limitReached, source_url: `${source.instance}/incident.do?sys_id=${sysId}`,
      meaning: "Exact requested text in a new visible work-note entry, not a scalar field or proof of attribution after uncertainty. Absence is limited by source ACLs and this bounded read." };
  }
  async function exact(number) {
    const rows = await source.list("incident", `number=${number}`, incidentFields.join(","), 2);
    if (rows.length !== 1 || rows[0].number !== number || !ID.test(rows[0].sys_id) ||
        typeof rows[0].sys_mod_count !== "string" || !VERSION.test(rows[0].sys_mod_count) ||
        !["assigned_to", "assignment_group"].every(field => typeof rows[0][field] === "string" &&
          (rows[0][field] === "" || ID.test(rows[0][field]))))
      throw new Error("Exact incident identity, version or assignment fields unavailable; no write sent.");
    return rows[0];
  }
  async function resolve(args) {
    const identity = args.identity.trim();
    if (!identity || /[\u0000-\u001f^]|javascript:/i.test(identity) ||
        args.field === "sys_id" && !ID.test(identity))
      throw new Error("Use a nonempty exact identity, not an encoded query.");
    const fields = args.field ? [args.field] : ["user_name", "email", "name", "first_name"];
    const candidates = new Map();
    let incomplete = false;
    for (const field of fields) {
      const rows = await source.list("sys_user", `${field}=${identity}`, userFields.join(","), 21);
      if (rows.length > 20) incomplete = true;
      for (const row of rows) {
        if (!ID.test(row.sys_id) || userFields.some(key => typeof row[key] !== "string") ||
            row[field].toLowerCase() !== identity.toLowerCase())
          throw new Error("Exact user identity evidence is incomplete or inconsistent.");
        const selected = Object.fromEntries(userFields.map(key => [key, row[key]]));
        if (candidates.has(row.sys_id) && JSON.stringify(candidates.get(row.sys_id)) !== JSON.stringify(selected))
          throw new Error("User identity changed during resolution; read again before selecting.");
        candidates.set(row.sys_id, selected);
      }
    }
    incomplete ||= candidates.size > 20;
    return { resolution: incomplete ? "incomplete" : candidates.size === 1 ? "unique" : candidates.size ? "ambiguous" : "not_found",
      candidates: [...candidates.values()].slice(0, 20).map(row => ({
        ...row, source_url: `${source.instance}/sys_user.do?sys_id=${row.sys_id}`,
      })), limitReached: incomplete,
      meaning: "Exact source identities only; not Entra synchronization or proof of assignment eligibility." };
  }
  async function referenceValues(schema, input) {
    const values = { ...input };
    for (const [field, value] of Object.entries(values)) {
      const spec = schema.fields[field];
      if (!spec) throw new Error(`Unknown incident field: ${field}.`);
      if (spec.readOnlyMetadata) throw new Error(`Source metadata marks ${field} read-only.`);
      if (!spec.reference) continue;
      if (value === null || value === "") { values[field] = ""; continue; }
      if (typeof value !== "string" || !ID.test(value))
        throw new Error(`Reference ${field} requires an exact source sys_id, or null/empty to clear.`);
      if (spec.reference === "sys_user" && (state.unresolved("sys_user") || state.unresolved("sys_user", value)))
        throw new Error("Referenced user has an unresolved operation; reconcile before incident assignment.");
      const rows = await source.list(spec.reference, `sys_id=${value}`, "sys_id", 2);
      if (rows.length !== 1 || rows[0].sys_id !== value)
        throw new Error(`Reference ${field} is absent, ambiguous or unreadable; no write sent.`);
    }
    return values;
  }
  async function mutate(name, args, callerKey) {
    if (state.events(args.operation_id).length) throw new Error("Operation UUID already used; inspect the original outcome without replay.");
    const creating = name === "create_incident", deleting = name === "delete_incident";
    const before = creating ? null : await exact(args.number.toUpperCase());
    if (before && before.sys_mod_count !== args.expected_mod_count) throw new Error("Incident changed since your read; no write sent.");
    if (state.unresolved("incident") || before && state.unresolved("incident", before.sys_id))
      throw new Error("Earlier incident outcome unresolved; a new UUID cannot replay it.");
    const schema = await records.discover("incident");
    const values = deleting ? undefined : await referenceValues(schema, args.values);
    const appending = !creating && !deleting && Object.hasOwn(values, "work_notes");
    if (appending && schema.fields.work_notes?.type !== "journal_input")
      throw new Error("Source work_notes is not a supported journal_input field; no write sent.");
    const preserveGroup = !creating && !deleting && (appending || Object.hasOwn(values, "assigned_to")) &&
      !Object.hasOwn(values, "assignment_group");
    const intent = { action: "incident_intent", operation_id: args.operation_id, caller_key: callerKey,
      table: "incident", sys_id: before?.sys_id, number: before?.number, before,
      values, tool: name, status: "prepared" };
    state.record(intent);
    let sourceResult, workNote;
    const observeNote = async entryId => {
      try { return await observeWorkNote(before.sys_id, values.work_notes, intent.note_baseline, entryId); }
      catch (error) {
        return { status: "unknown", error: error.message, diagnostic: error.diagnostic,
          meaning: "Work-note observation failed; no absence or append confirmation." };
      }
    };
    try {
      const guarded = createRecords({ source, state: { ...state, record: entry =>
        state.record(entry.status === "confirmed" ? { ...entry, status: "record_fields_confirmed" } : entry) },
      beforeWrite: async () => {
        if (before) {
          const current = await exact(before.number);
          if (current.sys_id !== before.sys_id || current.sys_mod_count !== before.sys_mod_count ||
              current.assigned_to !== before.assigned_to || current.assignment_group !== before.assignment_group)
            throw new Error("Incident context changed during preflight; no write sent.");
        }
        if (values) await referenceValues(schema, values);
        if (appending) {
          intent.note_baseline = await prepareWorkNote(before.sys_id, schema);
          const current = await exact(before.number);
          if (current.sys_id !== before.sys_id || current.sys_mod_count !== before.sys_mod_count)
            throw new Error("Incident changed during work-note preflight; no write sent.");
          state.record(intent);
        }
      },
      ...(appending ? { verifyWorkNote: async () => {
        workNote = await observeNote();
        if (workNote.status !== "observed")
          throw new Error("A new matching incident work note was not independently confirmed.");
      } } : {}) });
      sourceResult = await guarded.handle(creating ? "local_record_create" : deleting ? "local_record_delete" : "local_record_update", {
        table: "incident", operation_id: args.operation_id, ...(values ? { values } : {}),
        ...(creating ? { correlation_field: args.correlation_field } :
          { sys_id: before.sys_id, expected_mod_count: args.expected_mod_count }),
        ...(deleting ? { confirm: args.confirm } : {}),
      });
      if (sourceResult.reconciledAfterError)
        throw Object.assign(new Error("State was observed after a lost/error response; attribution remains uncertain. Do not retry."),
          { diagnostic: sourceResult.original_error?.diagnostic });
      if (!creating && !deleting && BigInt(sourceResult.record.sys_mod_count) <= BigInt(before.sys_mod_count))
        throw new Error("An advanced source version was not confirmed.");
      if (preserveGroup) {
        const after = await exact(before.number);
        if (after.assignment_group !== before.assignment_group ||
            after.assigned_to !== (Object.hasOwn(values, "assigned_to") ? values.assigned_to : before.assigned_to) ||
            after.sys_mod_count !== sourceResult.record.sys_mod_count)
          throw Object.assign(new Error("Intended assignee and unchanged assignment group were not both confirmed."),
            { outcome: { sys_id: after.sys_id, observed: after } });
      }
      const result = { ...sourceResult, status: "confirmed", source_write_attempted: true, atomic_compare_and_swap: false,
        ...(appending ? { work_note: workNote } : {}),
        ...(preserveGroup ? { assignment_group_preserved: true } : {}) };
      state.record({ ...intent, ...result, action: "incident_intent" });
      return result;
    } catch (error) {
      const attempted = state.isAttempted(args.operation_id);
      if (appending && attempted && !workNote) workNote =
        (error.diagnostic?.status === 401 || error.outcome?.record_fields?.diagnostic?.status === 401) ?
        { status: "unknown", error: "Source authentication rejected; no further observation attempted." } : await observeNote();
      const outcome = { operation_id: args.operation_id, status: attempted ? "uncertain" : "not_sent",
        source_write_attempted: attempted, source_rejected: attempted && error.diagnostic?.status >= 400 && error.diagnostic.status < 500,
        sys_id: sourceResult?.sys_id || error.outcome?.sys_id || before?.sys_id,
        observed: error.outcome?.observed || sourceResult?.record, diagnostic: error.diagnostic, error: error.message,
        original_error: sourceResult?.original_error || error.outcome?.original_error,
        ...(appending ? { work_note: workNote || { status: "not_sent" },
          record_fields: sourceResult?.record_fields || error.outcome?.record_fields || { status: attempted ? "unknown" : "not_sent" } } : {}),
        atomic_compare_and_swap: false };
      error.outcome = outcome;
      try { state.record({ ...intent, ...outcome, action: "incident_intent" }); }
      catch (receiptError) { outcome.receipt_error = receiptError.message; }
      throw error;
    }
  }
  async function status(args, callerKey) {
    const entries = state.events(args.operation_id);
    const own = entries.filter(row => row.action === "incident_intent" && row.caller_key === callerKey);
    if (!own.length) throw new Error("Incident operation is not available to this requester.");
    const last = own.at(-1), attempted = state.isAttempted(args.operation_id);
    const { caller_key, note_baseline, ...outcome } = last;
    if (outcome.status === "prepared") {
      outcome.status = attempted ? "uncertain" : "not_sent";
      outcome.source_write_attempted = attempted;
    }
    const sysId = last.sys_id || entries.findLast(row => ID.test(row.sys_id))?.sys_id;
    let current, observationError, workNote;
    if (sysId) {
      try { current = await records.handle("local_record_get", {
        table: "incident", sys_id: sysId, fields: incidentFields,
      }); } catch (error) { observationError = error.message; }
    }
    if (note_baseline && attempted) {
      if (!current?.found) workNote = { status: "unknown", error: "Incident is absent or unreadable; work-note observation withheld." };
      else try {
        workNote = await observeWorkNote(sysId, last.values.work_notes, note_baseline, last.work_note?.entry?.sys_id);
      } catch (error) { workNote = { status: "unknown", error: error.message, diagnostic: error.diagnostic }; }
    }
    return { operation_id: args.operation_id, status: outcome.status, outcome, current, observation_error: observationError,
      ...(workNote ? { work_note: workNote } : {}),
      unresolved_hold: state.unresolved("incident") || Boolean(sysId && state.unresolved("incident", sysId)),
      meaning: "Read-only observation; no replay, attribution upgrade or hold removal." };
  }
  async function handle(name, args, callerKey) {
    const tool = tools.find(item => item.name === name);
    if (!tool) throw new Error("Incident operation unavailable.");
    validate(tool.inputSchema, args);
    if (name === "get_incident_schema") return records.discover("incident");
    if (name === "resolve_incident_assignee") return resolve(args);
    if (name === "get_incident_operation") return status(args, callerKey);
    return mutate(name, args, callerKey);
  }
  return { tools, handle };
}
module.exports = { createIncidents };
