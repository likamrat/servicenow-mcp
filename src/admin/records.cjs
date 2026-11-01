const NAME = /^[a-zA-Z][a-zA-Z0-9_]{0,127}$/;
const ID = /^[a-f0-9]{32}$/;
const SYSTEM_FIELDS = ["sys_id", "sys_mod_count", "sys_created_on", "sys_updated_on", "sys_class_name"];
const primitive = { type: ["string", "number", "boolean", "null"] };
const table = { type: "string", pattern: NAME.source };
const sys_id = { type: "string", pattern: ID.source };
const operation_id = { type: "string", format: "uuid" };
const fields = { type: "array", items: { type: "string", pattern: NAME.source }, maxItems: 60 };
const values = { type: "object", minProperties: 1, maxProperties: 60, additionalProperties: primitive };
const object = (properties, required) => ({ type: "object", properties, required, additionalProperties: false });
const tool = (name, description, properties, required, readOnlyHint = true) => ({
  name, description, annotations: { readOnlyHint, ...(readOnlyHint ? {} : { destructiveHint: true, idempotentHint: false }) },
  inputSchema: object(properties, required),
});
const tools = [
  tool("local_record_schema", "Discover inherited source fields, choices and conditional policies. Metadata is not effective source permission.",
    { table, refresh: { type: "boolean" } }, ["table"]),
  tool("local_record_query", "Query structured AND filters with selected fields, at most100 records and an explicit limit indicator. No raw encoded query. Administrative reads are not the six-month Cowork searches.",
    { table, fields, limit: { type: "integer", minimum: 1, maximum: 100 },
      filters: { type: "array", maxItems: 12, items: object({ field: table, operator: { enum: ["eq", "contains", "starts_with"] }, value: primitive }, ["field", "operator", "value"]) } }, ["table"]),
  tool("local_record_get", "Read one exact source record/version, or report absence within the authorized account's visibility.", { table, sys_id, fields }, ["table", "sys_id"]),
  tool("local_record_create", "Create a business record with supplied values and independently read it back. Unique operation UUIDs never replay writes. Optional caller-supplied correlation permits read-only response-loss reconciliation. No account/access/executable configuration writes.",
    { table, values, operation_id, correlation_field: table }, ["table", "values", "operation_id"], false),
  tool("local_record_update", "Patch only supplied business values after a current version preflight; not atomic CAS. Independently read back values. No replay after uncertainty.",
    { table, sys_id, values, operation_id, expected_mod_count: { type: "string", pattern: "^\\d+$" } },
    ["table", "sys_id", "values", "operation_id", "expected_mod_count"], false),
  tool("local_record_delete", "Delete one authorized business record after a version preflight and confirm parent absence. Optional related reads report observed native effects, not universal cleanup or permission to delete children.",
    { table, sys_id, operation_id, expected_mod_count: { type: "string", pattern: "^\\d+$" }, confirm: { const: true, type: "boolean" },
      verify_related: { type: "array", maxItems: 30, items: object({ table, sys_id }, ["table", "sys_id"]) } },
    ["table", "sys_id", "operation_id", "expected_mod_count", "confirm"], false),
];
const ref = value => value && typeof value === "object" ? value.value : value;
const truth = value => value === true || value === "true" || value === "1";

function createRecords({ source, state }) {
  const { list, request, instance } = source;
  function readable(name) {
    if (typeof name !== "string" || !NAME.test(name)) throw new Error("Invalid table identifier.");
    if (/^(sys_auth|sys_credentials|oauth_|sys_oauth|sys_certificate|sys_password)/i.test(name))
      throw new Error("Credential-store records are not exposed.");
  }
  async function metadata(name, query, selected) {
    const result = [];
    let cursor = "";
    for (let page = 0; page < 20; page++) {
      const rows = await list(name, `${query}${cursor ? "^sys_id>" + cursor : ""}^ORDERBYsys_id`, `sys_id,${selected}`, 200);
      for (const row of rows) {
        if (!ID.test(row.sys_id) || row.sys_id <= cursor) throw new Error("Incomplete or non-progressing source metadata.");
        cursor = row.sys_id;
        result.push(row);
      }
      if (rows.length < 200) return result;
    }
    throw new Error("Source metadata exceeds bounded discovery.");
  }
  async function discover(name) {
    readable(name);
    const lineage = [];
    let current = name;
    for (let depth = 0; depth < 10; depth++) {
      if (!NAME.test(current) || lineage.includes(current)) throw new Error("Invalid source table inheritance.");
      const rows = await list("sys_db_object", `name=${current}`, "name,label,super_class.name", 2);
      if (rows.length !== 1 || rows[0].name !== current || !Object.hasOwn(rows[0], "super_class.name"))
        throw new Error("Source table or inheritance is not fully readable.");
      lineage.push(current);
      current = rows[0]["super_class.name"];
      if (!current) break;
    }
    if (current) throw new Error("Source table inheritance exceeds bounded discovery.");
    const dictionary = await metadata("sys_dictionary", `nameIN${lineage.join(",")}^elementISNOTEMPTY`,
      "name,element,internal_type,mandatory,read_only,default_value,reference,max_length,display,choice");
    const discovered = Object.create(null);
    for (const ancestor of lineage) for (const row of dictionary.filter(row => row.name === ancestor)) {
      if (!NAME.test(row.element) || Object.hasOwn(discovered, row.element)) continue;
      discovered[row.element] = { name: row.element, type: ref(row.internal_type), mandatory: truth(row.mandatory),
        readOnlyMetadata: truth(row.read_only), defaultValue: row.default_value || "", reference: ref(row.reference) || null,
        maxLength: Number(row.max_length) || null, display: truth(row.display), choiceMode: String(row.choice || "0"), choices: [] };
    }
    const choices = await metadata("sys_choice", `nameIN${lineage.join(",")}^inactive=false^language=en`, "name,element,value,label,dependent_value");
    for (const field of Object.values(discovered)) for (const ancestor of lineage) {
      const applicable = choices.filter(row => row.name === ancestor && row.element === field.name);
      if (!applicable.length) continue;
      field.choices = applicable.map(row => ({ value: row.value, label: row.label, dependentValue: row.dependent_value || null }));
      break;
    }
    const policies = await metadata("sys_data_policy2", `active=true^model_tableIN${lineage.join(",")}`, "short_description,model_table,conditions,inherit");
    const rules = policies.length ? await metadata("sys_data_policy_rule",
      `sys_data_policyIN${policies.map(row => row.sys_id).join(",")}`, "sys_data_policy,field,mandatory,disabled") : [];
    const mutationAllowed = !lineage.includes("sys_metadata") && !lineage.some(ancestor =>
      /^(sys_user(?:_|$)|sys_security_|sys_auth|sys_oauth|oauth_|sys_certificate|sys_credentials|ecc_|sys_trigger|sysauto|sys_script|sys_properties$|sys_db_object$|sys_dictionary$|sys_choice$|sys_scope$|sys_update_|sys_upgrade|sys_email$|sys_processor|sys_rest_|kb_uc_)/i.test(ancestor));
    return { table: name, lineage, mutationAllowed, fields: discovered,
      conditionalPolicies: policies.filter(row => row.model_table === name || truth(row.inherit)).map(row => ({
        name: row.short_description, table: row.model_table, condition: row.conditions, inherited: truth(row.inherit),
        fields: rules.filter(rule => ref(rule.sys_data_policy) === row.sys_id).map(rule => ({
          field: rule.field, mandatory: rule.mandatory, readOnly: rule.disabled,
        })),
      })) };
  }
  function permitted(schema, field, write = false) {
    if (!NAME.test(field) || (!Object.hasOwn(schema.fields, field) && !SYSTEM_FIELDS.includes(field))) throw new Error("Unknown source field.");
    const type = schema.fields[field]?.type || "";
    if (/password|encrypted|credential|secret/i.test(type) || /password|credential|token|secret|private_key|api_key/i.test(field))
      throw new Error("Credential field is not exposed.");
    if (write && (SYSTEM_FIELDS.includes(field) || field.startsWith("sys_") || /script|code|function/i.test(type)))
      throw new Error("System-managed or executable field is not writable.");
  }
  function select(schema, requested = []) {
    const chosen = requested.length ? requested : Object.values(schema.fields).filter(field => field.display || field.name === "number").map(field => field.name);
    for (const field of chosen) permitted(schema, field);
    return [...new Set(["sys_id", "sys_mod_count", "sys_created_on", "sys_updated_on", ...chosen])];
  }
  function linked(name, row, selected) {
    if (!row || !ID.test(row.sys_id)) throw new Error("Invalid source record identity.");
    return { ...Object.fromEntries(selected.filter(key => Object.hasOwn(row, key)).map(key => [key, ref(row[key])])),
      source_url: `${instance}/${name}.do?sys_id=${row.sys_id}` };
  }
  async function get(schema, id, fields) {
    const selected = select(schema, fields);
    const rows = await list(schema.table, `sys_id=${id}`, selected.join(","), 2);
    if (rows.length > 1 || (rows.length && rows[0].sys_id !== id)) throw new Error("Exact source identity mismatch.");
    return rows[0] ? linked(schema.table, rows[0], selected) : null;
  }
  function literal(value) {
    const text = value === null ? "" : String(value);
    if (text.length > 500 || /[\u0000-\u001f^]|javascript:/i.test(text)) throw new Error("Use literal structured filter values.");
    return text;
  }
  function validateValues(schema, values, creating) {
    if (!schema.mutationAllowed) throw new Error("Account, access-control and executable/configuration records require a supported semantic administration path.");
    for (const [field, value] of Object.entries(values)) {
      permitted(schema, field, true);
      const spec = schema.fields[field];
      if (spec.type === "boolean" && value !== null && ![true, false, "true", "false", "0", "1"].includes(value))
        throw new Error("Boolean source fields require an explicit boolean or source boolean string.");
      if (typeof value === "string" && value.length > Math.min(spec.maxLength || 20000, 20000)) throw new Error("Source field length exceeded.");
      if (["1", "3"].includes(spec.choiceMode) && spec.choices.length && value !== null && value !== "" &&
          !spec.choices.some(choice => choice.value === String(value))) throw new Error("Value is not an active source choice.");
    }
    if (creating) for (const spec of Object.values(schema.fields))
      if (spec.mandatory && !spec.defaultValue && !spec.name.startsWith("sys_") &&
          (values[spec.name] === undefined || values[spec.name] === null || values[spec.name] === ""))
        throw new Error(`Source dictionary requires ${spec.name}; conditional policies also apply.`);
  }
  function matches(schema, wanted, row) {
    return Boolean(row) && typeof row.sys_mod_count === "string" && /^\d+$/.test(row.sys_mod_count) &&
      Object.entries(wanted).every(([field, value]) => Object.hasOwn(row, field) &&
        (value === null ? row[field] === null || row[field] === "" :
          schema.fields[field]?.type === "boolean" ? [true, false, "true", "false", "0", "1"].includes(row[field]) &&
            truth(value) === truth(row[field]) : String(value) === String(row[field])));
  }
  async function handle(name, args) {
    const schema = await discover(args.table);
    if (name === "local_record_schema") return schema;
    if (name === "local_record_get") { const row = await get(schema, args.sys_id, args.fields); return { found: Boolean(row), record: row }; }
    if (name === "local_record_query") {
      const parts = (args.filters || []).map(filter => {
        permitted(schema, filter.field);
        return `${filter.field}${{ eq: "=", contains: "LIKE", starts_with: "STARTSWITH" }[filter.operator]}${literal(filter.value)}`;
      });
      parts.push("ORDERBYDESCsys_updated_on");
      const limit = args.limit ?? 20;
      const selected = select(schema, args.fields);
      const rows = await list(args.table, parts.join("^"), selected.join(","), limit);
      return { table: args.table, records: rows.map(row => linked(args.table, row, selected)), limitReached: rows.length === limit };
    }
    const creating = name === "local_record_create", deleting = name === "local_record_delete";
    if (!schema.mutationAllowed) throw new Error("Account, access-control and configuration records require a supported semantic administration path.");
    if (state.isAttempted(args.operation_id)) throw new Error("Operation UUID already attempted; reconcile without replay.");
    if (state.unresolved(args.table, args.sys_id)) throw new Error("Earlier source outcome unresolved; a new UUID cannot replay it.");
    if (!deleting) validateValues(schema, args.values, creating);
    const existing = creating ? null : await get(schema, args.sys_id, deleting ? [] : Object.keys(args.values));
    if (!creating && (!existing || existing.sys_mod_count !== args.expected_mod_count)) throw new Error("Record absent or changed since your read.");
    const related = args.verify_related || [];
    for (const item of related) await discover(item.table);
    let correlation;
    if (creating && args.correlation_field) {
      permitted(schema, args.correlation_field);
      if (!Object.hasOwn(args.values, args.correlation_field) || !literal(args.values[args.correlation_field]))
        throw new Error("Supply a nonempty correlation value in values.");
      correlation = `${args.correlation_field}=${literal(args.values[args.correlation_field])}`;
      if ((await list(args.table, correlation, "sys_id", 2)).length) throw new Error("Correlation already exists; no create attempted.");
    }
    const meta = { action: name, table: args.table, sys_id: args.sys_id, operation_id: args.operation_id, correlation };
    state.claim(args.operation_id, meta);
    let response, failure, row;
    try {
      response = await request(creating ? "POST" : deleting ? "DELETE" : "PATCH", args.table,
        { sysparm_display_value: "false", sysparm_exclude_reference_link: "true" }, args.values, args.sys_id);
      if (response?.result?.sys_id) state.record({ ...meta, status: "response", sys_id: response.result.sys_id });
    } catch (error) { failure = error; }
    try {
      if (failure?.diagnostic?.status === 401) throw failure;
      if (creating && response?.result?.sys_id) {
        if (!ID.test(response.result.sys_id)) throw new Error("Invalid created identity.");
        row = await get(schema, response.result.sys_id, Object.keys(args.values));
      } else if (creating && correlation) {
        const selected = select(schema, Object.keys(args.values));
        const rows = await list(args.table, correlation, selected.join(","), 2);
        if (rows.length !== 1) throw new Error("Create correlation not uniquely confirmed.");
        row = linked(args.table, rows[0], selected);
      } else if (!creating) row = await get(schema, args.sys_id, deleting ? [] : Object.keys(args.values));
      if (failure?.diagnostic?.status >= 400 && failure.diagnostic.status < 500)
        throw new Error("Source rejected the write; later state cannot establish attribution.");
      if (deleting ? Boolean(row) : !matches(schema, args.values, row)) throw new Error("Requested source state not confirmed.");
    } catch (error) {
      state.record({ ...meta, status: "uncertain", sys_id: response?.result?.sys_id || args.sys_id, reason: error.message, diagnostic: failure?.diagnostic });
      error.diagnostic = failure?.diagnostic;
      throw error;
    }
    const relatedRecords = [];
    for (const item of related) {
      try { relatedRecords.push({ ...item, absent: !(await get(await discover(item.table), item.sys_id)) }); }
      catch (error) { relatedRecords.push({ ...item, status: "verification_unavailable", error: error.message }); }
    }
    const result = { table: args.table, sys_id: row?.sys_id || args.sys_id, record: row || null,
      source_url: row?.source_url || existing?.source_url, operation_id: args.operation_id, reconciledAfterError: Boolean(failure),
      ...(deleting ? { deleted: true, absent: true, cleanup_complete: false, relatedRecords } : {}) };
    state.record({ ...meta, status: "confirmed", sys_id: result.sys_id, relatedRecords });
    return result;
  }
  return { tools, handle, discover };
}

module.exports = { tools, createRecords };
