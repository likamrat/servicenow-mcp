const { tools } = require("../contracts/cowork-tools.json");
const RECENT_QUERY = "sys_updated_on>javascript:gs.monthsAgo(6)";
const incidentFields = ["sys_id", "number", "short_description", "priority", "state", "assigned_to",
  "assignment_group", "opened_at", "category", "sys_updated_on", "sys_mod_count"];
const incidentDetail = [...incidentFields, "description", "impact", "urgency", "close_notes"];
const changeFields = ["sys_id", "number", "short_description", "type", "risk", "state", "start_date",
  "end_date", "assigned_to", "assignment_group", "sys_updated_on"];
const changeDetail = [...changeFields, "description", "impact"];

function createReads(source) {
  function number(value, prefix) {
    const result = typeof value === "string" ? value.trim().toUpperCase() : "";
    if (!new RegExp(`^${prefix}\\d+$`).test(result) || result.length > 40)
      throw new Error(`Provide a valid ${prefix} incident or change number.`);
    return result;
  }
  async function fetchRecords(table, query, fields, limit) {
    const data = await source.request("GET", table, { sysparm_query: query, sysparm_fields: fields.join(","),
      sysparm_limit: String(limit), sysparm_display_value: "true" });
    if (!Array.isArray(data?.result) || data.result.length > limit) throw new Error("ServiceNow returned an invalid record list.");
    return data.result.map(record => {
      if (!record || !/^[a-f0-9]{32}$/i.test(record.sys_id)) throw new Error("ServiceNow returned a record without a valid source ID.");
      return { ...Object.fromEntries(fields.filter(field => Object.hasOwn(record, field)).map(field => [field, record[field]])),
        source_url: `${source.instance}/${table}.do?sys_id=${record.sys_id}` };
    });
  }
  async function handle(name, args) {
    const tool = tools.find(item => item.name === name);
    if (!tool) throw new Error("Tool unavailable in this read-only connection.");
    if (!args || typeof args !== "object" || Array.isArray(args)) throw new Error("Tool arguments must be an object.");
    for (const [key, value] of Object.entries(args)) {
      if (!Object.hasOwn(tool.inputSchema.properties, key) || typeof value !== "string" ||
          !value.trim() || value.length > 200 || /[\u0000-\u001f^]|javascript:/i.test(value))
        throw new Error(`Invalid filter: ${key}. Use plain text, not an encoded query.`);
    }
    if (args.state && !/^-?\d+$/.test(args.state)) throw new Error("State must be a state number.");
    if (args.priority && !/^[1-5]$/.test(args.priority)) throw new Error("Priority must be 1 through 5.");
    const incident = name.endsWith("incident") || name.endsWith("incidents");
    const table = incident ? "incident" : "change_request";
    if (name.startsWith("get_")) {
      const selected = number(args.number, incident ? "INC" : "CHG");
      const rows = await fetchRecords(table, `${RECENT_QUERY}^number=${selected}`, incident ? incidentDetail : changeDetail, 1);
      if (!rows.length) throw new Error(`${incident ? "Incident" : "Change"} ${selected} not found within the last six months.`);
      return rows[0];
    }
    const parts = [RECENT_QUERY];
    if (args.state) parts.push(`state=${args.state}`);
    if (incident) {
      if (args.number) parts.push(`number=${number(args.number, "INC")}`);
      if (args.priority) parts.push(`priority=${args.priority}`);
      if (args.assigned_to) parts.push(`assigned_to.nameLIKE${args.assigned_to}`);
      if (args.query) parts.push(/^INC\d+$/i.test(args.query.trim()) ?
        `number=${number(args.query, "INC")}` : `short_descriptionLIKE${args.query}`);
    } else {
      if (args.type) parts.push(`type=${args.type}`);
      if (args.assignment_group) parts.push(`assignment_group.nameLIKE${args.assignment_group}`);
    }
    parts.push("ORDERBYDESCsys_updated_on");
    return fetchRecords(table, parts.join("^"), incident ? incidentFields : changeFields, 20);
  }
  return { tools, handle };
}
module.exports = { createReads, RECENT_QUERY };
