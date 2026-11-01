const { tools } = require("../contracts/cowork-tools.json");

const allowedHosts = new Set([
  "localhost", "127.0.0.1", "[::1]",
  ...configuredList("MCP_ALLOWED_HOSTS", (value) => {
    const host = requestHostname(value);
    return host === value.toLowerCase() ? host : null;
  }),
]);
const allowedOrigins = new Set(configuredList("MCP_ALLOWED_ORIGINS", requestOrigin));

const READ_TOOLS = new Set(["search_incidents", "get_incident", "search_changes", "get_change"]);
const RECENT_QUERY = "sys_updated_on>javascript:gs.monthsAgo(6)";
const INCIDENT_LIST_FIELDS = [
  "sys_id", "number", "short_description", "priority", "state", "assigned_to",
  "assignment_group", "opened_at", "category", "sys_updated_on",
];
const INCIDENT_DETAIL_FIELDS = [...INCIDENT_LIST_FIELDS, "description", "impact", "urgency", "close_notes"];
const CHANGE_LIST_FIELDS = [
  "sys_id", "number", "short_description", "type", "risk", "state", "start_date",
  "end_date", "assigned_to", "assignment_group", "sys_updated_on",
];
const CHANGE_DETAIL_FIELDS = [...CHANGE_LIST_FIELDS, "description", "impact"];
const SN_USER = process.env.SERVICENOW_USERNAME;
const SN_PASS = process.env.SERVICENOW_PASSWORD;

if (!process.env.SERVICENOW_INSTANCE || !SN_USER || !SN_PASS) {
  throw new Error("Set SERVICENOW_INSTANCE, SERVICENOW_USERNAME and SERVICENOW_PASSWORD in the process environment.");
}

function configuredList(name, validate) {
  const value = process.env[name];
  if (!value?.trim()) return [];
  return value.split(",").map((entry) => {
    const normalized = validate(entry.trim());
    if (!normalized) {
      const format = name === "MCP_ALLOWED_HOSTS" ? "hostnames without schemes or ports" : "exact HTTP(S) origins without paths";
      throw new Error(`${name} must be a comma-separated list of ${format}.`);
    }
    return normalized;
  });
}

function requestHostname(value) {
  if (typeof value !== "string") return null;
  const match = /^(\[[0-9a-f:]+\]|[a-z0-9.-]+)(?::(\d+))?$/i.exec(value);
  if (!match || !URL.canParse(`http://${value}`)) return null;
  if (!match[1].startsWith("[") && (match[1].length > 253 ||
      match[1].split(".").some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label)))) return null;
  if (match[2] && (Number(match[2]) < 1 || Number(match[2]) > 65535)) return null;
  const host = new URL(`http://${value}`).hostname;
  return host === match[1].toLowerCase() ? host : null;
}

function requestOrigin(value) {
  if (typeof value !== "string" || !URL.canParse(value)) return null;
  const url = new URL(value);
  return ["http:", "https:"].includes(url.protocol) && value === url.origin ? value : null;
}

function instanceOrigin(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error("SERVICENOW_INSTANCE must be an HTTPS origin.");
  }
  const localHttp = url.protocol === "http:" && ["127.0.0.1", "[::1]", "localhost"].includes(url.hostname);
  if ((url.protocol !== "https:" && !localHttp) || url.username || url.password ||
      url.pathname !== "/" || url.search || url.hash) {
    throw new Error("SERVICENOW_INSTANCE must be an HTTPS origin without credentials, path, query or fragment. HTTP is allowed only on loopback for local tests.");
  }
  return url.origin;
}

const SN_INSTANCE = instanceOrigin(process.env.SERVICENOW_INSTANCE);
const AUTH_HEADER = "Basic " + Buffer.from(`${SN_USER}:${SN_PASS}`).toString("base64");

async function snRequest(method, path) {
  if (method !== "GET") throw new Error("This connection is read-only.");
  const res = await fetch(`${SN_INSTANCE}/api/now/${path}`, {
    method,
    redirect: "error",
    signal: AbortSignal.timeout(15000),
    headers: {
      Authorization: AUTH_HEADER,
      Accept: "application/json",
    },
  });
  if (!res.ok) throw new Error(`ServiceNow API returned HTTP ${res.status}.`);
  return res.json();
}

function recordNumber(value, prefix) {
  const number = typeof value === "string" ? value.trim().toUpperCase() : "";
  if (!new RegExp(`^${prefix}\\d+$`).test(number) || number.length > 40)
    throw new Error(`Provide a valid ${prefix} incident or change number.`);
  return number;
}

function linkedRecords(data, table, fields) {
  if (!Array.isArray(data.result)) throw new Error("ServiceNow returned an invalid record list.");
  return data.result.map((record) => {
    if (!record || !/^[a-f0-9]{32}$/i.test(record.sys_id))
      throw new Error("ServiceNow returned a record without a valid source ID.");
    const selected = Object.fromEntries(
      fields.filter((field) => Object.hasOwn(record, field)).map((field) => [field, record[field]])
    );
    return { ...selected, source_url: `${SN_INSTANCE}/${table}.do?sys_id=${record.sys_id}` };
  });
}

async function fetchIncidents(args) {
  const parts = [RECENT_QUERY];
  if (args.number) parts.push(`number=${recordNumber(args.number, "INC")}`);
  if (args.state) parts.push(`state=${args.state}`);
  if (args.priority) parts.push(`priority=${args.priority}`);
  if (args.assigned_to) parts.push(`assigned_to.nameLIKE${args.assigned_to}`);
  if (args.query) {
    parts.push(/^INC\d+$/i.test(args.query.trim())
      ? `number=${recordNumber(args.query, "INC")}`
      : `short_descriptionLIKE${args.query}`);
  }
  parts.push("ORDERBYDESCsys_updated_on");
  const data = await snRequest(
    "GET",
    `table/incident?sysparm_query=${encodeURIComponent(parts.join("^"))}&sysparm_fields=${INCIDENT_LIST_FIELDS.join(",")}&sysparm_limit=20&sysparm_display_value=true`
  );
  return linkedRecords(data, "incident", INCIDENT_LIST_FIELDS);
}

async function handleTool(name, args) {
  if (!READ_TOOLS.has(name)) throw new Error("Tool unavailable in this read-only connection.");
  if (!args || typeof args !== "object" || Array.isArray(args))
    throw new Error("Tool arguments must be an object.");
  const schema = tools.find((tool) => tool.name === name).inputSchema;
  for (const [key, value] of Object.entries(args)) {
    if (!Object.hasOwn(schema.properties, key) || typeof value !== "string" ||
        !value.trim() || value.length > 200 || /[\u0000-\u001f^]|javascript:/i.test(value))
      throw new Error(`Invalid filter: ${key}. Use plain text, not an encoded query.`);
  }
  if (args.state && !/^-?\d+$/.test(args.state)) throw new Error("State must be a state number.");
  if (args.priority && !/^[1-5]$/.test(args.priority)) throw new Error("Priority must be 1 through 5.");
  switch (name) {
    case "search_incidents":
      return fetchIncidents(args);

    case "get_incident": {
      const number = recordNumber(args.number, "INC");
      const data = await snRequest(
        "GET",
        `table/incident?sysparm_query=${encodeURIComponent(`${RECENT_QUERY}^number=${number}`)}&sysparm_fields=${INCIDENT_DETAIL_FIELDS.join(",")}&sysparm_limit=1&sysparm_display_value=true`
      );
      const records = linkedRecords(data, "incident", INCIDENT_DETAIL_FIELDS);
      if (records.length === 0) throw new Error(`Incident ${number} not found within the last six months.`);
      return records[0];
    }

    case "search_changes": {
      const parts = [RECENT_QUERY];
      if (args.state) parts.push(`state=${args.state}`);
      if (args.type) parts.push(`type=${args.type}`);
      if (args.assignment_group) parts.push(`assignment_group.nameLIKE${args.assignment_group}`);
      parts.push("ORDERBYDESCsys_updated_on");
      const data = await snRequest(
        "GET",
        `table/change_request?sysparm_query=${encodeURIComponent(parts.join("^"))}&sysparm_fields=${CHANGE_LIST_FIELDS.join(",")}&sysparm_limit=20&sysparm_display_value=true`
      );
      return linkedRecords(data, "change_request", CHANGE_LIST_FIELDS);
    }

    case "get_change": {
      const number = recordNumber(args.number, "CHG");
      const data = await snRequest(
        "GET",
        `table/change_request?sysparm_query=${encodeURIComponent(`${RECENT_QUERY}^number=${number}`)}&sysparm_fields=${CHANGE_DETAIL_FIELDS.join(",")}&sysparm_limit=1&sysparm_display_value=true`
      );
      const records = linkedRecords(data, "change_request", CHANGE_DETAIL_FIELDS);
      if (records.length === 0) throw new Error(`Change ${number} not found within the last six months.`);
      return records[0];
    }
  }
}

function createApp() {
const express = require("express");
const app = express();
app.use((req, res, next) => {
  const hosts = req.headersDistinct.host;
  if (hosts?.length !== 1 || !allowedHosts.has(requestHostname(hosts[0]))) {
    return res.status(403).json({ error: "Request host is not allowed." });
  }
  const origins = req.headersDistinct.origin || [];
  if (origins.length > 1 || (origins.length === 1 && !allowedOrigins.has(requestOrigin(origins[0])))) {
    return res.status(403).json({ error: "Request origin is not allowed." });
  }
  next();
});
app.use(express.json({ limit: "2mb" }));
app.post("/mcp", async (req, res) => {
  const { method, params, id } = req.body || {};
  if (typeof method !== "string") {
    return res.status(400).json({
      jsonrpc: "2.0", id: id ?? null, error: { code: -32600, message: "Invalid request." },
    });
  }
  if (id === undefined) return res.sendStatus(202);

  switch (method) {
    case "ping":
      return res.json({ jsonrpc: "2.0", id, result: {} });

    case "initialize":
      return res.json({
        jsonrpc: "2.0",
        id,
        result: {
          protocolVersion: "2025-03-26",
          capabilities: { tools: {}, resources: {} },
          serverInfo: { name: "servicenow-mcp-server", version: "1.0.0" },
        },
      });

    case "tools/list":
      return res.json({ jsonrpc: "2.0", id, result: { tools } });

    case "resources/list":
      return res.json({ jsonrpc: "2.0", id, result: { resources: [] } });

    case "resources/read":
      return res.json({
        jsonrpc: "2.0", id, error: { code: -32602, message: "No resources are exposed." },
      });

    case "tools/call":
      try {
        const { name, arguments: args } = params || {};
        const result = await handleTool(name, args === undefined ? {} : args);
        return res.json({
          jsonrpc: "2.0", id,
          result: { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] },
        });
      } catch (err) {
        return res.json({
          jsonrpc: "2.0", id,
          result: {
            content: [{ type: "text", text: JSON.stringify({ error: err.message }) }],
            isError: true,
          },
        });
      }

    default:
      return res.status(400).json({
        jsonrpc: "2.0", id, error: { code: -32601, message: `Method not found: ${method}` },
      });
  }
});

app.get("/mcp", (_req, res) => res.status(405).set("Allow", "POST").end());

app.get("/health", async (_req, res) => {
  try {
    const data = await snRequest("GET", `table/incident?sysparm_query=${encodeURIComponent(RECENT_QUERY)}&sysparm_limit=1&sysparm_fields=number`);
    if (!Array.isArray(data.result)) throw new Error("ServiceNow returned an invalid record list.");
    res.json({ status: "ok", servicenow: "connected" });
  } catch (err) {
    res.status(503).json({ status: "error", message: err.message });
  }
});
return app;
}

if (require.main === module) {
  const port = Number(process.env.PORT || 3002);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("PORT must be an integer from 1 to 65535.");
  createApp().listen(port, "127.0.0.1", () => {
    console.log(`ServiceNow read-only MCP listening on http://127.0.0.1:${port}/mcp`);
  });
}

module.exports = { createApp, handleTool, tools, get app() { return createApp(); } };
