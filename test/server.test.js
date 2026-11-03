const assert = require("node:assert/strict");
const { before, after, test } = require("node:test");
const http = require("node:http");
const net = require("node:net");
const { once } = require("node:events");
const fs = require("node:fs");
const path = require("node:path");

const reads = ["search_incidents", "get_incident", "search_changes", "get_change"];
const writes = ["create_incident", "update_incident", "resolve_incident", "assign_incident", "create_change", "approve_change"];
const requests = [];
const boundary = "sys_updated_on>javascript:gs.monthsAgo(6)";
const incident = {
  sys_id: "a".repeat(32),
  number: "INC0098765",
  short_description: "Example network issue",
  description: "Synthetic scenario with an unconfirmed cause. Recorded workaround: use the approved document portal.",
  impact: "2",
  urgency: "2",
  close_notes: "Recorded resolution guidance, not a verified fix for another incident.",
  comments: "Excluded customer comment",
  work_notes: "Excluded internal journal entry",
  caller_id: { value: "private-caller", display_value: "Private caller" },
  u_private_detail: "Excluded custom field",
  sys_updated_on: new Date().toISOString(),
};
const oldIncident = { ...incident, sys_id: "b".repeat(32), number: "INC0000001", sys_updated_on: "2018-01-01 00:00:00" };
const change = {
  ...incident, sys_id: "c".repeat(32), number: "CHG0098765",
  description: "Synthetic change description",
  type: "normal", risk: "moderate", state: "-2",
  start_date: "2026-10-29 12:00:00", end_date: "2026-10-29 13:00:00",
};
const oldChange = { ...oldIncident, sys_id: "d".repeat(32), number: "CHG0000001" };
let source;
let server;
let endpoint;
let upstreamStatus = 200;
let upstreamResult;
let upstreamRedirect;

before(async () => {
  source = http.createServer((req, res) => {
    const url = new URL(req.url, "http://localhost");
    requests.push({ method: req.method, url });
    if (upstreamRedirect) {
      res.writeHead(302, { Location: upstreamRedirect });
      return res.end();
    }
    if (upstreamStatus !== 200) {
      res.writeHead(upstreamStatus, { "Content-Type": "application/json" });
      return res.end(JSON.stringify({ error: "private-upstream-detail" }));
    }
    const query = url.searchParams.get("sysparm_query") || "";
    let records = url.pathname.endsWith("/change_request") ? [change, oldChange] : [incident, oldIncident];
    const number = query.match(/(?:^|\^)number=([A-Z]+\d+)(?:\^|$)/)?.[1];
    if (number) records = records.filter((record) => record.number === number);
    if (query.includes(boundary)) records = records.filter((record) => record !== oldIncident && record !== oldChange);
    res.setHeader("Content-Type", "application/json");
    // Over-return fields deliberately so tests also verify the server's response projection.
    res.end(JSON.stringify({ result: upstreamResult === undefined ? records : upstreamResult }));
  }).listen(0, "127.0.0.1");
  await once(source, "listening");
  process.env.SERVICENOW_INSTANCE = `http://127.0.0.1:${source.address().port}`;
  process.env.SERVICENOW_USERNAME = "test-user";
  process.env.SERVICENOW_PASSWORD = "test-only";
  process.env.MCP_ALLOWED_HOSTS = "mcp.example.invalid";
  process.env.MCP_ALLOWED_ORIGINS = "https://client.example.invalid";
  const { app } = require("../src/server");
  server = app.listen(0, "127.0.0.1");
  await once(server, "listening");
  endpoint = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  if (server) await new Promise((resolve) => server.close(resolve));
  if (source) await new Promise((resolve) => source.close(resolve));
});

async function rpc(method, params = {}) {
  const response = await fetch(`${endpoint}/mcp`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  assert.equal(response.status, 200);
  return response.json();
}

async function requestWithHeaders(method, pathname, headers, body) {
  const url = new URL(endpoint);
  return new Promise((resolve, reject) => {
    const req = http.request({
      hostname: url.hostname, port: url.port, path: pathname, method, setHost: false,
      headers: {
        ...(body === undefined ? {} : { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) }),
        ...headers,
      },
    }, (res) => {
      let text = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => { text += chunk; });
      res.on("end", () => resolve({ status: res.statusCode, text }));
    });
    req.on("error", reject);
    req.end(body);
  });
}

test("rejects untrusted or ambiguous hosts and origins before parsing or upstream access", async () => {
  const host = new URL(endpoint).host;
  const body = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "search_incidents" } });
  const rejected = [
    { Host: "untrusted.example.invalid" },
    { Host: "untrusted.example.invalid", Origin: "http://untrusted.example.invalid" },
    { Host: "untrusted.example.invalid", "X-Forwarded-Host": host },
    { Host: "localhost.evil.example.invalid" },
    { Host: `${host}/path` },
    { Host: "localhost:0" },
    { Host: "localhost:65536" },
    { Host: host, Origin: "https://untrusted.example.invalid" },
    { Host: host, Origin: "https://client.example.invalid.evil.example.invalid" },
    { Host: host, Origin: "http://client.example.invalid" },
    { Host: host, Origin: "https://client.example.invalid/path" },
    { Host: host, Origin: "null" },
    { Host: host, Origin: "" },
    { Host: host, Origin: ["https://client.example.invalid", "https://untrusted.example.invalid"] },
  ];
  for (const headers of rejected) {
    const count = requests.length;
    for (const [method, pathname, payload] of [
      ["POST", "/mcp", body], ["GET", "/health", undefined],
    ]) {
      const response = await requestWithHeaders(method, pathname, headers, payload);
      assert.equal(response.status, 403, JSON.stringify(headers));
      assert.match(JSON.parse(response.text).error, /not allowed/);
    }
    assert.equal(requests.length, count, "Rejected requests must not reach ServiceNow");
  }
  const malformed = await requestWithHeaders("POST", "/mcp", { Host: "untrusted.example.invalid" }, "{");
  assert.equal(malformed.status, 403, "The boundary guard runs before the JSON body parser");
  for (const [rawHosts, status] of [
    ["", 400],
    [`Host: ${host}\r\nHost: untrusted.example.invalid\r\n`, 403],
  ]) {
    const count = requests.length;
    const response = await new Promise((resolve, reject) => {
      const socket = net.createConnection({ host: "127.0.0.1", port: Number(new URL(endpoint).port) }, () => {
        socket.write(`GET /health HTTP/1.1\r\n${rawHosts}Connection: close\r\n\r\n`);
      });
      let text = "";
      socket.setEncoding("utf8");
      socket.setTimeout(5000, () => socket.destroy(new Error("Timed out reading HTTP rejection")));
      socket.on("data", (chunk) => { text += chunk; });
      socket.on("end", () => resolve(text));
      socket.on("error", reject);
    });
    assert.ok(response.startsWith(`HTTP/1.1 ${status} `), "Missing or duplicate Host headers are rejected before dispatch");
    assert.equal(requests.length, count);
  }
});

test("accepts loopback and explicitly configured proxy hosts with approved or absent origins", async () => {
  const body = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "search_incidents" } });
  for (const headers of [
    { Host: new URL(endpoint).host },
    { Host: "localhost" },
    { Host: "[::1]" },
    { Host: "mcp.example.invalid" },
    { Host: "MCP.EXAMPLE.INVALID:443", Origin: "https://client.example.invalid" },
  ]) {
    const count = requests.length;
    const response = await requestWithHeaders("POST", "/mcp", headers, body);
    assert.equal(response.status, 200);
    assert.notEqual(JSON.parse(response.text).result.isError, true);
    assert.equal(requests.length, count + 1);
  }
});

test("advertises only read tools and rejects every write before contacting ServiceNow", async () => {
  const listed = await rpc("tools/list");
  assert.deepEqual(listed.result.tools.map((tool) => tool.name), reads);
  assert.ok(listed.result.tools.every((tool) => tool.annotations.readOnlyHint === true));
  const count = requests.length;
  for (const name of [...writes, "show_incident_dashboard", "unknown_tool"]) {
    const response = await rpc("tools/call", { name, arguments: { number: "INC0098765" } });
    assert.equal(response.result.isError, true, name);
    assert.match(response.result.content[0].text, /read-only/i);
  }
  assert.equal(requests.length, count);
});

test("looks up the supplied incident number within six months and returns its real source link", async () => {
  const response = await rpc("tools/call", { name: "get_incident", arguments: { number: incident.number.toLowerCase() } });
  assert.notEqual(response.result.isError, true);
  const result = JSON.parse(response.result.content[0].text);
  assert.equal(result.number, incident.number);
  assert.equal(result.source_url, `${process.env.SERVICENOW_INSTANCE}/incident.do?sys_id=${incident.sys_id}`);
  assert.equal(requests.at(-1).method, "GET");
  assert.equal(requests.at(-1).url.searchParams.get("sysparm_query"), `${boundary}^number=${incident.number}`);
  for (const number of [oldIncident.number, "INC0099999"]) {
    const missing = await rpc("tools/call", { name: "get_incident", arguments: { number } });
    assert.equal(missing.result.isError, true);
    assert.match(missing.result.content[0].text, /not found.*six months/i);
  }
});

test("keeps every incident search inside the date boundary, including keyword and number searches", async () => {
  for (const args of [
    {}, { query: "network" }, { state: "2", priority: "1", assigned_to: "Alex" },
    { number: incident.number }, { query: incident.number.toLowerCase() },
  ]) {
    const response = await rpc("tools/call", { name: "search_incidents", arguments: args });
    assert.notEqual(response.result.isError, true);
    const records = JSON.parse(response.result.content[0].text);
    assert.deepEqual(records.map((record) => record.number), [incident.number]);
    assert.equal(records[0].source_url, `${process.env.SERVICENOW_INSTANCE}/incident.do?sys_id=${incident.sys_id}`);
    const query = requests.at(-1).url.searchParams.get("sysparm_query");
    assert.ok(query.startsWith(`${boundary}^`));
    assert.ok(query.endsWith("^ORDERBYDESCsys_updated_on"));
    assert.equal(requests.at(-1).url.searchParams.get("sysparm_limit"), "20");
    if (args.query === "network") assert.ok(query.includes("^short_descriptionLIKEnetwork"));
    if (args.number || args.query === incident.number.toLowerCase()) assert.ok(query.includes(`^number=${incident.number}`));
  }
  for (const args of [
    { query: "x^NQsys_updated_on<2019-01-01" }, { assigned_to: "x^ORactive=true" },
    { query: "javascript:gs.getUserID()" }, { number: "INC0098765^NQactive=true" },
    { query: 123 }, { state: "bogus" }, { priority: "0" }, { query: "" },
    { unexpected_filter: "x" }, [], null, false,
  ]) {
    const count = requests.length;
    const response = await rpc("tools/call", { name: "search_incidents", arguments: args });
    assert.equal(response.result.isError, true, JSON.stringify(args));
    assert.equal(requests.length, count);
  }
});

test("change reads use GET, the same time boundary and links to returned source records", async () => {
  for (const [name, args] of [
    ["get_change", { number: change.number.toLowerCase() }],
    ["search_changes", { state: "-4", type: "normal", assignment_group: "Network" }],
  ]) {
    const response = await rpc("tools/call", { name, arguments: args });
    assert.notEqual(response.result.isError, true);
    const data = JSON.parse(response.result.content[0].text);
    const record = Array.isArray(data) ? data[0] : data;
    assert.equal(record.number, change.number);
    assert.equal(record.source_url, `${process.env.SERVICENOW_INSTANCE}/change_request.do?sys_id=${change.sys_id}`);
    assert.equal(requests.at(-1).method, "GET");
    assert.ok(requests.at(-1).url.searchParams.get("sysparm_query").startsWith(`${boundary}^`));
    if (name === "search_changes") {
      assert.deepEqual(data.map((entry) => entry.number), [change.number]);
      assert.equal(requests.at(-1).url.searchParams.get("sysparm_limit"), "20");
      assert.ok(requests.at(-1).url.searchParams.get("sysparm_query").endsWith("^ORDERBYDESCsys_updated_on"));
    }
  }
  const old = await rpc("tools/call", { name: "get_change", arguments: { number: oldChange.number } });
  assert.equal(old.result.isError, true);
  assert.match(old.result.content[0].text, /not found within the last six months/);
});

test("all record reads request and return explicit field sets, retaining supported detail evidence", async () => {
  const incidentList = ["sys_id", "number", "short_description", "priority", "state", "assigned_to", "assignment_group", "opened_at", "category", "sys_updated_on", "sys_mod_count"];
  const changeList = ["sys_id", "number", "short_description", "type", "risk", "state", "start_date", "end_date", "assigned_to", "assignment_group", "sys_updated_on"];
  for (const [name, record, table, fields] of [
    ["search_incidents", incident, "incident", incidentList],
    ["get_incident", incident, "incident", [...incidentList, "description", "impact", "urgency", "close_notes"]],
    ["search_changes", change, "change_request", changeList],
    ["get_change", change, "change_request", [...changeList, "description", "impact"]],
  ]) {
    const args = name.startsWith("get_") ? { number: record.number } : {};
    const response = await rpc("tools/call", { name, arguments: args });
    assert.notEqual(response.result.isError, true);
    const query = requests.at(-1).url.searchParams;
    assert.deepEqual(query.get("sysparm_fields").split(","), fields, name);
    assert.ok(query.get("sysparm_query").startsWith(`${boundary}^`), name);
    assert.equal(requests.at(-1).method, "GET");
    const data = JSON.parse(response.result.content[0].text);
    const selected = Object.fromEntries(fields.filter((field) => Object.hasOwn(record, field)).map((field) => [field, record[field]]));
    const expected = { ...selected, source_url: `${process.env.SERVICENOW_INSTANCE}/${table}.do?sys_id=${record.sys_id}` };
    assert.deepEqual(data, name.startsWith("search_") ? [expected] : expected, name);
    for (const excluded of ["comments", "work_notes", "caller_id", "u_private_detail"]) {
      assert.equal(Object.hasOwn(Array.isArray(data) ? data[0] : data, excluded), false, `${name}: ${excluded}`);
    }
  }
});

test("detail projection preserves missing, null and empty evidence without inventing fields", async () => {
  upstreamResult = [{
    sys_id: incident.sys_id, number: incident.number, description: incident.description,
    impact: null, close_notes: "", comments: incident.comments,
    source_url: "https://unrelated.example.invalid/wrong",
  }];
  try {
    const response = await rpc("tools/call", { name: "get_incident", arguments: { number: incident.number } });
    assert.notEqual(response.result.isError, true);
    assert.deepEqual(JSON.parse(response.result.content[0].text), {
      sys_id: incident.sys_id, number: incident.number, description: incident.description,
      impact: null, close_notes: "",
      source_url: `${process.env.SERVICENOW_INSTANCE}/incident.do?sys_id=${incident.sys_id}`,
    });
  } finally {
    upstreamResult = undefined;
  }
});

test("supports MCP initialization without resources and reports upstream failures safely", async () => {
  const initialized = await rpc("initialize", { protocolVersion: "2025-03-26" });
  assert.ok(initialized.result.capabilities.tools);
  assert.equal(initialized.result.serverInfo.version, "1.0.0");
  assert.equal(initialized.result.serverInfo.title, "ServiceNow");
  const notification = await fetch(`${endpoint}/mcp`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
  });
  assert.equal(notification.status, 202);
  assert.equal((await fetch(`${endpoint}/mcp`)).status, 405);
  assert.deepEqual((await rpc("resources/list")).result.resources, []);
  assert.equal((await rpc("resources/read", { uri: "ui://servicenow/incident-dashboard.html" })).error.code, -32602);
  const healthy = await fetch(`${endpoint}/health`);
  assert.equal(healthy.status, 200);
  assert.equal((await healthy.json()).servicenow, "connected");
  assert.equal(requests.at(-1).url.searchParams.get("sysparm_query"), boundary);
  upstreamStatus = 401;
  try {
    const failed = await rpc("tools/call", { name: "get_incident", arguments: { number: incident.number } });
    assert.equal(failed.result.isError, true);
    assert.match(failed.result.content[0].text, /HTTP 401/);
    assert.doesNotMatch(failed.result.content[0].text, /private-upstream-detail/);
    assert.equal((await fetch(`${endpoint}/health`)).status, 503);
  } finally {
    upstreamStatus = 200;
  }
});

test("shared Cowork contract exactly matches production tools/list", async () => {
  const declared = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "contracts", "cowork-tools.json"), "utf8"));
  assert.deepEqual(declared.tools.map((tool) => tool.name), reads);
  const liveTools = (await rpc("tools/list")).result.tools;
  for (const tool of declared.tools) {
    assert.equal(tool.inputSchema?.type, "object", `${tool.name} must include an inputSchema object`);
    assert.deepEqual(tool.inputSchema, liveTools.find((live) => live.name === tool.name).inputSchema,
      `${tool.name} must match the live input contract`);
  }
  assert.deepEqual(declared.tools, liveTools, "Packaged tool definitions must match tools/list");
});

test("incident discovery descriptions expose symptom routing and evidence limits without reading records", async () => {
  const count = requests.length;
  const { result } = await rpc("tools/list");
  const search = result.tools.find((tool) => tool.name === "search_incidents").description;
  const get = result.tools.find((tool) => tool.name === "get_incident").description;
  assert.match(search, /workplace IT symptoms[\s\S]*even when the user does not name ServiceNow or provide a ticket number/);
  assert.match(search, /one literal substring of the incident title \(short_description\), not the full description or semantic meaning/);
  assert.match(search, /number, state, priority, and assignee filters narrow results together/);
  assert.match(search, /up to 20 incidents/);
  assert.match(search, /ordinary document-finding without an IT problem does not call for this tool/);
  assert.match(get, /number supplied by the user or returned by search_incidents/);
  assert.match(get, /recorded impact and workaround; a title match alone does not confirm the cause/);
  for (const description of [search, get]) {
    assert.match(description, /Read-only/);
    assert.match(description, /updated within the last six months/);
    assert.match(description, /source link/);
    assert.match(description, /Respect explicit source restrictions/);
  }
  assert.equal(requests.length, count);
});

test("rejects malformed or out-of-scope change filters before upstream access", async () => {
  for (const [name, args] of [
    ["get_change", {}], ["get_change", { number: incident.number }],
    ["get_change", { number: "CHG1^NQactive=true" }],
    ["search_changes", { query: "database" }],
    ["search_changes", { state: "closed" }],
    ["search_changes", { assignment_group: "x^ORactive=true" }],
    ["search_changes", { type: "javascript:gs.getUserID()" }],
  ]) {
    const count = requests.length;
    assert.equal((await rpc("tools/call", { name, arguments: args })).result.isError, true);
    assert.equal(requests.length, count);
  }
});

test("empty lists are distinct from invalid upstream records and missing exact lookups", async () => {
  try {
    upstreamResult = [];
    assert.deepEqual(JSON.parse((await rpc("tools/call", { name: "search_changes" })).result.content[0].text), []);
    const missing = await rpc("tools/call", { name: "get_change", arguments: { number: change.number } });
    assert.equal(missing.result.isError, true);
    assert.match(missing.result.content[0].text, /not found within the last six months/);
    for (const result of [{}, [null], [{ number: incident.number, sys_id: "invalid" }]]) {
      upstreamResult = result;
      const response = await rpc("tools/call", { name: "search_incidents" });
      assert.equal(response.result.isError, true);
      assert.match(response.result.content[0].text, /invalid record list|valid source ID/);
    }
  } finally {
    upstreamResult = undefined;
  }
});

test("does not follow upstream redirects or forward credentials to another location", async () => {
  const count = requests.length;
  upstreamRedirect = `${process.env.SERVICENOW_INSTANCE}/unexpected`;
  try {
    const response = await rpc("tools/call", { name: "search_incidents" });
    assert.equal(response.result.isError, true);
    assert.equal(requests.length, count + 1);
    assert.doesNotMatch(response.result.content[0].text, /test-only|Basic /);
  } finally {
    upstreamRedirect = undefined;
  }
});
