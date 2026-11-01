const { tools } = require("../contracts/cowork-tools.json");
const { createReads, RECENT_QUERY } = require("./reads.cjs");
const { instanceOrigin } = require("./configuration.cjs");
const { requestHostname, requestOrigin, requestBoundary } = require("./http-boundary.cjs");

function configuredList(name, validate) {
  const value = process.env[name];
  if (!value?.trim()) return [];
  return value.split(",").map(entry => {
    const normalized = validate(entry.trim());
    if (!normalized) {
      const format = name === "MCP_ALLOWED_HOSTS" ? "hostnames without schemes or ports" : "exact HTTP(S) origins without paths";
      throw new Error(`${name} must be a comma-separated list of ${format}.`);
    }
    return normalized;
  });
}
const allowedHosts = new Set(["localhost", "127.0.0.1", "[::1]", ...configuredList("MCP_ALLOWED_HOSTS", value => {
  const host = requestHostname(value);
  return host === value.toLowerCase() ? host : null;
})]);
const allowedOrigins = new Set(configuredList("MCP_ALLOWED_ORIGINS", requestOrigin));
const SN_USER = process.env.SERVICENOW_USERNAME;
const SN_PASS = process.env.SERVICENOW_PASSWORD;
if (!process.env.SERVICENOW_INSTANCE || !SN_USER || !SN_PASS)
  throw new Error("Set SERVICENOW_INSTANCE, SERVICENOW_USERNAME and SERVICENOW_PASSWORD in the process environment.");
const SN_INSTANCE = instanceOrigin(process.env.SERVICENOW_INSTANCE);
const AUTH_HEADER = "Basic " + Buffer.from(`${SN_USER}:${SN_PASS}`).toString("base64");
async function snRequest(method, table, params) {
  if (method !== "GET") throw new Error("This connection is read-only.");
  const response = await fetch(`${SN_INSTANCE}/api/now/table/${table}?${new URLSearchParams(params)}`, {
    method, redirect: "error", signal: AbortSignal.timeout(15000),
    headers: { Authorization: AUTH_HEADER, Accept: "application/json" },
  });
  if (!response.ok) throw new Error(`ServiceNow API returned HTTP ${response.status}.`);
  return response.json();
}
const { handle: handleTool } = createReads({ instance: SN_INSTANCE, request: snRequest });

function createApp() {
  const express = require("express");
  const app = express();
  app.use(requestBoundary({ allowedHosts, allowedOrigins }));
  app.use(express.json({ limit: "2mb" }));
  app.post("/mcp", async (req, res) => {
    const { method, params, id } = req.body || {};
    if (typeof method !== "string") return res.status(400).json({
      jsonrpc: "2.0", id: id ?? null, error: { code: -32600, message: "Invalid request." },
    });
    if (id === undefined) return res.sendStatus(202);
    if (method === "ping") return res.json({ jsonrpc: "2.0", id, result: {} });
    if (method === "initialize") return res.json({ jsonrpc: "2.0", id, result: {
      protocolVersion: "2025-03-26", capabilities: { tools: {}, resources: {} },
      serverInfo: { name: "servicenow-mcp-server", version: "1.0.0" },
    } });
    if (method === "tools/list") return res.json({ jsonrpc: "2.0", id, result: { tools } });
    if (method === "resources/list") return res.json({ jsonrpc: "2.0", id, result: { resources: [] } });
    if (method === "resources/read") return res.json({
      jsonrpc: "2.0", id, error: { code: -32602, message: "No resources are exposed." },
    });
    if (method !== "tools/call") return res.status(400).json({
      jsonrpc: "2.0", id, error: { code: -32601, message: `Method not found: ${method}` },
    });
    try {
      const { name, arguments: args } = params || {};
      const result = await handleTool(name, args === undefined ? {} : args);
      return res.json({ jsonrpc: "2.0", id, result: { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] } });
    } catch (error) {
      return res.json({ jsonrpc: "2.0", id, result: {
        content: [{ type: "text", text: JSON.stringify({ error: error.message }) }], isError: true,
      } });
    }
  });
  app.get("/mcp", (_req, res) => res.status(405).set("Allow", "POST").end());
  app.get("/health", async (_req, res) => {
    try {
      const data = await snRequest("GET", "incident", { sysparm_query: RECENT_QUERY, sysparm_limit: "1", sysparm_fields: "number" });
      if (!Array.isArray(data.result)) throw new Error("ServiceNow returned an invalid record list.");
      res.json({ status: "ok", servicenow: "connected" });
    } catch (error) { res.status(503).json({ status: "error", message: error.message }); }
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
