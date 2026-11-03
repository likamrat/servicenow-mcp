const fs = require("node:fs");
const path = require("node:path");
const { validate } = require("./admin/validate.cjs");
const { instanceOrigin } = require("./configuration.cjs");
const { requestOrigin, requestBoundary } = require("./http-boundary.cjs");
const { SCOPE, USER_SCOPE, USER_ACCESS_SCOPE, MANAGEMENT_SCOPES, authProperties, CoworkAuthError } = require("./cowork-auth.cjs");
const userTools = require("./admin/users.cjs").tools;
const userAccessTools = require("./admin/user-access.cjs").tools;
const tools = [...require("../contracts/cowork-tools.json").tools, ...require("../contracts/incident-tools.json").tools, ...userTools, ...userAccessTools];
const toolScope = tool => userAccessTools.some(item => item.name === tool.name) ? USER_ACCESS_SCOPE :
  userTools.some(item => item.name === tool.name) ? USER_SCOPE : SCOPE;
const admittedTools = caller => tools.filter(tool => caller.scopes?.includes(toolScope(tool)));
const profileSchema = { type: "object", properties: { ...authProperties,
  format: { const: 1 }, instance: { type: "string" }, public_url: { type: "string", maxLength: 2048 },
  port: { type: "integer", minimum: 1, maximum: 65535 }, writes_enabled: { type: "boolean" },
  audit_enabled: { type: "boolean" },
  allowed_origins: { type: "array", maxItems: 10, uniqueItems: true, items: { type: "string" } },
}, required: [...Object.keys(authProperties), "format", "instance", "public_url", "writes_enabled"], additionalProperties: false };

function validateProfile(profile) {
  validate(profileSchema, profile, "Cowork connection");
  if (instanceOrigin(profile.instance) !== profile.instance) throw new Error("Cowork source origin must be canonical.");
  let url;
  try { url = new URL(profile.public_url); } catch { throw new Error("Cowork public URL must be an HTTPS /mcp URL."); }
  if (url.protocol !== "https:" || url.username || url.password || url.pathname !== "/mcp" || url.search || url.hash)
    throw new Error("Cowork public URL must be an HTTPS /mcp URL without credentials, query or fragment.");
  for (const origin of profile.allowed_origins || []) if (!requestOrigin(origin)) throw new Error("Invalid Cowork client origin.");
  return url;
}
function loadProfile(file) {
  if (!path.isAbsolute(file)) throw new Error("Cowork connection path must be absolute.");
  const relative = path.relative(path.resolve(__dirname, ".."), file);
  if (relative === "" || relative !== ".." && !relative.startsWith(".." + path.sep) && !path.isAbsolute(relative))
    throw new Error("Keep private Cowork configuration outside the source checkout.");
  const info = fs.lstatSync(file);
  if (!info.isFile() || info.isSymbolicLink() || info.size > 16384 ||
      process.platform !== "win32" && (info.mode & 0o022))
    throw new Error("Cowork connection must be an operator-controlled private regular file.");
  let profile;
  try { profile = JSON.parse(fs.readFileSync(file, "utf8")); }
  catch { throw new Error("Private Cowork configuration is not valid JSON; no file content emitted."); }
  validateProfile(profile);
  return profile;
}
function createCoworkApp({ profile, backend, verifyAccessToken,
  writeAudit = line => fs.writeSync(process.stderr.fd, line) }) {
  const resource = validateProfile(profile);
  if (typeof verifyAccessToken !== "function" || typeof backend?.handle !== "function")
    throw new Error("Authenticated Cowork dependencies are required.");
  if (profile.audit_enabled && typeof writeAudit !== "function") throw new Error("Cowork audit output is required when enabled.");
  function auditedResult(caller, tool, outcome, status, result) {
    if (profile.audit_enabled) {
      try {
        writeAudit(JSON.stringify({ event: "cowork_tool_audit",
          tenant_id: caller.tenant_id, object_id: caller.object_id, client_id: caller.client_id,
          tool: tool?.name ?? null, outcome, status }) + "\n");
      } catch {
        // Audit failure cannot turn an already attempted source operation into a retryable failure.
        result.content.push({ type: "text", text: "Caller audit output unavailable. The original tool outcome is unchanged; do not retry an attempted write." });
      }
    }
    return result;
  }
  const app = require("express")();
  app.disable("x-powered-by");
  app.use(requestBoundary({
    allowedHosts: new Set(["localhost", "127.0.0.1", "[::1]", resource.hostname]),
    allowedOrigins: new Set(profile.allowed_origins || []),
  }));
  const fullScopes = MANAGEMENT_SCOPES.map(scope => `api://${profile.audience}/${scope}`);
  const metadataPath = "/.well-known/oauth-protected-resource/mcp";
  const metadataUrl = new URL(metadataPath, resource.origin).href;
  app.get([metadataPath, "/.well-known/oauth-protected-resource"], (_req, res) => res.json({
    resource: resource.href, authorization_servers: [`https://login.microsoftonline.com/${profile.tenant_id}/v2.0`],
    scopes_supported: fullScopes, bearer_methods_supported: ["header"], resource_name: "ServiceNow records and users",
  }));
  app.use("/mcp", async (req, res, next) => {
    try {
      const headers = req.headersDistinct.authorization;
      const match = headers?.length === 1 && /^Bearer ([^\s,]+)$/i.exec(headers[0]);
      if (!match) throw new CoworkAuthError(401, "bearer_token_required");
      res.locals.requester = await verifyAccessToken(match[1]);
      next();
    } catch (error) {
      if (!(error instanceof CoworkAuthError)) return next(error);
      if (error.status !== 503) res.set("WWW-Authenticate",
        `Bearer resource_metadata="${metadataUrl}", scope="${fullScopes.join(" ")}"`);
      res.status(error.status).json({ error: error.code });
    }
  });
  app.use(require("express").json({ limit: "64kb" }));
  app.post("/mcp", async (req, res) => {
    const body = req.body;
    if (!body || Array.isArray(body) || body.jsonrpc !== "2.0" || typeof body.method !== "string" ||
        body.id !== undefined && !["string", "number"].includes(typeof body.id))
      return res.status(400).json({ jsonrpc: "2.0", id: null, error: { code: -32600, message: "Invalid request." } });
    const { method, params, id } = body;
    if (id === undefined) return res.sendStatus(202);
    if (method === "initialize") return res.json({ jsonrpc: "2.0", id, result: {
      protocolVersion: "2025-03-26", capabilities: { tools: {} }, serverInfo: { name: "servicenow-mcp", title: "ServiceNow", version: "1.0.0" },
    } });
    if (method === "ping") return res.json({ jsonrpc: "2.0", id, result: {} });
    if (method === "tools/list") return res.json({ jsonrpc: "2.0", id, result: { tools: admittedTools(res.locals.requester) } });
    if (method !== "tools/call") return res.status(400).json({ jsonrpc: "2.0", id, error: { code: -32601, message: "Method not found." } });
    const caller = res.locals.requester;
    const tool = tools.find(item => item.name === params?.name);
    const scopeAllowed = tool && caller.scopes?.includes(toolScope(tool));
    let dispatched = false;
    try {
      if (!tool) throw new Error("Tool unavailable through the Cowork incident interface.");
      if (!scopeAllowed) throw new Error("The verified delegated token lacks this tool's management scope.");
      if (!tool.annotations.readOnlyHint && !profile.writes_enabled) throw new Error("Cowork writes are disabled by the operator.");
      dispatched = true;
      const result = await backend.handle(tool.name, params.arguments === undefined ? {} : params.arguments,
        `${caller.tenant_id}:${caller.object_id}:${caller.client_id}`);
      const status = ["confirmed", "no_change", "uncertain", "not_sent"].includes(result?.status) ? result.status : "completed";
      return res.json({ jsonrpc: "2.0", id, result: auditedResult(caller, tool, "success", status,
        { content: [{ type: "text", text: JSON.stringify(result) }] }) });
    } catch (error) {
      const status = !tool ? "tool_unavailable" : !scopeAllowed ? "scope_required" : !dispatched ? "writes_disabled" :
        ["uncertain", "not_sent"].includes(error.outcome?.status) ? error.outcome.status : "failed";
      return res.json({ jsonrpc: "2.0", id, result: auditedResult(caller, tool, dispatched ? "error" : "not_dispatched", status,
        { isError: true, content: [{ type: "text", text: JSON.stringify({
        error: error.message, diagnostic: error.diagnostic, outcome: error.outcome,
      }) }] }) });
    }
  });
  app.get("/mcp", (_req, res) => res.status(405).set("Allow", "POST").end());
  app.use((_req, res) => res.status(404).json({ error: "Not found." }));
  app.use((error, _req, res, _next) => {
    if (error.type === "entity.parse.failed") return res.status(400).json({ error: "Invalid JSON request." });
    if (error.type === "entity.too.large") return res.status(413).json({ error: "Request body exceeds the supported size." });
    console.error("Cowork HTTP request failed before dispatch (INTERNAL_REQUEST_ERROR).");
    res.status(500).json({ error: "Cowork request failed before dispatch." });
  });
  return app;
}
module.exports = { createCoworkApp, loadProfile, validateProfile, tools };
