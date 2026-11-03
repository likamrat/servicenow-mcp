const { instanceOrigin } = require("../configuration.cjs");
const ID = /^[a-f0-9]{32}$/;
const NAME = /^[a-zA-Z][a-zA-Z0-9_]{0,127}$/;
const METHODS = new Set(["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]);

function createSource({ instance, username, password, fetchImpl = fetch }) {
  instance = instanceOrigin(instance);
  if (!username || !password) throw new Error("Source credentials are required.");
  const authorization = "Basic " + Buffer.from(`${username}:${password}`).toString("base64");
  let authenticationRejected = false;
  function sanitize(value) {
    return String(value).replaceAll(authorization, "<redacted>").replaceAll(authorization.slice(6), "<redacted>")
      .replaceAll(password, "<redacted>").replaceAll(username, "<principal>")
      .replace(/(?:Basic|Bearer)\s+[A-Za-z0-9+/_=.-]+/gi, "<redacted-auth>")
      .replace(/(?:password|token|secret|authorization|set-cookie)\s*[:=]\s*\S+/gi, "<redacted-field>")
      .replace(/<[^>]*>/g, "").slice(0, 1000);
  }
  async function boundedBody(response, limit) {
    const reader = response.body?.getReader();
    if (!reader) throw new Error("Source response body is missing.");
    const chunks = [];
    let size = 0;
    try {
      for (;;) {
        const next = await reader.read();
        if (next.done) break;
        size += next.value.byteLength;
        if (size >= limit) { await reader.cancel(); throw new Error("Source response exceeds the supported size."); }
        chunks.push(Buffer.from(next.value));
      }
    } finally { reader.releaseLock(); }
    return Buffer.concat(chunks);
  }
  async function send(url, options) {
    if (authenticationRejected) throw new Error("Source authentication was rejected; stop this process and correct its approved credentials before further calls.");
    let response;
    try {
      response = await fetchImpl(url, {
        ...options, redirect: "error", signal: AbortSignal.timeout(20000),
        headers: { Authorization: authorization, Accept: "application/json", ...options.headers },
      });
    } catch { throw new Error("Source transport failed; a sent write may have taken effect. Reconcile without replay."); }
    if (!response.ok) {
      if (response.status === 401) authenticationRejected = true;
      const error = new Error(`ServiceNow API returned HTTP ${response.status}.`);
      error.diagnostic = { status: response.status };
      if (/^application\/(?:json|[\w.-]+\+json)(?:;|$)/i.test(response.headers.get("content-type") || "")) {
        try {
          const body = JSON.parse((await boundedBody(response, 8192)).toString("utf8"));
          const detail = body?.error || body;
          for (const field of ["code", "message", "detail"])
            if (["string", "number"].includes(typeof detail?.[field])) error.diagnostic[field] = sanitize(detail[field]);
        } catch { error.diagnostic.detail = "Error body unavailable or not safely decodable."; }
      } else if (response.body) await response.body.cancel();
      throw error;
    }
    return response;
  }
  async function request(method, table, params = {}, values, id) {
    if (!METHODS.has(method) || typeof table !== "string" || !NAME.test(table) ||
        (id !== undefined && (typeof id !== "string" || !ID.test(id)))) throw new Error("Invalid source identity.");
    try {
      const response = await send(`${instance}/api/now/table/${table}${id ? "/" + id : ""}?${new URLSearchParams(params)}`, {
        method, headers: { "Content-Type": "application/json" },
        ...(values === undefined ? {} : { body: JSON.stringify(values) }),
      });
      if (response.status === 204) return null;
      try { return JSON.parse((await boundedBody(response, 8 * 1024 * 1024)).toString("utf8")); }
      catch { throw new Error("Invalid or oversized source response; reconcile any sent write before further action."); }
    } catch (error) {
      error.diagnostic = { ...error.diagnostic, request: { method, table } };
      throw error;
    }
  }
  async function list(table, query, fields, limit = 100) {
    const data = await request("GET", table, { sysparm_query: query, sysparm_fields: fields,
      sysparm_limit: String(limit), sysparm_display_value: "false", sysparm_exclude_reference_link: "true" });
    if (!Array.isArray(data?.result) || data.result.length > limit) throw new Error("Invalid or over-limit source record list.");
    return data.result;
  }
  async function downloadAttachment(id, maxBytes) {
    if (!ID.test(id) || maxBytes !== 120000) throw new Error("Invalid bounded PNG download.");
    const response = await send(`${instance}/api/now/attachment/${id}/file`, {
      method: "GET", headers: { Accept: "image/png, application/octet-stream" },
    });
    return boundedBody(response, maxBytes);
  }
  async function uploadAttachment(prepared) {
    const url = new URL(prepared.url);
    if (url.origin !== instance || url.pathname !== "/api/now/attachment/file" || url.username || url.password ||
        [...url.searchParams.keys()].sort().join(",") !== "file_name,table_name,table_sys_id" ||
        url.searchParams.get("table_name") !== "sys_ux_theme_asset" || !ID.test(url.searchParams.get("table_sys_id")) ||
        url.searchParams.get("file_name") !== prepared.file_name || prepared.method !== "POST")
      throw new Error("Unqualified PNG attachment request.");
    require("./png.cjs").inspectPng(prepared.body);
    const response = await send(url.href, { method: "POST", headers: { "Content-Type": "image/png" }, body: prepared.body });
    try { return JSON.parse((await boundedBody(response, 1024 * 1024)).toString("utf8")); }
    catch { throw new Error("Attachment response unavailable; reconcile without another upload."); }
  }
  return { instance, request, list, downloadAttachment, uploadAttachment };
}

module.exports = { createSource };
