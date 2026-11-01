const path = require("node:path");

function instanceOrigin(value) {
  let url;
  try { url = new URL(value); } catch { throw new Error("SERVICENOW_INSTANCE must be an HTTPS origin."); }
  const loopback = url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if ((url.protocol !== "https:" && !loopback) || url.username || url.password ||
      url.pathname !== "/" || url.search || url.hash)
    throw new Error("SERVICENOW_INSTANCE must be an HTTPS origin without credentials, path, query or fragment.");
  return url.origin;
}

function configuration(env = process.env) {
  const instance = instanceOrigin(env.SERVICENOW_INSTANCE);
  const username = env.SERVICENOW_USERNAME;
  const password = env.SERVICENOW_PASSWORD;
  if (!username || !password || /[\u0000-\u001f^]|javascript:/i.test(username))
    throw new Error("Supply valid SERVICENOW_USERNAME and SERVICENOW_PASSWORD through the protected process environment.");
  const directory = env.SERVICENOW_MCP_DATA_DIR;
  if (!directory || !path.isAbsolute(directory))
    throw new Error("SERVICENOW_MCP_DATA_DIR must be an absolute private directory outside the source checkout.");
  return { instance, username, password, directory };
}

module.exports = { instanceOrigin, configuration };
