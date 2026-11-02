const assert = require("node:assert/strict");
const { test } = require("node:test");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const http = require("node:http");
const { once } = require("node:events");
const { spawn } = require("node:child_process");

test("declared stdio entrypoint works without npm dependencies when explicitly given process configuration", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "servicenow-plugin-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const plugin = path.join(root, "plugin");
  fs.mkdirSync(plugin);
  for (const name of ["src", "contracts"])
    fs.cpSync(path.join(__dirname, "..", name), path.join(plugin, name), { recursive: true });
  const seen = [];
  const id = "a".repeat(32);
  const source = http.createServer((req, res) => {
    seen.push(new URL(req.url, "http://localhost"));
    res.setHeader("Content-Type", "application/json");
    const user = { sys_id: id, sys_mod_count: "0", user_name: "sample", first_name: "Sample",
      last_name: "", title: "", active: "false", locked_out: "true", notification: "1", user_password: "must-not-return" };
    res.end(JSON.stringify({ result: req.url.includes("/sys_user") ? [user] : [] }));
  }).listen(0, "127.0.0.1");
  await once(source, "listening");
  t.after(() => { source.closeAllConnections(); source.close(); });
  const child = spawn(process.execPath, [path.join(plugin, "src", "stdio.cjs")], {
    cwd: plugin, env: { ...process.env, NODE_PATH: "", SERVICENOW_INSTANCE: `http://127.0.0.1:${source.address().port}`,
      SERVICENOW_USERNAME: "operator", SERVICENOW_PASSWORD: "synthetic-only",
      SERVICENOW_MCP_DATA_DIR: path.join(root, "private"), MCP_ALLOWED_HOSTS: "", MCP_ALLOWED_ORIGINS: "" },
    stdio: ["pipe", "pipe", "pipe"],
  });
  t.after(() => { if (child.exitCode === null) child.kill(); });
  let output = "", errors = "";
  child.stdout.on("data", data => { output += data; });
  child.stderr.on("data", data => { errors += data; });
  const requests = [
    { id: 1, method: "initialize", params: { protocolVersion: "2025-03-26" } },
    { method: "notifications/initialized" },
    { id: 2, method: "tools/list" },
    { id: 3, method: "tools/call", params: { name: "search_incidents", arguments: { query: "sample" } } },
    { id: 4, method: "tools/call", params: { name: "local_admin_user_get", arguments: { sys_id: id } } },
  ];
  child.stdin.end(requests.map(request => JSON.stringify({ jsonrpc: "2.0", ...request })).join("\n") + "\n");
  const [code] = await once(child, "close");
  assert.equal(code, 0, errors);
  assert.equal(errors, "");
  const messages = output.trim().split("\n").map(JSON.parse);
  assert.deepEqual(messages.map(message => message.id), [1, 2, 3, 4]);
  assert.equal(messages[0].result.serverInfo.version, "1.0.0");
  const names = messages[1].result.tools.map(tool => tool.name);
  for (const name of ["local_record_create", "local_admin_user_delete_administrative", "local_admin_patch_theme_style_pair",
    "local_admin_apply_theme_logo", "local_admin_user_create_disabled", "local_admin_import_theme_logo",
    "lookup_users", "get_user", "create_user", "update_user", "assess_user_delete", "delete_user", "get_user_operation"])
    assert.ok(names.includes(name), name);
  assert.deepEqual(JSON.parse(messages[2].result.content[0].text), []);
  const user = JSON.parse(messages[3].result.content[0].text);
  assert.equal(user.record.sys_id, id);
  assert.equal(Object.hasOwn(user.record, "user_password"), false);
  assert.equal(seen.length, 2);
  assert.match(seen[0].searchParams.get("sysparm_query"), /^sys_updated_on>javascript:gs.monthsAgo\(6\)\^/);
  assert.equal(seen[0].searchParams.get("sysparm_limit"), "20");
});
