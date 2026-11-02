const assert = require("node:assert/strict");
const { test } = require("node:test");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const http = require("node:http");
const crypto = require("node:crypto");
const { once } = require("node:events");
const { spawn, spawnSync, execFileSync } = require("node:child_process");
const { loadBinding } = require("../src/plugin.cjs");

test("marketplace release matches the portable root manifest and preserves installed plugin identity", () => {
  const root = path.join(__dirname, "..");
  const plugin = JSON.parse(fs.readFileSync(path.join(root, "plugin.json"), "utf8"));
  const marketplace = JSON.parse(fs.readFileSync(path.join(root, ".github", "plugin", "marketplace.json"), "utf8"));
  assert.equal(plugin.$schema, "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json");
  assert.equal(marketplace.name, "servicenow-community");
  const entry = marketplace.plugins.find(item => item.name === plugin.name);
  assert.equal(`${entry.name}@${marketplace.name}`, "servicenow-mcp@servicenow-community");
  assert.equal(entry.version, plugin.version);
  assert.match(plugin.version, /^\d+\.\d+\.\d+$/);
  assert.equal(entry.source, "./");
  assert.equal(plugin.repository, "https://github.com/likamrat/servicenow-mcp");
  assert.equal(fs.existsSync(path.join(root, entry.source, "mcp.json")), true);
  assert.equal(fs.existsSync(path.join(root, entry.source, "skills", "servicenow-operations", "SKILL.md")), true);
  assert.equal(fs.existsSync(path.join(root, entry.source, "skills", "servicenow-themes", "SKILL.md")), true);
  assert.equal(Object.hasOwn(plugin, "branch"), false);
  assert.equal(Object.hasOwn(plugin, "ref"), false);
});

test("plugin uses only PLUGIN_DATA and a pinned synthetic protected provider, never ambient source credentials", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "servicenow-binding-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const data = path.join(root, "plugin-data");
  fs.mkdirSync(data);
  const powershell = execFileSync("pwsh", ["-NoLogo", "-NoProfile", "-Command", "(Get-Process -Id $PID).Path"], { encoding: "utf8" }).trim();
  const username = "synthetic-provider-user", password = "synthetic-provider-password";
  let calls = 0;
  const source = http.createServer((req, res) => {
    calls++;
    assert.equal(req.headers.authorization, "Basic " + Buffer.from(`${username}:${password}`).toString("base64"));
    res.setHeader("Content-Type", "application/json");
    res.end('{"result":[]}');
  }).listen(0, "127.0.0.1");
  await once(source, "listening");
  t.after(() => { source.closeAllConnections(); source.close(); });
  const instance = `http://127.0.0.1:${source.address().port}`;
  const provider = path.join(root, "synthetic.psm1");
  fs.writeFileSync(provider, `
function Get-ServiceNowStoredCredential {
  [pscustomobject]@{
    Instance = '${instance}'
    UserNameSecure = ConvertTo-SecureString '${username}' -AsPlainText -Force
    PasswordSecure = ConvertTo-SecureString '${password}' -AsPlainText -Force
  }
}
Export-ModuleMember -Function Get-ServiceNowStoredCredential
`);
  const binding = { format: 1, instance, powershell_path: powershell, provider_module: provider,
    powershell_sha256: crypto.createHash("sha256").update(fs.readFileSync(powershell)).digest("hex"),
    provider_getter: "Get-ServiceNowStoredCredential",
    provider_sha256: crypto.createHash("sha256").update(fs.readFileSync(provider)).digest("hex"),
    state_directory: path.join(root, "retained-state") };
  const file = path.join(data, "connection.json");
  fs.writeFileSync(file, JSON.stringify(binding), { mode: 0o600 });
  const originalBinding = fs.readFileSync(file);
  const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "mcp.json"), "utf8"));
  const config = manifest.mcpServers["servicenow-portable"];
  assert.equal(config.type, "stdio");
  assert.equal(config.command, "node");
  const pluginRoot = path.join(__dirname, "..");
  const child = spawn(process.execPath, config.args.map(arg => arg.replaceAll("${PLUGIN_ROOT}", pluginRoot)), {
    env: { PLUGIN_DATA: data, SERVICENOW_INSTANCE: "invalid-ambient", SERVICENOW_PASSWORD: "must-not-use" },
    stdio: ["pipe", "pipe", "pipe"],
  });
  t.after(() => { if (child.exitCode === null) child.kill(); });
  let output = "", errors = "";
  child.stdout.on("data", data => { output += data; });
  child.stderr.on("data", data => { errors += data; });
  child.stdin.end([
    { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-03-26" } },
    { jsonrpc: "2.0", method: "notifications/initialized" },
    { jsonrpc: "2.0", id: 2, method: "tools/list" },
    { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "search_incidents", arguments: {} } },
  ].map(JSON.stringify).join("\n") + "\n");
  const [code] = await once(child, "close");
  assert.equal(code, 0, errors);
  assert.equal(errors, "");
  const responses = output.trim().split("\n").map(JSON.parse);
  assert.equal(responses[0].result.serverInfo.version, "1.0.0");
  const advertised = responses[1].result.tools;
  for (const tool of require("../contracts/cowork-authenticated-tools.json").tools)
    assert.deepEqual(advertised.find(item => item.name === tool.name), tool, `Protected packaged entrypoint exposes ${tool.name}`);
  assert.deepEqual(JSON.parse(responses[2].result.content[0].text), []);
  assert.deepEqual(fs.readFileSync(file), originalBinding, "Loading the package must not replace the approved private binding");
  assert.equal(calls, 1);
  assert.equal(output.includes(username), false);
  assert.equal(output.includes(password), false);
  fs.appendFileSync(provider, "\n# changed\n");
  assert.throws(() => loadBinding(data), /provider module changed/);
  assert.equal(calls, 1);
  fs.writeFileSync(provider, "function Get-ServiceNowStoredCredential { throw 'SN_SYNTHETIC_SECRET_MUST_NOT_LEAK' }\nExport-ModuleMember -Function Get-ServiceNowStoredCredential\n");
  binding.provider_sha256 = crypto.createHash("sha256").update(fs.readFileSync(provider)).digest("hex");
  fs.writeFileSync(file, JSON.stringify(binding), { mode: 0o600 });
  const failed = spawnSync(process.execPath, config.args.map(arg => arg.replaceAll("${PLUGIN_ROOT}", pluginRoot)), {
    env: { PLUGIN_DATA: data }, input: "", encoding: "utf8", timeout: 10000,
  });
  assert.equal(failed.status, 1);
  assert.equal(failed.stdout, "");
  assert.match(failed.stderr, /SN_GETTER_FAILED/);
  assert.doesNotMatch(failed.stderr, /SYNTHETIC_SECRET_MUST_NOT_LEAK/);
  assert.equal(calls, 1);
});
