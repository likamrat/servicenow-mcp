const assert = require("node:assert/strict");
const { test } = require("node:test");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const net = require("node:net");
const { once } = require("node:events");
const { createHash } = require("node:crypto");
const { spawn, execFileSync } = require("node:child_process");

test("the existing protected provider launches the authenticated loopback interface without exposing credentials", { timeout: 15000 }, async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "cowork-start-"));
  let child, serverPid, closed;
  t.after(async () => {
    if (serverPid) {
      try { process.kill(serverPid, "SIGTERM"); } catch (error) { if (error.code !== "ESRCH") throw error; }
    } else if (child && child.exitCode === null) child.kill();
    if (closed) await closed;
    fs.rmSync(root, { recursive: true, force: true });
  });
  const reservation = net.createServer().listen(0, "127.0.0.1");
  await once(reservation, "listening");
  const port = reservation.address().port;
  await new Promise(resolve => reservation.close(resolve));
  const directory = path.join(root, "binding"), state = path.join(root, "state");
  fs.mkdirSync(directory); fs.mkdirSync(state);
  const powershell = execFileSync("pwsh", ["-NoLogo", "-NoProfile", "-Command", "(Get-Process -Id $PID).Path"], { encoding: "utf8" }).trim();
  const provider = path.join(root, "synthetic.psm1");
  const instance = "https://service.example.invalid";
  fs.writeFileSync(provider, `function Get-ServiceNowStoredCredential {
    [pscustomobject]@{ Instance='${instance}'; UserNameSecure=(ConvertTo-SecureString 'synthetic-user' -AsPlainText -Force);
    PasswordSecure=(ConvertTo-SecureString 'synthetic-password' -AsPlainText -Force) }
  }\nExport-ModuleMember -Function Get-ServiceNowStoredCredential\n`);
  const hash = file => createHash("sha256").update(fs.readFileSync(file)).digest("hex");
  fs.writeFileSync(path.join(directory, "connection.json"), JSON.stringify({
    format: 1, instance, powershell_path: powershell, powershell_sha256: hash(powershell),
    provider_module: provider, provider_sha256: hash(provider),
    provider_getter: "Get-ServiceNowStoredCredential", state_directory: state,
  }), { mode: 0o600 });
  fs.writeFileSync(path.join(state, "cowork-profile.json"), JSON.stringify({
    format: 1, instance, public_url: "https://mcp.example.invalid/mcp", port,
    tenant_id: "11111111-1111-4111-8111-111111111111", audience: "22222222-2222-4222-8222-222222222222",
    client_id: "33333333-3333-4333-8333-333333333333", writes_enabled: false,
  }), { mode: 0o600 });
  child = spawn(process.execPath, [path.join(__dirname, "..", "src", "cowork-start.cjs"), directory], {
    env: { SERVICENOW_INSTANCE: "invalid-ambient", SERVICENOW_PASSWORD: "must-not-use" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  closed = once(child, "close");
  let output = "", errors = "";
  child.stderr.on("data", bytes => { errors += bytes; });
  const ready = new Promise((resolve, reject) => {
    child.stdout.on("data", bytes => {
      output += bytes;
      const line = output.split(/\r?\n/).find(value => value.startsWith('{"event":"cowork-listening"'));
      if (line) {
        const event = JSON.parse(line);
        serverPid = event.pid;
        resolve(event);
      }
    });
    child.once("error", reject);
    child.once("close", () => { if (!serverPid) reject(new Error("Synthetic launcher exited before readiness: " + errors)); });
  });
  const event = await ready;
  assert.equal(event.port, port);
  assert.equal(event.writes_enabled, false);
  const unauthorized = await fetch(`http://127.0.0.1:${port}/mcp`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
  });
  assert.equal(unauthorized.status, 401);
  await unauthorized.arrayBuffer();
  assert.doesNotMatch(output + errors, /synthetic-user|synthetic-password|must-not-use/);
});
