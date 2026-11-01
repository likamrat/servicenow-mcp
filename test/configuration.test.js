const assert = require("node:assert/strict");
const { test } = require("node:test");
const { spawnSync } = require("node:child_process");
const path = require("node:path");

const cwd = path.join(__dirname, "..");
const env = {
  ...process.env, MCP_ALLOWED_HOSTS: "", MCP_ALLOWED_ORIGINS: "",
  SERVICENOW_INSTANCE: "https://servicenow.example.invalid",
  SERVICENOW_USERNAME: "test-user", SERVICENOW_PASSWORD: "test-only",
};

test("invalid instance origins fail without disclosing credentials", () => {
  for (const instance of [
    "", "not-an-origin", "http://servicenow.example.invalid",
    "https://user:password@servicenow.example.invalid",
    "https://servicenow.example.invalid/path",
    "https://servicenow.example.invalid?token=placeholder",
    "https://servicenow.example.invalid#fragment",
  ]) {
    const result = spawnSync(process.execPath, ["-e", "require('./src/server')"], {
      cwd, env: { ...env, SERVICENOW_INSTANCE: instance }, encoding: "utf8",
    });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /SERVICENOW_INSTANCE/);
    assert.doesNotMatch(result.stderr, /test-only|user:password|token=placeholder/);
  }
});

test("request configuration rejects wildcard, malformed and ambiguous entries", () => {
  for (const [name, values] of Object.entries({
    MCP_ALLOWED_HOSTS: [
      "*", ".", "mcp..example.invalid", "*.example.invalid", "https://mcp.example.invalid",
      "mcp.example.invalid:443", "mcp.example.invalid/path", "mcp.example.invalid,",
    ],
    MCP_ALLOWED_ORIGINS: [
      "*", "null", "https://client.example.invalid/path",
      "https://client.example.invalid/", "https://client.example.invalid,",
      "https://user:password@client.example.invalid",
    ],
  })) for (const value of values) {
    const result = spawnSync(process.execPath, ["-e", "require('./src/server')"], {
      cwd, env: { ...env, [name]: value }, encoding: "utf8",
    });
    assert.notEqual(result.status, 0);
    assert.ok(result.stderr.includes(name));
    assert.doesNotMatch(result.stderr, /test-only|user:password/);
  }
});

test("default origin policy allows machine clients and rejects browser origins", () => {
  const result = spawnSync(process.execPath, ["-e", `
    const { once } = require("node:events");
    const { app } = require("./src/server");
    (async () => {
      const server = app.listen(0, "127.0.0.1");
      try {
        await once(server, "listening");
        const statuses = [];
        for (const origin of [undefined, "https://client.example.invalid", "null"]) {
          const response = await fetch("http://127.0.0.1:" + server.address().port + "/mcp", {
            method: "POST",
            headers: { "Content-Type": "application/json", ...(origin ? { Origin: origin } : {}) },
            body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
          });
          statuses.push(response.status);
          await response.arrayBuffer();
        }
        console.log(JSON.stringify(statuses));
      } finally {
        server.closeAllConnections();
        await new Promise(resolve => server.close(resolve));
      }
    })().catch(error => { console.error(error.message); process.exitCode = 1; });
  `], { cwd, env, encoding: "utf8", timeout: 10000 });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), [200, 403, 403]);
});
