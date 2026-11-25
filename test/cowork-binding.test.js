const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { test } = require("node:test");

const tenant = "11111111-1111-4111-8111-111111111111";
const client = "22222222-2222-4222-8222-222222222222";
const audience = "33333333-3333-4333-8333-333333333333";
const tokenUrl = `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`;
const command = path.join(__dirname, "..", "scripts", "cowork-binding.cjs");

function fixture(t, host, alter = () => {}) {
  const endpoint = `https://host-${host}.example.invalid/mcp`;
  const referenceId = `test-vault-${host}`;
  const profile = {
    format: 1, instance: "https://service.example.invalid", public_url: endpoint,
    tenant_id: tenant, audience, client_id: client, writes_enabled: false,
  };
  const server = { mcpServerUrl: endpoint, authorization: { type: "OAuthPluginVault", referenceId } };
  const manifest = {
    id: `44444444-4444-4444-8444-44444444444${host}`,
    agentConnectors: [{ toolSource: { remoteMcpServer: server } }],
  };
  const saved = { referenceId, baseUrl: endpoint, clientId: client, scope: "api://example/Incident.Manage offline_access",
    tokenUrl, refreshUrl: tokenUrl };
  alter({ manifest, profile, saved, server });
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "cowork-binding-"));
  const files = [manifest, profile, saved].map((data, index) => {
    const file = path.join(root, `${index}.json`);
    fs.writeFileSync(file, JSON.stringify(data), { mode: 0o600 });
    return file;
  });
  t.after(() => { for (const file of files) fs.unlinkSync(file); fs.rmdirSync(root); });
  return files;
}

const run = (...groups) => spawnSync(process.execPath, [command, ...groups.flat()], { encoding: "utf8" });

test("independent deployments can share the Entra client without reusing package bindings", t => {
  const result = run(fixture(t, 1), fixture(t, 2), fixture(t, 3));
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /3 deployment\(s\).*Live route and token renewal not checked/);
});

test("the check reports stale bindings, missing refresh settings, and reused deployment identity", t => {
  const first = fixture(t, 1);
  const second = fixture(t, 2, ({ manifest, profile, saved, server }) => {
    manifest.id = manifest.id.replace(/2$/, "1").toUpperCase();
    profile.public_url = profile.public_url.replace("host-2", "host-1");
    server.authorization.referenceId = "test-vault-1";
    saved.scope = "api://example/Incident.Manage";
    saved.refreshUrl = "";
  });
  const result = run(first, second);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /Deployment 2: The package server URL/);
  assert.match(result.stderr, /OAuth reference does not match/);
  assert.match(result.stderr, /missing offline_access/);
  assert.match(result.stderr, /Token and Refresh endpoints/);
  assert.match(result.stderr, /reuse the same app/);
  assert.match(result.stderr, /reuse the same endpoint/);
  assert.match(result.stderr, /reuse the same registration/);
  assert.doesNotMatch(result.stderr, /host-\d|test-vault/);
});

test("an unexpected field in the registration receipt is rejected without echoing its contents", t => {
  const result = run(fixture(t, 1, ({ saved }) => { saved.clientSecret = "synthetic-secret"; }));
  assert.equal(result.status, 1);
  assert.match(result.stderr, /Use only these saved OAuth fields/);
  assert.doesNotMatch(result.stderr, /clientSecret|synthetic-secret/);
});
