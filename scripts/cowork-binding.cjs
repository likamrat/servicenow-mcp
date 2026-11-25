const fs = require("node:fs");
const { authProperties } = require("../src/cowork-auth.cjs");
const { loadProfile } = require("../src/cowork-http.cjs");

const registrationFields = ["referenceId", "baseUrl", "clientId", "scope", "tokenUrl", "refreshUrl"];
const guid = new RegExp(authProperties.client_id.pattern, "i");

function readObject(file, label) {
  try {
    const info = fs.lstatSync(file);
    if (!info.isFile() || info.size > 65536) throw new Error("Invalid file");
    const data = JSON.parse(fs.readFileSync(file, "utf8").replace(/^\uFEFF/, ""));
    if (data && typeof data === "object" && !Array.isArray(data)) return data;
  } catch {
    throw new Error(`${label} must be a readable JSON object in a regular file no larger than 64 KiB.`);
  }
  throw new Error(`${label} must contain a JSON object.`);
}

function main(args) {
  if (!args.length || args.length % 3)
    throw new Error("Supply <manifest.json> <absolute cowork-profile.json> <saved-oauth-fields.json> for each deployment.");
  const seen = { app: new Set(), endpoint: new Set(), registration: new Set() };
  const failures = [];
  for (let i = 0; i < args.length; i += 3) {
    const fail = message => failures.push(`Deployment ${i / 3 + 1}: ${message}`);
    const manifest = readObject(args[i], "The package manifest");
    const saved = readObject(args[i + 2], "The saved OAuth fields");
    if (Object.keys(saved).some(key => !registrationFields.includes(key)) ||
        registrationFields.some(key => typeof saved[key] !== "string")) {
      fail(`Use only these saved OAuth fields as strings: ${registrationFields.join(", ")}.`);
      continue;
    }
    let profile;
    try { profile = loadProfile(args[i + 1]); }
    catch {
      fail("Could not read a valid Cowork profile. Use the absolute path to the operator-controlled profile outside the checkout.");
      continue;
    }

    const connector = manifest.agentConnectors?.[0]?.toolSource?.remoteMcpServer;
    if (typeof manifest.id !== "string" || !guid.test(manifest.id) ||
        !Array.isArray(manifest.agentConnectors) || manifest.agentConnectors.length !== 1 ||
        connector?.authorization?.type !== "OAuthPluginVault" || !connector.authorization.referenceId ||
        typeof connector.authorization.referenceId !== "string") {
      fail("Expected an app ID and exactly one remote connector with an OAuthPluginVault registration reference.");
      continue;
    }
    if (connector.mcpServerUrl !== profile.public_url || saved.baseUrl !== profile.public_url)
      fail("The package server URL, saved OAuth Base URL, and backend public_url must match exactly.");
    if (connector.authorization.referenceId !== saved.referenceId)
      fail("The package OAuth reference does not match the saved registration ID.");
    if (saved.clientId.toLowerCase() !== profile.client_id)
      fail("The saved OAuth client ID does not match the backend client_id.");
    if (!saved.scope.split(/[\s,]+/).includes("offline_access"))
      fail("The saved OAuth Scope is missing offline_access.");
    const tokenUrl = `https://login.microsoftonline.com/${profile.tenant_id}/oauth2/v2.0/token`;
    if (saved.tokenUrl !== tokenUrl || saved.refreshUrl !== tokenUrl)
      fail("The saved Token and Refresh endpoints must both match the backend tenant's Entra v2 token endpoint.");

    for (const [kind, value] of [
      ["app", manifest.id.toLowerCase()],
      ["endpoint", new URL(profile.public_url).href],
      ["registration", connector.authorization.referenceId],
    ]) {
      if (seen[kind].has(value)) fail(`Independent deployments reuse the same ${kind}.`);
      seen[kind].add(value);
    }
  }
  if (failures.length) throw new Error(failures.join("\n"));
  console.log(`Saved binding fields match for ${args.length / 3} deployment(s). Live route and token renewal not checked.`);
}

try { main(process.argv.slice(2)); }
catch (error) { console.error(error.message); process.exitCode = 1; }
