const path = require("node:path");
const { configuration } = require("./configuration.cjs");
const { createAdmin } = require("./admin/index.cjs");
const { createEntraVerifier } = require("./cowork-auth.cjs");
const { loadProfile, createCoworkApp } = require("./cowork-http.cjs");

async function main() {
  const config = configuration();
  const profile = loadProfile(path.join(config.directory, "cowork-profile.json"));
  if (profile.instance !== config.instance) throw new Error("Cowork configuration and protected source origin differ.");
  const backend = createAdmin(config);
  const verifyAccessToken = await createEntraVerifier(profile);
  const port = profile.port ?? 3003;
  const server = createCoworkApp({ profile, backend, verifyAccessToken }).listen(port, "127.0.0.1", () => {
    console.log(JSON.stringify({ event: "cowork-listening", pid: process.pid, host: "127.0.0.1",
      port, path: "/mcp", writes_enabled: profile.writes_enabled }));
  });
  server.on("error", error => {
    console.error(`Cowork listener failed (${error.code || "LISTENER_ERROR"}); no alternative port selected.`);
    process.exitCode = 1;
  });
}
if (require.main === module) main().catch(error => { console.error(error.message); process.exitCode = 1; });
module.exports = { main };
