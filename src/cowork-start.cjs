const path = require("node:path");
const { loadBinding, launchProtected } = require("./plugin.cjs");
const { loadProfile } = require("./cowork-http.cjs");

function main() {
  if (process.argv.length !== 3) throw new Error("Usage: node src/cowork-start.cjs <absolute directory containing connection.json>");
  const binding = loadBinding(process.argv[2]);
  const profile = loadProfile(path.join(binding.stateDirectory, "cowork-profile.json"));
  if (profile.instance !== binding.instance) throw new Error("Cowork configuration and protected binding source origins differ.");
  launchProtected(binding, "cowork");
}
if (require.main === module) {
  try { main(); } catch (error) { console.error(error.message); process.exitCode = 1; }
}
module.exports = { main };
