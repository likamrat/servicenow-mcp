const fs = require("node:fs");
const path = require("node:path");
const root = path.join(__dirname, "..");
const lock = require("../package-lock.json");
const groups = new Map();
for (const [location, entry] of Object.entries(lock.packages).sort(([a], [b]) => a.localeCompare(b))) {
  if (!location) continue;
  const directory = path.join(root, ...location.split("/"));
  const files = fs.readdirSync(directory).filter(name => /^(?:licen[cs]e|copying|notice)(?:\.|$)/i.test(name)).sort();
  if (!files.length) throw new Error("Missing locked dependency license: " + location);
  const text = files.map(file => `${file}\n${fs.readFileSync(path.join(directory, file), "utf8").replace(/\r\n/g, "\n").trim()}`).join("\n\n");
  if (!groups.has(text)) groups.set(text, []);
  groups.get(text).push(`${location} ${entry.version} (${entry.license})`);
}
const output = "Third-party notices for the locked optional HTTP dependency closure.\n" +
  "These packages retain their own licenses; the project MIT license does not replace them.\n\n" +
  [...groups].map(([text, packages]) => packages.join("\n") + "\n\n" + text).join("\n\n" + "=".repeat(72) + "\n\n") + "\n";
const target = path.join(root, "THIRD_PARTY_NOTICES.txt");
if (process.argv.includes("--write")) fs.writeFileSync(target, output);
else if (fs.readFileSync(target, "utf8") !== output) throw new Error("Dependency notices differ from the installed locked packages.");
