const { tools } = require("../src/cowork-http.cjs");
const fs = require("node:fs");
const path = require("node:path");
const output = JSON.stringify({ tools }, null, 2) + "\n";
const target = path.join(__dirname, "..", "contracts", "cowork-authenticated-tools.json");
if (process.argv.includes("--write")) fs.writeFileSync(target, output);
else if (process.argv.includes("--check")) {
  if (fs.readFileSync(target, "utf8").replace(/\r\n/g, "\n") !== output)
    throw new Error("Generated authenticated Cowork contract differs from runtime tools.");
} else process.stdout.write(output);
