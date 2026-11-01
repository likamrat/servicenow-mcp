const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const root = path.join(__dirname, "..");
for (const directory of ["src", "test", "scripts"]) {
  for (const file of fs.readdirSync(path.join(root, directory), { recursive: true })) {
    if (!/\.(?:js|cjs)$/.test(file)) continue;
    const result = spawnSync(process.execPath, ["--check", path.join(root, directory, file)], { stdio: "inherit" });
    if (result.status !== 0) process.exit(result.status || 1);
  }
}
