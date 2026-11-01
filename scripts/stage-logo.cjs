const path = require("node:path");
const { configuration } = require("../src/configuration.cjs");
const { createState } = require("../src/admin/state.cjs");
const { createLogoStaging } = require("../src/admin/staging.cjs");

async function main() {
  const [sourcePath, expected_sha256, file_name, ...extra] = process.argv.slice(2);
  if (!sourcePath || !expected_sha256 || !file_name || extra.length)
    throw new Error("Usage: node scripts/stage-logo.cjs <absolute PNG path> <SHA256> <filename.png>");
  const config = configuration();
  const state = createState(config);
  const manifest = await state.run(() => createLogoStaging(path.join(config.directory, "staged-logos"))
    .stage({ sourcePath, expected_sha256, file_name }));
  process.stdout.write(JSON.stringify(manifest) + "\n");
}
main().catch(error => { process.stderr.write(error.message + "\n"); process.exitCode = 1; });
