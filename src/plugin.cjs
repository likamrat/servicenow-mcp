const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { spawn } = require("node:child_process");
const { instanceOrigin } = require("./configuration.cjs");

function regularFile(file) {
  if (typeof file !== "string" || !path.isAbsolute(file)) throw new Error("Binding paths must be absolute.");
  if (!fs.lstatSync(file).isFile() || fs.lstatSync(file).isSymbolicLink())
    throw new Error("Binding executable/provider paths must identify regular files.");
  return fs.realpathSync(file);
}
function inside(root, file) {
  const relative = path.relative(root, file);
  return relative === "" || relative !== ".." && !relative.startsWith(".." + path.sep) && !path.isAbsolute(relative);
}
function loadBinding(dataDirectory) {
  if (!dataDirectory || !path.isAbsolute(dataDirectory)) throw new Error("This plugin requires the host-provided PLUGIN_DATA directory.");
  const directory = fs.realpathSync(dataDirectory);
  const file = path.join(directory, "connection.json");
  if (!fs.existsSync(file)) throw new Error(`Missing operator-approved nonsecret binding: ${file}`);
  const info = fs.lstatSync(file);
  if (!info.isFile() || info.isSymbolicLink() || info.size > 16384 ||
      process.platform !== "win32" && (info.mode & 0o022))
    throw new Error("Connection binding must be a bounded, operator-controlled regular file.");
  const bytes = fs.readFileSync(file);
  let binding;
  try { binding = JSON.parse(bytes.toString("utf8")); }
  catch { throw new Error("Connection binding is not valid JSON; no file content was emitted."); }
  const keys = ["format", "instance", "powershell_path", "powershell_sha256", "provider_module", "provider_sha256", "provider_getter", "state_directory"];
  if (!binding || typeof binding !== "object" || Array.isArray(binding) ||
      Object.keys(binding).length !== keys.length || keys.some(key => !Object.hasOwn(binding, key)) ||
      binding.format !== 1 || binding.provider_getter !== "Get-ServiceNowStoredCredential" ||
      [binding.provider_sha256, binding.powershell_sha256].some(hash => typeof hash !== "string" || !/^[a-f0-9]{64}$/.test(hash)))
    throw new Error("Invalid nonsecret connection binding; credentials and arbitrary commands are not supported fields.");
  if (instanceOrigin(binding.instance) !== binding.instance) throw new Error("Binding instance must be a canonical origin.");
  const powershell = regularFile(binding.powershell_path);
  const provider = regularFile(binding.provider_module);
  if (!/^pwsh(?:\.exe)?$/i.test(path.basename(powershell)) || !/\.psm1$/i.test(provider))
    throw new Error("Binding requires an approved PowerShell executable and credential-provider module.");
  if (/[*?\[\]]/.test(binding.provider_module) || /[*?\[\]]/.test(provider))
    throw new Error("Provider module paths must not contain PowerShell wildcard syntax.");
  if (crypto.createHash("sha256").update(fs.readFileSync(powershell)).digest("hex") !== binding.powershell_sha256)
    throw new Error("Approved PowerShell executable changed; review its identity before updating the binding.");
  if (crypto.createHash("sha256").update(fs.readFileSync(provider)).digest("hex") !== binding.provider_sha256)
    throw new Error("Approved provider module changed; review its identity before updating the binding.");
  if (typeof binding.state_directory !== "string" || !path.isAbsolute(binding.state_directory) ||
      inside(path.resolve(__dirname, ".."), path.resolve(binding.state_directory)) ||
      inside(directory, path.resolve(binding.state_directory)))
    throw new Error("Operation state must remain outside both the plugin package and its uninstallable PLUGIN_DATA directory.");
  return { file, powershell, hash: crypto.createHash("sha256").update(bytes).digest("hex"),
    instance: binding.instance, stateDirectory: binding.state_directory };
}
function launchProtected(binding, mode) {
  const entrypoints = { stdio: "stdio.cjs", cowork: "cowork-server.cjs" };
  if (!Object.hasOwn(entrypoints, mode)) throw new Error("Unsupported protected server entrypoint.");
  // PowerShell needs .EXE recognition even when native command paths are absolute.
  const child = spawn(binding.powershell, [
    "-NoLogo", "-NoProfile", "-NonInteractive", "-File", path.join(__dirname, "..", "scripts", "start-stdio.ps1"),
    "-BindingPath", binding.file, "-BindingSHA256", binding.hash,
    "-NodePath", process.execPath, "-ServerPath", path.join(__dirname, entrypoints[mode]),
  ], { env: process.platform === "win32" ? { PATHEXT: ".EXE" } : {}, stdio: "inherit", windowsHide: true });
  child.on("error", () => { process.stderr.write("Unable to start the approved PowerShell adapter.\n"); process.exitCode = 1; });
  child.on("exit", code => { process.exitCode = code ?? 1; });
  for (const signal of ["SIGINT", "SIGTERM"]) process.on(signal, () => child.kill(signal));
  return child;
}
function main() {
  launchProtected(loadBinding(process.env.PLUGIN_DATA), "stdio");
}
if (require.main === module) {
  try { main(); } catch (error) { process.stderr.write(error.message + "\n"); process.exitCode = 1; }
}
module.exports = { loadBinding, launchProtected };
