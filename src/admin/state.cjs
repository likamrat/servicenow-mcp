const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

function createState({ directory, instance, username }) {
  const root = path.resolve(__dirname, "..", "..");
  if (!path.isAbsolute(directory)) throw new Error("Private state directory must be absolute.");
  directory = path.resolve(directory);
  const relative = path.relative(root, directory);
  if (relative === "" || (!relative.startsWith(".." + path.sep) && relative !== ".." && !path.isAbsolute(relative)))
    throw new Error("Keep private state outside the distributable checkout.");
  for (let current = directory; ; current = path.dirname(current)) {
    if (fs.existsSync(current) && fs.lstatSync(current).isSymbolicLink())
      throw new Error("Private state must not traverse symlinks or junctions.");
    if (current === path.dirname(current)) break;
  }
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  const journal = path.join(directory, "operations.jsonl");
  const lock = path.join(directory, "operation.lock");
  const binding = { format: 1, instance, principal: username };
  let entries = [];
  function append(entry) {
    const row = { at: new Date().toISOString(), ...entry };
    const fd = fs.openSync(journal, "a", 0o600);
    try { fs.writeSync(fd, JSON.stringify(row) + "\n"); fs.fsyncSync(fd); }
    finally { fs.closeSync(fd); }
    entries.push(row);
  }
  function attempted(id) { return entries.some(row => row.operation_id === id && row.status === "attempt"); }
  function claim(id, meta) {
    if (attempted(id)) throw new Error("Operation UUID already attempted; reconcile without replay.");
    append({ ...meta, operation_id: id, status: "attempt" });
  }
  async function run(action) {
    let fd;
    try { fd = fs.openSync(lock, "wx", 0o600); }
    catch (error) {
      if (error.code === "EEXIST") throw new Error("Private state is owned by another operation or an interrupted process. Do not remove its lock until the owner and pending source effects are reconciled.");
      throw error;
    }
    try {
      fs.writeSync(fd, JSON.stringify({ pid: process.pid, nonce: crypto.randomUUID(), instance }));
      fs.fsyncSync(fd);
      const identity = path.join(directory, "binding.json");
      if (!fs.existsSync(identity)) {
        const freshFiles = ["operation.lock", "account-contract.json", "image-contract.json", "access-contract.json",
          "cowork-profile.json", "retained-user-ids.json"];
        if (fs.readdirSync(directory).some(file => !freshFiles.includes(file)))
          throw new Error("Unbound nonempty state directory; do not adopt or reset existing state.");
        const file = fs.openSync(identity, "wx", 0o600);
        try { fs.writeSync(file, JSON.stringify(binding)); fs.fsyncSync(file); } finally { fs.closeSync(file); }
      }
      let saved;
      try { saved = JSON.parse(fs.readFileSync(identity, "utf8")); }
      catch { throw new Error("Private state binding is invalid; preserve it for operator recovery."); }
      if (saved.format !== binding.format || saved.instance !== instance || saved.principal !== username)
        throw new Error("Private state belongs to another instance or principal.");
      try { entries = fs.existsSync(journal) ? fs.readFileSync(journal, "utf8").split("\n").filter(Boolean).map(JSON.parse) : []; }
      catch { throw new Error("Private operation journal is invalid; preserve it for operator recovery."); }
      if (entries.some(entry => !entry || typeof entry !== "object" || Array.isArray(entry) ||
          typeof entry.operation_id !== "string" || typeof entry.status !== "string"))
        throw new Error("Private operation journal contains an invalid entry; no operation dispatched.");
      return await action();
    } finally {
      fs.closeSync(fd);
      fs.unlinkSync(lock);
    }
  }
  function retainedIds() {
    const file = path.join(directory, "retained-user-ids.json");
    const ids = fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, "utf8")) : [];
    if (!Array.isArray(ids) || ids.some(id => typeof id !== "string" || !/^[a-f0-9]{32}$/.test(id)))
      throw new Error("Invalid private user retention holds.");
    return ids;
  }
  function unresolved(table, id) {
    const candidates = entries.filter(row => row.status === "attempt" && row.table === table &&
      (id ? entries.some(entry => entry.operation_id === row.operation_id && entry.sys_id === id) : !row.sys_id));
    return candidates.some(row => {
      const last = entries.filter(entry => entry.operation_id === row.operation_id).at(-1);
      return !["confirmed", "rejected_source_acl", "no_change"].includes(last.status);
    });
  }
  function pendingTheme(themeId) {
    return entries.filter(row => row.status === "attempt" && row.theme_id === themeId).some(row =>
      !["confirmed", "resolved_by_restore", "no_change", "rejected"].includes(
        entries.filter(entry => entry.operation_id === row.operation_id).at(-1).status));
  }
  function status(id) {
    const receipts = [];
    for (const [folder, suffix] of [
      ["user-account-v2-receipts", ".operation.json"],
      ["theme-style-receipts", ".operation.json"],
      ["modern-logo-restore-receipts", ".json"],
      ["logo-import-receipts", ".json"],
      ["access-operation-receipts", ".operation.json"],
      ["definition-operation-receipts", ".json"],
    ]) {
      const file = path.join(directory, folder, id + suffix);
      if (!fs.existsSync(file)) continue;
      const info = fs.lstatSync(file);
      if (info.isSymbolicLink() || !info.isFile() || info.size > 32 * 1024 * 1024)
        throw new Error("Unsafe or oversized private operation receipt.");
      receipts.push({ kind: folder, outcome: JSON.parse(fs.readFileSync(file, "utf8")) });
    }
    return { operation_id: id, entries: entries.filter(row => row.operation_id === id), receipts };
  }
  return { directory, run, record: append, claim, isAttempted: attempted, retainedIds, unresolved, pendingTheme,
    status, events: id => structuredClone(entries.filter(row => row.operation_id === id)) };
}

module.exports = { createState };
