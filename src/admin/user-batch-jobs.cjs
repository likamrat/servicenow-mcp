const fs = require("node:fs");
const path = require("node:path");
const { randomUUID, createHash } = require("node:crypto");
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const ITEM = /^[a-zA-Z0-9_-]{1,80}$/;

function createUserBatchJobs({ source, state, principal, kind }) {
  if (!["create", "delete"].includes(kind)) throw new Error("Unsupported user batch kind.");
  const directory = path.join(state.directory, `user-${kind}-batches`);
  const jobs = new Map();
  const callerHash = caller => createHash("sha256").update(caller).digest("hex");
  function file(batchId, suffix = "") {
    if (!UUID.test(batchId)) throw new Error("Invalid user batch identity.");
    return path.join(directory, `${batchId}${suffix}.json`);
  }
  function evidenceFile(batchId, itemKey) {
    if (!ITEM.test(itemKey)) throw new Error("Invalid user batch item identity.");
    return file(batchId, ".item." + itemKey);
  }
  function safeDirectory() {
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
    if (!fs.lstatSync(directory).isDirectory() || fs.lstatSync(directory).isSymbolicLink())
      throw new Error("Unsafe private bulk receipt directory.");
  }
  function save(destination, value, exclusive = false) {
    safeDirectory();
    const temporary = destination + "." + randomUUID() + ".tmp";
    const fd = fs.openSync(temporary, "wx", 0o600);
    try { fs.writeSync(fd, JSON.stringify(value)); fs.fsyncSync(fd); }
    finally { fs.closeSync(fd); }
    try {
      if (exclusive) {
        fs.linkSync(temporary, destination);
        fs.unlinkSync(temporary);
      } else {
        if (fs.existsSync(destination) && (!fs.lstatSync(destination).isFile() || fs.lstatSync(destination).isSymbolicLink()))
          throw new Error("Unsafe private bulk receipt.");
        fs.renameSync(temporary, destination);
      }
    } finally { if (fs.existsSync(temporary)) fs.unlinkSync(temporary); }
  }
  function read(destination) {
    if (!fs.existsSync(destination)) throw new Error("Bulk receipt not available.");
    if (fs.lstatSync(directory).isSymbolicLink()) throw new Error("Unsafe private bulk receipt directory.");
    const info = fs.lstatSync(destination);
    if (!info.isFile() || info.isSymbolicLink() || info.size > 64 * 1024 * 1024)
      throw new Error("Unsafe or oversized private bulk receipt.");
    return JSON.parse(fs.readFileSync(destination, "utf8"));
  }
  function create(batchId, caller, values) {
    const batch = { ...values, format: 1, instance: source.instance, principal, caller_hash: callerHash(caller),
      batch_id: batchId, created_at: new Date().toISOString() };
    save(file(batchId), batch, true);
    return batch;
  }
  function owned(batchId, caller) {
    const batch = read(file(batchId));
    if (batch.format !== 1 || batch.batch_id !== batchId || batch.instance !== source.instance ||
        batch.principal !== principal || batch.caller_hash !== callerHash(caller))
      throw new Error("Bulk receipt not available to this caller/instance/principal.");
    return batch;
  }
  function persist(batch) {
    batch.updated_at = new Date().toISOString();
    save(file(batch.batch_id), batch);
  }
  function launch(batch, phase, action, failurePhase) {
    if (![phase, failurePhase].every(value => typeof value === "string" && /^[a-z][a-z0-9_]{0,63}$/.test(value)) ||
        typeof action !== "function")
      throw new Error("Explicit user batch run/failure phases and action are required.");
    const job = {};
    if (jobs.has(batch.batch_id)) throw new Error("User batch already running in this process.");
    jobs.set(batch.batch_id, job);
    setImmediate(() => {
      state.run(async () => {
        batch.phase = phase;
        persist(batch);
        await action();
        if (jobs.get(batch.batch_id) === job) jobs.delete(batch.batch_id);
      }).catch(error => {
        batch.phase = failurePhase;
        batch.error = { message: error.message, diagnostic: error.diagnostic, outcome: error.outcome };
        try { persist(batch); }
        catch (receiptError) {
          job.failure = receiptError.message;
          process.stderr.write("Bulk receipt persistence failed; preserve the shared journal and do not replay.\n");
        }
      }).finally(() => {
        if (!job.failure && jobs.get(batch.batch_id) === job) jobs.delete(batch.batch_id);
      });
    });
  }
  return {
    create, owned, persist, launch,
    saveEvidence: (batchId, itemKey, evidence) => save(evidenceFile(batchId, itemKey), evidence),
    readEvidence: (batchId, itemKey) => read(evidenceFile(batchId, itemKey)),
    stopRequested: batch => fs.existsSync(file(batch.batch_id, ".stop")),
    requestStop: batch => save(file(batch.batch_id, ".stop"), { requested_at: new Date().toISOString() }),
    observation: batch => ({ execution_observation: jobs.has(batch.batch_id) ?
      "owned_running_process" : "another_process_or_interrupted_do_not_replay",
    process_error: jobs.get(batch.batch_id)?.failure }),
  };
}
module.exports = { createUserBatchJobs };
