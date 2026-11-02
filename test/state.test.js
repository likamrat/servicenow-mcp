const assert = require("node:assert/strict");
const { test } = require("node:test");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { createState } = require("../src/admin/state.cjs");

test("private state refuses overlapping owners, rebinding and unbound historical journals", async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "servicenow-state-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const config = { directory, instance: "https://service.example.invalid", username: "operator" };
  const state = createState(config), second = createState(config);
  let release;
  const held = state.run(() => new Promise(resolve => { release = resolve; }));
  await assert.rejects(second.run(async () => {}), /another operation/);
  release();
  await held;
  await second.run(async () => {});
  await assert.rejects(createState({ ...config, username: "different" }).run(async () => {}), /another instance or principal/);
  const legacy = path.join(directory, "legacy");
  fs.mkdirSync(legacy);
  fs.writeFileSync(path.join(legacy, "operations.jsonl"), '{"status":"attempt"}\n');
  await assert.rejects(createState({ ...config, directory: legacy }).run(async () => {}), /Unbound nonempty/);
  assert.equal(fs.readFileSync(path.join(legacy, "operations.jsonl"), "utf8"), '{"status":"attempt"}\n');
});

test("one state instance queues callers without swallowing errors or bypassing consumed operation guards", { timeout: 10000 }, async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "servicenow-state-queue-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const state = createState({ directory, instance: "https://service.example.invalid", username: "operator" });
  const entered = Promise.withResolvers(), release = Promise.withResolvers();
  const order = [];
  const operation_id = "11111111-1111-4111-8111-111111111111";
  const first = state.run(async () => {
    order.push("first");
    state.claim(operation_id, { table: "incident", sys_id: "a".repeat(32) });
    entered.resolve();
    await release.promise;
    throw new Error("Original uncertain source failure");
  });
  const firstError = assert.rejects(first, /Original uncertain source failure/);
  await entered.promise;
  const replay = state.run(async () => {
    order.push("replay");
    state.claim(operation_id, { table: "incident", sys_id: "a".repeat(32) });
  });
  const replayError = assert.rejects(replay, /already attempted/);
  const observation = state.run(async () => {
    order.push("observation");
    assert.equal(state.unresolved("incident", "a".repeat(32)), true);
    return state.status(operation_id);
  });
  assert.deepEqual(order, ["first"]);
  release.resolve();
  await Promise.all([firstError, replayError]);
  const outcome = await observation;
  assert.deepEqual(order, ["first", "replay", "observation"]);
  assert.equal(outcome.entries.length, 1);
  assert.equal(outcome.entries[0].status, "attempt");
  assert.equal(fs.existsSync(path.join(directory, "operation.lock")), false);
});
