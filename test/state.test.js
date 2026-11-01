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
