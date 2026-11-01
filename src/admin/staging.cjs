const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { inspectPng } = require("./png.cjs");
const { instanceOrigin } = require("../configuration.cjs");

function readBounded(file, limit) {
  for (let current = path.resolve(file); ; current = path.dirname(current)) {
    if (fs.existsSync(current) && fs.lstatSync(current).isSymbolicLink()) throw new Error("Logo paths cannot traverse links.");
    if (current === path.dirname(current)) break;
  }
  const fd = fs.openSync(file, "r");
  try {
    const before = fs.fstatSync(fd);
    if (!before.isFile() || before.size <= 0 || before.size >= limit) throw new Error("Invalid logo file size or type.");
    const buffer = Buffer.alloc(limit);
    let length = 0;
    while (length < limit) {
      const count = fs.readSync(fd, buffer, length, limit - length, null);
      if (!count) break;
      length += count;
    }
    const after = fs.fstatSync(fd);
    if (length >= limit || length !== before.size || after.size !== before.size || after.mtimeMs !== before.mtimeMs)
      throw new Error("Logo file changed while reading.");
    return buffer.subarray(0, length);
  } finally { fs.closeSync(fd); }
}
function filename(value) {
  if (typeof value !== "string" || !/^[a-zA-Z0-9][a-zA-Z0-9._ -]{0,100}\.png$/i.test(value) ||
      /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(value)) throw new Error("Invalid PNG filename.");
  return value;
}
function write(file, value) {
  const fd = fs.openSync(file, "wx", 0o600);
  try { fs.writeSync(fd, value); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}
function createLogoStaging(directory) {
  return {
    stage({ sourcePath, expected_sha256, file_name }) {
      if (!path.isAbsolute(sourcePath) || !/^[a-f0-9]{64}$/.test(expected_sha256)) throw new Error("Absolute source path and exact SHA256 required.");
      const bytes = readBounded(sourcePath, 120000);
      const actual = inspectPng(bytes);
      if (actual.sha256 !== expected_sha256) throw new Error("Logo hash mismatch.");
      const staging_id = crypto.randomUUID();
      const manifest = { version: 1, staging_id, file_name: filename(file_name), ...actual };
      fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
      write(path.join(directory, `${staging_id}.png`), bytes);
      write(path.join(directory, `${staging_id}.json`), JSON.stringify(manifest));
      return manifest;
    },
    readVerified({ staging_id, expected_sha256 }) {
      if (!/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(staging_id) ||
          !/^[a-f0-9]{64}$/.test(expected_sha256)) throw new Error("Invalid immutable staging reference.");
      const manifest = JSON.parse(readBounded(path.join(directory, `${staging_id}.json`), 4096).toString("utf8"));
      if (manifest.version !== 1 || manifest.staging_id !== staging_id || manifest.sha256 !== expected_sha256)
        throw new Error("Staging manifest mismatch.");
      filename(manifest.file_name);
      const bytes = readBounded(path.join(directory, `${staging_id}.png`), 120000);
      const actual = inspectPng(bytes);
      for (const key of Object.keys(actual)) if (actual[key] !== manifest[key]) throw new Error("Staged bytes changed.");
      return { manifest, bytes };
    },
  };
}
function prepareAttachmentRequest({ instance, staging, staging_id, expected_sha256, target_table, target_sys_id, file_name, qualifiedTargetTables }) {
  if (target_table !== "sys_ux_theme_asset" || !qualifiedTargetTables?.includes(target_table) || !/^[a-f0-9]{32}$/.test(target_sys_id))
    throw new Error("Unqualified image attachment target.");
  const { manifest, bytes } = staging.readVerified({ staging_id, expected_sha256 });
  const remoteName = filename(file_name ?? manifest.file_name);
  const query = new URLSearchParams({ table_name: target_table, table_sys_id: target_sys_id, file_name: remoteName });
  return { url: `${instanceOrigin(instance)}/api/now/attachment/file?${query}`, method: "POST", body: bytes,
    staged: manifest, file_name: remoteName };
}

module.exports = { createLogoStaging, prepareAttachmentRequest };
