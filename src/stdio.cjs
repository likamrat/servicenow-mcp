const { configuration } = require("./configuration.cjs");
const { createAdmin } = require("./admin/index.cjs");
const { createInterface } = require("node:readline");

async function main() {
  const admin = createAdmin(configuration());
  const tools = admin.tools;
  const write = response => process.stdout.write(JSON.stringify(response) + "\n");
  async function dispatch(message) {
    const { id, method, params } = message || {};
    if (!message || Array.isArray(message) || message.jsonrpc !== "2.0" || typeof method !== "string" ||
        id !== undefined && typeof id !== "string" && typeof id !== "number") {
      write({ jsonrpc: "2.0", id: id ?? null, error: { code: -32600, message: "Invalid request." } });
      return;
    }
    if (id === undefined) return;
    let result;
    if (method === "initialize") result = {
      protocolVersion: "2025-03-26", capabilities: { tools: {} },
      serverInfo: { name: "servicenow-mcp", version: "1.0.0" },
    };
    else if (method === "ping") result = {};
    else if (method === "tools/list") result = { tools };
    else if (method === "tools/call") {
      try {
        const name = params?.name;
        const args = params?.arguments === undefined ? {} : params.arguments;
        const value = await admin.handle(name, args);
        result = { content: [{ type: "text", text: JSON.stringify(value) }] };
      } catch (error) {
        result = { isError: true, content: [{ type: "text", text: JSON.stringify({
          error: error.message, diagnostic: error.diagnostic, outcome: error.outcome,
        }) }] };
      }
    } else {
      write({ jsonrpc: "2.0", id, error: { code: -32601, message: "Method not found." } });
      return;
    }
    write({ jsonrpc: "2.0", id, result });
  }
  let pendingBytes = 0;
  process.stdin.on("data", chunk => {
    pendingBytes += Buffer.byteLength(chunk);
    if (pendingBytes > 2 * 1024 * 1024) {
      process.stderr.write("MCP input exceeds the supported size.\n");
      process.exitCode = 1;
      process.stdin.destroy();
    }
  });
  const input = createInterface({ input: process.stdin, crlfDelay: Infinity });
  for await (const line of input) {
    pendingBytes = 0;
    if (Buffer.byteLength(line) > 2 * 1024 * 1024) throw new Error("MCP request exceeds the supported size.");
    let message;
    try { message = JSON.parse(line); }
    catch { write({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Invalid JSON." } }); continue; }
    await dispatch(message);
  }
}

if (require.main === module) main().catch(error => {
  process.stderr.write(error.message + "\n");
  process.exitCode = 1;
});

module.exports = { main };
