const { instanceOrigin } = require("../configuration.cjs");
const { createSource } = require("./source.cjs");
const { createState } = require("./state.cjs");
const { createRecords } = require("./records.cjs");
const { createDeletion } = require("./deletion.cjs");
const { tools: styleTools, createThemeStyleOperations } = require("./theme-style.cjs");
const { createLogoRestoreOperations } = require("./logo-restore.cjs");
const { validate } = require("./validate.cjs");
const path = require("node:path");
const { tools: accountTools, createUserAccountOperations } = require("./user-account.cjs");
const { tools: importTools, createLogoImportOperations, createLogoImportPolicy } = require("./logo-import.cjs");
const { createLogoStaging } = require("./staging.cjs");
const { reviewedContract } = require("./contracts.cjs");
const id = { type: "string", pattern: "^[a-f0-9]{32}$" };
const uuid = { type: "string", format: "uuid" };
const version = { type: "string", pattern: "^\\d+$" };
const object = properties => ({ type: "object", properties, required: Object.keys(properties), additionalProperties: false });
const userFields = ["sys_id", "sys_mod_count", "user_name", "first_name", "last_name", "title", "active", "locked_out", "notification"];
const extraTools = [
  { name: "local_admin_user_get", description: "Read one exact user with a fixed minimal profile/status projection. Does not expose credentials or establish lifecycle/delete permission.",
    annotations: { readOnlyHint: true }, inputSchema: object({ sys_id: id }) },
  { name: "local_operation_status", description: "Read this private instance/principal-bound journal for an operation UUID. Evidence only: does not clear holds, replay or authorize writes.",
    annotations: { readOnlyHint: true }, inputSchema: object({ operation_id: uuid }) },
  { name: "local_admin_set_branding_property", description: "Update only the existing documented Next Experience login-illustrations string property after exact name/value/version checks. Source readback is not visual UI proof.",
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false },
    inputSchema: object({ sys_id: id, operation_id: uuid, expected_mod_count: version,
      property_name: { type: "string", const: "glide.ui.polaris.login.show_illustrations" },
      expected_value: { type: "string", enum: ["true", "false"] }, value: { type: "string", enum: ["true", "false"] } }) },
];

function createAdmin(config) {
  const instance = instanceOrigin(config.instance);
  if (typeof config.username !== "string" || !config.username || /[\u0000-\u001f^]|javascript:/i.test(config.username))
    throw new Error("Invalid source principal.");
  const source = createSource({ ...config, instance });
  const state = createState({ ...config, instance });
  const records = createRecords({ source, state });
  const deletion = createDeletion({ source, state, principal: config.username });
  const dependencies = { ...source, ...state, principal: config.username, instance, directory: config.directory };
  const themes = createThemeStyleOperations(dependencies);
  const logos = createLogoRestoreOperations(dependencies);
  const conditional = [...accountTools.filter(tool => tool.name !== "local_admin_user_get"), ...importTools]
    .map(tool => ({ ...tool, description: "Requires an operator-reviewed source contract; unavailable until configured and matched. " + tool.description }));
  const tools = [...records.tools, ...deletion.tools, ...styleTools, ...logos.tools, ...extraTools, ...conditional];
  const routes = new Map([
    ...records.tools.map(tool => [tool.name, records.handle]),
    ...deletion.tools.map(tool => [tool.name, deletion.handle]),
    ...styleTools.map(tool => [tool.name, themes.handle]),
    ...logos.tools.map(tool => [tool.name, logos.handle]),
  ]);
  async function branding(args) {
    const read = async () => {
      const rows = await source.list("sys_properties", `sys_id=${args.sys_id}`, "sys_id,name,value,type,ignore_cache,sys_mod_count", 2);
      if (rows.length !== 1 || rows[0].sys_id !== args.sys_id || rows[0].name !== args.property_name || rows[0].type !== "string")
        throw new Error("Existing branding property identity or string metadata changed.");
      return rows[0];
    };
    const before = await read();
    if (before.value !== args.expected_value || before.sys_mod_count !== args.expected_mod_count) throw new Error("Branding value/version changed.");
    if (before.value === args.value) return { changed: false, record: before };
    if (state.unresolved("sys_properties", args.sys_id)) throw new Error("Earlier property outcome unresolved.");
    const meta = { action: "local_admin_set_branding_property", table: "sys_properties", sys_id: args.sys_id,
      operation_id: args.operation_id, before_value: before.value, desired_value: args.value };
    state.claim(args.operation_id, meta);
    let failure;
    try { await source.request("PATCH", "sys_properties", {}, { value: args.value }, args.sys_id); } catch (error) { failure = error; }
    try {
      if (failure?.diagnostic?.status === 401) throw failure;
      const after = await read();
      if (failure?.diagnostic?.status >= 400 && failure.diagnostic.status < 500 ||
          after.value !== args.value || after.ignore_cache !== before.ignore_cache)
        throw new Error("Branding change not confirmed or source rejected the change.");
      state.record({ ...meta, status: "confirmed", after_mod_count: after.sys_mod_count });
      return { changed: true, before, record: after, operation_id: args.operation_id,
        visualVerification: "Required separately on the actual source UI." };
    } catch (error) {
      state.record({ ...meta, status: "uncertain", reason: error.message, diagnostic: failure?.diagnostic });
      throw error;
    }
  }
  async function handle(name, args = {}) {
    const tool = tools.find(tool => tool.name === name);
    if (!tool) throw new Error("Operation not available in this portable build; consult its capability prerequisites.");
    validate(tool.inputSchema, args);
    return state.run(async () => {
      if (!tool.annotations.readOnlyHint && state.isAttempted(args.operation_id)) throw new Error("Operation UUID already attempted; no replay.");
      if (name === "local_admin_patch_theme_style_pair" && state.pendingTheme(args.theme_id))
        throw new Error("Earlier theme operation unresolved; reconcile or use its guarded restoration, not a new patch UUID.");
      if (routes.has(name)) {
        const result = await routes.get(name)(name, args);
        if (name === "local_admin_restore_theme_style_pair" && result.status === "confirmed")
          state.record({ operation_id: args.snapshot_id, status: "resolved_by_restore", restoration_operation_id: args.operation_id });
        return result;
      }
      if (accountTools.some(tool => tool.name === name) && name !== "local_admin_user_get") {
        if (!tool.annotations.readOnlyHint && state.unresolved("sys_user", args.sys_id))
          throw new Error("Earlier account/deletion outcome unresolved; no new UUID replay.");
        const policy = reviewedContract("account", state.directory, instance);
        policy.protectedIds = [...new Set([...policy.protectedIds, ...state.retainedIds()])];
        policy.protectedNames = [...new Set([...policy.protectedNames, "admin", "guest", "system"])];
        return createUserAccountOperations({ ...dependencies, policy }).handle(name, args);
      }
      if (importTools.some(tool => tool.name === name)) {
        const qualified = reviewedContract("image", state.directory, instance);
        return createLogoImportOperations({ ...dependencies,
          staging: createLogoStaging(path.join(state.directory, "staged-logos")), guards: logos.guards,
          checkPolicy: createLogoImportPolicy({ discover: records.discover, list: source.list, qualified }),
        }).handle(name, args);
      }
      if (name === "local_operation_status") return { operation_id: args.operation_id, entries: state.status(args.operation_id) };
      if (name === "local_admin_set_branding_property") return branding(args);
      const rows = await source.list("sys_user", `sys_id=${args.sys_id}`, userFields.join(","), 2);
      if (rows.length > 1 || rows.length && (rows[0].sys_id !== args.sys_id || userFields.some(field => !Object.hasOwn(rows[0], field))))
        throw new Error("Exact user identity or selected fields unavailable.");
      return { found: Boolean(rows.length), record: rows.length ? {
        ...Object.fromEntries(userFields.map(field => [field, rows[0][field]])),
        source_url: `${instance}/sys_user.do?sys_id=${args.sys_id}`,
      } : null };
    });
  }
  return { tools, handle };
}

module.exports = { createAdmin };
