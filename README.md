# ServiceNow MCP

Version **1.0.0**. A local ServiceNow MCP implementation with native GitHub
Copilot plugin packaging and a separate, restricted Cowork interface.

The native plugin includes record schema discovery and CRUD, exact user reads,
guarded administrative deletion, draft colors and existing PNG-logo bindings.
User lifecycle and new PNG imports additionally require operator-reviewed
source contracts. Managed nonprivileged groups/roles/assignments similarly
require reviewed account/access contracts. This is **not** a claim of all native
administrative tools or compatibility with every ServiceNow release.
See [capabilities](CAPABILITIES.md).

## GitHub Copilot app

Requires Node.js 24+, PowerShell7, an approved protected-credential provider,
and a GitHub Copilot app supporting Agent Plugins1.0 and stdio MCP. The adapter
does not download packages, enroll credentials, launch a browser or expose an
HTTP listener. The JavaScript backend uses only Node built-ins.

The native entrypoint reads an operator-approved, **nonsecret**
`connection.json` from the host-provided `PLUGIN_DATA` directory. Missing
configuration fails with that exact file path. Its closed format is:

```json
{
  "format": 1,
  "instance": "https://servicenow.example.invalid",
  "powershell_path": "<absolute approved pwsh executable path>",
  "powershell_sha256": "<approved executable SHA256>",
  "provider_module": "<absolute approved credential-provider .psm1 path>",
  "provider_sha256": "<approved provider SHA256>",
  "provider_getter": "Get-ServiceNowStoredCredential",
  "state_directory": "<absolute private directory outside the package and PLUGIN_DATA>"
}
```

The provider must export the fixed `Get-ServiceNowStoredCredential` function
and return `Instance`, `UserNameSecure` and `PasswordSecure`, with both values
as PowerShell `SecureString` objects. It must use an existing approved store;
no provider or stored credentials are bundled. The instance must match the
binding. This interface is not an arbitrary command or model-controlled tool.
Review the provider and executable identities before provisioning the binding;
hash changes fail closed rather than being accepted automatically.

The fixed adapter invokes the pinned provider, passes its values only in the
child Node process environment, then clears/disposes them. Credentials never
enter arguments, a JSON file or stdout. Raw provider errors are replaced with
bounded failure codes. It does not depend on inherited source variables.
On Windows it resolves the provider's LocalAppData location through the OS,
not through a guessed user path. The current protected demo provider is
Windows-specific; another platform needs an approved provider implementing
the same interface, not copied machine-bound store files.

**Actual desktop installation remains unverified.** Source-level synthetic
provider/stdio checks do not prove app installation, plugin-origin skill
selection or a real source call. The native app's marketplace/install action
and provisioning its actual `PLUGIN_DATA` binding require operator approval.

For a standalone backend launch, these explicit process environment entries
are the underlying interface; the native adapter supplies them privately:

| Variable | Value |
|---|---|
| `SERVICENOW_INSTANCE` | Your HTTPS instance origin, without credentials or a path |
| `SERVICENOW_USERNAME` | Authorized source account |
| `SERVICENOW_PASSWORD` | Account secret; never put it in chat or plugin files |
| `SERVICENOW_MCP_DATA_DIR` | Absolute private state directory outside the checkout |

Use a source account with the least privileges needed for the intended actions.
The adapter does not grant source permissions or bypass ACLs. The operating
system must restrict the state directory to its operator; file modes alone
do not establish Windows ACL protection.

Once private configuration is supported and installation is approved, open
**Customize**, use the marketplace settings control beside the
marketplace dropdown, and add this repository's Git URL. Find
`servicenow-mcp` in `servicenow-community`, select **Install**, then confirm it
is enabled in **Installed**. The selected revision must contain root
`plugin.json`, `mcp.json`, `skills/` and `.github/plugin/marketplace.json`.
See [GitHub's app customization guide](https://docs.github.com/en/copilot/how-tos/github-copilot-app/customize-github-copilot-app).

The app starts `node` with `src/plugin.cjs`; its fixed PowerShell adapter starts
`src/stdio.cjs`. Missing binding or unavailable/pin-mismatched prerequisites fail
explicitly. Do not copy secrets into `mcp.json` or `connection.json`.
No install hook changes global configuration or starts another service.

Verify in a fresh conversation that `servicenow-portable` is the actual tool
registration and that skill-load events identify this plugin's paths. Existing
same-name personal or repository skills can shadow the packaged skills. A
parser check, `tools/list`, or a personal-skill invocation is not desktop
installation or source-operation proof. Do not disable other registrations
without their owner's approval.

## Cowork read-only process

The separate Cowork package lives in
[likamrat/servicenow-cowork-plugin](https://github.com/likamrat/servicenow-cowork-plugin).
Its versioned tool description consumes `contracts/cowork-tools.json`.
`src/server.js` serves exactly those four tools, never the administrative
registry.

Run `npm ci --ignore-scripts` in this checkout, supply the three source
environment variables above, and run `npm start`. The default endpoint is
`http://127.0.0.1:3002/mcp`; `PORT` can select another port. The process stays
attached to the terminal. It does not read `.env` files.

The HTTP interface implements Streamable HTTP initialization and JSON tool
responses, not legacy SSE. Searches select at most20 records updated in the
last six months. Incident query text is a literal title substring. Empty
results are distinct from source errors and do not prove instance-wide absence.

There is **no inbound HTTP authentication** in this restricted process.
Keep it on loopback. `MCP_ALLOWED_HOSTS` (exact hostnames without ports) and
`MCP_ALLOWED_ORIGINS` (exact HTTP(S) origins) are request checks, not
authentication. Any external relay requires separate exposure authorization
and access-control review. Never relay an administrative endpoint. This
repository neither creates a tunnel nor deploys cloud infrastructure.

## Private state and recovery

The stdio tools create an instance/principal-bound journal and guarded recovery
snapshots under `SERVICENOW_MCP_DATA_DIR`. They serialize operations across
processes sharing that directory and retain attempted UUIDs across restart.
They do not lock other tools or source writers. Use a distinct fresh
directory for another instance or account; the adapter refuses to adopt an
existing unbound journal. Do not reset or migrate another installation's state.

Optional `retained-user-ids.json` is a private JSON array of exact user IDs.
Existing holds are read on every operation; the current operator and observed
cascades into protected users remain protected even when the array is empty.
Do not remove holds merely to make deletion pass.

After an uncertain write, preserve the original operation ID and inspect
`local_operation_status` plus exact source reads. A new UUID is not replay
permission. Paired-style restoration uses the original snapshot and current
guards. Source version checks are preflight checks, **not atomic CAS**.

An interrupted process may leave `operation.lock`. Stop and establish the
owning process and its last source effects before any manual lock removal.
Do not delete journals or snapshots to repair a lock. Disabling/uninstalling
the plugin does not undo ServiceNow effects. The host may remove `PLUGIN_DATA`
on uninstall, so operation state is required outside that directory. Preserve
the nonsecret binding separately when needed; never delete private state to
make a fresh installation bypass an unresolved operation.

## Development and licensing

`npm run check` checks JavaScript syntax; `npm test` exercises the production
interfaces against synthetic sources. No tests require a real instance.
`npm run notices:check` verifies the dependency notices after `npm ci`.

Original project code is MIT. Upstream attribution is in [NOTICE](NOTICE);
source and dependency provenance is in [PROVENANCE.md](PROVENANCE.md).
Dependencies retain their own licenses, including ISC and BSD-3-Clause.
