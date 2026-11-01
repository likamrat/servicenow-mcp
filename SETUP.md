# Setup

Choose the connection for your client:

- [GitHub Copilot app](#github-copilot-app): packaged skills and stdio tools.
- [Other MCP clients](#other-mcp-clients): launch the Node.js stdio server.
- [Microsoft Copilot Cowork](#cowork-read-only-server): operate the restricted HTTP server.

Use Node.js 24+ and a ServiceNow account with the permissions needed for your
work. Administrative tools also read dictionary, choice and policy metadata.
Additional source-policy requirements are listed in [CAPABILITIES.md](CAPABILITIES.md).

## GitHub Copilot app

The plugin requires an app that supports Agent Plugins 1.0 and stdio MCP,
PowerShell 7, and a provider implementing the [credential interface](#credential-provider).

1. In **Customize**, open the marketplace settings control and add
   `https://github.com/likamrat/servicenow-mcp`.
2. Install **servicenow-mcp** from **servicenow-community** and enable it in
   **Installed**.
3. Configure `connection.json` as described below, then start a fresh conversation.

These are the app's documented
[marketplace and plugin controls](https://docs.github.com/en/copilot/how-tos/github-copilot-app/customize-github-copilot-app#adding-plugins).

### Connection file

The app supplies a private `PLUGIN_DATA` directory. On first start, the server
reports the exact path of its missing `connection.json`. Create that file there;
do not guess the plugin's data path or place the file in the source checkout.

Replace the placeholders with absolute paths and lowercase SHA256 hashes:

```json
{
  "format": 1,
  "instance": "https://your-instance.service-now.com",
  "powershell_path": "<absolute path to pwsh or pwsh.exe>",
  "powershell_sha256": "<SHA256 of that executable>",
  "provider_module": "<absolute path to your credential-provider .psm1>",
  "provider_sha256": "<SHA256 of that module>",
  "provider_getter": "Get-ServiceNowStoredCredential",
  "state_directory": "<absolute private operation-state directory>"
}
```

This file contains paths and identities, not credentials. The state directory
must be outside both the checkout and `PLUGIN_DATA`, which the app may remove
on uninstall. Restrict the binding, provider and state directory to the operator
using operating-system permissions, including Windows ACLs where applicable.

Review the executable and provider before recording their hashes. For a known
file, PowerShell can calculate its hash without executing it:

```powershell
(Get-FileHash -LiteralPath '<absolute file path>' -Algorithm SHA256).Hash.ToLowerInvariant()
```

The plugin refuses changed hashes. Review an update before changing a pin;
do not automatically accept whichever executable or module is present.

### Credential provider

Use an existing credential-manager adapter; no provider or secret store is
bundled. Its `.psm1` module must export `Get-ServiceNowStoredCredential` and
return one object with these fields:

| Field | Type | Requirement |
|---|---|---|
| `Instance` | String | Matches the configured HTTPS origin exactly. |
| `UserNameSecure` | PowerShell `SecureString` | The source account name. |
| `PasswordSecure` | PowerShell `SecureString` | The source account password. |

The fixed launcher calls that getter and passes the credentials to the Node.js
child in memory. Credentials are not passed in arguments or written to
`connection.json`. Provider failures return bounded error codes.

A Windows DPAPI provider is tied to its owning Windows account. Other platforms
need a provider backed by their own credential manager. If no provider is
available, use the [direct stdio interface](#other-mcp-clients) with a client's
supported secret configuration instead.

### Check the connection

In a fresh conversation, select the `servicenow-portable` connection and request
a read-only incident search, such as “Find recent ServiceNow incidents about VPN.”
An empty list is a valid result; an unavailable tool or authentication error is not.

The packaged skills are `servicenow-operations` and `servicenow-themes`.
Existing personal or repository copies can take precedence, so check the loaded
skill's path when diagnosing an unexpected selection.

## Other MCP clients

Clone the server:

```sh
git clone https://github.com/likamrat/servicenow-mcp.git
cd servicenow-mcp
```

Configure a **stdio** server in your client:

| Setting | Value |
|---|---|
| Command | `node` |
| Arguments | The absolute path to this checkout's `src/stdio.cjs` |

Supply these environment entries explicitly through the client's supported
configuration and secret-input mechanism:

| Variable | Value |
|---|---|
| `SERVICENOW_INSTANCE` | HTTPS instance origin, without credentials, path, query or fragment. |
| `SERVICENOW_USERNAME` | Authorized source account. |
| `SERVICENOW_PASSWORD` | Password from your credential manager. |
| `SERVICENOW_MCP_DATA_DIR` | Absolute private state directory outside the checkout. |

The stdio backend uses Node built-ins; it needs no npm dependencies. It does not
load `.env` files. Keep private client configuration and credentials outside the
repository. For an explicitly configured terminal process, the same entrypoint
is available as `npm run start:stdio`.

## Cowork read-only server

From this checkout, set the three `SERVICENOW_INSTANCE`, `SERVICENOW_USERNAME`
and `SERVICENOW_PASSWORD` environment entries above, then run:

```sh
npm ci --ignore-scripts
npm start
```

The server listens at `http://127.0.0.1:3002/mcp` and stays attached to the
terminal. Stop it with Ctrl+C. It uses Streamable HTTP, not legacy SSE, and
exposes only the four incident/change lookup tools. It has no operation journal.

| Optional variable | Meaning |
|---|---|
| `PORT` | Listening port; defaults to `3002`. |
| `MCP_ALLOWED_HOSTS` | Comma-separated additional exact hostnames, without schemes or ports. |
| `MCP_ALLOWED_ORIGINS` | Comma-separated exact HTTP(S) origins, without paths. Browser origins are rejected by default. |

**This endpoint has no client authentication.** Host/origin checks are not
authentication. Keep it on loopback; an externally reachable endpoint needs
deliberate access restrictions. Anyone able to reach it can use the configured
account's read access.

Follow the companion
[Cowork setup guide](https://github.com/likamrat/servicenow-cowork-plugin/blob/main/SETUP.md)
to configure its HTTPS connection and install the client package. Use this
read-only entrypoint, not an administrative service.

## Operation state and recovery

The stdio server keeps instance/account-bound journals and restoration snapshots
in its private state directory. Processes sharing that directory serialize their
operations; this does not lock other tools or ServiceNow writers. Source version
checks are preflight checks, not atomic compare-and-swap.

| Situation | Action |
|---|---|
| A write times out or returns an uncertain outcome | Inspect `local_operation_status` and exact source records. Do not resend with the same or a new operation ID. |
| A paired-style change is partial | Use its original snapshot and current guards for an authorized restoration. |
| `operation.lock` remains after interruption | Establish the owning process and its last source effects before removing the lock. Preserve the journal. |
| The instance or source account changes | Use a separate state directory; do not rebind an existing journal. |
| Users must be retained | Maintain their exact IDs in the private `retained-user-ids.json` array. The operator is protected independently. |
| The plugin is uninstalled | Preserve the external state directory. Uninstalling does not undo ServiceNow changes or resolve pending operations. |

Place reviewed account, access and image policy files in the same private
directory. See [source-policy configuration](CAPABILITIES.md#source-policy-configuration)
for their formats and the operations that require them.
