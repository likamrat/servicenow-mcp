# Setup

Choose the connection for your client:

- [GitHub Copilot app](#github-copilot-app): packaged skills and stdio tools.
- [Other MCP clients](#other-mcp-clients): launch the Node.js stdio server.
- [Microsoft Copilot Cowork](#cowork-authenticated-server): operate the authenticated restricted HTTP interface.

Use Node.js 24+ and a ServiceNow account with the permissions needed for your
work. Administrative tools also read dictionary, choice and policy metadata.
Additional source-policy requirements are listed in [CAPABILITIES.md](CAPABILITIES.md).

## GitHub Copilot app

The plugin requires an app that supports Agent Plugins 1.0 and stdio MCP,
PowerShell 7, and a provider implementing the [credential interface](#credential-provider).

1. Open **Add** > **Manage marketplaces** and register
   `https://github.com/likamrat/servicenow-mcp`.
2. Open **Add** > **Plugin**.
3. In **Name**, enter `servicenow-mcp@servicenow-community`, then select **Install**.
4. Configure `connection.json` as described below, then start a fresh conversation.

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

## Cowork authenticated server

Cowork uses one authenticated connector to the shared backend. It exposes the
four existing six-month incident/change reads plus incident schema discovery,
exact assignee resolution, create/update/delete and requester-owned operation
status. It does not expose generic table or account administration. The source
account, credentials and operation state use the existing protected binding
above; there is no separate assignment service or identity map.

The canonical generated tool contract is
[`contracts/cowork-authenticated-tools.json`](contracts/cowork-authenticated-tools.json).
Regenerate it with `npm run contract:cowork -- --write`; verify it with
`npm run contract:cowork -- --check`. Native stdio exposes the same incident
operations alongside its existing administrative tools.

### Incoming OAuth connection

Register or reuse an explicitly approved Entra resource API and OAuth client.
Do not substitute a Graph or Work IQ audience, an ID token, or an app-only
token. The protected resource verifies RS256, the tenant-specific v2 issuer,
expiry/not-before/issued-at, `tid`, exact resource application GUID `aud`,
authorized client application GUID `azp`, delegated `scp=Incident.Manage`, and
an immutable requester `oid`. It has no person or incident allowlist.

The resource API must issue v2 access tokens (`requestedAccessTokenVersion: 2`).
Request `api://<resource-application-id>/Incident.Manage` and the refresh scope
required by the client. Configure the client's approved callback and consent
through its supported registration flow. Cowork uses `OAuthPluginVault`; its
`referenceId` is the Microsoft token-store registration ID, not an Entra app ID.
Client secrets belong in the approved token store, never in this checkout or
the backend configuration.

Every `/mcp` request, including discovery of tools and reads, requires a valid
token. Unauthenticated resource metadata is available at
`/.well-known/oauth-protected-resource/mcp` and
`/.well-known/oauth-protected-resource`. The 401 challenge identifies that
metadata and the required scope. This server is a protected resource, not an
authorization server, dynamic client registrar or token store.

### Backend connection and launch

In the protected binding's external `state_directory`, create an
operator-controlled `cowork-profile.json`:

```json
{
  "format": 1,
  "instance": "https://your-instance.service-now.com",
  "public_url": "https://your-approved-mcp-host/mcp",
  "tenant_id": "<tenant GUID>",
  "audience": "<resource application GUID>",
  "client_id": "<authorized OAuth client application GUID>",
  "writes_enabled": false,
  "port": 3003
}
```

`instance` must match the existing binding. Optional `allowed_origins` contains
exact client HTTP(S) origins; browser origins are rejected by default. Keep the
profile outside the checkout. The backend does not create registrations,
consent, external routes or credentials.

```text
npm ci --ignore-scripts
npm run start:cowork -- "<absolute directory containing connection.json>"
```

The launcher verifies the existing executable/provider hashes and passes
credentials only in its child process environment. The backend binds to
`127.0.0.1` and reports its owned HTTP PID/port. Use only a separately approved
HTTPS route to this authenticated listener; never route to the legacy
administrative service or anonymous endpoint. Keep the launcher under an
owned process tree and stop that tree or the reported HTTP PID when finished.

Begin with `writes_enabled: false`, verify authenticated retrieval from the
installed Cowork client and qualify its real confirmation behavior. Enable
writes only under the operator's approved configuration and user-authorized
target/change scope. The switch and MCP annotations are not per-operation
user consent. A successful local test or tool listing is not installed
Cowork acceptance.

For assignment, read the incident/version, resolve the exact ServiceNow
identity, then call `update_incident` with only `values.assigned_to` and the
current `expected_mod_count`. `null` or `""` clears the assignee. The backend
checks reference existence and independently verifies the assignee and
preserved group; it does not invent an active-user/role predicate or execute
dynamic reference qualifiers. Source reference-list eligibility, ACLs and
business rules are distinct evidence. An Entra email alone does not establish
an existing ServiceNow identity mapping. Ambiguous or truncated resolution
requires clarification, not selection of the first candidate.

Creation uses actual source mandatory fields/defaults; deletion requires exact
authorization and inspection of material native effects. Exact mutation
preflights and operation recovery are not the six-month search interface.
Deletion confirms parent absence only and returns `cleanup_complete: false`.
An error response, changed group, partial readback or lost response retains
the original evidence and an uncertainty hold. Use `get_incident_operation`;
do not retry under the same or a new operation UUID or automatically change
source permissions to force success.

## Cowork read-only server

This legacy interface is retained for local read-only clients. It is not the
authenticated Cowork CRUD route.

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

For the Cowork client package, follow the companion
[Cowork setup guide](https://github.com/likamrat/servicenow-cowork-plugin/blob/main/SETUP.md)
and the authenticated interface above, not this legacy listener.

## Operation state and recovery

The shared backend keeps instance/account-bound journals and restoration snapshots
in its private state directory. Calls on one backend instance queue before taking
the exclusive state-file lock. Other instances/processes using that directory
are refused while an owner holds the lock; they are not automatically retried.
This does not lock other ServiceNow writers. Source version checks are preflight
checks, not atomic compare-and-swap.

| Situation | Action |
|---|---|
| A write times out or returns an uncertain outcome | Inspect `get_incident_operation` for incident operations, or native `local_operation_status`, and exact source records. Do not resend with the same or a new operation ID. |
| A paired-style change is partial | Use its original snapshot and current guards for an authorized restoration. |
| `operation.lock` remains after interruption | Establish the owning process and its last source effects before removing the lock. Preserve the journal. |
| The instance or source account changes | Use a separate state directory; do not rebind an existing journal. |
| Users must be retained | Maintain their exact IDs in the private `retained-user-ids.json` array. The operator is protected independently. |
| The plugin is uninstalled | Preserve the external state directory. Uninstalling does not undo ServiceNow changes or resolve pending operations. |

Before a controlled restart, stop incoming calls and account for all clients and
helpers sharing the state directory, not just HTTP connections. Wait for in-flight
state operations to complete. A forced process termination can retain the lock;
startup does not remove it. The four bounded ticket reads do not acquire this
lock, so successful retrieval alone does not establish state-operation readiness.

Place reviewed account, access and image policy files in the same private
directory. See [source-policy configuration](CAPABILITIES.md#source-policy-configuration)
for their formats and the operations that require them.
