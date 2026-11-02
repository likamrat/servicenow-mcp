# Run the authenticated Cowork server

This guide is for the administrator hosting the MCP backend. A Cowork user needs
an installed, approved OAuth connector; they do not need a local clone, Node.js
or a PowerShell provider.

This repository supplies the server, not a Cowork installation package, OAuth
registration wizard or public HTTPS hosting. Before starting, you need:

- Node.js 24+, PowerShell 7, and a ServiceNow account with the required permissions.
- An existing protected credential provider on the server machine.
- Approved Entra resource/client registrations and a matching Cowork OAuth connector.
- An approved HTTPS route to this machine's loopback listener.

This server offers incident/change reads, incident writes, user profile
operations and reviewed user-access operations. It does not expose arbitrary
tables, group/role administration or themes.

Supply a Cowork client package configured for OAuth and the bundled
[authenticated tool contract](../contracts/cowork-authenticated-tools.json)
for the tools it exposes. A package with authorization `None` cannot connect to
this listener.

## 1. Prepare authentication

There are two separate logins: Cowork's delegated OAuth token identifies the
caller; the server's protected provider supplies the ServiceNow account used for
source calls. Cowork sign-in does not grant that account additional source access.

Configure an Entra resource API to issue v2 access tokens
(`requestedAccessTokenVersion: 2`). Register the approved client's callback and
consent to only the delegated permissions it needs:

| Scope | Available tools |
|---|---|
| `Incident.Manage` | Incident/change reads, incident schema, assignee resolution, incident create/update/delete and recovery. |
| `User.Manage` | User lookup, schema, profile create/update, assessed deletion and recovery. |
| `User.Access.Manage` | Reviewed access-policy inspection, assessment, apply and recovery. |

Request scopes as `api://<resource-application-id>/<scope>` plus the client's
required refresh scope. Adding a permission requires approved consent; installing
server code does not expand existing consent.

The connector must use `OAuthPluginVault`. Its `referenceId` is the Microsoft
token-store registration ID, not an Entra application ID. Keep client secrets in
that approved store.

The server accepts RS256 delegated access tokens for the configured tenant,
resource application GUID (`aud`) and client application GUID (`azp`), with an
immutable caller `oid`, valid token times and a supported scope. Graph/Work IQ
tokens, ID tokens and app-only tokens are not substitutes.

## 2. Connect the server to ServiceNow

Clone the repository and install its HTTP dependencies:

```sh
git clone https://github.com/likamrat/servicenow-mcp.git
cd servicenow-mcp
npm ci --ignore-scripts
```

You can reuse an existing approved plugin connection file. Otherwise, create a
private directory outside the checkout for `connection.json`, and choose a
separate private operation-history directory outside both of those directories.

Your protected `.psm1` provider must export `Get-ServiceNowStoredCredential` and
return one object: `Instance` is the exact HTTPS instance origin;
`UserNameSecure` and `PasswordSecure` are PowerShell `SecureString` values.
It must run noninteractively as the server's operating-system account.
No provider or credential-enrollment tool is included.

Use absolute paths to the actual PowerShell executable and provider files, not
symbolic links. After reviewing both files, calculate each hash:

```powershell
(Get-FileHash -LiteralPath '<absolute file path>' -Algorithm SHA256).Hash.ToLowerInvariant()
```

Write the connection file, replacing all placeholders:

```json
{
  "format": 1,
  "instance": "https://your-instance.service-now.com",
  "powershell_path": "<absolute path to pwsh or pwsh.exe>",
  "powershell_sha256": "<lowercase SHA256 of the executable>",
  "provider_module": "<absolute path to your provider .psm1>",
  "provider_sha256": "<lowercase SHA256 of the provider module>",
  "provider_getter": "Get-ServiceNowStoredCredential",
  "state_directory": "<absolute private operation-history directory>"
}
```

Use an origin without a trailing slash. Escape Windows backslashes in JSON,
for example `"C:\\private\\provider.psm1"`. Protect these locations with OS
permissions. Credentials stay in the provider; the launcher passes them to its
child process in memory. Hash mismatches stop startup and require review.

## 3. Configure and start the listener

Create `cowork-profile.json` in the connection's `state_directory`:

```json
{
  "format": 1,
  "instance": "https://your-instance.service-now.com",
  "public_url": "https://your-approved-mcp-host/mcp",
  "tenant_id": "<lowercase tenant GUID>",
  "audience": "<lowercase resource application GUID>",
  "client_id": "<lowercase authorized OAuth client application GUID>",
  "writes_enabled": false,
  "port": 3003
}
```

The instance must match the connection file. `public_url` must use HTTPS with
exactly `/mcp` as its path and no query or fragment. Browser origins are rejected by
default; optional `allowed_origins` accepts exact approved HTTP(S) origins.

From the checkout, run:

```text
npm run start:cowork -- "<absolute directory containing connection.json>"
```

The server listens on `127.0.0.1` and reports its PID and port. Route the approved
HTTPS address to this listener. Do not route it to `npm start`, which runs the
legacy anonymous service. Keep the launcher under an owned process tree.

Every `/mcp` request, including tool discovery and reads, requires a valid token.
The public resource metadata is at `/.well-known/oauth-protected-resource/mcp`
and `/.well-known/oauth-protected-resource`; the 401 challenge points to it.
This server does not issue tokens or register clients.

## 4. Connect Cowork and start with a read

Configure the approved OAuth connector with the HTTPS `/mcp` URL and its
token-store registration, install it through your organization's Cowork process,
then sign in. In a new conversation, ask:

> Find recent ServiceNow incidents about VPN.

Expect records from the intended instance or a successful empty result. Keep
`writes_enabled: false` until you have checked the client's confirmation behavior
and approved which changes it may perform. Enabling writes is an operator setting,
not consent to any particular record change.

User creation/profile updates and access grants also need the relevant
[reviewed source policies](OPERATIONS.md#reviewed-source-policies). Those are
optional capabilities, not prerequisites for an incident lookup.

## Diagnose and operate

| Failure | Check |
|---|---|
| Startup rejects the binding/provider | File paths, approved hashes, provider export/result and the server account's access to its store. |
| `401` or `invalid_token` | Token audience, tenant issuer, validity and access-token type; use the approved sign-in flow. |
| `delegated_management_scope_required` or `requester_not_authorized` | Delegated scopes, authorized client ID and caller identity. |
| `authorization_keys_unavailable` | Server access to the tenant's signing-key endpoint; do not weaken token validation. |
| A tool is missing or scope is denied | The connector's granted scope. Incident permission does not include user/access tools. |
| Writes disabled | The operator setting; do not enable it as a substitute for user authorization. |
| ServiceNow rejects a call | The configured source account's credentials, record permissions or native rules. |

To restart, stop incoming calls and let in-flight operations finish before
stopping the owned process tree or reported HTTP PID. Preserve the history
directory. A forced stop or uncertain write needs
[operation recovery](OPERATIONS.md#operation-recovery), not an automatic retry.

### Optional caller audit

Set `audit_enabled: true` in `cowork-profile.json` to write a JSON line to stderr
after an authenticated tool call finishes or is rejected by a tool/write gate.
It records `tenant_id`, `object_id`, `client_id`, registered tool name, outcome
and bounded status. It does not record tokens, arguments, records or raw errors.
Keep these identity-bearing logs access-controlled.

Audit is off by default. Authentication failures, discovery and notifications
produce no caller event; an interrupted call may have no completion line.
For recovery reads, the status can describe an earlier write. Missing audit
output never proves a write did not happen and is not a reason to retry it.
