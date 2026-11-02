# Setup

[Documentation](README.md) | [Repository overview](../README.md)

Run commands from the repository root unless a section says otherwise.
Source, script and configuration paths in code examples are repository-relative;
private configuration belongs in the external directories described below.

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

### Update an installed plugin

The native plugin release is **1.1.0**. Its root `plugin.json` and marketplace
entry use the same release version and retain the stable
`servicenow-mcp@servicenow-community` identity. The catalog's `source: "./"` points
to this repository's plugin root; it does not depend on an implementation branch
or a private copied runtime. The published default branch is `main`.

Open the installed **servicenow-mcp** plugin and choose **Update plugin**, then
start a new chat. Confirm that the installed entry shows the new release and
that the new chat uses the plugin-provided `servicenow-portable` server with the
shared incident, user CRUD and reviewed-access tools. Do not treat a separately
configured global `ServiceNow` server or a copied checkout's `tools/list` as
proof that the installed plugin updated.

The update replaces package files, not the approved external credential provider
or operation state. Retain the existing host-provided `PLUGIN_DATA` binding and
its external journal/policies; do not reinstall, clear data or copy credentials
into the package to make an update work. If the installed version, source or
component provenance remains stale, diagnose the app's supported update path.
A declared version and a local package test do not independently prove a
particular host completed the update.

The plugin release version is distinct from the MCP server's `serverInfo`
version and the Agent Plugins schema version. The latter remain `1.0.0`;
changing distribution metadata does not change the protocol or source guards.

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

Cowork uses one authenticated connector to the shared backend. Its catalog has
the four existing six-month incident/change reads plus incident schema discovery,
exact assignee resolution, create/update/delete and requester-owned operation
status, eight generic user CRUD tools and four policy-controlled access
continuation tools. It does not expose arbitrary table,
credential, role/group or theme administration. The source
account, credentials and operation state use the existing protected binding
above; there is no separate assignment service or identity map.

The canonical generated tool contract is
[`contracts/cowork-authenticated-tools.json`](../contracts/cowork-authenticated-tools.json).
Regenerate it with `npm run contract:cowork -- --write`; verify it with
`npm run contract:cowork -- --check`. Native stdio exposes the same incident
operations alongside its existing administrative tools.

### Incoming OAuth connection

Register or reuse an explicitly approved Entra resource API and OAuth client.
Do not substitute a Graph or Work IQ audience, an ID token, or an app-only
token. The protected resource verifies RS256, the tenant-specific v2 issuer,
expiry/not-before/issued-at, `tid`, exact resource application GUID `aud`,
authorized client application GUID `azp`, an immutable requester `oid`, and at
least one supported delegated scope. `Incident.Manage` admits the ten existing
incident/change tools. `User.Manage` admits the eight user CRUD tools. Both scopes
admit the eighteen incident/user tools. `User.Access.Manage` admits the four
reviewed-access tools; all three scopes admit twenty-two. Listing and dispatch enforce the
same separation; an incident-only token cannot manage users. There is no person
or incident allowlist.

The resource API must issue v2 access tokens (`requestedAccessTokenVersion: 2`).
Request only the resource permissions required by the client:
`api://<resource-application-id>/Incident.Manage` and/or
`api://<resource-application-id>/User.Manage` and/or
`api://<resource-application-id>/User.Access.Manage`, plus its required refresh scope.
Adding either user scope requires an explicitly approved resource permission/client
consent change; existing incident consent is not expanded by installing code.
Configure the client's approved callback and consent
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

### Optional verified-caller audit

Set `audit_enabled: true` in the private `cowork-profile.json` to emit one JSON
line to the backend's standard error stream after each authenticated tool call
finishes or is rejected by the tool/write gate. Omit it or use `false` to keep
auditing off. Retain the output only in the operator's access-controlled local
logs: immutable object IDs are user identifiers. This adds no network log
destination, per-person allowlist or token capture.

Each `cowork_tool_audit` event has only `tenant_id`, `object_id`, `client_id`,
`tool`, `outcome` and `status` in addition to the fixed event name. Identity
comes from the verified delegated token, not request arguments. Tool names
come from the registered catalog; an unregistered name becomes `null`.
Tokens, headers, request IDs, arguments, operation IDs, source records,
responses and raw error text are never included.

`outcome` is `success`, `error` or `not_dispatched`. Status is a bounded label:
`completed`, `confirmed`, `no_change`, `uncertain`, `not_sent`, `failed`,
`writes_disabled`, `scope_required` or `tool_unavailable`. For an operation-status read, its
status can describe the earlier operation; it does not mean a new write ran.
Authentication failures, discovery calls and notifications do not emit
verified-caller events. An interrupted call may have no completion line;
absence is not proof that no source write occurred.

Auditing does not replace the durable operation journal, prove user consent
or change source authority. If audit output fails, the original tool result
is preserved with a fixed audit-unavailable warning; do not retry a write
to obtain an audit line. Each caller can read only their own operation
receipts; uncertainty and consumed-UUID guards remain shared across callers.
Other authorized tenant accounts use their own native Cowork sign-in and
must meet the same tenant, issuer, audience, client and scope checks.

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

## Generic user CRUD

These tools run in the same backend for native stdio and authenticated HTTP.
Any agent may obtain name/email context through its separately authorized Work IQ,
directory or other source, then call the MCP. The MCP does not contact Graph or
Work IQ, verify directory claims, adopt a Microsoft identity, or accept a
`directory_verified` flag. Its outcomes explicitly report
`directory_verified: false`. Source profile data and actual caller authentication
are different kinds of evidence.

| Tool | Purpose |
|---|---|
| `get_user_schema` | Source fields supported by this profile path and fingerprints for operator policy review; not permission. |
| `lookup_users` | Exact name/first-name/login/email lookup with unique/ambiguous/not_found/incomplete outcomes; no mandatory email input. |
| `get_user` | Exact source user/version and ordinary contact/status projection. |
| `create_user` | Source-valid login plus first/last name, title and optional email. Explicit inactive, locked, notification-disabled human creation; no password or access input. |
| `update_user` | Only supplied first/last name, title or email, guarded by current source version. Login, lifecycle, credentials and roles are not profile fields. |
| `assess_user_delete` | Current native deletion impact, target/version, related effects and caller-bound assessment. |
| `delete_user` | Existing native administrative delete path with that assessment, fresh version/impact hash, confirmation and all declared native-effect acknowledgments. |
| `get_user_operation` | Caller-owned receipt/current observation; no replay or cleanup claims. |

An existing username or email collision is not adoption permission. Lookup first,
inspect candidates and use an unambiguous existing account for an authorized
operation; never create a duplicate or attach an external identity automatically.
Creation requires native source username uniqueness plus an operator review of
query visibility, since empty ACL-filtered results alone cannot establish
absence. Email is not assumed to have a source uniqueness constraint. Collision
checks and version guards are preflights, not atomic CAS against other writers.
The source's real field lengths apply, including usernames that contain `@`;
the agent must choose a source-valid login rather than truncate an email.

### Reviewed ordinary-profile policy

Create/update are unavailable until a qualified operator installs a
`user-profile-contract.json` in the existing private state directory:

```json
{
  "format": 1,
  "instance": "https://your-instance.service-now.com",
  "schema_sha256": "<reviewed full inherited sys_user schema fingerprint>",
  "rules_sha256": "<reviewed inherited active user-rule identity/version fingerprint>",
  "sourceEvidenceSha256": "<private review evidence SHA256>",
  "protectedIds": [],
  "protectedNames": ["admin", "guest", "system"],
  "absence_visibility_reviewed": true
}
```

`get_user_schema` supplies fingerprint inputs; **do not automatically turn those
values into approval**. Review actual mandatory/default/unique behavior, source
query visibility and native create/update effects first. The fingerprints are
compared on each write, and native `user_name` uniqueness is rechecked. The
existing account/access contracts and their older tools are not relaxed or
relabelled; this separate policy authorizes the ordinary contact/profile path.
The current source operator, named/ID-protected users and retention holds remain
protected. External/provider-managed and service/unknown identities are not
ordinary profile-update targets.

Schema output separates `generic_record_interface.mutation_allowed=false`
(the generic `local_record_*` exclusion for user records) from the supported
semantic user tools. `semantic_user_interface.policy_status` and
`source_permission` are `not_evaluated` on this read, not a write denial or
approval. The normal create/update/delete guards still run on their own paths.
Presentation labels do not change the underlying reviewed schema fingerprint.
For source choice mode `2`, `choice_semantics` explicitly identifies suggestions,
not a restricted picklist; ordinary string/length and actual source policies
still apply. Do not require a suggested title when the source allows other text.

Creation explicitly overrides unsafe-for-this-path lifecycle defaults with
`active=false`, `locked_out=true`, `notification="1"`, `identity_type="human"`,
`internal_integration_user=false` and `web_service_access_only=false`. It supplies
no password, login enrollment or access values. Native rules may still create an
active primary Email notification-device child and an identity hash; do not
silently remove either. Email updates can synchronize all native primary devices,
name updates can synchronize live profiles, and any update to a locked account
can invoke session/OAuth revocation hooks. Requested fields/status are read back;
native child/notification effects are disclosed, not claimed universally verified.

User deletion retains the existing broader administrative semantics: active,
contact-bearing and role/group-linked users are not automatically excluded.
Current-operator/retention and related native-cascade protection, ordered impact
pagination, fresh versions/hash and exact acknowledgments still apply. Deletion
does not remove roles first, reassign work or manually delete children.
`cleanup_complete` stays false, independently of confirmed parent absence.

All writes durably record intent/attempt before dispatch and preserve source
response identities and partial observations. An uncertain create is not retried
with a different UUID or caller. If the response was lost, a later matching
account is recorded as observed, not falsely attributed as a confirmed creation.
Caller-owned recovery survives restart; shared holds prevent cross-caller replay.

### Agent-composed creation, reviewed access and assignment

The intended sequence is agent-side context lookup, exact source lookup, generic
creation only when authorized absence is established, then separately qualified
assignee eligibility and a fresh guarded incident update using the source sys_id.
Never put an email string into `assigned_to`.

`create_user` returns `assignee_readiness: "not_evaluated"`. It grants no role or
group membership and does not activate/unlock the account. A source reference
qualifier may require memberships or ACL-bearing roles; a human identity and
successful creation do not satisfy those requirements. Do not invent an
active-user prerequisite when the actual qualifier does not contain one.

The four generic reviewed-access tools provide that continuation on the same
backend. They do not widen the older managed-definition tools or create a
special-purpose onboarding service:

| Tool | Purpose |
|---|---|
| `inspect_user_access_policy` | With no arguments, list configured definition-policy keys. With `policy`, qualify that enabled key against current source evidence before a user exists. Alternatively, supply `group_id`/`role_id` and optional `activate` to obtain unapproved review evidence. |
| `assess_user_access` | Read exact user/access state for a qualified policy; save a five-minute, caller-bound assessment with missing stages. |
| `apply_user_access` | Apply only missing stages from that assessment after exact native-effect acknowledgments and fresh source checks. |
| `get_user_access_operation` | Inspect the caller's original stage receipts and current access, without resuming or replaying a grant. |

Definition policies contain no preloaded user names or directory IDs. The agent
resolves each requested person at runtime and supplies the legitimate source
user ID. Work IQ or another directory tool belongs to the agent-side context
step; supplied source attributes do not become backend-verified directory claims.

An empty-argument policy listing returns `qualification: "not_evaluated"` and
`policy_available: null`, alongside each configured `enabled` flag. It does not
perform source qualification or mean that a policy is unavailable. An explicit
definition review returns `qualification: "review_required"`; an enabled
policy-key check returns `qualification: "matched_reviewed_evidence"` and
`policy_available: true` only after the existing checks pass. None of these
states substitutes for caller authorization, source permission or user consent.

Preflight the selected policy **before** `create_user`. An unavailable/disabled
policy or insufficient caller scope should not produce avoidable accounts.
When policy and authorization are present, the actual agent invokes
`create_user`, `assess_user_access`, `apply_user_access` and `update_incident`.
Worker/coordinator scripts must not provision or grant directly to set up a
successful-looking demo. The backend's internal source HTTP requests are the
normal implementation of those MCP tools.

### Reviewed existing-definition access policy

No access continuation is enabled by default. Install a reviewed
`user-access-contract.json` in the existing private state directory:

```json
{
  "format": 1,
  "instance": "https://your-instance.service-now.com",
  "sourceEvidenceSha256": "<private source review evidence SHA256>",
  "protectedIds": [],
  "protectedNames": ["admin", "guest", "system"],
  "policies": [
    {
      "key": "support-assignee",
      "group_id": "<reviewed existing group sys_id or null>",
      "role_id": "<reviewed existing role sys_id or null>",
      "activate": false,
      "enabled": false,
      "allow_role_delegation": false,
      "allow_unresolved_acl_references": false,
      "evidence_sha256": "<reviewed inspect_user_access_policy fingerprint>",
      "native_effects": ["<exact effects returned by inspection>"],
      "direct_origin_values": ["<reviewed native direct-grant origin value>"]
    }
  ]
}
```

Use JSON `null`, not the string `"null"`, for an omitted group or role. At least
one group, role or explicit activation must be selected. `activate` defaults to
false for inspection and must be explicit in installed policy. Enable a key only
after the actual group, role and access effects are reviewed and authorized.
An inspection result or copied fingerprint is not approval.

Read-only inspection walks the complete bounded downward role closure, preserving
every edge identity/version and role flags. It reads the selected group's direct
role relationships, linked ACL definitions, and inherited schemas/active hooks
for the seven affected user/access tables. ACL and executable rule bodies are
hashed in memory, never emitted or installed as source code. Identity/version
pages must be complete, ordered and consistent. The review must additionally
cover application role checks, visibility limits and native hook semantics;
neither the fingerprint nor non-elevated flags establish absence of privilege.
The runtime rechecks the evidence before assessment and before each source stage.
Identity queries are bounded and batched, not unbounded user inventories.

If linked ACL definitions are missing, an empty direct lookup alone never
qualifies a policy. Inspection can classify an exact link as
`source_native_reference_unresolved` only with complete, complementary native
reference evidence: every original link/role/target/version matches its base
read and joined-ID `ISEMPTY` read, the joined-ID `ISNOTEMPTY` read returns none,
and target name/class are explicitly empty. A known-visible control from the
already-read definition set must match its target name/class and show the
opposite native predicate results. Queries are constrained to the already-read
closure link IDs; unrelated links are not admitted. Projected reference
`sys_id` may echo the raw target ID and is never used as existence proof.

Without this evidence and a working positive control, missing definitions still
fail closed with `linked_acl_definition_incomplete` or a precise source/evidence
error. The bounded diagnostic includes counts, at most ten missing ACL IDs and
twenty referring link/role IDs, plus truncation; no bodies or credentials.
Contradictions, changed versions, missing fields, access failures and incomplete
coverage always stop qualification. There is no blind fallback/retry, privilege
elevation or source-link cleanup.

The exact unresolved links, complementary native rows and visible control are
retained in `unresolved_acl_references` and the policy fingerprint. This is not a
claim of physical deletion, universal visibility or absence of privilege. An
operator may accept **only that exact reviewed source-native classification**
with `allow_unresolved_acl_references: true`; omitted/false stays closed. The
runtime rechecks the same evidence before every access stage. A definition
becoming visible, changing linkage or a failed control invalidates the approved
fingerprint. No inaccessible ACL is silently discarded or invented.

Administrative/elevated/scoped-admin or restricted-grantor roles are not
supported, even through a containing role. Parented or externally managed
groups are also blocked: their membership/role inheritance has not been
implemented as a universal assumption. Root local groups may be active and may
carry explicitly reviewed ACL-bearing roles. No definition is adopted into the
older managed-definition store and no role/group definition is changed.

If any role in the reviewed closure has `can_delegate=true`, inspection discloses
that condition and adds `reviewed-role-delegation-eligibility` to its native
effects. Installed policy must explicitly set `allow_role_delegation=true` to
permit the existing role metadata after review of the actual native meaning.
`can_delegate` describes a role that can be delegated, not authority for the user
to administer roles. The separate `role_delegator` role remains hard-blocked
alongside administrative roles. This does not flip the source flag, grant role
administration or create a delegation; it prevents treating that default/flag as
harmless or silently ignoring it. All other hard role protections remain.

`direct_origin_values` records actual source origin values, including a
non-GUID sentinel if the source uses one. The backend writes only `{user,role}`
for a direct grant and `{user,group}` for membership; native inherited/state/
origin bookkeeping is read back, never fabricated. Missing contained-role
expansion, unexpected membership/role additions, changed unrelated roles or
unreadable origins leave the operation uncertain. Existing applicable
relationships are reused without adding duplicates.

Activation runs only when the selected policy explicitly requires it and the
user is inactive and locked. It writes only `active=true`, requires a new source
version and preserves lock/notification/identity state. It never unlocks,
sets a password or proves that all possible authentication channels are disabled.
Native membership recomputation or other unexpected effects stop later stages.
Do not add activation merely because an incident reference predicate is assumed
to require it; inspect the actual source requirements.

Each apply records durable caller/target intent and a source-attempt journal
before sending any stage. Confirmed stages and response IDs are retained if a
later stage is denied or fails. Lost responses, partial native expansion or
policy drift between stages never trigger automatic retry, rollback or deletion.
The user hold also blocks assignment and older user-target access paths until
the original uncertainty is reconciled. Caller-bound recovery is read-only;
another UUID or caller does not bypass it.

This implements the generic local path, not proof of a deployed policy or
universal source permission. Qualify a fresh natural request such as
“Assign this incident to Morgan Lee” through the actual client with authorized
directory discovery and MCP creation/access/assignment evidence. Do not turn the
acceptance prompt into tool instructions or require a person's email routinely.

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
