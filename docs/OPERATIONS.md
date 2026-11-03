# Policies and recovery

For operators enabling optional administration or recovering interrupted work.
Ordinary incident lookups do not require these policy files.

## Reviewed source policies

Some writes depend on how your ServiceNow installation implements schemas,
business rules and access. A qualified administrator must review that behavior
before enabling the operation. The server compares current source evidence
against the approved file and stops when it changes.

Store contracts in the private operation-history directory. Keep review evidence
private. Discovery output and matching hashes do not themselves approve a policy
or establish source permission. Do not regenerate approvals automatically after
source drift.

| File | Enables |
|---|---|
| `user-profile-contract.json` | Ordinary user creation/profile updates. |
| `user-access-contract.json` | Reviewed grants using existing groups/roles and optional activation. |
| `account-contract.json` | Native bounded account lifecycle operations. |
| `access-contract.json` | Native managed group/role/assignment operations, alongside the account contract. |
| `image-contract.json` | Fresh PNG logo import. |

### Ordinary user profiles

Review the full inherited `sys_user` schema and active user rules, including
mandatory/default/unique behavior, query visibility and native create/update
effects. `get_user_schema` supplies the schema/rule fingerprints. Native username
uniqueness is required; an empty filtered lookup cannot establish absence.

Create `user-profile-contract.json` only after that review:

```json
{
  "format": 1,
  "instance": "https://your-instance.service-now.com",
  "schema_sha256": "<reviewed schema SHA256>",
  "rules_sha256": "<reviewed active-rule identity/version SHA256>",
  "sourceEvidenceSha256": "<private review evidence SHA256>",
  "protectedIds": [],
  "protectedNames": ["admin", "guest", "system"],
  "absence_visibility_reviewed": true
}
```

Add your protected IDs/names. The current operator and retention holds are also
protected. Externally managed, service or unknown identities are not ordinary
profile-update targets.

Creation explicitly sets `active=false`, `locked_out=true`, `notification="1"`,
`identity_type="human"`, `internal_integration_user=false` and
`web_service_access_only=false`. Review native notification-device creation,
profile/device synchronization and locked-account revocation effects.
Do not delete those native children as an implicit cleanup step.

The schema's `generic_record_interface.mutation_allowed=false` describes the
generic table-tool exclusion, not the semantic user interface.
`semantic_user_interface.policy_status` and `source_permission` are
`not_evaluated` on discovery. Choice mode `2` means suggestions rather than a
restricted picklist; actual source string limits and policies still apply.

### Existing groups and roles

Use `inspect_user_access_policy` with exact `group_id`/`role_id` and optional
`activate` to gather review evidence. Review the full downward role inheritance,
linked ACLs, source hooks, schema, native effects and visibility limitations.
The evidence covers affected user/access tables; application-specific role
checks and actual hook semantics still need operator review.

Install `user-access-contract.json` with the policy disabled until approved:

```json
{
  "format": 1,
  "instance": "https://your-instance.service-now.com",
  "sourceEvidenceSha256": "<private review evidence SHA256>",
  "protectedIds": [],
  "protectedNames": ["admin", "guest", "system"],
  "policies": [
    {
      "key": "support-assignee",
      "group_id": "<reviewed existing group sys_id>",
      "role_id": null,
      "activate": false,
      "enabled": false,
      "allow_role_delegation": false,
      "allow_unresolved_acl_references": false,
      "evidence_sha256": "<reviewed inspection SHA256>",
      "native_effects": ["<exact effect returned by inspection>"],
      "direct_origin_values": ["<reviewed native direct-grant origin>"]
    }
  ]
}
```

Use JSON `null` for an omitted group or role. Select at least one group, role or
explicit activation. Replace the `native_effects` array with every effect
returned by inspection. Definition policies contain no preloaded people: each
request resolves its target user at runtime.

Before enabling a policy, account for these limits:

- Administrative, elevated, scoped-admin and restricted-grantor roles are blocked,
  including roles reached through inheritance. Parented and externally managed
  groups are unsupported. Root local groups can carry reviewed ACL-bearing roles;
  "nonadministrative" does not mean unprivileged.
- A role with `can_delegate=true` requires `allow_role_delegation=true` and review
  of the disclosed `reviewed-role-delegation-eligibility` effect. This permits the
  reviewed metadata; it does not create delegation or grant role administration.
  The `role_delegator` role remains blocked.
- Missing linked ACL definitions normally block qualification. The exception flag
  accepts only the exact reviewed `source_native_reference_unresolved` evidence,
  not arbitrary unreadable ACLs. Classification requires complete matching base
  and joined-ID `ISEMPTY` results, no `ISNOTEMPTY` result, empty target name/class,
  and a known-visible control with the opposite predicates. Missing controls,
  inconsistent versions or access failures still block. Changed visibility or
  linkage invalidates the fingerprint.
- `direct_origin_values` must reflect native direct-grant origins, including a
  non-GUID sentinel if used by the source. The server writes only direct
  `{user,role}` or `{user,group}` relationships and reads native inherited/origin
  bookkeeping back. It does not fabricate that bookkeeping.
- Activation, if explicitly selected, changes only `active=true` for an inactive,
  locked user. It preserves lock/notification/identity state and does not prove
  all authentication channels are disabled. Do not enable it based on an assumed
  assignee requirement.

The runtime rechecks policy evidence before assessment and each write stage.
Partial expansion, unexpected additions or changed unrelated roles leave the
operation uncertain. A user's unresolved hold also blocks assignment and older
user-target access paths. Recovery reads never resume the grant.

### Native account and managed-access contracts

These contracts serve the native administrative tools, separately from the two
semantic user policies above.

`account-contract.json` requires `format: 2`, the exact `instance`,
`sourceEvidenceSha256`, `protectedIds`, `protectedNames`, and
`businessRuleVersions`: an array of `sys_id`/`sys_mod_count` pairs. Review native
account effects and complete active-user-rule coverage. Each assessment/write
compares the current complete rule/version set.

Start with `inspect_user_account_policy`. It is available without a contract and
returns the inherited user schema, native username uniqueness, active-rule
versions and content fingerprints, including declarative rule templates.
`policy_status` distinguishes `missing`, `matching` and `drifted`; none means
effective source write permission. Rule links identify the source definitions
whose scripts, conditions and templates must actually be reviewed.

For a new qualification, retain the review evidence privately and install:

```json
{
  "format": 2,
  "instance": "https://your-instance.service-now.com",
  "sourceEvidenceSha256": "<SHA256 of the completed private source review>",
  "protectedIds": ["<source-protected user sys_id>"],
  "protectedNames": ["admin", "guest", "system", "mms-service-account", "sharedservice.worker"],
  "businessRuleVersions": [{"sys_id": "<reviewed rule sys_id>", "sys_mod_count": "<current version>"}],
  "schema_sha256": "<reviewed schema SHA256>",
  "rules_sha256": "<reviewed complete rule-content SHA256>",
  "reviewedAccessPolicies": []
}
```

Replace the example rule with the **entire** inspected version set, and use only
real protected IDs (an empty array is valid when no additional IDs apply).
The schema and rule-content hashes must be supplied together. Older version-only
contracts remain compatible and are reported as `legacy_rule_versions_only`;
they are not silently upgraded. Inspection never writes or approves a contract.
Do not copy a fixture contract, approve an unread rule, substitute a discovery
hash for review evidence, or automatically refresh after drift.

Before adding these optional fields to a shared state directory, verify that
every runtime using it supports them. Older runtimes reject unknown contract
fields. Update those runtimes through their existing deployment controls before
installing the reviewed contract; preserve the directory, journals and bindings.
Do not strip reviewed fields or copy state to bypass an incompatible runtime.

Review create-time notification-device/identity-hash effects; profile/device
synchronization; locked-account session/OAuth revocation; provider unlinking;
contextual group changes on activation/deactivation; unlock's failed-attempt
reset; source query visibility and username uniqueness. Passwords, MFA, identity
conversion and role grants remain outside these lifecycle actions.

For an existing account with roles/groups, `reviewedAccessPolicies` may name
enabled policies from the existing `user-access-contract.json`. Each policy's
complete role closure, ACLs and source evidence is rechecked through the same
governed access implementation. Every current role and membership must be covered;
activation/unlock additionally require activation enabled in **every** selected
policy. This is an explicit lifecycle qualification, not an arbitrary-role
allowlist or permission to add missing access. Empty/omitted keys retain the
role/group block. Unknown or privileged access is not approved by ordinary
account CRUD. Unexpected native access changes remain uncertain, even when the
requested status was observed.

After installation in the existing state directory, run the inspection again,
then `local_admin_user_assess` for the intended exact ID. Use its per-action
`eligibility`, current version and `required_native_effects` for the separately
authorized status change. Do not retry a write just to learn its acknowledgments.
Profile acknowledgments depend on the supplied fields; names synchronize
`live_profile`, and any update while locked may revoke sessions/OAuth.
Active business responsibilities still prevent lock/deactivation; merely having
an assignment does not prohibit activation/unlock or authorize reassignment.

`access-contract.json` requires `format: 1`, the exact `instance`,
`sourceEvidenceSha256`, `directOriginDefaults`, and `tables`. Each table entry
contains reviewed `rules` and `dictionary` ID/version arrays for:
`sys_user_group`, `sys_user_role`, `sys_user_has_role`, `sys_group_has_role`,
`sys_user_role_contains` and `sys_user_grmember`.

Managed-access writes also need the account contract and ownership receipts for
definitions created by this installation. Importing another installation's
receipts is not a supported adoption mechanism. Complete bounded hook/dictionary
coverage is rechecked on writes.

### PNG imports

`image-contract.json` requires `format: 1`, the exact `instance`,
`schema_sha256` and `rules_sha256`. The schema fingerprint covers the complete
`local_record_schema` result for `sys_ux_theme_asset`; the rule fingerprint
covers sorted exact/inherited active insert-rule fields selected in
[`src/admin/logo-import.cjs`](../src/admin/logo-import.cjs). Fingerprints use
recursively key-sorted JSON and SHA256. Review Global-scope/image-asset
assumptions and actual native insert effects before recording them.

For an authorized PNG, run from the checkout with the server's environment
already configured:

```text
node scripts/stage-logo.cjs <absolute-PNG-path> <expected-SHA256> <filename.png>
```

Staging returns an immutable ID/hash; it does not upload. Supply those values
to the import tool. Supported PNGs are static, noninterlaced, 8-bit RGB/RGBA,
at most 400 x 50 pixels and strictly under 120,000 bytes. Asset creation, binary
upload and theme binding are separate stages. Verify visible effects in the intended
experience; a saved link alone does not prove the rendered result.

## Operation recovery

The private state directory holds instance/account-bound journals and restoration
snapshots. Preserve it across updates and uninstalls: removing the plugin neither
undoes ServiceNow changes nor resolves pending writes.

When a write times out, loses its response or reports partial/uncertain results,
keep its original operation ID and inspect it read-only:

| Write family | Recovery tool |
|---|---|
| Incidents | `get_incident_operation` |
| User profiles/deletion | `get_user_operation` |
| Reviewed access | `get_user_access_operation` |
| Native administration | `local_operation_status` |
| Bulk user deletion | `local_admin_user_delete_batch_status`; use each saved user operation ID with `local_operation_status` for its journal entries. |
| Bulk user creation | `get_user_bulk_create`; preserves per-target create/profile/activate/unlock receipts. See [bulk creation](BULK-USER-CREATION.md). |

A bulk job's parent journal entry is `confirmed` when execution or requested
cancellation finishes safely. Its `batch_phase` and per-target counts still
distinguish completed work, cancellation, blocked users and unattempted targets.
This confirms job settlement, not that every account changed. Failed or uncertain
source operations retain their original holds and prevent a safe restart.

Validated Table API request failures include `diagnostic.request.method` and
`diagnostic.request.table`. Deletion-impact read failures also include
`diagnostic.assessment_stage`, such as `role_grants` or `cascade_relationship`.
These fields identify the failed request without adding headers, query strings,
record values or response bodies to the diagnostic.
The existing sanitized source error remains intact. No source correlation ID
is invented. Both bulk status paths retain this diagnostic in their existing
job or target error; older receipts remain unchanged.

This provenance does not resolve an ACL denial or authorize a retry. If an
assessment fails before producing a plan, stop and retain the original batch.
Any separately authorized diagnostic reproduction should assess only the
original first target, read-only, and stop at the first failure. Do not restart
the whole batch or bypass the unreadable dependency.

Do not resend with the same or a new ID, switch callers to bypass a hold, or
automatically roll back. Preserve the original error, returned identities and
later observations. A matching record found after response loss is an observation,
not proof that the original create succeeded. Remote receipts are caller-owned;
uncertainty holds are shared.

| Situation | Operator action |
|---|---|
| Interrupted operation leaves `operation.lock` | Establish its owning process and reconcile pending source effects before removing the lock. Preserve the journal. |
| Instance or source account changes | Use a separate state directory; do not rebind the old history. |
| A user must be retained | Add its exact source ID to the private `retained-user-ids.json` array. The operator is protected independently. |
| A paired-style write is partial | Retain complete original values and the snapshot. Use fresh guards for an explicitly authorized restoration; do not reconstruct or resend the patch. |
| Source access is denied | Stop the denied operation. Do not change permissions or routes to force success. |

Calls within one backend queue for its exclusive state-file lock. Other
processes using that directory are refused while the lock is held, not retried.
This does not lock other ServiceNow writers; version preflights are not atomic
compare-and-swap.

Before a controlled restart, stop incoming work from all clients and wait for
in-flight state operations. Forced termination can leave the lock behind;
startup does not remove it. The four bounded ticket reads do not acquire that
lock, so a successful search does not establish write/recovery readiness.

### Bulk user deletion

Submit the authorized IDs and exact logins to
`local_admin_user_delete_batch_assess`, with a new batch UUID and
`preserve_user_ids` for accounts that must remain. Read status until assessment
finishes, then review the complete counts, dependency summaries and affected
records. A ServiceNow cascade warning can include business records such as
expense lines; a user-cleanup request does not override a prohibition on those
effects. Resolve material scope conflicts before execution.

Pass the completed plan hash, a new operation UUID and the declared native-effect
acknowledgments to `local_admin_user_delete_batch`. The job runs inside the
installed MCP process under the shared operation lock. Keep that process running;
updates, restarts and forced termination can interrupt the job. Status and
cancellation remain available without waiting for that lock. Cancellation waits
for the current source operation to finish and stops before another target.

The private `user-delete-batches` directory retains caller-bound plans, progress,
full per-user evidence and stop requests. Preserve it with the existing journal.
Jobs never restart automatically. Status read from another process reports
`another_process_or_interrupted_do_not_replay`, which does not establish that the
owner is dead. Reconcile the owner, original user operation IDs and source effects
before resolving an interrupted lock. Do not resubmit attempted or uncertain
targets in a new batch.

The lock does not cover UI users or other ServiceNow clients. Refresh the target
inventory after their changes, and keep externally deleted accounts separate from
MCP-confirmed deletions. Reassess unattempted drifted targets rather than forcing
the old plan.
