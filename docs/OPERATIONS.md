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
