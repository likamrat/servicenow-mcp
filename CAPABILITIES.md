# Tool reference

Tools use the configured ServiceNow account and remain subject to its permissions.
Write operations require authorization for the intended change; a confirmation
field or successful assessment does not grant source permissions.

| Operation | Interface | Prerequisite and limit |
|---|---|---|
| Incident/change reads | `search_incidents`, `get_incident`, `search_changes`, `get_change` | Six-month window; search limit 20; explicit projected fields and source links |
| Incident CRUD and assignee changes | `get_incident_schema`, `resolve_incident_assignee`, `create_incident`, `update_incident`, `delete_incident`, `get_incident_operation` | Shared native/Cowork backend. Exact reference IDs, current version preflight, durable requester-bound outcome and no replay after uncertainty. Set/change/clear `assigned_to`; preserve group unless explicitly changed. No user/incident fixtures or account/access writes. Source eligibility and permissions remain authoritative |
| Generic user CRUD | `get_user_schema`, `lookup_users`, `get_user`, `create_user`, `update_user`, `assess_user_delete`, `delete_user`, `get_user_operation` | Shared native/remote semantics. Remote `User.Manage` required independently of incident scope. Create/update require reviewed `user-profile-contract.json`; ordinary name/title/email only, no lifecycle/credential/access fields. Native deletion impact/current-operator/retention checks reused. Agent context is unverified profile input, not directory identity proof |
| Reviewed generic access continuation | `inspect_user_access_policy`, `assess_user_access`, `apply_user_access`, `get_user_access_operation` | Remote `User.Access.Manage`, enabled reviewed `user-access-contract.json`, current caller-bound assessment and native effects. Applies missing existing root-local-group membership/direct role closure and activation only if configured. No person fixtures, arbitrary grants, definitions, inherited bookkeeping, unlock or password writes; partial stages retain a no-replay hold |
| Business records, including incidents, KBs and articles | `local_record_schema`, `local_record_query`, `local_record_get`, `local_record_create`, `local_record_update`, `local_record_delete` | Live inherited dictionary/choice/data-policy reads; source ACLs and lifecycle rules govern writes. Account, credential, access and executable configuration are excluded, including inherited protected tables |
| Exact user read | `local_admin_user_get` | Minimal profile/status projection; not credential or bulk-user export |
| Administrative deletion | `local_admin_user_delete_assess`, `local_admin_user_delete_administrative` | Current target version, impact hash and native-effect acknowledgments. Protects the operator and retained users. Does not require an inactive account or blank contact fields. Parent absence and related outcomes are reported separately; `cleanup_complete` stays false |
| Disabled-user creation, profile, activation, deactivation/lock, lock, unlock | `local_admin_user_assess`, `local_admin_user_create_disabled`, `local_admin_user_update_profile`, `local_admin_user_activate`, `local_admin_user_deactivate_and_lock`, `local_admin_user_lock`, `local_admin_user_unlock` | Requires a reviewed account contract; limited to eligible local human accounts, with protected-identity, relationship and native-effect guards |
| Managed nonprivileged groups, roles and direct assignments | `local_admin_access_read`, group/role create and description-update tools, group deletion, direct user-role/group-member/group-role add/remove, role deletion assessment | Requires account/access contracts and per-definition ownership receipts created by this installation. Namespaced nonprivileged scope, disabled/locked local-user guards and native inherited-role readback remain. Role-definition deletion is not registered |
| Login illustration setting | `local_admin_set_branding_property` | Only the existing documented `glide.ui.polaris.login.show_illustrations` string property |
| Draft colors/radius | `local_admin_patch_theme_style_pair`, `local_admin_restore_theme_style_pair` | Current-principal-owned global unpublished draft, two exclusive core styles, raw hashes/versions and exact original values. Two writes are not atomic; complete originals and partial outcomes are retained |
| Existing PNG logo | `local_admin_apply_theme_logo`, `local_admin_remove_theme_logo_link` | Exclusive owned unpublished target and existing owned image/attachment; actual PNG bytes/hash checked. Changes only the modern link, preserving assets and unrelated bindings |
| Fresh PNG logo | `local_admin_import_theme_logo` | Immutable local staging and a matching privately reviewed image contract. Asset creation and upload are separate, non-atomic stages; neither applies the logo or permits automatic cleanup |

Blank optional related-record versions in deletion evidence remain blank,
not zero. Ordered pagination continues beyond one hundred related records.
Unreadable or inconsistent evidence blocks assessment. Known relationships
are not a complete hidden/dynamic cascade graph or proof of session revocation.

## Source-policy configuration

Account lifecycle, managed access and PNG imports compare installed source
rules or schemas with operator-reviewed policy files. Missing or changed policy
blocks the relevant write. This is the adapter's safeguard, not a universal
ServiceNow installation requirement.

Store these files in the private operation-state directory. They are operator
configuration, not model-supplied tool arguments:

* `account-contract.json`: `format: 2`, the exact `instance`,
  `sourceEvidenceSha256`, `protectedIds`, `protectedNames`, and
  `businessRuleVersions` entries containing `sys_id` and `sys_mod_count`.
  A qualified administrator must review the native account effects and complete
  active-user-rule coverage before supplying this contract. Every write and
  assessment compares the current complete rule/version set. Metadata alone
  does not establish that the reviewed semantics hold on another release.
* `image-contract.json`: `format: 1`, the exact `instance`, `schema_sha256`,
  and `rules_sha256`. The schema fingerprint covers the complete
  `local_record_schema` result for `sys_ux_theme_asset`. The rule fingerprint
  covers sorted exact/inherited active insert-rule fields selected in
  `src/admin/logo-import.cjs`. Fingerprints use recursively key-sorted JSON
  and SHA256. A qualified review must cover the image-asset/Global-scope
  assumptions and native insert effects. The adapter compares content
  fingerprints but never writes captured rule bodies into the package or
  its journal.
* `access-contract.json`: `format: 1`, the exact `instance`,
  `sourceEvidenceSha256`, `directOriginDefaults`, and `tables` containing
  reviewed `rules`/`dictionary` ID-version arrays for `sys_user_group`,
  `sys_user_role`, `sys_user_has_role`, `sys_group_has_role`,
  `sys_user_role_contains`, and `sys_user_grmember`. Writes recheck every
  table's complete bounded hook/dictionary coverage. This complements rather
  than replaces the account contract. Access tools manage definitions created
  by this installation; importing another installation's ownership receipts is
  not a supported adoption mechanism.

Review the relevant source behavior before recording a policy. Discovery alone
is not qualification, and changed fingerprints require review rather than
automatic replacement.

## PNG staging

For an authorized PNG, run the following locally in the configured environment:

```text
node scripts/stage-logo.cjs <absolute-PNG-path> <expected-SHA256> <filename.png>
```

Use the returned immutable staging ID/hash with the import tool. Staging
does not upload. Supported PNGs are static, noninterlaced, 8-bit RGB/RGBA,
at most 400 x 50 pixels and strictly under 120,000 bytes. It is not a generic
attachment uploader. Visible logo/color effects require separate observation
in the intended user experience.

## Scope

The server does not expose existing-definition adoption, role-definition
deletion, password changes, SVG/JPEG import, portal branding, theme creation,
publication or default/user-theme selection. Fonts, custom icons and typography
are also outside its tool set.

Use the appropriate ServiceNow interface for those operations. Generic record
tools are not a substitute for unsupported account or configuration actions.
