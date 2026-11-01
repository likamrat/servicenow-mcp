# Capability boundaries

All writes require actual user/host authorization and effective source
permissions. Confirmation fields, successful assessment and tool availability
are not consent. The two operator skills describe workflow semantics; they
do not install missing source capabilities.

| Operation | Portable interface | Prerequisite and limit |
|---|---|---|
| Incident/change reads | `search_incidents`, `get_incident`, `search_changes`, `get_change` | Six-month window; search limit20; explicit projected fields and source links |
| Business records, including incidents, KBs and articles | `local_record_schema/query/get/create/update/delete` | Live inherited dictionary/choice/data-policy reads; source ACLs and lifecycle rules govern writes. Account, credential, access and executable configuration are excluded, including inherited protected tables |
| Exact user read | `local_admin_user_get` | Minimal profile/status projection; not credential or bulk-user export |
| Administrative deletion | `local_admin_user_delete_assess`, `local_admin_user_delete_administrative` | Fresh operator/target/rule/relationship assessment, exact target version and impact hash, explicit native-effect acknowledgments. No fixture, disabled-account or empty-contact prerequisite. Observed parent absence is separate from known related outcomes; `cleanup_complete` stays false |
| Disabled-user creation, profile, activation, deactivation/lock, lock, unlock | `local_admin_user_assess`, `local_admin_user_create_disabled`, `local_admin_user_update_profile`, `local_admin_user_activate`, `local_admin_user_deactivate_and_lock`, `local_admin_user_lock`, `local_admin_user_unlock` | Requires a matching privately reviewed account contract. Existing bounded local-human, protected-identity, relationship and native-effect guards remain |
| Managed nonprivileged groups, roles and direct assignments | `local_admin_access_read`, group/role create and description-update tools, group deletion, direct user-role/group-member/group-role add/remove, role deletion assessment | Requires account/access contracts and per-definition ownership receipts created by this installation. Namespaced nonprivileged scope, disabled/locked local-user guards and native inherited-role readback remain. Role-definition deletion is not registered |
| Login illustration setting | `local_admin_set_branding_property` | Only the existing documented `glide.ui.polaris.login.show_illustrations` string property |
| Draft colors/radius | `local_admin_patch_theme_style_pair`, `local_admin_restore_theme_style_pair` | Current-principal-owned global unpublished draft, two exclusive core styles, raw hashes/versions and exact original values. Two writes are not atomic; complete originals and partial outcomes are retained |
| Existing PNG logo | `local_admin_apply_theme_logo`, `local_admin_remove_theme_logo_link` | Exclusive owned unpublished target and existing owned image/attachment; actual PNG bytes/hash checked. Changes only the modern link, preserving assets and unrelated bindings |
| Fresh PNG logo | `local_admin_import_theme_logo` | Immutable local staging and a matching privately reviewed image contract. Asset creation and upload are separate, non-atomic stages; neither applies the logo or permits automatic cleanup |

Blank optional related-record versions in deletion evidence remain blank,
not zero. Ordered pagination continues beyond one hundred related records.
Unreadable or inconsistent evidence blocks assessment. Known relationships
are not a complete hidden/dynamic cascade graph or proof of session revocation.

## Source contracts, not installation history

The account and image tools are advertised with an explicit prerequisite.
Without that prerequisite they return a capability-not-ready error before a
source mutation. No historic approval, trial account, fixture ID, credential
store or captured vendor body is distributed.

These are this implementation's private review requirements, not universal
ServiceNow installation restrictions. They are trusted operator inputs, not
model-supplied tool arguments:

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
  than replaces the account contract. Existing-definition adoption requires a
  separately trusted current-target authorization interface and is not supplied
  by copying an old managed receipt.

Do not generate these files by accepting whatever discovery returns. Source
drift requires review, not automatic rebasing of fingerprints. A missing
reviewed contract is a real readiness gap, not an instruction to relax guards.
The package provides no universal release contract or automatic enrollment.

For an authorized PNG, run the following locally in the configured environment:

```text
node scripts/stage-logo.cjs <absolute-PNG-path> <expected-SHA256> <filename.png>
```

Use the returned immutable staging ID/hash with the import tool. Staging
does not upload. Supported PNGs are static, noninterlaced, 8-bit RGB/RGBA,
at most400x50 pixels and strictly under120000 bytes. It is not a generic
attachment uploader. Visible logo/color effects require separate observation
in the intended user experience.

## Not yet provided by this portable package

Existing-definition adoption, native password operations, new SVG/JPEG
imports, portal branding, and theme publication/default/unpublication are not silently
substituted with generic Table API writes. Their earlier native implementations
need separate portable reviewed contracts; password/native theme paths also
need an approved browser/session interface, and password handles need a
protected-secret provider. No vendor implementation snapshot can substitute
for those contracts.

Theme creation and user-specific selection remain supported-platform UI
operations, not claims made by a draft-style patch. Fonts, custom icons and
typography are outside this delivery. No cloud hosting is included.
