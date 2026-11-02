# Supported operations

All tools use the configured ServiceNow account. Source permissions, business
rules and data policies still apply. The assistant must have authorization for
the requested change; a tool's confirmation field or assessment is not consent.

Native stdio clients have the full tool set. Authenticated Cowork exposes only
the incident, user-profile and reviewed-access sections below, filtered by
delegated scope.

## Incidents and changes

| Task | Tools |
|---|---|
| Find and inspect incidents | `search_incidents`, `get_incident` |
| Find and inspect changes | `search_changes`, `get_change` |
| Discover incident fields and resolve an assignee | `get_incident_schema`, `resolve_incident_assignee` |
| Create, update or delete an incident | `create_incident`, `update_incident`, `delete_incident` |
| Inspect a previous write | `get_incident_operation` |

The four incident/change lookup tools cover records updated in the last six
months; searches return at most 20 records. Incident search matches a literal
substring of the short description. Empty or truncated results do not prove
instance-wide absence. Change requests are read-only through these tools.

For assignment, resolve the exact ServiceNow user and use its `sys_id` in
`update_incident.values.assigned_to`, with the incident's current
`expected_mod_count`. `null` or `""` clears the assignee. The assignment group
is preserved unless explicitly changed. An email is not an assignee ID.

Assignee resolution does not provision users or establish source eligibility.
Ambiguous/incomplete results require clarification. Actual reference qualifiers,
ACLs and native rules govern eligibility; the server does not execute dynamic
qualifiers or assume a universal active-user requirement.

Creation uses source mandatory fields/defaults. Before deleting an incident,
inspect material relationships/native effects and obtain authorization for that
exact record. Mutation preflights
and recovery reads are not limited to the six-month search window. Confirmed
parent deletion does not prove complete cleanup.

## User profiles

| Task | Tools |
|---|---|
| Discover supported fields | `get_user_schema` |
| Resolve and read an account | `lookup_users`, `get_user` |
| Create or update an ordinary profile | `create_user`, `update_user` |
| Assess and delete an account | `assess_user_delete`, `delete_user` |
| Inspect a previous write | `get_user_operation` |

Cowork requires `User.Manage`, independently of incident permission.
Create/update also require an operator-reviewed profile policy. Creation requires
a source-valid login and at least one profile field: first name, last name,
title or email. Source mandatory-field rules still apply. It creates an
inactive, locked, notification-disabled human account with no password or
access grants. Updates accept only supplied first/last name, title and email;
login, status, credentials and access are not profile fields.

Lookup reports unique, ambiguous, not-found or incomplete results. An existing
login/email collision does not authorize adoption or duplicate creation.
ACL-filtered absence alone is not proof that an account does not exist.

An assistant may obtain profile context through separately authorized directory
or Work IQ tools. This server does not contact those services or verify that
context; user results report `directory_verified: false`. Creation reports
assignee readiness as not evaluated.

Native rules can create/synchronize notification devices and profiles or invoke
revocation hooks on locked-account updates. Requested fields are read back;
those wider effects are disclosed, not claimed universally verified.

Deletion protects the current operator and retained users. It requires a fresh
caller-bound assessment, target version, impact hash and exact native-effect
acknowledgments. Active or role/group-linked users are not automatically
excluded. The tool does not remove roles first, reassign work or manually delete
children; `cleanup_complete` remains false.

## Reviewed access for an existing user

| Task | Tool |
|---|---|
| List policies, qualify a policy, or inspect definition evidence | `inspect_user_access_policy` |
| Assess missing access for a specific user | `assess_user_access` |
| Apply approved missing stages | `apply_user_access` |
| Inspect the original stages without replay | `get_user_access_operation` |

Cowork requires `User.Access.Manage`. No access policy is enabled by default.
An operator-reviewed policy can add membership in an existing root local group,
a direct nonadministrative role with its reviewed inherited roles, and activation
if explicitly configured. It cannot create definitions, grant arbitrary access,
unlock an account or set a password.

Listing policies without arguments does not qualify them. A policy-key check
must match reviewed source evidence before assessment; an explicit group/role
inspection returns review inputs, not approval. Assessments last five minutes
and are caller-bound.

For an authorized create-and-assign workflow, check the intended access policy
and caller permissions before creating a user. Then resolve/create the source
identity, assess/apply missing access, and update the incident with fresh guards.
Keep a created account and confirmed stages if a later stage fails; do not
replay, roll back or delete them automatically.

## Native-only administration

These operations are available through local stdio, not the Cowork connector.

| Area | Tools and limits |
|---|---|
| Business records | `local_record_schema`, `local_record_query`, `local_record_get`, `local_record_create`, `local_record_update`, `local_record_delete`. Includes knowledge bases/articles; excludes account, credential, access and executable configuration tables, including protected inherited tables. |
| Exact user read | `local_admin_user_get`; a minimal profile/status view, not a credential or bulk-user export. |
| Account lifecycle | `local_admin_user_assess`, `local_admin_user_create_disabled`, `local_admin_user_update_profile`, `local_admin_user_activate`, `local_admin_user_deactivate_and_lock`, `local_admin_user_lock`, `local_admin_user_unlock`. Reviewed account policy and eligible local-human identities required. |
| Administrative deletion | `local_admin_user_delete_assess`, `local_admin_user_delete_administrative`; current impact/version guards and native-effect acknowledgments, with operator/retention protection. |
| Managed groups/roles | `local_admin_access_read` and group/role create/update, group deletion, direct membership/role add/remove tools. Requires account/access policies and installation-owned definition receipts. Namespaced nonprivileged scope and disabled/locked-user guards apply. Role deletion is assessment-only. |
| Login illustration | `local_admin_set_branding_property`; only the existing `glide.ui.polaris.login.show_illustrations` string property. |
| Draft colors/radius | `local_admin_patch_theme_style_pair`, `local_admin_restore_theme_style_pair`; a global unpublished draft owned by the configured source account, with two exclusive core styles and current version/hash guards. Paired writes are not atomic; complete originals are retained. |
| Existing PNG logo | `local_admin_apply_theme_logo`, `local_admin_remove_theme_logo_link`; an exclusive unpublished target and PNG asset owned by the configured source account. Verifies actual PNG bytes/hash. Changes the modern link, preserving assets and unrelated bindings. |
| Fresh PNG logo | `local_admin_import_theme_logo`; immutable staging plus reviewed image policy. Asset creation and upload are separate stages; import does not apply the logo. |
| Native recovery | `local_operation_status`; inspect the original operation rather than resending it. |

Schema discovery includes inherited dictionary, choices and data-policy
metadata. Discovery is not proof of effective write permission. Structured
record filters combine with AND; use separate queries for alternatives.

Deletion impact reads paginate beyond 100 related records. Required target/rule
versions remain strict; optional blank relationship versions stay blank, not
zero. Unreadable/inconsistent evidence blocks assessment. Known relationships
are not a complete hidden-cascade graph or proof of session revocation.

The tool set does not include password changes, adoption of existing definitions
into the managed-definition store, role-definition deletion, SVG/JPEG or font
import, typography/custom-icon settings, theme creation/publication/selection,
or portal branding. Wider workflows
in the bundled skills require separately available tools or supported UI; they
do not add capabilities to this server.

## Operator reference

[Policies and recovery](OPERATIONS.md) explains the optional source contracts,
PNG staging and handling of uncertain writes. Those policies belong to the
operator's private configuration, not to user prompts or tool arguments.
