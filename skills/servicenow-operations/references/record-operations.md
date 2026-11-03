# Record and account operations

Use the current request and live supported tools, not previous test cohorts or
historical grants. The tool families below describe supported workflow shapes;
discover each actual schema before execution. An unavailable semantic action
is a capability gap, not permission to use generic writes instead.

## Source model and guarded writes

Use schema discovery for inherited fields, mandatory/default/read-only metadata,
reference targets, choices and conditional policies. Resolve actual reference
IDs and lifecycle values. Structured query filters combine with AND; separate
queries are needed for alternatives. Honor returned limits and coverage.
Use exact table/ID reads for identity, source URL and current version.

Keep account, credential, access-control and executable configuration changes
on their supported semantic administration paths, outside business-record
`values`. This adapter boundary is not a universal ban on administration.

1. Establish authorization for the exact target, change and material native
   effects. Coordinate conflicting writers. If teardown is denied or unknown,
   agree retention before creating records described as disposable.
2. Retain the intent, authorization, table/identity, intended values and current
   version privately before sending. Use the tool's operation ID and durable
   journal where supported. A new operation ID cannot make replay safe.
3. For creation, supply schema-valid values without assuming the adapter adds
   business defaults. Where supported and appropriate, retain a unique
   caller-supplied correlation value for response-loss reconciliation. Preserve
   returned identities and independently read back the requested fields.
4. For updates, pass only intended changes and the current version guard
   (`expected_mod_count` on the local record adapter). Re-read and review drift
   instead of forcing a stale update. Preflight version checks are not atomic
   compare-and-swap unless the source explicitly guarantees it.
5. Before deletion, inspect concrete relationships and native effects. Supply
   known related identities to the tool's verification contract where supported;
   this neither discovers every dependency nor authorizes child deletion.
   `confirm: true` is an API guard, not user consent.
6. Confirm exact parent absence and each expected related outcome. A filtered
   search is not deletion proof. Report retained identities, changed references
   and unverified effects separately from confirmed deletion.

## Failure and recovery

| Evidence | Response |
|---|---|
| Invalid arguments or version/dependency guard | Establish whether a write was sent. Correct a legitimate input mistake within scope, or resolve the guard; preserve the original receipt. |
| Explicit mandatory-field/data-policy exception | Reconcile effects first. Use actual policy evidence for a minimal input correction within authorization; leave source policy unchanged. HTTP status alone does not distinguish this from an ACL denial. |
| Explicit ACL/security denial | Stop that operation. Do not change identity, roles, lifecycle, policy or UI/API route to manufacture success. Retain the record and diagnostic. |
| Authentication rejection | Follow [environment](environment.md). Stop subsequent calls through the failed authentication channel. |
| Timeout, lost response, disconnect, 5xx or partial write | Mark uncertain. Reconcile read-only using the exact identity, original correlation value and journal. Do not resend under the same or a new operation ID. |

Retain both the original error and later read-only observations. An uncertain,
rejected or already-attempted result is not replay permission. If the source
state remains inconclusive, stop related mutations and report the uncertainty.

## Account identity and protection

Before any account change, resolve the requested identities and inspect their
current state. Protect the current operator and explicit retention holds,
including native cascades into protected accounts. A capability question or
example is not an instruction to act on those names.

For names rather than IDs, use minimal `sys_user` fields such as `sys_id`,
`user_name`, `name`, `first_name`, `last_name` and `sys_mod_count`. Resolve an
explicit login with exact `user_name`, a full name with exact `name`, and a
bare first name with exact `first_name` candidates. When the intended field is
unspecified, consider plausible exact login/display-name alternatives. Union
and deduplicate IDs across separate queries; AND filters are not OR search.
Do not select the first row or substitute substring matching for identity.

No exact match means not found. Multiple plausible identities or a truncated
candidate set require clarification. Resolve a retention conflict against the
actual prior instruction. Do not bulk-inventory unrelated users, or create,
rename or adopt an account to manufacture identity or eligibility.

## User lifecycle and deletion

If a native lifecycle tool reports a missing reviewed account contract, use
`inspect_user_account_policy` when available. It gathers actual source schema,
rule/template fingerprints and readiness without installing or approving a
policy. Missing qualification is not an ACL denial. Keep source review and
contracts private, under the runtime owner's control; do not copy fixture
policies, switch to direct API writes or mark discovery as reviewed.

Use the available user semantic tools for creation, profile updates,
activation, deactivation/locking, unlocking and deletion. Read their distinct
preconditions and effects. A disabled-user creation path may exclude credentials
and access fields; status transitions do not implicitly set a password, change
notification preferences or restore sessions. Account for native primary-device
creation and synchronization without assuming child cleanup.

Use a fresh assessment's per-action eligibility and exact native-effect
acknowledgments. Activation preserves lock; unlocking requires an active user
and preserves notification/password/access state. Existing roles and groups
need explicit coverage by current reviewed access policies, not removal to
evade guards. Business responsibilities can block lock/deactivation without
being a universal activation/unlock prohibition. Unexpected access changes
or a lost write response remain uncertain, even with matching source readback.

Choose the supported deletion path for the requested account. A disposable
cohort restriction belongs to that tool, not to all ServiceNow users. An
administrative supplied-ID deletion path can have different eligibility and
impact rules from ordinary-profile or disposable-account tools. Do not alter
the target to evade whichever path's guards apply.

Where exposed, use `local_admin_user_delete_assess` for fresh deletion impact,
then `local_admin_user_delete_administrative` for the unambiguously authorized
ID. Inspect target/status/identity markers, current operator, retention holds,
relationship identities/versions, native effects, rule versions and coverage.
Assessment is not approval or effective source permission.

For an authorized set, prefer the native bulk tools when available instead of
an agent-side loop of individual deletes. Submit exact IDs/logins and preservation
IDs to `local_admin_user_delete_batch_assess`; review its completed plan, all
dependency summaries and any material native effects. Explicit dictionary
cascades can include business records and their own dependents. Do not treat
deleting a user as permission to override an existing business-record hold.
Execute with `local_admin_user_delete_batch` and the reviewed plan hash, then
read `local_admin_user_delete_batch_status` for per-user outcomes. It runs targets
sequentially inside the MCP and stops on uncertainty. Use
`local_admin_user_delete_batch_cancel` to request a stop between operations.
Keep the MCP process alive and preserve its original batch/user operation IDs;
interrupted jobs must not be replayed.

Read all required impact pages according to the tool's contract. A page size
is not a total eligibility cap. Hidden/dynamic relationships, unreadable or
non-progressing pages, and partial inventories remain unknown. Pagination
does not provide an atomic source snapshot.

Preserve optional blank relationship-version metadata as raw unversioned
evidence when the schema permits it; do not coerce it to zero or claim a version
guard. Required target/rule versions remain strict.

For the administrative path, pass the fresh target version and impact hash,
unique operation ID, confirmation field and exact declared native-effect
acknowledgments required by its schema. Retain authorization before sending.
A direct unambiguous request for named accounts already identifies intent;
ask further only for genuine ambiguity, a required host/source gate, retention
conflict or materially unexpected effects. Tool fields cannot replace those gates.

Execute authorized targets sequentially and retain per-target outcomes.
Activation, role removal, reassignment, identity conversion and direct child
deletion are not implicit steps. Source ACLs, business rules and hooks remain
authoritative. Stop further targets if uncertain effects could overlap them;
sequential calls are not an atomic bulk transaction.

Confirm parent absence with an exact read and inspect relevant observed
children/references. A missing assignment is not deletion of its role definition;
cleared business references are not deletion of the business record. A
`parent_absent` result does not establish universal cleanup, session revocation
or notification effects. Preserve an explicit `cleanup_complete: false`.

## Passwords and authentication channels

Use the installation's approved protected-secret interface and current native
policy. If a password tool accepts an opaque user-bound handle, pass that handle
through its documented field without exposing or decrypting its contents.
Do not assume a particular operating system or secret-provider implementation.

Treat password acceptance, reset-flag updates and status transitions as separate
stages. A partial failure can leave the password changed; preserve outcomes and
do not repeat the secret stage after ambiguity. Host-required credential-change
handoffs remain in force even when a tool is advertised.

API and interactive login are distinct authentication channels. Verify the
exact authenticated identity, not an HTTP success, password-set acceptance or
administrator-cookie reuse. Respect MFA, CAPTCHA, consent and required-change
gates. A required-change page is not unrestricted login. Report rejection per
channel without guessing its cause or granting roles to make a check pass.

For authorized rotation, retain a verified prior working baseline and its
actual origin; a caller assertion or accepted password write is not a baseline.
Bound negative checks and avoid automatic login retries. Read current reset
and status fields rather than carrying an older observation forward.

## Groups, roles and assignments

Discover supported definition and assignment actions independently. Apply the
tool's managed/nonprivileged scope and namespace only where required by that
tool. Definition creation does not authorize elevated or contained privileges.
Existing-definition adoption, if supported, requires the runtime's trusted
scope and durable enrollment; it does not itself grant source access.

Capture direct relationship identities and versions. Verify inherited access
expansion/removal and remaining origins separately from cached-login permissions.
Do not delete inherited children directly. A read-only deletion assessment or
metadata inventory is not a registered delete operation or complete use closure.
Unknown visibility requires an honest limitation, not relaxed source access.

## Configuration changes

A denied record operation does not authorize changing its access policy.
A later explicitly scoped configuration task is separate: capture the before
state, supported mechanism, intended effect and restoration route. Use an
actual configuration tool or qualified UI, not executable business-record
values. Missing capability and source denial stop that path.

Verify the authorized configuration effect before any separately authorized
dependent record operation. Preserve earlier denials and receipts; new approval
does not make an uncertain earlier write safe to replay. Resume interrupted
multi-record work only from its reconciled state, not from a connectivity check.
