# Bulk user creation

Native clients can submit one supplied roster for asynchronous assessment and
creation/reconciliation. The server uses the same durable job store and source
lock as bulk deletion. It runs the existing semantic user operations; it does
not send a table-level bulk insert or offer an atomic transaction. These tools
are not exposed through Cowork.

## Assess and start

1. Call `assess_user_bulk_create` with a new `batch_id` UUID and `targets`
   containing 1 to 500 `{user_name, profile}` objects. Profiles accept only
   supplied first name, last name, title and email. No directory lookup occurs.
2. Read `get_user_bulk_create` until assessment finishes. Status remains
   available while the job owns the source lock. Use `offset` and `limit` to
   read all target evidence when `has_more` is true.
3. Review the identities, proposed changes, policy blockers and native effects.
   A fully assessed batch returns `assessment_sha256` and `native_effects`.
4. With authorization for that exact roster and its effects, call
   `start_user_bulk_create` with the original `batch_id`, its
   `expected_assessment_sha256`, `confirm: true` and the complete
   `acknowledged_native_effects` list. Read status for the outcome.

For an existing account, supply `existing: {sys_id, expected_mod_count}` and
its current login as `user_name`. A blank email does not make an account absent.
The batch can fill a supplied email without replacing the source ID or renaming
the login. Existing candidates without this explicit binding block assessment.
Case-insensitive login/email collisions, ambiguous names, incomplete lookup
coverage and stale versions also block the affected work. The server does not
pick one candidate or invent missing profile values.

Omit `final_state` to create missing accounts inactive and locked while preserving
existing lifecycle state. To request activation and unlocking explicitly, pass
`final_state: {active: true, locked_out: false}`. The server creates a disabled
account first, then uses separate assessed activation and unlock operations.
Notification preferences stay unchanged on existing accounts; new accounts use
notification `"1"`. No stage sets a password or grants/removes access.

## Source qualification

The existing reviewed `user-profile-contract.json` qualifies profile operations.
Reconciling an existing account also requires its native account assessment.
Active/unlocked batches require matching reviewed schema and rule-content hashes
in `account-contract.json`. Accounts with existing roles or memberships need
current `reviewedAccessPolicies` coverage, including activation approval.
Business assignments alone do not deny activation.

Use the [policy review procedure](OPERATIONS.md) for missing coverage. Discovery
hashes do not approve themselves. Do not copy fixture contracts, strip roles,
omit blocked staff or weaken source ACLs to make a batch pass.

## Outcomes and recovery

The manifest retains the caller, instance, principal, inputs, source versions
and stable per-target/per-stage operation IDs before execution. Evidence records
each stage intent before dispatch and its result before the next stage.
Completed targets distinguish `created`, `corrected` and `already_matching`.
Blocked or uncertain targets retain their confirmed earlier stages; remaining
targets stay unstarted. Final readback checks every supplied profile and requested
lifecycle state again after target execution. These sequential reads are not an
atomic source snapshot.

`cancel_user_bulk_create` requests a stop between stages. It cannot cancel an
in-flight source request or undo confirmed changes. Interrupted jobs do not
resume automatically. Keep the original batch and operation IDs, state directory,
receipts and source identities. Read-only recovery or matching source state
cannot attribute a lost write, clear a hold or authorize a new-UUID replay.
