# Connection, authentication and capability discovery

## Use the configured installation

Resolve the intended ServiceNow instance from the user's request and the
host's configured connection. Use that installation's approved authentication
automatically. Neither these skills nor their examples select an instance,
operator, endpoint or account.

Keep local bindings, runtime ownership, credential-provider documentation and
operation receipts outside distributable skill directories. Consult existing
host/runtime documentation supplied for this installation when needed; do not
invent private helper names, paths or signatures. If the binding cannot be
established safely, report the missing information.

Registered MCP tools normally reuse the service's configured login. For UI
work, prefer the existing approved browser session or documented authenticated
browser setup. A newly opened logged-out browser is not proof that stored
authentication failed. Follow the host's browser permissions and use an owned
headless/background context when suitable; leave unrelated user windows alone.

Handle credentials only through the installation's approved protected mechanism.
Keep secret values out of chat, tool arguments, ordinary files, command history,
screenshots and traces. Do not copy or decrypt a secret store to improvise
another login mechanism. Mandatory sign-in, MFA, CAPTCHA, consent or credential
change gates require their host-defined user action.

## Diagnose the specific boundary

| Observation | Next step |
|---|---|
| Tool missing from the host catalog | Check registration and current discovery through supported host controls. A backend inventory is not proof that the app exposes it. |
| Service unreachable or transport failure | Inspect the configured endpoint's permitted read-only status and existing runtime documentation. Preserve the actual error. |
| Administrator authentication rejected | Stop repeated login attempts and use that installation's approved repair/sign-in route. Do not silently substitute another identity. |
| Target-user login rejected | Record that authentication channel's result separately; it does not establish failure of the administrator's saved login. |
| Source ACL/security denial | Stop the denied operation and retain the evidence. Authentication success does not override source policy. |
| Validation or data-policy error | Reconcile any possible write effects, then use actual schema/policy evidence to distinguish invalid input from an access denial. |

Keep service health, app-visible tool discovery, authentication and actual
source execution separate. Neither an HTTP success nor an empty query proves
all four. A current session can have stale discovery; use supported refresh or
a fresh context when needed, not a second server or guessed provider namespace.
Explain authentication failures using the actual server name and failure reason.

## Check registration and skill origin

The plugin registers its native server as `ServiceNow`; `servicenow-portable`
is the old registration. Use the actual discovered namespace, not a guessed
prefix. A real new app invocation must show **ServiceNow** to establish visible
naming acceptance; protocol metadata alone is insufficient.

Check the loaded skill's reported base directory after an update. A same-named
personal or project skill can supply older instructions instead of the plugin
copy; updating the plugin does not update that separate copy. Resolve the
duplicate through the host's supported skill management with the user's choice,
preserving custom content. Do not overwrite or delete global skills, edit host
caches or create duplicate registrations. An intentionally disabled plugin,
MCP server or skill is not evidence that the implementation lacks the capability.

## Separate service surfaces

The authenticated Cowork interface has its own 22-tool incident/profile/reviewed
access contract and delegated scopes. Native bulk user operations are not in it.
Other installations may expose only read-only incident/change tools. Do not
infer native capabilities or mutation permission from either restricted surface,
or expose an expanded backend as a replacement endpoint.

Use existing runtime ownership and status procedures. Starting, stopping,
replacing, tunneling or reconfiguring a server is separate work with its own
authorization; it is not part of ordinary record access. Missing functionality
is a concrete capability gap, not permission to install another backend,
relax policy or bypass a host gate.
