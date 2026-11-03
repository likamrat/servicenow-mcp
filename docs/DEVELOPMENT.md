# Development

Use Node.js 24+ and PowerShell 7. From the repository root:

```sh
npm ci --ignore-scripts
npm run check
npm test
npm run notices:check
```

The tests use synthetic sources; no ServiceNow credentials are needed.
`npm run check` checks JavaScript syntax, and the tests cover the source guards,
transports and protected plugin entrypoint.

After changing shared tools, regenerate and check the authenticated contract:

```sh
npm run contract:cowork -- --write
npm run contract:cowork -- --check
```

## Plugin releases

Keep the release versions in `plugin.json` and
`.github/plugin/marketplace.json` aligned. Preserve the
`servicenow-mcp@servicenow-community` identity and the marketplace's `source: "./"`
reference to the repository root.

The plugin release, private npm package version, MCP `serverInfo` version and
Agent Plugins schema version describe different things. A documentation/skill
release bumps the plugin and marketplace together; it need not change the npm
package or protocol metadata.
Test the installed plugin's supported update path as well as local packaging.
Do not change or copy a user's external provider binding or operation history.
The MCP registration key is exactly `ServiceNow`; keep only that server entry.
The protocol title is also `ServiceNow`, while the protocol name remains
`servicenow-mcp`. Version 2.0.0 changes the old `servicenow-portable` registration,
so the major version reflects the required review of server-specific permissions
and rules. Plugin tests cover the
single registration and reuse of the private binding, policy and journal.
They do not emulate the app's label formatter or prove visible acceptance.
Verify **ServiceNow** on a real updated app invocation before closing the naming
fix. Follow the [migration steps](SETUP.md#update-an-installed-plugin).

The native manifest is [`mcp.json`](../mcp.json). The generated authenticated
HTTP contract is
[`contracts/cowork-authenticated-tools.json`](../contracts/cowork-authenticated-tools.json).

## Legacy anonymous read-only server

`npm start` runs a compatibility interface for local read-only clients, not the
authenticated Cowork server. After installing dependencies, supply
`SERVICENOW_INSTANCE`, `SERVICENOW_USERNAME` and `SERVICENOW_PASSWORD` through a
protected process environment and run it from the checkout. It listens at
`http://127.0.0.1:3002/mcp`; stop it with Ctrl+C.

It uses Streamable HTTP and exposes only the four incident/change lookup tools,
with no operation journal or client authentication. Anyone who can reach it can
read through the configured ServiceNow account. Keep it on loopback; host/origin
checks do not authenticate a caller.

| Optional variable | Meaning |
|---|---|
| `PORT` | Listening port; defaults to `3002`. |
| `MCP_ALLOWED_HOSTS` | Additional exact hostnames, comma-separated, without schemes or ports. |
| `MCP_ALLOWED_ORIGINS` | Exact HTTP(S) origins, comma-separated, without paths. Browser origins are rejected by default. |

For remote clients use the [authenticated Cowork server](COWORK.md).

## Dependencies and attribution

Dependency changes must retain their license notices. See
[source and dependency provenance](PROVENANCE.md) for the runtime and attribution
requirements.
