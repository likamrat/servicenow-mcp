# Documentation

[Repository overview](../README.md)

| Guide | Contents |
|---|---|
| [Setup](SETUP.md) | Client connections, credential-provider binding, OAuth scopes, reviewed source policies and operation recovery. |
| [Tool reference](CAPABILITIES.md) | Supported record, user, access and theme operations, their prerequisites and limits. |
| [Source and dependency provenance](PROVENANCE.md) | Source lineage, runtime components and third-party dependency notices. |

## Start here

- [GitHub Copilot app](SETUP.md#github-copilot-app)
- [Update an installed plugin](SETUP.md#update-an-installed-plugin)
- [Other MCP clients](SETUP.md#other-mcp-clients)
- [Authenticated Cowork server](SETUP.md#cowork-authenticated-server)
- [Generic user CRUD](SETUP.md#generic-user-crud)
- [Reviewed access policy](SETUP.md#reviewed-existing-definition-access-policy)
- [Operation state and recovery](SETUP.md#operation-state-and-recovery)

## Package references

The installable [operations skill](../skills/servicenow-operations/SKILL.md) and
[themes skill](../skills/servicenow-themes/SKILL.md) retain their required
entrypoints in `skills/`. The [authenticated tool contract](../contracts/cowork-authenticated-tools.json)
and [native MCP manifest](../mcp.json) describe the client interfaces.

[LICENSE](../LICENSE), [NOTICE](../NOTICE) and
[third-party notices](../THIRD_PARTY_NOTICES.txt) remain at the repository root.
Commands in the guides run from the repository root unless stated otherwise.
