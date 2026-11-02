# ServiceNow MCP

Connect your AI assistant to ServiceNow to find and update incidents, manage
users and knowledge records, and make draft theme changes. Ask in natural
language, and get results with links back to the original records.

Works with the GitHub Copilot app, Microsoft Copilot Cowork and other MCP
clients. Available actions depend on the client and configured connection.

## Get started with GitHub Copilot

You need **Node.js 24+**, **PowerShell 7**, and an existing ServiceNow account
with the permissions for your work.

1. Open **Add > Manage marketplaces** and add:
   ```text
   https://github.com/likamrat/servicenow-mcp
   ```
2. Open **Add > Plugin**.
3. Enter `servicenow-mcp@servicenow-community` and select **Install**.
4. Complete the one-time connection setup in the [setup guide](docs/SETUP.md),
   then start a new chat. The guide also covers Cowork and other MCP clients.

Already installed? **Update plugin**, then start a new chat.

Installation adds the plugin, not ServiceNow access. ServiceNow permissions
and configured policies govern which actions are available.

## Try it

Start with a lookup, then ask for the change you need:

- “Find recent ServiceNow incidents about VPN.”
- “Assign INC0012345 to Morgan Lee.”
- “Find the ServiceNow user Morgan Lee.”

The incident number and person are illustrative; replace them with your own.

## Documentation

- [Tool reference](docs/CAPABILITIES.md) — supported operations and limits.
- [Documentation index](docs/README.md) — configuration, recovery and development.

## Credits and license

The original read-only adapter is based on
[fizamusthafa/servicenow-cowork-plugin](https://github.com/fizamusthafa/servicenow-cowork-plugin).
Maintained by Lior Kamrat. [MIT license](LICENSE); see [NOTICE](NOTICE) for attribution.
