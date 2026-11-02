# ServiceNow MCP

Connect your AI assistant to ServiceNow to find and update incidents, manage
users and knowledge records, and make draft theme changes. Ask in natural
language, and get results with links back to the original records.

Works with the GitHub Copilot app, Microsoft Copilot Cowork and other MCP
clients. Available actions depend on the client and configured connection.

## Get started

For the GitHub Copilot plugin, you need Node.js 24+, PowerShell 7 and an existing
protected ServiceNow credential provider. Installation adds tools and skills;
the one-time connection setup connects them to your account.

Follow [Connect to ServiceNow](docs/SETUP.md) for the complete plugin setup or
the direct stdio path for clients with protected environment configuration.
For Cowork, an administrator must supply a matching OAuth connector and
[host the authenticated backend](docs/COWORK.md).

To update an installed Copilot plugin, select **Update plugin** and start a new chat.

## Try it

Start with a lookup, then ask for the change you need:

- “Find recent ServiceNow incidents about VPN.”
- “Find the ServiceNow user Morgan Lee.”
- “Assign INC0012345 to Morgan Lee.”

The incident number and person are illustrative; replace them with your own.

## Architecture

```mermaid
---
config:
  flowchart:
    rankSpacing: 25
    nodeSpacing: 25
    padding: 12
    subGraphTitleMargin:
      bottom: 12
---
flowchart TB
    Context["Work IQ / directory tools"]
    subgraph Clients["AI assistants"]
        Local["GitHub Copilot<br/>Other local MCP clients"]
        Remote["Microsoft Copilot Cowork"]
    end
    Context -. "Optional identity context" .-> Clients

    subgraph MCP["ServiceNow MCP: shared backend"]
        direction LR
        Operations["Reads + writes<br/>Write checks:<br/>schema, policy, version"]
        Journal[("Operation journal<br/>Read-only recovery")]
        Operations -. "Write intent<br/>and outcome" .-> Journal
    end
    Local -->|"Local stdio"| MCP
    Remote -->|"Authenticated HTTP<br/>Scoped tools"| MCP
    MCP <-->|"API calls and readback"| ServiceNow["ServiceNow<br/>Account permissions<br/>Native rules"]
```

Source calls use the configured ServiceNow account; the assistant composes the workflow.

## Documentation

- [Supported operations](docs/CAPABILITIES.md): available tasks, tools and limits.
- [Documentation index](docs/README.md): operator policies, recovery and development.

## Credits and license

The original read-only adapter is based on
[fizamusthafa/servicenow-cowork-plugin](https://github.com/fizamusthafa/servicenow-cowork-plugin).
Maintained by Lior Kamrat. [MIT license](LICENSE); see [NOTICE](NOTICE) for attribution.
