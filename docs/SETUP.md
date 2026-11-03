# Connect to ServiceNow

Use this guide to connect the GitHub Copilot plugin or another local MCP client.
If you use Cowork, your administrator must provide an authenticated connector.
Hosting that connector is covered in the [Cowork server guide](COWORK.md).

## GitHub Copilot app

Installing the plugin adds tools and skills. Installation does not provision
the ServiceNow account used for this connection or configure its credentials.
The one-time setup below tells the plugin where to get that account's existing
credentials and where to keep operation history.

### 1. Check what you need

- Node.js 24+ and PowerShell 7, installed on the machine running the plugin.
- A GitHub Copilot app that supports Agent Plugins and stdio MCP.
- A ServiceNow account permitted to read the records you want to use.
- An existing protected PowerShell credential provider on that machine.

The provider is a `.psm1` module exporting `Get-ServiceNowStoredCredential`.
That function must return one object with `Instance` (the exact HTTPS instance
origin), `UserNameSecure` and `PasswordSecure` (both PowerShell `SecureString`
values). It must work without interactive prompts under the account running
Copilot. A Windows DPAPI-backed provider must run as its owning Windows user.

**No provider or credential-enrollment tool is included.** If you do not have
one, ask your administrator to supply it before continuing. A client with a
protected environment-variable mechanism can instead use the stdio instructions
later on this page.

### 2. Install the plugin

1. Open **Customize** in Copilot's sidebar. Select the marketplace settings
   control next to the marketplace dropdown and add
   `https://github.com/likamrat/servicenow-mcp`.
2. On **Browse**, find `servicenow-mcp` from the `servicenow-community`
   marketplace and select **Install**.
3. Start a new chat. The server's first startup reports
   `Missing operator-approved nonsecret binding:` followed by the full path to
   `connection.json`. Keep that path for the next step.

This initial missing-file error is expected. The app supplies the private
`PLUGIN_DATA` directory; do not guess its location or use the plugin's installed
source directory.

### 3. Create the connection file

Choose a private directory for operation history outside both the plugin package
and `PLUGIN_DATA`. The server uses it to record attempted writes and recover
their outcomes. Keeping it outside the installation preserves that history
through updates and uninstalling the plugin.

Get the absolute paths of the approved PowerShell executable (`pwsh` or
`pwsh.exe`) and provider module. Use the actual files, not symbolic links.
For each file, calculate its SHA256:

```powershell
(Get-FileHash -LiteralPath '<absolute file path>' -Algorithm SHA256).Hash.ToLowerInvariant()
```

Create `connection.json` at the exact path reported in step 2:

```json
{
  "format": 1,
  "instance": "https://your-instance.service-now.com",
  "powershell_path": "<absolute path to pwsh or pwsh.exe>",
  "powershell_sha256": "<lowercase SHA256 of the executable>",
  "provider_module": "<absolute path to your provider .psm1>",
  "provider_sha256": "<lowercase SHA256 of the provider module>",
  "provider_getter": "Get-ServiceNowStoredCredential",
  "state_directory": "<absolute private operation-history directory>"
}
```

Replace every placeholder. In JSON, write a Windows path as
`"C:\\folder\\file.psm1"`. The instance is an origin with no trailing slash,
path, query or embedded credentials. Keep all eight fields as shown.

The file contains no password: the launcher calls your provider and passes its
credentials to the server in memory. The hashes prevent it from running a
changed executable or provider without review. Protect the connection file,
provider and history directory with operating-system permissions, including
Windows ACLs where applicable. Do not put credentials in this file or chat.

### 4. Make a first request

Start a new chat with the plugin enabled and ask:

> Find recent ServiceNow incidents about VPN.

Copilot should use **ServiceNow** and return matching records with source
links, or an empty result. Check that any returned link points to your instance.
This first lookup does not need an account/access policy file.

Once connected, ask for the work you need. Available changes depend on the
ServiceNow account's permissions and any operator-reviewed policies; installing
the plugin does not grant those permissions.

### Update an installed plugin

Choose **Update plugin**, then start a new chat. Keep your existing connection,
credential provider and operation-history directory; no re-enrollment is needed.

The server advertises the display title **ServiceNow**. The plugin identity
`servicenow-mcp@servicenow-community`, internal MCP name `servicenow-mcp` and
legacy registration key `servicenow-portable` remain stable. "Portable" was a
packaging identifier, not a separate ServiceNow product or capability limit.
Do not add a second server or rename the key to change its label: client
approvals may be tied to that key.

Some clients format the registration key instead of honoring MCP
`serverInfo.title`. If your updated client still shows "Servicenow Portable",
the server handshake alone is **not** a verified UI fix. Use only a
host-supported display-name override that preserves the registration, or a
host-supported migration that retains bindings and approvals. The Agent Plugins
1.0 MCP manifest has no display-name/alias field; adding an invented property
does not solve this. Never edit private host databases or silently recreate
approval state. Keep the existing connection until the host supports that
display correction, and verify both Customize and a fresh tool invocation.

### If the connection fails

| What you see | What to do |
|---|---|
| `node` or PowerShell cannot start | Check the required runtimes and the executable path available to Copilot. |
| Missing `connection.json` | Create it at the exact path in the startup error, not in the repository. |
| Executable/provider changed | Review the changed file, then update only its approved hash. Do not accept an unknown replacement. |
| `SN_IMPORT_FAILED`, `SN_GETTER_FAILED` or `SN_PROVIDER_RESULT_MISMATCH` | Ask the provider's owner to check its export, access to the protected store, and the exact instance/types required in step 1. |
| Authentication rejected | Stop repeated attempts. Check the configured account and provider through your approved authentication-repair process. |
| Source access denied | Ask the ServiceNow administrator about the specific denied read. A working login does not grant record access. |
| Missing operator-reviewed account source contract | Run `inspect_user_account_policy`, review actual source effects, and complete the [native account qualification](OPERATIONS.md#native-account-and-managed-access-contracts) in the existing history directory. This is a setup gap, not proof that ServiceNow disallows account changes. |
| Tools missing after installation or update | Check that the plugin is enabled and open a new chat. |

Preserve the server name and exact error when asking for help, but omit secrets.

## Other MCP clients

Use this path when your client can launch a local stdio server and supply secrets
through its protected configuration. It requires Node.js 24+ and a ServiceNow
account. PowerShell and the plugin's provider are not required.

1. Clone the server:

   ```sh
   git clone https://github.com/likamrat/servicenow-mcp.git
   cd servicenow-mcp
   ```

2. Add a **stdio** MCP server to your client. Set the command to `node` and its
   argument to the absolute path of this checkout's `src/stdio.cjs`. Use an
   absolute Node executable path if the client cannot find `node`.

3. Supply these environment variables through the client's protected
   configuration, outside the checkout:

   | Variable | Value |
   |---|---|
   | `SERVICENOW_INSTANCE` | Your HTTPS instance origin, without path, query, trailing slash or credentials. |
   | `SERVICENOW_USERNAME` | The authorized ServiceNow account name. |
   | `SERVICENOW_PASSWORD` | Its password from your protected credential mechanism. |
   | `SERVICENOW_MCP_DATA_DIR` | An absolute private operation-history directory outside the checkout. |

4. Restart that client connection and ask for the same read-only incident search
   shown above. A successful empty result is valid; an authentication error is not.

No `npm install` is needed for stdio, and the server does not load `.env` files.
For a terminal process whose environment is already configured, run
`npm run start:stdio` from the checkout. Updating this installation means updating
its checkout and restarting its client connection, not using **Update plugin**.
