# Development

[Documentation](README.md) | [Repository overview](../README.md)

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

Keep the native plugin and marketplace release versions aligned when publishing
a plugin update. See [installed-plugin updates](SETUP.md#update-an-installed-plugin)
for the distinction between package and protocol versions.

Dependency changes must retain their license notices. See
[source and dependency provenance](PROVENANCE.md) for the runtime and attribution
requirements.
