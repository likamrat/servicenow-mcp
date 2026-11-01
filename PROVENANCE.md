# Source and dependency provenance

## Authored source

The public read-only baseline is
`likamrat/servicenow-cowork-plugin@0b6aa835259e505e34bf954682516c89d4ec2e44`.
Its MIT license and NOTICE identify the original
`fizamusthafa/servicenow-cowork-plugin@05c37c3` lineage. Both copyright notices
are retained in LICENSE.

`contracts/cowork-tools.json` is byte-identical to that baseline's
`plugin/mcp-tools.json`; SHA256:
`0da5f1eb731a69c7d14079ded76a382976a0ffb61ad3feafe94c9bd2c6af1548`.
The HTTP server and read-only tests retain its behavior. Express is loaded
only by the HTTP factory so the native stdio package requires no npm runtime
dependencies.

The seven operator skill files are unchanged from the maintained repository's
authored candidate `54bdb474f07841fa1ffc664ab83da5cfa257ff1a`, matching the
portable-skills source accepted at `8790a8c832256a95e9d58317101dfae5628d6705`.
Private invocation evidence and installed bindings are not part of this source.

The administrative adapters adapt previously authored local operator code:
record discovery/guarded CRUD, administrative impact/deletion, paired styles,
PNG validation/staging/linkage/import and bounded user lifecycle.
Managed nonprivileged group/role/assignment adapters retain source-policy
and unresolved-resource guards. The adapters'
instance, credential, filesystem and source-contract inputs are injected.
The old runtime assembler, launch control, approval receipts, journals,
retention lists, source schema snapshots and vendor script/action/page bodies
are not included. New configuration, state ownership and stdio composition
are original code for this package.

The MIT repository metadata alone is not clearance for future imports.
Third-party implementation bodies and unknown-rights evidence must be
qualified separately; the reviewed-contract mechanism does not grant rights
to redistribute the material a reviewer consulted.

## Runtime closure

The native stdio path consists of `src/stdio.cjs`, `src/configuration.cjs`,
`src/server.js`, `src/admin/`, and `contracts/cowork-tools.json`, using Node
built-ins. No browser, operating-system credential module, database or
private session directory is required to load it.

The optional read-only HTTP entrypoint additionally uses Express. Exact
versions, package registry URLs and integrity digests are retained in
`package-lock.json`. `THIRD_PARTY_NOTICES.txt` contains the unmodified license
texts from the installed locked dependency closure, grouped only when the
texts are byte-identical. MIT, ISC and BSD-3-Clause remain distinct licenses.
Dependencies are not vendored in this repository; retain their notices if
redistributing a built package that includes them. Node.js is a separately
installed runtime with its own license/notices.
