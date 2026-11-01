---
name: servicenow-themes
description: >-
  Plan, inspect, change, preview, apply or restore ServiceNow themes and branding.
  Use for colors, logos, fonts, component styling, light/dark palettes, login
  branding, theme selection or publication, including reversible-change planning.
  Distinguish Theme Builder, workspaces, portals and login surfaces. Not a
  read-only Cowork ticket scenario or a general page-layout redesign.
license: MIT
---

# ServiceNow themes

Use `servicenow-operations` for shared connection/authentication, tool discovery,
authorization and uncertain-write recovery. Install the two backend skills
together. Use the host's browser/app guidance for actual UI interaction.

## Select the surface and intent

Identify the instance, target surface/theme/user, requested changes, supplied
assets and draft/apply/restore intent. Scope comes from the current request,
not a previous trial. A planning request does not authorize service access,
uploads or preference changes. Honor host permission gates.

Read [surfaces](references/surfaces.md) before selecting a branding mechanism.
Qualify actual controls and reach; denied version metadata leaves that version
unknown, not every branding workflow unavailable.

## Capture and change

Read [workflow](references/workflow.md) before planning or performing theme
creation, editing, preview, publication, selection or restoration. Capture exact
original settings, identities and the restoration route. Prefer an isolated
unpublished custom theme when the requested task permits. Draft authoring can
autosave; editing a published theme can affect users on refresh.

For logos, fonts, images or palette inputs, also read
[assets](references/assets.md). Use observed supported controls or a discovered
semantic tool. Keep navigation, business content and unrelated preferences
outside the requested branding scope.

## Preview and apply

Inspect the requested changes together on the actual target experience.
Verify saved values and visible appearance, including affected readability,
interaction states and asset fit. Preview may contain live business data;
inspecting a theme does not authorize editing those records.

Stay in draft/preview unless application was requested. Publication, default
ordering and a named user's selection are different effects. Verify the
intended user/surface after refresh, not just an editor thumbnail.

## Restore or hand off

For a temporary change, restore recorded meaningful settings and verify source
state plus visible appearance. Use current guards, preserve normal audit changes
and account for retained drafts/assets. For a lasting change, retain its
prior-state/restoration reference privately.

Report the surface and settings actually changed, application reach,
restored/retained state and remaining unknowns. Save evidence outside installed
skills. One login property or preview does not qualify every branding surface.
