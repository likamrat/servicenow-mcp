# Palette and assets

Use supplied assets/palette and their permitted use. Keep the original asset
and reference. For an authorized reversible trial without a brand brief, retain
the chosen values privately rather than turning them into a reusable brand.

## Qualify the input and target

Check the actual release/control's formats, size limits and action-specific
roles before upload. Theme Builder, portal and workspace-icon constraints differ.
Font licensing and upload/installation permission are separate from choosing
an existing color or font. Use documented controls without adding roles.

For example, the linked logo procedure documents SVG/PNG/JPG up to 400 x 50 px
and under 120 KB; the font procedure documents WOFF/TTF/ZIP under 2 MB, one family
per upload, a family-count limit and no variable-font support. These are
release-specific baselines, not universal constraints. Recheck the target.

The Attachment API is a binary-upload primitive, not a theme
upload/bind/activate/restore contract. Neither an asset schema nor an attachment
on an arbitrary row proves that the visible logo changes. A built-in icon gallery
does not prove custom vector-library replacement support.

## Import, bind and inspect

Discover the supported format-specific workflow. A PNG tool does not imply
SVG, JPEG or font support. If the installation exposes staged import tools,
use their documented immutable staging reference/hash and current target
version/hash guards; do not invent staging helpers or submit arbitrary paths
or bytes to a reference-only interface.

Treat asset creation, binary upload and binding as distinct stages. Preserve
the original operation ID, error, returned asset/file/link identities and
partial effects. Reconcile a consumed or uncertain import through source reads
or its read-only reconciliation tool; do not upload again to manufacture success.

Resolve actual theme/style/asset relationships and reverse associations.
Bindings may live on a style rather than a legacy theme-asset table; empty
legacy links or unchanged root JSON do not prove that no logo was saved.
For fresh imports, independently verify the returned attachment's actual
bytes, format, dimensions and hash where supported. Metadata or old retained
bytes are not proof of the fresh upload.

Apply with the returned approved asset identities and fresh guards. For the
`local_admin_*_theme_logo`, SVG or JPEG families when exposed, discover import,
apply, link-removal and reconciliation schemas separately. Link creation alone
is not a new binary upload, and none implies publication/default/user selection.

Inspect the rendered logo in a fresh actual experience preview with its resolved
source and natural dimensions. Accessible alt text can retain a vendor label
after a custom image is applied. Check scaling, clipping and light/dark contrast.

## Fonts and palettes

Importing a font makes it available; selecting the theme's font is a separate
change. Verify the selected and rendered family, glyphs and fallback behavior.
Where a font tool has separate import/completion/reattachment stages, follow
the actual returned state and identities instead of treating upload as selection.

Inspect the selected theme's alternate-palette controls rather than assuming
custom dark palettes or editable vendor defaults. Verify foreground/background
contrast and affected focus, hover, error and disabled states. A palette
generator's result is not proof of the entire experience's accessibility.

## Restore the intended relationship

Restore the recorded font/asset binding or remove only the authorized
cycle-created link, using current versions and exact returned identities.
Keep retained assets/files and unrelated bindings unless their deletion was
separately authorized. Removing a relationship, deleting a binary and
unpublishing a theme are different effects.

Preserve actual provenance of UI-created versus tool-created links. Keep
changed/partial state explicit until source preservation and visible restoration
are verified. Use the [workflow](workflow.md) for shared restoration rules.

## Product references

- [Upload a logo, Brazil](https://www.servicenow.com/docs/r/brazil/platform-user-interface/tb-upload-logo.html)
- [Upload a custom font, Brazil](https://www.servicenow.com/docs/r/brazil/platform-user-interface/upload-custom-font.html)
- [Attachment API, Brazil](https://www.servicenow.com/docs/r/brazil/api-reference/rest-apis/c_AttachmentAPI.html)
- [Colors and alternate palettes, Zurich](https://www.servicenow.com/docs/r/zurich/platform-user-interface/difference-themes-variants.html)
