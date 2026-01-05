# Stage 3 setup assets

Drop your images here to upgrade the “wow effect” of the installer UI.

Prefer placing assets in `site/_blackcat/asset/` (outside web docroot) — the kernel front controller serves them at `/_blackcat/assets/<filename>`.
This folder (`site/public/_blackcat/assets/`) is kept for convenience / legacy and will also work if you drop the files here.

Suggested files (PNG, no text recommended):
- `https-required-cat.png` — shown when setup is opened over HTTP (BlackCat refuses; HTTPS required).
- `hero-banner.png` — optional hero header background or banner.
- `trusted-vs-untrusted.png` — optional split illustration for release trust / integrity.
- `favicon.png` (64×64 or 128×128) — high-contrast icon for tiny sizes (tab / bookmarks).

Guidelines:
- Prefer dark UI style (fits the installer theme).
- Avoid third‑party logos/trademarks.
- Keep text minimal (or none) so it works in any language.
