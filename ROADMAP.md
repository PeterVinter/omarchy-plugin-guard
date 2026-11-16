# Roadmap

Not in 0.1:

- Re-scan installed plugins when they update, and alert when HEAD moves past a
  reviewed commit. `~/.local/state/plugin-guard/reviewed.json` already records
  the URL and commit of everything installed through Plugin Guard.
- Pin an installed plugin to its reviewed commit, so `omarchy plugin update`
  cannot move it without a new scan.
- Follow statements that span several lines (a `FileView` whose `path:` is on
  another line than the write, shell variables that hold a path).
- Translations beyond English (`i18n/<code>.json`).
- A button that copies the enable command after an install.
