# Changelog

## 0.1.3

- **A password manager or keyring named alone is a medium finding, not a high one.** `gnome-keyring`, `libsecret`, `kwallet`, `Bitwarden` and `1Password` used to be "touches credentials, keyrings or browser profiles" (high) wherever the word appeared, so a catalog entry for a password manager, or a list of secrets to mask, made a plugin DANGER. They are now a medium `sensitive-name` ("Names a password manager or keyring"). The same names as part of a path (`~/.config/Bitwarden`, `/usr/bin/kwalletd6`, `gnome-keyring/`) and everything that reaches a store (`~/.ssh`, `~/.gnupg`, `~/.local/share/keyrings`, `secret-tool`, `org.freedesktop.secrets`, browser profiles, `Login Data`, `~/.config/gh/hosts` and the rest) stay high.
- Tests: two new cases. The version in `scanner.py` is 0.1.3 too.

## 0.1.2

Fixes the Low finding from the review of 0.1.1: the scan's resource limits started only after the Git checkout.

- **A storage and process budget applies while the repository is fetched.** Each git call that writes untrusted content (clone, checkout, and the clone made when installing) runs in its own process group with a CPU-time limit (120 s) and a per-file size limit (150 MB), and is killed as soon as the scan's folder holds more than 250 MB or the 180 s time limit passes. Anything git left running is killed with it.
- **The clone no longer checks out files.** `git clone --no-checkout` fetches the history; then the size of the tree is read from the tree objects (`git ls-tree -r -l`) and the checkout starts only if it holds at most 20,000 files and 120 MB. A larger repository is refused before any file is written, with a new error, "The repository is too large to scan safely" (`too-large`), and nothing is left in `/tmp`.
- The scan, the verdicts and the rules are unchanged. The version in `scanner.py` is 0.1.2 too.
- Tests: eight new cases in `tests/test_scanner.py` (tree over the byte or file budget, no checkout when refused, git killed while writing past the disk budget, the whole process group killed, the timeout, the file-size limit).

## 0.1.1

Listing and documentation only; the plugin's scanning, verdicts and install behavior are unchanged.

- **A short description.** The manifest description, shown on the marketplace card, is now: "Know what an Omarchy plugin can do before you install it: a safe, caution or danger verdict."
- **A new preview image.** `preview.png` is now a 1920x1080 poster with three real verdicts (Danger, Caution and Safe) in three Omarchy themes, built from the existing screenshots.
- **README first screen.** A one-line pitch, the new image and a short "Why you will want it" list before the details.
- The version in `scanner.py` is 0.1.1 too.

## 0.1.0

First release.
