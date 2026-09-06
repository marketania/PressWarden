# Changelog

All notable changes to PressWarden are documented here.

## 1.0.1 — 2026-09-06

Quality-of-life and documentation release.

- FULL now asks before running the slow `wp-uploads-deep` image-content scan.
- Added `PRESSWARDEN_UPLOADS_DEEP`: empty asks interactively, `1` always runs, and `0` always skips.
- Non-interactive FULL runs skip the slow image scan unless explicitly enabled.
- Suite summaries correctly record the slow check as `skipped` when declined.
- Exported PressWarden/API environment variables now override persistent config values for reliable one-shot execution.
- Removed the public maintainer email from documentation and switched security-report guidance to private GitHub reporting / Marketania.com.
- Added clearer Marketania project-maintainer attribution.

## 1.0.0 — 2026-09-06

Initial public release.

- Host-agnostic recursive WordPress discovery with nested-install awareness and validated discovery caching.
- Fast, full, database, cleanup, doctor, and file-modification workflows through one `presswarden` CLI.
- Official WordPress core integrity verification with targeted quarantine-backed repair.
- WordPress.org plugin lifecycle and checksum integrity checks.
- Context-aware PHP malware/webshell detection with false-positive reductions.
- `.htaccess`, `wp-config.php`, PHP runtime, filesystem, upload, persistence, admin, theme/plugin, and database auditing.
- Wordfence WAF-aware `auto_prepend_file` validation.
- Conservative log/metadata inode cleanup.
- JSON suite summaries.
- Optional WPScan and Hostinger enrichments.
