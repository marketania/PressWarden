# Changelog

All notable changes to PressWarden are documented here.

## 1.0.4 — 2026-09-06

Detection-quality and output-polish release.

- Database maintenance now treats `CHECK TABLE` responses such as `The storage engine for the table doesn't support check` as informational unsupported operations, not corruption.
- Unsupported CHECK operations are no longer sent through automatic repair or counted as unresolved/unhealthy tables.
- Added a high-signal obfuscated remote-loader detector to FAST and FULL scans. It requires packed numeric/string reconstruction plus XOR/`chr`/`ord` decoding plus a browser/network loading sink.
- Added a regression fixture modeled on the White-Engine behavior: packed/XOR-decoded external script loading must be detected while an ordinary local `wp_enqueue_script()` call remains clean.
- WordPress.org plugin lifecycle output now shows each exception group's local ACTIVE/INACTIVE state explicitly.
- Normal WordPress.org listings are labeled `LISTED` instead of the ambiguous `ACTIVE` label.
- WordPress.org `Plugin not found` / HTTP 404 metadata is normalized to `EXTERNAL` rather than falling into `OTHER`.
- Must-use plugin wording was cleaned up for provider-neutral output while still identifying recognized ManageWP/Hostinger MU components.
- Upload guidance now references `./presswarden full` instead of old internal script names.
- Added a repository `VERSION` file as the single source of truth for CLI/runtime/installer version reporting.
- Database helper remains compatible with PHP 7.4-era shared hosts.

## 1.0.3 — 2026-09-06

Shared-host portable installation release.

- Quick install now defaults to a local `./PressWarden/` directory instead of requiring `~/.local/bin`, symlinks, or PATH changes.
- Portable installs run directly with `./presswarden`.
- Portable config is stored at `PressWarden/config/config`.
- Portable reports, cache, and quarantine are stored under `PressWarden/var/`.
- Portable mode automatically scans outside the program directory, preferring a sibling `domains/` or `public_html/` tree when present.
- Rerunning the installer updates an existing portable installation in place while preserving its private config and runtime data.
- Installer output now includes the PressWarden ASCII logo plus concise next-step commands.
- `uninstall.sh` recognizes portable mode and can remove the self-contained PressWarden directory.
- The previous user-level `~/.local/bin/presswarden` installation remains available through `PRESSWARDEN_INSTALL_MODE=user`.

## 1.0.2 — 2026-09-06

Fleet-lock usability release.

- Added `presswarden lock [path]` to enable `DISALLOW_FILE_MODS=true` across all discovered WordPress installations.
- Added `presswarden unlock [path]` to disable `DISALLOW_FILE_MODS` temporarily for updates and maintenance.
- Added `presswarden lock-status [path]` for a read-only fleet status check.
- `lock` and `unlock` use a single fleet-level confirmation instead of prompting once per site.
- Existing `presswarden file-mods status|on|off` commands remain available for backward compatibility and advanced use.
- Lock/unlock continue to use quarantine-backed `wp-config.php` backups and automatic rollback on WP-CLI failure.

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
