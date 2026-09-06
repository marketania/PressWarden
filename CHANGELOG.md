# Changelog

All notable changes to PressWarden are documented here.

## 1.1.0 — 2026-09-06

Threat Intelligence release.

- Added a native threat-intelligence knowledge base with stable `PW-*` rule IDs, severity/confidence metadata, campaign references, and source documentation.
- Added `./presswarden intel status`, `./presswarden intel update`, and `./presswarden intel scan`.
- Added `php-threat-intel` for request-controlled dynamic function execution and high-confidence credential-capture/exfiltration chains.
- Added `js-threat-intel` for decoded JavaScript execution, obfuscated dynamic script-loader injection, and hidden external iframe behavior.
- Added `wp-db-malware` to inspect prefiltered `wp_options` and `wp_posts` rows for high-signal stored browser malware without printing stored payload content.
- Added `wp-campaign-intel` with high-specificity WP-VCD and SocGholish/NDSW markers plus separate behavior-based coverage for Balada/Sign1-like techniques.
- FAST now includes native PHP/JavaScript/campaign/database threat intelligence with no API keys required.
- Added a focused `intel` suite for threat investigation without the entire FULL maintenance sweep.
- Added local CISA Known Exploited Vulnerabilities caching and CVE correlation for known-exploitation prioritization, with the official CISA GitHub mirror as a fallback for feed retrieval.
- Added optional Wordfence Intelligence V3 dual-feed support using a user-supplied `PRESSWARDEN_WORDFENCE_TOKEN`: the Scanner Feed drives installed-version detection, while matching Production Feed UUIDs add CVE/CVSS enrichment when available.
- Wordfence matches are correlated with CISA KEV; known-exploited CVEs are elevated. Feed data remains local and is not redistributed by PressWarden.
- Added optional Patchstack product/version intelligence using `PRESSWARDEN_PATCHSTACK_KEY`, with fleet-wide component/version deduplication, local TTL caching, configurable lookup caps, exploitation awareness, and CISA KEV correlation.
- Existing WPScan vulnerability intelligence remains optional/user-token driven.
- External vulnerability feeds are not bundled or redistributed with PressWarden; downloaded data stays in the user's local intelligence directory.
- `presswarden doctor` now reports native-rule counts, campaign references, CISA KEV cache state, separate Wordfence Scanner/Production cache state, Patchstack readiness, and the intelligence data path.
- Added malicious + benign regression fixtures for White-Engine-style XOR loaders, decoded JavaScript loaders, NDSW/SocGholish markers, dynamic PHP execution, and credential exfiltration.
- Extended portable-mode tests to verify local threat-intelligence paths and `intel status` behavior.

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
