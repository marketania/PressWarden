# Changelog

All notable changes to PressWarden are documented here.

## 1.1.0 — 2026-09-06

Threat Intelligence and fleet-security release.

- Added `./presswarden baseline create|status|diff` plus the `./presswarden changes` shortcut for local security-state baselining and change detection.
- Baselines record SHA-256 + size for security-relevant executable/configuration files and, when WP-CLI is available, plugin/theme versions and state, administrator usernames, and cron hook/recurrence metadata.
- Baselines intentionally exclude volatile uploads, caches, logs, backups, temporary trees, and similar high-churn paths from change tracking while normal security scans continue to inspect their relevant scopes.
- Baseline manifests do not store file contents, passwords, API keys, database payloads, or other secret values; previous accepted baselines are retained locally for future history/reinfection workflows.
- Added `./presswarden incident [path]`, an evidence-first compromise/reinfection suite combining baseline changes, fleet correlation, persistence, malware, administrator/application-password inventory, integrity, vulnerability intelligence, upload, and database-threat checks.
- Incident Mode deliberately excludes `wp-db-maintenance`, so database repair/optimization does not alter state during evidence collection. The existing deep-upload preference remains unchanged: empty asks interactively, `1` runs, `0` skips, and noninteractive execution skips unless explicitly enabled.
- Added `./presswarden correlate [path]` and the `fleet-correlate` check for cross-site outbreak signals. To avoid normal package duplication noise, correlation is restricted to file hashes, administrator identities, or cron state that are new/changed relative to the accepted baseline and repeat across multiple WordPress installations.
- Baseline changes and fleet correlation are review-only evidence signals and never trigger automatic removal or quarantine by themselves.
- Added dedicated baseline, incident-safety, and fleet-correlation CI regressions covering secret-free manifests, noisy-upload exclusion, new/changed/removed file detection, administrator/plugin changes, previous-baseline history, evidence-first incident composition, and duplicate-file false-positive protection.
- Added a native threat-intelligence knowledge base with stable `PW-*` rule IDs, category/severity/confidence/type metadata, source/reference fields, and added/updated dates.
- Added [`intel/README.md`](intel/README.md) defining the native manifest-plus-detector architecture, rule contract, evidence standards, and contribution requirements.
- Added `./presswarden intel status`, `./presswarden intel update`, and `./presswarden intel scan`.
- Added `php-threat-intel` for request-controlled dynamic function execution and high-confidence credential-capture/exfiltration chains.
- Added `PW-PHP-006` behavior coverage for admin-targeted remote browser payloads requiring WordPress-admin context, `manage_options`, Windows User-Agent gating, remote retrieval, decoding, and browser-output behavior.
- Added `js-threat-intel` for decoded JavaScript execution, obfuscated dynamic script-loader injection, hidden external iframe behavior, and decoded browser redirect targets.
- Tightened `PW-JS-002` so decoding elsewhere in a file is no longer enough: the decoded/reconstructed value must reach the dynamic script source in addition to script creation and DOM insertion.
- Added `PW-JS-004` for decoded/reconstructed values that flow into `location`, `location.assign()`, or `location.replace()` redirect sinks; ordinary static redirects remain clean.
- Expanded `wp-db-malware` beyond stored browser JavaScript to include database-resident PHP execution payloads, encoded redirect/reinfector-style options, and suspicious administrator persistence identities without printing stored payload bodies.
- Added `PW-DB-004`, `PW-DB-005`, and `PW-DB-006` with conservative alert/review thresholds. Generic unusual admin names, PHP snippets, or hexadecimal option names are not sufficient by themselves.
- Added a reusable pure PHP database-threat classifier so database detection logic can be regression-tested without requiring a live WordPress database.
- The `db` suite now runs `wp-db-malware` between database security/isolation checks and maintenance, so database-only scans include stored-threat and privileged-persistence inspection.
- Added `wp-campaign-intel` with high-specificity WP-VCD and SocGholish/NDSW markers plus separate behavior-based coverage for Balada/Sign1-like techniques.
- Expanded campaign knowledge with VexTrio/redirect-like persistence and admin-targeted fake-browser-update behavior while retaining attribution restraint for generic techniques.
- FAST includes native PHP/JavaScript/campaign/database threat intelligence with no API keys required.
- Added a focused `intel` suite for threat investigation without the entire FULL maintenance sweep.
- Added optional external YARA compatibility through `PRESSWARDEN_YARA_RULES`. PressWarden bundles no third-party YARA collections; external matches are review-only and never trigger automatic remediation.
- External YARA runs only in FULL, Incident Mode, and `intel scan`, not FAST, and scans validated outermost WordPress roots to avoid duplicate nested-site work.
- `presswarden doctor`, `presswarden config`, and `presswarden intel status` report external YARA readiness without exposing rule content or secrets.
- Added local CISA Known Exploited Vulnerabilities caching and CVE correlation for known-exploitation prioritization, with the official CISA GitHub mirror as a fallback for feed retrieval.
- Added optional Wordfence Intelligence V3 dual-feed support using a user-supplied `PRESSWARDEN_WORDFENCE_TOKEN`: the Scanner Feed drives installed-version detection, while matching Production Feed UUIDs add CVE/CVSS enrichment when available.
- Wordfence matches are correlated with CISA KEV; known-exploited CVEs are elevated. Feed data remains local and is not redistributed by PressWarden.
- Large Wordfence feeds are validated and matched with a bounded-memory streaming JSON reader instead of whole-feed `json_decode()`, keeping intelligence usable on constrained shared hosting.
- Wordfence Scanner matching retains only installed-version matches in memory; Production is streamed only to enrich matching vulnerability UUIDs.
- Wordfence match output shows available source/copyright attribution metadata supplied by the feed.
- Added optional Patchstack product/version intelligence using `PRESSWARDEN_PATCHSTACK_KEY`, with fleet-wide component/version deduplication, local operational TTL caching, configurable lookup caps, exploitation awareness, and CISA KEV correlation.
- Authenticated Wordfence and Patchstack requests do not place API credentials in external process command arguments; curl authentication is supplied through private stdin configuration with a PHP HTTPS fallback.
- Existing WPScan vulnerability intelligence remains optional/user-token driven and does not build or cache a local WPScan vulnerability database.
- Rechecked third-party intelligence/licensing boundaries for Wordfence, CISA KEV, Patchstack, WPScan, and external YARA; details are documented in `intel/SOURCES.md` rather than copying third-party databases into the MIT repository.
- `presswarden doctor` reports native-rule counts, campaign references, CISA KEV cache state, separate Wordfence Scanner/Production cache state, Patchstack readiness, external YARA readiness, and the intelligence data path.
- Added malicious + benign regression fixtures for White-Engine-style XOR loaders, decoded JavaScript loaders, decoded redirects, NDSW/SocGholish markers, dynamic PHP execution, credential exfiltration, admin-targeted remote payloads, and database threat classifiers.
- Added external-YARA regression coverage with a synthetic YARA executable and an explicit CI guard that no `.yar`/`.yara` collections are bundled under `intel/`.
- Added CI coverage for PHP helper syntax, authenticated-intel credential handling, external YARA behavior, and a 12+ MB synthetic Wordfence feed parsed/matched under a 12 MB PHP memory limit.
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
