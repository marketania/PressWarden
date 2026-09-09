# Changelog

All notable changes to PressWarden are documented here.

## 1.1.8 — 2026-09-09

Complete-or-refuse security baselines.

- Record per-site file/plugin/theme/administrator/cron coverage, capture policy and snapshot hashes. Failed traversal, hashing, changed file identities, invalid inventories or failed writes cannot activate a partial baseline or produce false removal deltas.
- Refresh discovery for baseline captures and compare only matching site sets, exclusions, policy and captured categories. Missing sites and lost WP-CLI availability return INCOMPLETE (2), not mass removal findings. File-only baselines remain usable without WP-CLI or PHP; previously captured runtime state cannot be silently downgraded.
- Validate WP-CLI CSV headers, fields, states and resource limits without executing input or forwarding raw diagnostics. Preserve quoted commas and compare duplicate cron hooks using sorted recurrence sets rather than an arbitrary last row.
- Keep nested-site ownership separate and prune excluded sites/scanner state from parent captures. Use NUL-delimited candidate paths and refuse unrepresentable control-character paths rather than silently dropping them.
- Serialize baseline readers/writers with an exclusive lock, stage private snapshots, preserve old generations in unique history directories, and restore the previous generation after failed activation when possible. Retain evidence and the lock if recovery is unconfirmed.
- Publish unique private change TSV reports without replacing history. Apply the same coverage gate to incident baseline checks and fleet correlation; run the correlate helper through Bash on source checkouts too.
- Legacy snapshots remain untouched until explicit recreation, when they are archived. Their previously unrecorded coverage is unknown, not retroactively certified. No automatic migration, deletion or acceptance of changed state.
- Add CSV, coverage-loss, scope/exclusion, mutation, concurrent operation, activation/rollback, interruption, report preservation, permissions and PHP 7.4 tests. Existing detection, quarantine, updater, private config and other scan suites are unchanged.

## 1.1.7 — 2026-09-08

Verified quarantine and conservative action safety.

- Snapshot selected targets before interactive approval, then require matching source identities/hashes and verified quarantine copies before removal. No automatic remediation or unverified fallback.
- Allocate unique private cases with manifests, inert `.bin` copies, SHA-256 records and per-entry outcomes. Retain partial evidence after interruption or failure; never overwrite or migrate older quarantine folders.
- Capture symlinks as link-target text without following their referents. Revalidate protected/excluded paths, scanner state and ancestors. Refuse special files, hard links, unsafe paths, out-of-scope targets and oversized selections.
- Preserve narrowly scoped VCS/disposable-metadata directory actions using checked leaf removal and empty-directory removal instead of recursive force deletion. Unexpected new entries remain untouched.
- Propagate failed approved actions as INCOMPLETE (2), including partial removals. Disable further generic actions after a quarantine/reporting failure.
- Add read-only `quarantine list` and `quarantine verify CASE_ID`; separate stored-copy verification from recorded removal status. No restore/purge command or WordPress bootstrap is introduced.
- Add copy/source mutation, corruption, manifest/journal failure, protected-scope, concurrency, interruption, privacy, limits and PHP 7.4 regressions.
- Malware rules, thresholds, existing suite membership, updater behavior, private config, baselines and historical reports are unchanged. Baseline/discovery rewrites are intentionally separate.

## 1.1.6 — 2026-09-07

Conservative reporting and focused-recheck update.

- Add `./presswarden inspect php|js|db [directory]` to run one existing read-only intelligence layer with discovery, exclusions and suite JSON. No feed refresh, generic file-removal prompt or database maintenance; PHP mode is the three scoped intelligence rules, not the complete PHP scanner.
- Give each check/suite a uniquely reserved run ID instead of timestamp-only report names. Create new console/finding/deletion reports and new report directories with private permissions without changing the caller's umask or altering historical files.
- Publish per-run JSON without replacing existing destinations, then publish the compatible `*-latest-summary.json` alias using a complete same-directory staged file. Refuse symlink/non-file destinations and surface publication failures while retaining available reports.
- Include `run_id` in suite JSON and run headers. Existing fields, flat report-directory layout and summary aliases remain available.
- Failed finding-detail writes disable generic file actions and finish with INCOMPLETE (2); bounded console output no longer claims an unavailable full findings log. Suite result-record write failures are also propagated.
- Add focused-inspection, same-second concurrent allocation, private-permission, umask, symlink/history preservation, atomic JSON reader/writer, failed-evidence and latest-publication regressions, including PHP 7.4 helper compatibility.
- Detection rules, severity thresholds, API/feed configuration, existing scan suites, updater recovery, private config, baselines and quarantine behavior are unchanged. No new API keys, Node.js or Composer dependencies.

## 1.1.5 — 2026-09-07

Database evidence quality and honest scan coverage.

- Replaced unbounded, silent `LIMIT 1000` database reads with ordered keyset pagination, bounded batches, per-value and per-site byte limits, and explicit incomplete results when limits or queries fail.
- Stored PHP-serialized scalar/array values are read by a bounded inert reader, never PHP unserialization. JSON/widget/builder strings and inline script blocks are analyzed independently using the existing scoped JavaScript recognizer.
- Ordinary iframe embeds, unrelated hidden elements, minification/decoding alone, and independent widget/script values no longer combine into database malware alerts. Hidden-frame findings require recognized behavior in that same frame's handler.
- Stored PHP evidence requires a supported execution argument containing request/decode evidence; comments and isolated decoders do not suffice. Database PHP findings remain REVIEW.
- Administrator identity checks validate the current-blog top-level administrator role key rather than relying on substring matches; identity-only indicators are REVIEW, not proof of account ownership. No account is modified.
- Generic hex option names with encoded text/multiple URLs are no longer findings alone; PW-DB-006 requires recognized behavior in the decoded value. Custom site-wide script storage retains a narrowly scoped review.
- Database evidence uses a validated output protocol and row IDs only. Raw WP-CLI/SQL diagnostics, stored payloads, post titles, usernames, and email addresses are not forwarded into reports. Early findings survive later incomplete inspection.
- Shared check logging now returns exit 2 when report initialization or the console-log writer fails, rather than hiding logging failure behind a clean check.
- Added malicious/benign, serialization/object-rejection, pagination, budget, partial-failure, privacy, PHP 7.4 and isolated MySQL SQL integration tests. Existing unsupported-CHECK TABLE, WordPress, PHP, JavaScript, updater and private-state protections remain unchanged.
- Documented candidate scope, optional row/byte budgets, and the fact that WP-CLI bootstraps WordPress: SELECT-only inspection is not isolated from compromised MU plugins or drop-ins.

## 1.1.4 — 2026-09-07

Scoped PHP intelligence and reliable evidence release.

- Replaced whole-file/proximity matching for PW-PHP-004/005/006 with a native token-based recognizer. Comments, quoted examples, unrelated methods, overwritten variables and wrong script arguments no longer supply false evidence.
- Added ordered request-callable recognition, strict literal dispatch-allowlist handling, and same-request credential/TLS evidence with cURL handle and option tracking.
- Admin-targeted decoded browser output is REVIEW, not a claim of confirmed malware. All three PHP intelligence rules are read-only, with rule/line/behavior evidence and no generic bulk deletion prompt.
- Reused identical-content results through a bounded process-local cache without trusting paths, modification times, previous scans or plugin names.
- PHP intelligence now returns incomplete status on dependency, discovery, read, validator or evidence-output failures, retaining prior findings rather than reporting false CLEAN sections.
- Added malicious/benign, privacy, resource-boundary, runtime-failure, PHP 7.4 and SHA-256-pinned official PHP corpus tests, plus injected copies of Wordfence's real utility file.
- Existing JavaScript, packed-XOR/White-Engine, PHP quick/deep, WordPress/database, updater recovery, private-state and configuration protections remain unchanged. Coverage limits are documented in `docs/PHP-DETECTION.md`.

## 1.1.3 — 2026-09-07

Update safety, recovery, and configuration guidance.

- Validate update archives before extraction: reject unsafe paths, duplicate/conflicting entries, links, special files, unsafe PAX overrides, privileged modes, malformed headers, truncation, and excessive archive size/count. Use the installed validator, not downloaded code.
- Add HTTPS-only downloads with timeouts, required-template checks, and pre/post-install shell/PHP-helper syntax validation.
- Serialize updaters with an atomic local lock. Block new CLI scans while updating; administrators should finish existing scans first.
- Handle catchable interruptions with rollback. Keep the complete recovery workspace and lock if restoration fails instead of silently deleting the last good code copy.
- Refuse custom private data/config paths that overlap managed code and refuse symlinked managed directories.
- Add `./presswarden config-new`: list unassigned template option names without displaying values, executing shell configuration, or rewriting either file. Updates show a brief advisory when applicable.
- Limit `doctor` shell checks to distributed code, not quarantined scripts/reports; report required dependency/syntax failures with exit code 2 and check PHP/zlib update readiness.
- Add offline archive/resource-limit, interrupted/overlapping-update, recovery-preservation, configuration-privacy, and doctor-scope regressions with PHP 7.4 compatibility coverage.
- Document recovery procedures, supported archive limits, and trust/concurrency limitations in `docs/UPDATING.md`. Existing malware detection rules and private-state preservation remain unchanged.

## 1.1.2 — 2026-09-07

Detection quality and reliable scan results.

- Replaced JavaScript whole-file/proximity correlations with a bounded lexical recognizer. Comments, quoted examples, regex literals, and template text are not executable-code evidence.
- JavaScript loader/redirect recognition now tracks supported same-scope values, simple aliases, assignment order, reassignment, browser-global shadowing, and the actual inserted script object. Independent functions and minified modules do not share payload facts.
- Visitor targeting must belong to a recognized enclosing condition, not merely appear near a browser sink. Encoded HTTP URLs with visitor targeting are REVIEW, not proof of malware or campaign attribution; IP hosts receive no automatic severity increase.
- Decoded executable-URI and decoded browser-code execution patterns can still produce ALERT. A later lower-confidence match cannot downgrade an alert already detected in the same file.
- Corrected Unicode character reconstruction and nested-template/regex handling using actual upstream package cases. The recognizer is intentionally conservative, not a full ECMAScript parser or interprocedural taint engine.
- JavaScript findings include rule IDs, source lines, sink evidence, and hostnames without exposing decoded URL credentials, query strings, or payload bodies. Control characters in filenames are escaped.
- JavaScript behavioral findings no longer offer the generic bulk delete/quarantine prompt. Inspection and provenance verification come before remediation.
- Added a bounded, process-local SHA-256 result cache for identical fleet files. Cache entries contain findings metadata, not source bodies; changed contents are reanalyzed and each site's filename remains visible.
- Missing PHP, unreadable files, discovery traversal failures, and JavaScript validator failures return an incomplete result instead of a false clean verdict. JavaScript discovery uses NUL-delimited paths and includes `.mjs`/`.cjs` within the 6 MiB size scope.
- Fixed suite summaries reporting ALL CLEAR when checks failed or were missing. Failed checks, no completed checks, empty site discovery, and report-write failures now return exit 2. Deliberately skipped checks are explicitly reported as partial coverage.
- Added JSON coverage fields: `coverage_status`, `checks_completed`, `checks_skipped`, and `checks_failed`, while retaining existing report fields. Coverage describes execution of the selected checks, not universal malware-detection coverage.
- Added 50 JavaScript precision regressions, a 5.6 MB bounded-memory test, suite-error/skip tests, URL-redaction and content-cache tests, and PHP 7.4 compatibility testing.
- Added isolated, SHA-256-pinned official Elementor, Wordfence, and WordPress JavaScript corpus tests, plus actual upstream bundles with synthetic appended injections. No third-party source or signature collections are bundled into the distribution.
- Documented evidence thresholds, execution completeness, test commands, and analysis limitations in [`docs/DETECTION-QUALITY.md`](docs/DETECTION-QUALITY.md).
- Includes the preceding PHP utility-file false-positive reductions, GNU/BSD `stat` fallbacks, installed-version intelligence User-Agent, same-version code-refresh wording, and hashing/self-update readiness in `doctor`.
- Private configuration, reports, quarantine, baseline state, intelligence-provider data handling, shared-host no-process-substitution support, and the existing WordPress/PHP/database safety regressions are retained.

## 1.1.1 — 2026-09-06

Unified updater release.

- `./presswarden update` now updates both PressWarden program code and enabled threat-intelligence feeds in one maintenance workflow.
- Threat intelligence is refreshed only after the newly downloaded PressWarden code passes validation and is installed, so the refresh uses the new intelligence implementation rather than the old one.
- Program updates continue to preserve private `config/config`, reports, quarantine, baselines, caches, and existing intel state; the post-update intelligence refresh may intentionally update provider cache files under the intel state directory.
- A transient intelligence/feed/network failure does not roll back a successfully validated program update. Existing feed caches are preserved by the intelligence layer, the CLI reports the partial failure, and exits `1` so automation can detect that the refresh should be retried.
- Update source validation now requires the threat-intelligence library in addition to core runtime files.
- Expanded updater regression coverage to prove successful post-update intel refresh, safe partial failure behavior, symlink execution, obsolete-code removal, malformed-package rejection, and preservation of private state.

## 1.1.0 — 2026-09-06

Threat Intelligence and fleet-security release.

- Added `./presswarden baseline create|status|diff` plus the `./presswarden changes` shortcut for local security-state baselining and change detection.
- Baselines record SHA-256 + size for security-relevant executable/configuration files and, when WP-CLI is available, plugin/theme versions and state, administrator usernames, and cron hook/recurrence metadata.
- Baselines intentionally exclude volatile uploads, caches, logs, backups, temporary trees, and similar high-churn paths from change tracking while normal security scans continue to inspect their relevant scopes.
- Baseline manifests do not store file contents, passwords, API keys, database payloads, or other secret values; previous accepted baselines are retained locally for future history/reinfection workflows.
- Added `./presswarden incident [path]`, an evidence-first compromise/reinfection suite combining baseline changes, fleet correlation, persistence, malware detection, administrator/application-password inventory, integrity verification, vulnerability intelligence, upload checks, and database threat inspection.
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
