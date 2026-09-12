# Changelog

All notable changes to PressWarden are documented here.

## 1.1.19 — 2026-09-12

Structured finding history with fail-closed resolution semantics.

- Add per-suite structured observation history with NEW, RECURRING, CHANGED, RESOLVED and NOT RECHECKED states. These are scan-observation states, not compromise/remediation timestamps or attacker attribution.
- Capture issue/review findings centrally before remediation using stable check/rule/site/relative-path identities where possible, bounded fingerprints, controlled database row locators, and digests for generic evidence. Raw generic evidence, database values, credentials, salts and payload bodies are not stored in history reports.
- Permit RESOLVED only after trustworthy comparable coverage: same suite/scope stream, complete discovery, internally complete finding capture, successful owning-check recheck, non-overlapping runs, and comparable PressWarden version. Skipped/failed/missing checks, capture mismatch, version transition, overlap or incomplete discovery produce NOT RECHECKED instead.
- Keep prior NOT RECHECKED findings active so a partial run cannot make evidence disappear. History capture-count mismatches fail closed and do not advance the comparison pointer.
- Integrate safe continuation by copying structured observations for carried completed checks into the new child run. Interrupted/running runs never publish resolution history or advance finalized comparison state.
- Add read-only `history [RUN_ID]`, private no-replace per-run history JSON, an atomic per-suite/scope pointer serialized with PHP flock, resource bounds, symlink/non-regular refusal and PHP 7.4 regressions.
- Preserve malware thresholds, verified quarantine, complete-or-refuse baselines, safe continuation, transactional wp-config mutations, updater recovery and shared-host portability.

## 1.1.18 — 2026-09-11

Transactional wp-config mutation hardening.

- Replace three independent wp-config backup/write paths with one shared transaction layer for lock/unlock, supported `wp-settings set` mutations, and core automatic-update policy. Plugin/theme automatic-update preferences remain separate WordPress option state.
- Prepare changes on a private staged copy through WP-CLI `--config-file`, verify the exact requested value before touching the live config, then revalidate the original live identity/content immediately before same-directory atomic publication.
- Keep a unique private verified backup and bounded metadata for every real change. Exact no-op mutations succeed without creating a backup. Per-site PHP `flock()` serializes PressWarden config writers without requiring the external `flock` binary.
- Refuse symlink/hard-linked/oversized configs, replacement inodes that cannot preserve the live file's owner/group/mode, and any live source that changes during staging. External changes win rather than being overwritten.
- Verify the published bytes, mode and WordPress constant. Automatic rollback is attempted only while the live file is still exactly the bytes PressWarden published; otherwise the verified backup is retained for manual recovery.
- Make lock/unlock return INCOMPLETE (2) when any selected site mutation fails while retaining independent successful site changes. Preserve shared-host portability and add PHP 7.4, race, concurrency, privacy and existing command regressions.
- No malware thresholds, quarantine semantics, baseline/continuation behavior, updater recovery or plugin/theme preference logic changed.

## 1.1.17 — 2026-09-11

Safe continuation of interrupted suite scans.

- Add `continue [RUN_ID]` with `resume` as a compatibility alias. A continuation starts a new run, carries only the parent's completed clean/findings/skipped prefix, reruns the first unfinished check from the beginning, and executes the remaining original plan.
- Capture a private exact scope snapshot for every new suite run: selected WordPress roots, target-specific exclusions, root and discovery depth. Continuation fresh-discovers sites and refuses when the PressWarden version, suite, check plan, or scope differs. Pre-1.1.17 runs intentionally cannot be continued because they lack this compatibility evidence.
- Preserve prior findings in the combined continuation summary and expose `continued_from` / `checks_carried` in JSON. Carried checks are visibly labeled in the terminal and are not re-executed.
- Refuse continuation when the interrupted step is `wp-db-maintenance`, because that check performs automatic database writes and an interrupted write-capable step must not be blindly replayed. Other interrupted checks are rerun from current live state; any interactive remediation requires fresh confirmation/revalidation.
- Allow continuation only for INTERRUPTED/FAILED or provably abandoned RUNNING records. Completed or ordinary incomplete runs are not treated as resumable.
- Add scope mismatch, version/check-plan mismatch, old-run refusal, DB-maintenance refusal, privacy and PHP 7.4 regressions. No malware thresholds, quarantine guarantees, baseline semantics or updater behavior are weakened.

## 1.1.16 — 2026-09-11

Resilient suite run state and interruption visibility.

- Add a private atomic per-suite run-state journal keyed by the existing unique report run ID. Track the selected checks, active step, per-check result/finding count, discovery completeness, site counts, report path, timestamps, signal and final exit state without storing WordPress secrets or payload contents.
- Catch `HUP`, `INT` and `TERM` in the shared suite runner and record `INTERRUPTED` with the active check before exiting. Unexpected shell exits are recorded as `FAILED`; normal finished suites record `COMPLETED` or `INCOMPLETE`. A run-state write failure lets validated checks continue but forces the suite verdict INCOMPLETE.
- Add read-only `last-run` and `run-status [RUN_ID]` commands that do not discover sites or bootstrap WordPress. A stale RUNNING record can report that its recorded PID is no longer present when PHP POSIX support is available; uncatchable SIGKILL is never falsely described as a clean completion.
- Keep each run record bounded to allowlisted operational metadata with private run directories, 0600 atomic JSON publication, safe run IDs, symlink/non-regular refusal and a private atomic `latest` pointer. Historical run IDs are never overwritten.
- Deliberately do not add automatic resume yet: replaying partially completed suites safely requires stronger version/scope/exclusion/check-plan compatibility guarantees, especially around stateful or destructive operations.
- Add interruption, unexpected-exit, completed-run, malformed-state, symlink, privacy and PHP 7.4 regressions. Existing malware thresholds, quarantine semantics, baseline transactions, updater recovery, website targeting and shared-host portability remain unchanged.

## 1.1.15 — 2026-09-11

Quarantine stale-selection diagnostics and operator clarity.

- Preserve the exact-content approval guarantee: quarantine snapshots still bind interactive approval to the bytes that produced the finding, and any target that changes or disappears before removal still refuses the whole batch.
- Contextualize the pre-removal whole-selection revalidation so missing/unreadable targets are reported as an approved-selection change rather than an unexplained generic quarantine failure.
- State explicitly when the stale-selection failure happens before any removal starts and tell the operator to rerun the current check to refresh findings/action scope.
- Remove the redundant third shell-level INCOMPLETE line when the PHP quarantine helper already emitted controlled failure diagnostics.
- Add runtime regressions for changed content and a target disappearing after the approval snapshot; verify an unchanged sibling remains untouched and no quarantine case is created for the refused stale batch.

## 1.1.14 — 2026-09-10

Discovery completeness and cache-boundary reliability.

- Propagate partial WordPress discovery into direct-check and suite verdicts. Validated-site results still run and remain visible, but a traversal/discovery failure can no longer end as CLEAN or ALL CLEAR; suite JSON now includes `discovery_status`.
- Harden discovery-cache trust: require a bounded regular non-symlink cache, reject malformed/unknown records, validate cached WordPress roots inside the selected scan root (including canonical containment when `realpath` is available), deduplicate roots, and rebuild derived labels/tree/domain data from validated paths rather than trusting cached display metadata.
- Publish discovery cache through a private same-directory temporary file and atomic rename. Incomplete discovery is never cached, and an unsafe existing cache object is left untouched rather than followed.
- Add regressions for traversal returning partial candidates, direct-check/suite false-clean prevention, out-of-root cache poisoning, symlinked cache files, oversized cache input, private permissions, and existing runtime behavior. No malware rules, target semantics, remediation, quarantine, baseline, or WordPress policy thresholds changed.
- Add measured per-WordPress-tree progress to FULL recursive world-writable and symlink scans. Recursive traversal failures retain completed findings but make the check INCOMPLETE instead of allowing a false clean result.
- Treat permission and symlink posture findings as read-only in FAST/FULL filesystem checks; they no longer offer generic delete/quarantine remediation.

## 1.1.13 — 2026-09-10

Automatic-update reliability fixes from live fleet testing.

- Make plugin/theme auto-update enable/disable idempotent. Change only items that need changing (`--disabled-only` / `--enabled-only`) so WP-CLI does not turn already-correct items into a false batch failure. Repeated commands are successful no-ops.
- Harden preference rollback to clear only currently enabled items before restoring the saved enabled-name list. Existing per-site preference snapshots and verification remain in place.
- Keep readable standalone fleet status when one site cannot be inspected: show available results, identify the failed site and stage, retain partial detail evidence, and still return INCOMPLETE (2). Add measured site progress to this status command.
- Accept `auto-update` as a convenience alias for the canonical `auto-updates` command. Preserve website-name targeting, Fast/Full `wp-settings` integration, updater blockers, private state, detection rules and remediation behavior.

## 1.1.12 — 2026-09-09

Unified WordPress policy dashboard and fleet baseline differences.

- Add `wp-settings` for a full one-site policy view and a compact fleet baseline with only differing sites. Tied values are reported as MIXED rather than selecting an arbitrary baseline.
- Replace the separate Fast/Full auto-update inventory step with the unified `wp-settings` check; existing `auto-updates` mutation commands remain available. Policy differences are informational and do not replace dedicated security findings.
- Collect one allowlisted normalized policy record per site, covering file/editor controls, core/plugin/theme updates, updater blockers, cron/recovery, environment/development, debug/cache, retention/resources and selected configuration posture. Never emit arbitrary wp-config values, credentials, salts, API keys or source bodies.
- Add confirmed, backed-up and verified setters for editor, cron, Recovery Mode, environment, development mode, debug, FORCE_SSL_ADMIN and alternate cron. Hosting/plugin-sensitive values remain inventory-only.
- Preserve website-name targeting, exclusions, verified quarantine, baseline semantics, updater recovery, scan progress and detector thresholds.

## 1.1.11 — 2026-09-09

WordPress automatic-update policy controls and suite-wide progress context.

- Add `auto-updates status`, `auto-updates core minor|major|disabled`, and plugin/theme enable/disable actions for one website name, nested target, directory, or the full fleet. Core changes back up and verify wp-config.php; plugin/theme changes snapshot prior enabled-item preferences and verify the resulting counts.
- Add a read-only `wp-auto-updates` check to Fast and Full. Fleet output is compact; detailed per-site policy remains in the private detail report. Known global blockers are shown separately and are never silently removed.
- Add exact suite completion context to every check banner/RUN line. Existing PHP/JavaScript/database checks retain their measured inner progress; other checks show completed-check percentage rather than invented time/work estimates.
- Preserve detector thresholds, remediation policy, verified quarantine, baselines, updater recovery, website-name targeting, private configuration and branding.

## 1.1.10 — 2026-09-09

Visible progress for quiet intelligence checks.

- Show file-list collection and real processed-file percentages during PHP/JavaScript intelligence; show sites attempted/current site during database inspection. Reuse existing path lists and selected sites, without extra directory scans, source reads, queries or API requests.
- Refresh a bounded terminal-only line at most once every two seconds between work units. Keep transient output out of saved reports, evidence protocols and JSON. Sanitize site labels and retain existing logging, verdict, cache, exclusion and remediation semantics.
- Enable progress automatically in supported terminals; add optional `PRESSWARDEN_PROGRESS=0` to disable. Missing/restricted terminals, cron and ordinary nonterminal redirects remain quiet. No runtime Python, background monitors, process substitution or new dependencies for existing non-PHP workflows.
- Do not invent time estimates, row percentages or whole-suite time completion. Partial discovery/analysis cannot produce a successful PHP/JS progress completion. Other checks retain their existing output.
- Add pseudo-terminal, throttling, NUL-path count, redirection, disabled/dependency-limited display, failed analysis and unchanged report/verdict tests, plus PHP 7.4 compatibility. Private config, baselines, quarantine, website-name commands and branding remain unchanged.

## 1.1.9 — 2026-09-09

Website-name commands and compact PHP environment reporting.

- Accept local website names across commands that take a scan target: `scan example.com`, `lock example.com`, `unlock example.com`, focused inspections, baselines and more. Add `sites` to list known local names and `all` as an explicit fleet selector; existing directory arguments remain supported.
- Resolve only freshly discovered, structurally valid installations under the configured root. Recognize common domain/document-root layouts and plain WP_HOME/WP_SITEURL literals in otherwise unnamed roots without executing WordPress or contacting a website. Optional private alias files cover opaque layouts. Refuse unknown/excluded/ambiguous names rather than broadening scope.
- Preserve recursive directory semantics and carry fleet-relative nested exclusions into narrowed scans. Show nested installation counts before named lock/unlock approval. Use readable LOCKED/UNLOCKED status wording; no lock constant or backup workflow change.
- Replace the optional Hostinger PHP wall of settings/domain lists with consistency counts and differences grouped by website. Save full values, custom defaults and ranges to private reports; add `inspect runtime [target] --details` for explicit full display.
- Fix numeric-string array-key comparisons that produced outliers equal to their own baseline. Keep empty values explicit without tab-column shifts; normalize documented boolean spellings and OPCache megabyte spellings only. Group version-derived provider paths without suppressing unexpected path changes. Distinguish incomplete option coverage from consistency.
- Add parser, command-routing, name ambiguity, exclusions, no-bootstrap, compact/detail/privacy and provider-failure tests including PHP 7.4. Existing malware thresholds, quarantine, updater preservation, baselines, branding and established suite membership remain unchanged.
- Run distributed Bash entry points through Bash so website actions also work from source checkouts without executable bits.

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
