# Press family source ownership inventory

Pinned source: `marketania/PressWarden@63adec182b4d3a20dbd5e24daa9b9fa0e98510b8` (1.1.24).

Every tracked source file is classified before product extraction. Mixed files are split by capability, not blindly moved.

| Source file | Owner | Decision |
|---|---|---|
| `.github/workflows/auto-update-quality.yml` | HARDEN | Policy CI, with unrelated scan-state assertions left in Warden. |
| `.github/workflows/baseline-quality.yml` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `.github/workflows/ci.yml` | SHARED/REIMPLEMENT | Separate mixed workflow responsibilities; independent validation per product. |
| `.github/workflows/config-transaction-quality.yml` | HARDEN | Policy CI, with unrelated scan-state assertions left in Warden. |
| `.github/workflows/db-quality.yml` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `.github/workflows/detection-quality.yml` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `.github/workflows/finding-history-quality.yml` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `.github/workflows/litespeed-db-quality.yml` | GARDEN | Maintenance CI without security-suite coupling. |
| `.github/workflows/litespeed-full-quality.yml` | GARDEN | Maintenance CI without security-suite coupling. |
| `.github/workflows/php-quality.yml` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `.github/workflows/progress-quality.yml` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `.github/workflows/quarantine-quality.yml` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `.github/workflows/report-quality.yml` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `.github/workflows/run-state-quality.yml` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `.github/workflows/update-quality.yml` | SHARED/REIMPLEMENT | Separate mixed workflow responsibilities; independent validation per product. |
| `.github/workflows/ux-quality.yml` | SHARED/REIMPLEMENT | Separate mixed workflow responsibilities; independent validation per product. |
| `.github/workflows/wp-settings-quality.yml` | HARDEN | Policy CI, with unrelated scan-state assertions left in Warden. |
| `.gitignore` | SHARED/REIMPLEMENT | Product-specific entry points, docs/config, installers and namespaces; retain original MIT provenance. |
| `CHANGELOG.md` | SHARED/REIMPLEMENT | Product-specific entry points, docs/config, installers and namespaces; retain original MIT provenance. |
| `CONTRIBUTING.md` | SHARED/REIMPLEMENT | Product-specific entry points, docs/config, installers and namespaces; retain original MIT provenance. |
| `LICENSE` | SHARED/REIMPLEMENT | Product-specific entry points, docs/config, installers and namespaces; retain original MIT provenance. |
| `README.md` | SHARED/REIMPLEMENT | Product-specific entry points, docs/config, installers and namespaces; retain original MIT provenance. |
| `SECURITY.md` | SHARED/REIMPLEMENT | Product-specific entry points, docs/config, installers and namespaces; retain original MIT provenance. |
| `VERSION` | SHARED/REIMPLEMENT | Product-specific entry points, docs/config, installers and namespaces; retain original MIT provenance. |
| `checks/baseline-changes.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `checks/confcheck.sh` | WARDEN+HARDEN | Keep inert configuration evidence; migrate debug/lock mutations to transactional setters. |
| `checks/doctor.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `checks/external-yara.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `checks/file-mods.sh` | HARDEN | Intentional configuration policy. |
| `checks/filesystem-security-full.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `checks/filesystem-security.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `checks/fleet-correlate.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `checks/host-persistence.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `checks/htcheck.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `checks/js-threat-intel.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `checks/litespeed-db.sh` | GARDEN | Explicit maintenance/performance operations. |
| `checks/litespeed.sh` | GARDEN | Explicit maintenance/performance operations. |
| `checks/php-obfuscated-loader.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `checks/php-runtime.sh` | WARDEN+HARDEN | Read-only PHP threat visibility may overlap; provider configuration comparison belongs to Harden. |
| `checks/php-threat-intel.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `checks/phpcheck.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `checks/phpdeep.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `checks/phpquick.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `checks/sensitive-files.sh` | WARDEN+GARDEN | Keep exposure evidence; move disposable metadata and archived-log cleanup to Garden. |
| `checks/wp-access.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `checks/wp-auto-updates.sh` | HARDEN | Intentional configuration policy. |
| `checks/wp-campaign-intel.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `checks/wp-core.sh` | WARDEN | Core integrity and explicit evidence-first incident remediation; no repair from routine scan. |
| `checks/wp-db-maintenance.sh` | GARDEN | Explicit maintenance/performance operations. |
| `checks/wp-db-malware.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `checks/wp-db.sh` | WARDEN+HARDEN | Keep DB threat/credential isolation; move authentication/cache salt rotation to Harden. |
| `checks/wp-patchstack-intel.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `checks/wp-plugin-integrity.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `checks/wp-plugins.sh` | WARDEN+GARDEN | Retain plugin/MU threat inspection; move cache coverage to Garden status. |
| `checks/wp-root.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `checks/wp-settings.sh` | HARDEN | Intentional configuration policy. |
| `checks/wp-themes.sh` | GARDEN | Routine theme coverage inventory, not malware detection. |
| `checks/wp-uploads-deep.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `checks/wp-uploads.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `checks/wp-vulnerabilities.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `checks/wp-wordfence-intel.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `config/config.example` | SHARED/REIMPLEMENT | Product-specific entry points, docs/config, installers and namespaces; retain original MIT provenance. |
| `docs/ARCHITECTURE.md` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `docs/AUTO-UPDATES.md` | HARDEN | Configuration operator documentation. |
| `docs/BASELINES.md` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `docs/CONFIG-TRANSACTIONS.md` | HARDEN | Configuration operator documentation. |
| `docs/CONTINUATION.md` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `docs/DATABASE-SCANNING.md` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `docs/DETECTION-QUALITY.md` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `docs/FINDING-HISTORY.md` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `docs/LITESPEED-DATABASE.md` | GARDEN | Maintenance operator documentation. |
| `docs/LITESPEED.md` | GARDEN | Maintenance operator documentation. |
| `docs/PHP-DETECTION.md` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `docs/PROGRESS.md` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `docs/QUARANTINE.md` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `docs/REPORTS.md` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `docs/RUN-STATE.md` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `docs/SITE-TARGETS.md` | SHARED/REIMPLEMENT | Independent installation/discovery/update documentation. |
| `docs/UPDATING.md` | SHARED/REIMPLEMENT | Independent installation/discovery/update documentation. |
| `docs/WP-SETTINGS.md` | HARDEN | Configuration operator documentation. |
| `install.sh` | SHARED/REIMPLEMENT | Product-specific entry points, docs/config, installers and namespaces; retain original MIT provenance. |
| `integrations/README.md` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `intel/README.md` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `intel/SOURCES.md` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `intel/campaigns.tsv` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `intel/native-rules.tsv` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `lib/_lib.sh` | SHARED/REIMPLEMENT | Keep scanner runtime in Warden; compose smaller independent operations runtimes in siblings. |
| `lib/_runner.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `lib/baseline-capture.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `lib/baseline-csv.php` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `lib/baseline.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `lib/config-options.php` | SHARED/REIMPLEMENT | Independently adapt bounded generic runtime; no runtime import from siblings. |
| `lib/config-transaction-shell.sh` | HARDEN | Configuration policy and safe transactional mutation. |
| `lib/config-transaction.php` | HARDEN | Configuration policy and safe transactional mutation. |
| `lib/config-transaction.sh` | HARDEN | Configuration policy and safe transactional mutation. |
| `lib/db-report.php` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `lib/db-scan-cli.php` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `lib/db-scan.php` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `lib/db-threat-classify.php` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `lib/db-values.php` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `lib/env-discovery.sh` | SHARED/REIMPLEMENT | Independently adapt bounded generic runtime; no runtime import from siblings. |
| `lib/finding-history.php` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `lib/finding-history.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `lib/intel.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `lib/js-flow.php` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `lib/js-threat-cli.php` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `lib/json-object-stream.php` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `lib/litespeed-db-state.php` | GARDEN | Measured LiteSpeed DB state. |
| `lib/php-environment.php` | WARDEN+HARDEN | Read-only PHP threat visibility may overlap; provider configuration comparison belongs to Harden. |
| `lib/php-flow.php` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `lib/php-threat-cli.php` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `lib/progress.php` | SHARED/REIMPLEMENT | Independently adapt bounded generic runtime; no runtime import from siblings. |
| `lib/progress.sh` | SHARED/REIMPLEMENT | Independently adapt bounded generic runtime; no runtime import from siblings. |
| `lib/quarantine-cli.php` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `lib/quarantine.php` | WARDEN+GARDEN | Retain evidence transaction in Warden; remove maintenance eligibility, separately implement bounded Garden cleanup with backups. |
| `lib/quarantine.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `lib/remediation.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `lib/report-json.php` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `lib/reports.sh` | SHARED/REIMPLEMENT | Independently adapt bounded generic runtime; no runtime import from siblings. |
| `lib/run-continuation.php` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `lib/run-continuation.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `lib/run-state.php` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `lib/run-state.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `lib/site-target.php` | SHARED/REIMPLEMENT | Independently adapt bounded generic runtime; no runtime import from siblings. |
| `lib/site-target.sh` | SHARED/REIMPLEMENT | Independently adapt bounded generic runtime; no runtime import from siblings. |
| `lib/suite-summary.php` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `lib/ui.sh` | SHARED/REIMPLEMENT | Independently adapt bounded generic runtime; no runtime import from siblings. |
| `lib/update-guard.php` | SHARED/REIMPLEMENT | Independently adapt bounded generic runtime; no runtime import from siblings. |
| `lib/update.sh` | SHARED/REIMPLEMENT | Independently adapt bounded generic runtime; no runtime import from siblings. |
| `lib/wordfence-match.php` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `lib/wp-policy-runtime.php` | HARDEN | Configuration policy and safe transactional mutation. |
| `lib/wp-policy-summary.php` | HARDEN | Configuration policy and safe transactional mutation. |
| `lib/wp.sh` | SHARED/REIMPLEMENT | Independently adapt bounded generic runtime; no runtime import from siblings. |
| `presswarden` | SHARED/REIMPLEMENT | Product-specific entry points, docs/config, installers and namespaces; retain original MIT provenance. |
| `suites/db.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `suites/fast.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `suites/full.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `suites/incident.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `suites/inspect.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `suites/intel.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `tests/baseline-coverage.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `tests/baseline-csv.php` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `tests/baseline-transactions.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `tests/baseline.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `tests/config-advice.sh` | SHARED/REIMPLEMENT | Separate mixed CLI fixtures; retain ownership-specific safety contracts. |
| `tests/config-transaction.sh` | HARDEN | Migrate policy/transaction fixtures and assertions. |
| `tests/db-mysql.php` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `tests/db-runtime.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `tests/db-scan.php` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `tests/db-values.php` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `tests/discovery-reliability.sh` | SHARED/REIMPLEMENT | Separate mixed CLI fixtures; retain ownership-specific safety contracts. |
| `tests/doctor-scope.sh` | SHARED/REIMPLEMENT | Separate mixed CLI fixtures; retain ownership-specific safety contracts. |
| `tests/filesystem-progress.py` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `tests/finding-history.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `tests/fleet-correlate.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `tests/incident.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `tests/inspect.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `tests/intel-security.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `tests/js-flow.php` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `tests/js-memory.php` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `tests/litespeed-db.sh` | GARDEN | Migrate LiteSpeed command/counter fixtures; add backup failure cases. |
| `tests/litespeed-full-cli.sh` | GARDEN | Migrate LiteSpeed command/counter fixtures; add backup failure cases. |
| `tests/php-environment-runtime.sh` | HARDEN | Migrate policy/transaction fixtures and assertions. |
| `tests/php-environment.php` | HARDEN | Migrate policy/transaction fixtures and assertions. |
| `tests/php-flow.php` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `tests/php-intel-runtime.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `tests/php-memory.php` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `tests/php-upstream.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `tests/progress-terminal.py` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `tests/progress.php` | SHARED/REIMPLEMENT | Separate mixed CLI fixtures; retain ownership-specific safety contracts. |
| `tests/quarantine-interruption.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `tests/quarantine-runtime.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `tests/quarantine.php` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `tests/report-json.php` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `tests/report-preservation.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `tests/run-continuation.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `tests/run-state.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `tests/runtime-reliability.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `tests/site-lock.sh` | HARDEN | Migrate policy/transaction fixtures and assertions. |
| `tests/site-target.php` | SHARED/REIMPLEMENT | Separate mixed CLI fixtures; retain ownership-specific safety contracts. |
| `tests/site-target.sh` | SHARED/REIMPLEMENT | Separate mixed CLI fixtures; retain ownership-specific safety contracts. |
| `tests/smoke.sh` | SHARED/REIMPLEMENT | Separate mixed CLI fixtures; retain ownership-specific safety contracts. |
| `tests/suite-progress.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `tests/threat-intel-regressions.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `tests/update-guard.php` | SHARED/REIMPLEMENT | Separate mixed CLI fixtures; retain ownership-specific safety contracts. |
| `tests/update-hardening.sh` | SHARED/REIMPLEMENT | Separate mixed CLI fixtures; retain ownership-specific safety contracts. |
| `tests/update.sh` | SHARED/REIMPLEMENT | Separate mixed CLI fixtures; retain ownership-specific safety contracts. |
| `tests/upstream-corpus.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `tests/upstream-corpus.sha256` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `tests/wordfence-stream.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `tests/wp-auto-updates.sh` | HARDEN | Migrate policy/transaction fixtures and assertions. |
| `tests/wp-policy-runtime.php` | HARDEN | Migrate policy/transaction fixtures and assertions. |
| `tests/wp-policy-summary.sh` | HARDEN | Migrate policy/transaction fixtures and assertions. |
| `tests/wp-settings.sh` | HARDEN | Migrate policy/transaction fixtures and assertions. |
| `tests/yara-integration.sh` | WARDEN | Retain security detection, evidence, intelligence, reporting, fixtures or supporting documentation. |
| `uninstall.sh` | SHARED/REIMPLEMENT | Product-specific entry points, docs/config, installers and namespaces; retain original MIT provenance. |
