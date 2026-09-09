# Reports and focused rechecks

## Focused inspection

```bash
./presswarden inspect php [directory]
./presswarden inspect js [directory]
./presswarden inspect db [directory]
```

Use these to retest a finding without running unrelated checks. `php` runs only `php-threat-intel` (PW-PHP-004/005/006); `js` runs `js-threat-intel`; `db` runs `wp-db-malware`. These are fixed mappings, not arbitrary script execution. Discovery, optional directory selection, exclusions, existing analysis budgets and evidence verdicts remain unchanged. An omitted directory uses the normal configured/portable root. Invalid modes or extra arguments return 2; no discovered sites is incomplete, not clean.

These checks offer no generic file-removal prompts, do not refresh vulnerability feeds and do not run database maintenance. They are a focused subset, not a replacement for `fast`, `full`, `incident` or `intel scan`. They still create normal reports/cache entries. Database inspection still boots WordPress through WP-CLI: plugins skipped by WP-CLI do not constitute a sandbox for MU plugins, configuration or drop-ins. The check's own SELECT-only queries do not prevent bootstrap side effects. See [database scope](DATABASE-SCANNING.md).

`inspect runtime [website or directory] [--details]` adds a focused PHP-environment check in 1.1.9. Website names work for all inspection modes; see [site targets and compact PHP output](SITE-TARGETS.md). Runtime checks may use optional php.net/hosting API lookups but do not load WordPress or refresh vulnerability feeds.

## Names, privacy and preservation

Starting with 1.1.6, each check and suite reserves a random-suffixed run identifier. The existing flat layout is retained, for example:

```text
var/reports/
  inspect-js-20260907-120000.AbC123.log
  inspect-js-20260907-120000.AbC123-summary.json
  inspect-js-latest-summary.json
  js-threat-intel-20260907-120000.DeF456.log
  js-threat-intel-20260907-120000.DeF456-findings.log
```

The `.log` and `*-findings.log`/`*-deletions.log` conventions remain. Empty detail/deletion logs from this invocation are removed as before. No old reports are deleted, renamed or migrated. Consumers should use returned paths, `run_id`, glob patterns or the existing latest alias rather than constructing an exact filename from a second-resolution timestamp. Suite `run_id` identifies the suite's own report set; child checks have distinct identifiers and are not a parent/child tracing system.

New report files are created with owner-only access (0600 or stricter). Newly created report directories are private (0700 or stricter). Existing directories/files are not recursively chmodded. The caller's umask is restored/unchanged, so this does not change site repair permissions. Previously generated reports may still have their original permissions; place reports outside a public web root. Filesystem permissions do not protect against the same account, privileged users, configured ACLs or an administrator serving files through a web server.

## JSON publication and automation

Per-run JSON is fully staged beside its destination and published with an atomic no-replace hard link. The old `SUITE-latest-summary.json` alias is updated with a same-directory rename only after valid complete JSON is available. Both operations use local filesystem primitives, not copying over a live alias. This requires a filesystem and PHP setup that permits local file linking/rename. Publication errors are explicit; no fallback writes over a historical report.

An existing symlink, directory or special-file destination is refused. The symlink and its target are left untouched. Normal concurrent readers of the latest alias see the previous complete JSON or the new complete JSON, not an in-progress copy. With simultaneous scans, whichever publishes last becomes latest; start-time ordering is not promised. Read `generated_at`, `run_id`, `root` and `coverage_status` before acting on an alias. A failed publication leaves an older latest alias in place and returns 2, so the alias alone does not prove that the most recent command succeeded.

Existing JSON fields are preserved; `run_id` is additive. `exit_code`/`coverage_status` describe the scan and console-writing stage available when that JSON was generated. A subsequent latest-alias publication failure can make the final CLI exit code 2 even though the retained unique JSON describes completed checks. Automation must also check the command's exit status.

A failure to save finding details marks the check incomplete and suppresses its generic file-action prompt. Console findings/counts remain visible up to the configured display cap; the tool no longer claims the hidden remainder was saved. This does not replace configuration-specific remediation workflows elsewhere in the application.

Reports are not signed forensic evidence or durable transactional storage. Same-account filesystem races, hostile ancestors, full disks, process termination and power loss remain limitations. Report directories and the executing account must be trusted. Atomic publication is not an fsync/power-loss durability guarantee. Uncatchable termination can leave empty private reservation directories or temporary staged files; this update does not automatically delete them.

## Regression tests

```bash
php tests/report-json.php
bash tests/report-preservation.sh
bash tests/inspect.sh
```

The tests use temporary fixtures, simultaneous publishers/readers, deliberately fixed timestamps, unsafe preexisting destinations and injected writer failures. No live client sites or databases are used.
