# Targeted database evidence

PressWarden 1.1.5 inspects candidate `options`, `posts`, and current-blog administrator role metadata through the existing WordPress database handle. SQL issued by this check is SELECT-only: no repair, deletion, normalization or option updates. The broader `db` and `full` suites still contain their separate maintenance checks; this does not change those workflows.

## How evidence is classified

Independent strings within serialized arrays/JSON, widget fields, script elements, and iframe handlers remain separate. The existing scoped JavaScript recognizer analyzes supported browser flows. A remote script in one field and a decoder in another cannot establish a relationship. HTML comments, non-JavaScript script types, raw-text elements and nested templates do not provide executable script evidence.

- `PW-DB-001`: supported decoded browser behavior; stronger decoded execution/executable targets can be ALERT, visitor-targeted encoded HTTP behavior is REVIEW.
- `PW-DB-002`: hidden remote iframe with recognized decoded behavior in its own event handler, REVIEW. Normal analytics/video frames and unrelated hidden page elements are not enough.
- `PW-DB-003`: external scripts in known site-wide `header_scripts`, `footer_scripts`, `custom_scripts` or `custom_js` options, REVIEW. An intentional integration may explain this.
- `PW-DB-004`: suspicious identity on metadata containing the top-level `administrator` role key, REVIEW. A published identity indicator is not proof of unauthorized ownership. No identity values are printed. WordPress derives roles from role keys, so a false value alone is not interpreted as reliable removal of inherited permissions.
- `PW-DB-005`: stored PHP with a supported execution argument containing request/decode evidence, REVIEW. Storage does not prove that a plugin executes it.
- `PW-DB-006`: 32-hex option name with a base64 value containing recognized browser behavior, REVIEW. A hash-like name, long blob or list of URLs alone is insufficient.

These rules cannot delete/quarantine code or modify rows. Findings identify the site, rule, source table category and numeric row ID, not post titles, option values, usernames, emails, source bodies or decoded URLs. More than one matching rule per row can be retained.

## Bounded reads and completeness

Candidate queries use a text prefilter, ordered primary-key pagination and batches of at most 16 rows. Nonstandard table prefixes and the current blog's capability key are respected. The check does not enumerate every blog in a multisite network or inspect arbitrary third-party tables/postmeta.

Defaults per WordPress installation:

```bash
PRESSWARDEN_DB_MAX_ROWS=5000       # per source: options, posts, administrator metadata
PRESSWARDEN_DB_MAX_BYTES=33554432  # 32 MiB across fetched values in that installation
```

These optional overrides can be added to private config; updates do not insert them automatically. Allowed ranges are 1–50,000 rows and 1,024–268,435,456 bytes. A single value above 1 MiB is not fetched and is reported as incomplete. A lookahead query distinguishes exactly-at-limit scans from those with remaining candidates. Limits bound fetched data/analysis, not database query execution time: text prefilters may still examine many database rows.

Query/read/bootstrap errors, unsupported serialized types, malformed candidate data, analysis limits, failed evidence output or absent completion records produce INCOMPLETE and exit 2. Findings already emitted are retained where available. Other sites continue. Healthy sites are summarized instead of producing a success line per site. The output-protocol reader has an 8 MiB cap; unusually large finding streams are incomplete rather than silently truncated.

A completed result covers the selected candidates and recognized patterns, not the entire database, a transactional snapshot, full PHP/JavaScript interpretation or a clean-site guarantee. Dynamic/custom encodings, cross-field flows and arbitrary PHP execution paths remain outside this recognizer. The complementary filesystem/integrity checks remain important.

## Stored values and trust boundaries

The native reader handles ordinary serialized scalars and arrays with explicit byte, depth and node limits. It does not call `unserialize()` or `maybe_unserialize()`, instantiate serialized objects, resolve references, run payloads or contact decoded URLs. Unsupported object/reference forms are incomplete inspection, not malware verdicts. See PHP's [unserialize security warning](https://www.php.net/manual/en/function.unserialize.php).

Raw WP-CLI/bootstrap output is captured in a private temporary workspace, filtered through a strict record protocol, and removed on normal completion or catchable interruption. Only controlled failure codes are reported, never exception messages or raw SQL. Forced termination/power loss can leave private temporary files; this is not a secure-erasure guarantee.

**WP-CLI still loads WordPress.** `--skip-plugins` does not skip MU plugins, and configuration/drop-in/bootstrap code can run before this helper. These changes do not make a compromised WordPress runtime a trusted or isolated forensic reader. A malicious runtime can affect query results or output. On a severely compromised host, inspect an isolated copy or use a separately trusted forensic database connection. See [WP-CLI eval-file parameters](https://developer.wordpress.org/cli/commands/eval-file/) and [WordPress role derivation](https://developer.wordpress.org/reference/classes/wp_user/get_role_caps/).

## Validation

```bash
php -d memory_limit=64M tests/db-values.php
php -d memory_limit=64M tests/db-scan.php
bash tests/db-runtime.sh
```

The Database Quality workflow also runs PHP 7.4 and real MySQL SQL integration using temporary tables in an isolated CI service. Fixtures cover unrelated scripts/widgets, nested templates, inert serialized values, object rejection, role keys, results beyond the old 1,000-row cutoff, exact/exceeded limits, retained early findings, protocol failures and private diagnostics. Existing database maintenance and detection regressions remain enabled. No live client database is used by these tests.
