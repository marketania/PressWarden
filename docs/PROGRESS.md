# Progress during long checks

PHP intelligence, JavaScript intelligence, and targeted database inspection now show a compact progress line in a normal SSH terminal. It works in `fast`/`full`/`incident`/`intel scan` when those checks run, and in focused `inspect php|js|db` commands. It is display only: detector scope, thresholds, caches, findings, exit codes and remediation behavior are unchanged.

```text
    Collecting files | roots visited: 12/85 | example.com | 0m 8s
    PHP: 57% | 24,804/43,509 files processed | 4m 18s
```

The examples are illustrative. A single line is refreshed in place, at most once every two seconds between phase boundaries. The existing suite `[9/20]` label remains the check position, not a claim that 45% of the scan's time has elapsed.

## What the numbers mean

- Collection shows roots visited, not a file percentage. Parent trees can contain nested installations, so root counts need not equal the installation count in the banner.
- PHP and JavaScript use the already-built NUL-delimited path list for the denominator. Counting it does not traverse the websites again or reread source bodies. Processed files include lightweight screening, reused identical-content results, and failed attempts; the final coverage/verdict still determines whether analysis succeeded. Files outside the existing check scope are not included.
- Database progress counts selected installations attempted and shows the current site. It does not count database rows or estimate progress inside a running query. An incomplete site's attempt can advance the counter without making that site clean.
- Unknown totals show counts rather than a made-up percentage. PHP/JS only display their final 100% when their helper completes the expected list without errors; partial discovery suppresses percentage completion. The scan can still report findings or a later reporting failure. 100% is not a CLEAN verdict.

Counters and elapsed time update between files/roots/sites. They do not animate while a single blocking file read, parser call or WP-CLI operation is executing. There is no background monitor or time-remaining estimate. Other checks retain their existing output; this release does not attach fake percentages to operations that do not expose measurable work units.

## Controls and private reports

Progress is on automatically when the original console is a terminal, a controlling `/dev/tty` is usable and TERM is not `dumb`. Suite logging pipelines preserve that decision. It is quiet in cron, redirected nonterminal sessions and restricted shells without a usable terminal. Normal scans still run when progress cannot be displayed.

Turn it off for one command:

```bash
PRESSWARDEN_PROGRESS=0 ./presswarden inspect php all
```

Or set `PRESSWARDEN_PROGRESS=0` in private `config/config`. The default is `auto`; `1` requests display through an available controlling terminal even when the original streams are redirected. It never creates a progress log or requires a pseudo-terminal in automation. No config edit is required to enable the default behavior. Updates replace only the example template, not private configuration.

Transient progress goes directly to the controlling terminal. It does not enter saved console logs, finding records, helper stdout/stderr protocols or JSON reports. Terminal session-recording tools can of course capture what is displayed. Fixed labels, numbers and sanitized site labels are used; source bodies, credentials and database payloads are never displayed. Width is bounded to the initial terminal size; resize the terminal before starting for best results.

The implementation adds no runtime Python, background processes, process substitution, /dev/fd access, extra database queries or new API requests. Python is used only for pseudo-terminal regression tests. Optional progress does not install traps or change existing signal behavior. An interrupted phase can leave a transient line on screen, but cannot leave a monitor process behind.

## Tests

`python3 tests/progress-terminal.py` exercises real pseudo-terminals, logging pipelines, percentages, throttling, missing/disabled terminals, unusual names and unchanged findings/JSON. `php tests/progress.php` checks optional operation without a terminal, including PHP 7.4. All fixtures are temporary; no live website or database is accessed.
