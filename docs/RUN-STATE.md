# Suite run state and interrupted scans

PressWarden records a small private state file while a suite is running so a dropped SSH session, terminal close, or catchable signal cannot be confused with a completed audit.

This applies to suite-driven commands such as `fast`, `full`, `incident`, `db`, focused `inspect` suites, and threat-intelligence scans. It does not turn destructive operations such as quarantine, baseline activation, updates, or configuration changes into resumable jobs.

## Status values

A suite run can end as:

- `COMPLETED` — the suite finished and its normal exit code was recorded. A completed run may still contain findings.
- `INCOMPLETE` — the suite reached its normal finalization path but one or more checks, discovery, report writes, or run-state writes were incomplete.
- `INTERRUPTED` — PressWarden received `HUP`, `INT`, or `TERM` before the suite finalized.
- `FAILED` — the suite process exited unexpectedly without using its normal finalization path.
- `RUNNING` — no final marker has been written yet. `run-status` may also show whether the recorded PID appears active when the PHP POSIX extension is available.

`SIGKILL` cannot be trapped by any application. If the host kills PressWarden with an uncatchable signal, the state file can remain `RUNNING`. When process liveness can be checked and the recorded PID is gone, `run-status` explicitly tells the operator to treat that record as interrupted/abandoned. PID reuse means a positive liveness observation is advisory, not proof that the original process is still the same run.

## Commands

Show the most recently started suite run:

```bash
./presswarden last-run
```

The equivalent command is:

```bash
./presswarden run-status
```

Inspect a particular run ID shown in a report or previous status output:

```bash
./presswarden run-status full-20260911-202000.ABC123
```

These commands are read-only. They do not discover websites, bootstrap WordPress, modify site content, or create a new report.

## What is stored

Run state is kept under the private PressWarden state directory:

```text
var/runs/
  latest
  RUN_ID/
    state.json
```

The record contains only bounded operational metadata such as:

- PressWarden version
- run ID and suite name
- root path
- start/update/finish times
- current check and suite position
- selected check names
- per-check completion state, finding count, and elapsed seconds
- discovery completeness
- site/group counts
- signal and exit code when applicable
- the corresponding suite report-log path

It does **not** store database passwords, WordPress salts, API keys, malware payload bodies, database values, or arbitrary `wp-config.php` constants.

New run directories are private. State publication is atomic and refuses unsafe symlink/non-regular state paths. Each run uses the already unique report run ID, so historical run records are not replaced by later runs.

## SSH disconnects

An SSH disconnect commonly sends `SIGHUP` to the foreground job. PressWarden records the active suite check as `INTERRUPTED` before exiting when that signal reaches the suite runner.

Example:

```text
PRESSWARDEN RUN STATUS

RUN        full-20260911-202000.ABC123
SUITE      full
STATUS     INTERRUPTED
CURRENT    [12/28] wp-plugins
SIGNAL     HUP
NOTE       This run did not complete. Partial reports may still contain useful validated evidence.
```

The finding/report files produced before interruption remain useful evidence, but the interrupted suite must not be treated as a completed security audit.

## No automatic resume yet

Version 1.1.16 deliberately does not add automatic `resume` behavior. Replaying a partially completed suite safely requires stronger compatibility checks for scanner version, selected checks, discovery scope, exclusions, and any stateful/destructive step.

For now, use `last-run` to identify where the suite stopped, then rerun the affected read-only check or rerun the suite. PressWarden prefers a trustworthy rerun over mixing incompatible evidence from two executions.
