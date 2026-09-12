# Suite run state and interrupted scans

PressWarden records a small private state file while a suite is running so a dropped SSH session, terminal close, or catchable signal cannot be confused with a completed audit.

This applies to suite-driven commands such as `fast`, `full`, `incident`, `db`, focused `inspect` suites, and threat-intelligence scans. It does not turn quarantine, baseline activation, updates, or configuration changes into resumable jobs.

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

The equivalent status command is:

```bash
./presswarden run-status
```

Inspect a particular run ID shown in a report or previous status output:

```bash
./presswarden run-status full-20260911-202000.ABC123
```

Safely continue the latest eligible interrupted/failed run:

```bash
./presswarden continue
```

Or name the parent run explicitly:

```bash
./presswarden continue full-20260911-202000.ABC123
```

`resume` is accepted as a compatibility alias for `continue`.

`last-run` and `run-status` are read-only. `continue` starts a new suite run; it never revives the old shell process or reuses a previous remediation approval.

## What is stored

Run state is kept under the private PressWarden state directory:

```text
var/runs/
  latest
  RUN_ID/
    .lock
    state.json
    scope.json
```

The state record contains only bounded operational metadata such as:

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

Starting with 1.1.17, `scope.json` also records the private continuation boundary:

- selected scan root
- discovery depth
- exact discovered WordPress roots
- target-specific exclusions
- a SHA-256 fingerprint over that normalized scope

It does **not** store database passwords, WordPress salts, API keys, malware payload bodies, database values, or arbitrary `wp-config.php` constants.

New run directories are private. State/scope publication is atomic and refuses unsafe symlink/non-regular paths. Each run uses the already unique report run ID, so historical run records are not replaced by later runs.

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

## Safe continuation

Version 1.1.17 adds fail-closed suite continuation. PressWarden starts a **new** run, carries only the parent's contiguous completed prefix, and reruns the first unfinished check from the beginning before continuing with the rest of the original plan.

Before carrying anything, PressWarden requires:

- the same PressWarden version;
- complete original discovery;
- the same suite and exact check plan;
- fresh discovery of the exact same WordPress roots;
- the same root, discovery depth, and target-specific exclusions.

If any of those boundaries changed, PressWarden refuses to combine the two audits and tells the operator to run the suite again.

Runs created before 1.1.17 cannot be continued because they do not contain the required `scope.json` evidence. A currently active `RUNNING` record is never continued. A stale RUNNING record is eligible only when process liveness can be checked and its recorded PID is no longer active.

The write-capable `wp-db-maintenance` check is deliberately not replayed if it was the interrupted check. Its repair/optimization operations may have partly completed before the disconnect, so the operator must run a fresh DB or Full suite explicitly. Other checks restart from current live state, and any interactive remediation requires fresh confirmation and existing quarantine/revalidation safeguards.

See [Safe suite continuation](CONTINUATION.md) for the complete rules and limitations.
