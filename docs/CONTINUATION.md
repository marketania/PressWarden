# Safe suite continuation

PressWarden 1.1.17 can continue an interrupted suite without rerunning checks that already completed successfully in the same audit chain.

```bash
./presswarden continue
./presswarden continue RUN_ID
```

`resume` is accepted as a compatibility alias, but `continue` is the documented command.

## What continuation means

Continuation does **not** revive a killed shell process. It starts a new PressWarden run and links it to the interrupted parent logically:

1. Read the parent's private run-state and scope snapshot.
2. Require the same PressWarden version.
3. Require complete original discovery.
4. Restore the stored root, discovery depth, and target-specific exclusions.
5. Fresh-discover WordPress installations.
6. Require the exact same selected-site scope and check plan.
7. Carry only the parent's contiguous completed prefix (`clean`, `findings`, or `skipped`).
8. Rerun the first unfinished check from the beginning against current live state.
9. Run the remaining checks normally.

Carried checks are visible as `▶ CARRY` and are included in the new suite summary without being re-executed. The new JSON summary identifies the parent run with `continued_from` and records `checks_carried`.

## Refusals are deliberate

PressWarden refuses continuation when:

- the PressWarden version changed;
- original discovery was incomplete;
- the selected WordPress roots changed;
- target-specific exclusions or discovery depth changed;
- the suite/check plan changed;
- the parent run already completed;
- a RUNNING parent still appears active;
- process liveness cannot be proven for a stale RUNNING record;
- completed results are not a clean contiguous prefix;
- the interrupted step is `wp-db-maintenance`;
- the run predates 1.1.17 and therefore lacks the required scope snapshot.

These refusals prevent two different audits from being silently combined.

## Why database maintenance is special

`wp-db-maintenance` can automatically repair genuinely unhealthy tables and runs `OPTIMIZE TABLE`. If the shell disappears during that write-capable step, PressWarden cannot prove exactly which database operation completed before interruption. It therefore refuses to replay that step through `continue`.

Run a fresh `db` or `full` suite explicitly after reviewing the database state.

## Remediation in other checks

Some checks can offer interactive remediation. A continuation never replays a previous approval. The interrupted check is rescanned from the current live state and any action requires fresh confirmation and the existing quarantine/revalidation safeguards.

## Scope metadata

Each new suite run stores a private 0600 `scope.json` next to its run-state. It contains only operational scope metadata such as the root, discovery depth, selected WordPress paths, target-specific exclusions, and a SHA-256 fingerprint. It does not contain WordPress credentials, salts, API tokens, malware payloads, or database values.

## Limitations

A continuation is not an atomic snapshot of the server. Websites may legitimately change between the parent and continuation. PressWarden guarantees compatible scanner version/scope/check-plan boundaries and reruns the unfinished check, but remaining checks observe the live state when they execute.

`SIGKILL` cannot be trapped. A stale `RUNNING` record is only continuation-eligible when process liveness can be checked and the recorded PID is no longer active; otherwise PressWarden refuses and recommends a fresh run.
