# Finding history

PressWarden 1.1.19 adds structured observation history for security findings produced by suite checks. History is evidence correlation, not a malware verdict and not a compromise timeline.

## States

- **NEW** — this finding identity was not active in the previous comparable structured history snapshot. `NEW` means first observed by this history stream, not that the file/account/payload was newly created.
- **RECURRING** — the same finding identity and fingerprint were observed again.
- **CHANGED** — the same stable finding identity was observed again, but its bounded fingerprint changed. This does not identify who or what changed it.
- **RESOLVED** — a previously active finding was absent after a trustworthy comparable recheck of the check that owned it.
- **NOT RECHECKED** — PressWarden cannot safely decide whether the prior finding persists because coverage, capture integrity, version comparability, overlap, or the owning check was insufficient.

`RESOLVED` never means PressWarden necessarily removed or repaired the finding. It only means the prior observation was absent under the documented comparison conditions.

## Resolution is fail-closed

PressWarden may mark a prior finding `RESOLVED` only when all of these are true:

1. The current run belongs to the same suite and exact scope fingerprint.
2. WordPress discovery for the current run was complete.
3. Structured history capture for the run was complete and internally consistent with the check finding counts.
4. The check that owned the prior finding completed as `clean` or `findings`; skipped, missing, failed, or unknown checks cannot resolve anything.
5. The current run does not overlap the previous finalized history run.
6. The previous history snapshot was produced by the same PressWarden version. The first run after a version change may carry observations forward, but unmatched prior findings are `NOT RECHECKED` until another comparable run under the new version.

If any condition fails, absence becomes `NOT RECHECKED`, not `RESOLVED`.

## Stable identities

History uses a bounded identity rather than storing complete finding bodies.

For file-backed findings the identity is based on:

- check name
- stable rule ID when available (otherwise a deterministic scanner-section key)
- website label
- path relative to that WordPress installation

The fingerprint uses file SHA-256 for regular files up to the documented size bound plus relevant mode/severity context. Large files and non-regular objects use bounded metadata/evidence fingerprints.

Database history uses only the controlled rule/site/row locator already emitted by the database validator. Stored database values are not copied into history.

Generic non-file evidence is represented by a digest. The raw evidence line is not stored in `history.json`.

## Continuations

`./presswarden continue` starts a new linked run. Completed checks carried from the interrupted parent also carry their structured observation records into the child. The interrupted run itself never advances the finalized history pointer.

The continuation run compares against the last valid finalized history snapshot for the same suite and scope.

## Storage

History is private PressWarden state:

```text
var/
  runs/
    RUN_ID/
      observations/
      capture-errors/
      site-map.json
      history.json
  history/
    index/
      <suite-scope-key>.json
```

New directories are private and JSON files are owner-only subject to stricter caller permissions. Historical `history.json` reports are no-replace. The current comparison pointer is serialized with a per-stream PHP `flock()` and updated atomically.

History is bounded to protect shared hosting resources. It stores no database passwords, WordPress salts, API keys, payload bodies, arbitrary wp-config values, or complete generic evidence strings.

## Commands

Show the latest finalized suite history:

```bash
./presswarden history
```

Show a specific run:

```bash
./presswarden history RUN_ID
```

The command is read-only. It does not discover websites, bootstrap WordPress, run WP-CLI, or modify history.

Interrupted/running runs do not publish resolution history. Use `./presswarden last-run` / `run-status` for their execution state, and `./presswarden continue` where safe.

## Limitations

Finding history begins when 1.1.19 structured observations are captured; old text reports are not retroactively parsed into authoritative identities. A detector/section that lacks a stable locator can still be tracked using a digest identity, but `CHANGED` semantics are strongest for stable file/database locations.

History classifies PressWarden observations. It does not prove compromise time, attacker identity, infection mechanism, or causal remediation.
