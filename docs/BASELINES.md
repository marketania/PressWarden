# Reliable baselines and change comparisons

A baseline records observed state. It is not proof of cleanliness, an operator approval certificate, or a complete forensic image. Review a site before using its current state as a reference.

```bash
./presswarden baseline create [path]
./presswarden baseline status [path]
./presswarden changes [path]
```

## Complete-or-refuse capture

Version 1.1.8 records file, plugin, theme, administrator and cron coverage separately for each selected installation. A successful command with a validated header and zero rows is an empty inventory. An unavailable WP-CLI command, nonzero exit, missing header, invalid CSV, failed hash/read/traversal or changed file identity is not an empty inventory.

A failed capture cannot replace `current`. Comparisons are deliberately all-or-nothing: no deltas are emitted unless both snapshots have validated manifests, the same selected sites/exclusions/capture policy, and the same captured categories. One failed category stops this baseline comparison; other incident-suite checks can still run. A missing installation or an intentional exclusion change is incomparable scope, not evidence that all its files/users were removed. Reconcile the scope before explicitly accepting a new reference with `baseline create`.

Without WP-CLI, a new file-only baseline is permitted and clearly labeled. It can be compared to another file-only capture without requiring PHP. When WP-CLI is present, its inventories must succeed and PHP CLI is required to validate their CSV. Losing WP-CLI cannot silently downgrade an existing baseline that contains runtime state. Restore availability before recreating that reference. Runtime inventory acquisition still loads WordPress: MU plugins, configuration and drop-ins are not sandboxed, even with `--skip-plugins`.

Legacy baselines do not have coverage records or policy hashes. Their completeness cannot be reconstructed reliably. `status`, comparisons and correlation therefore report unknown/incomplete coverage until the administrator explicitly recreates the baseline after reviewing the current state. Recreation preserves the old directory in history. Updating PressWarden itself never migrates, rewrites or recreates baselines.

## Scope and stored data

The existing executable/configuration file selection and volatile-directory exclusions remain. Fresh discovery is forced for each capture; its traversal errors are consumed by the baseline gate rather than cached as a complete result. This is not a broader discovery-cache/security rewrite for every scanner check. Existing discovery depth/pruning still limits the selected installations.

A nested installation belongs to its own site label, not also its parent's file manifest. Discovered excluded sites and scanner/report/cache/quarantine directories below a site are pruned from that site's capture. File candidates use NUL delimiters. Paths containing control characters cannot be represented safely in the existing TSV format and make capture incomplete, not silently absent. No source file is included or executed by the file hasher.

Manifests contain file SHA-256/size and the existing low-sensitivity runtime fields: plugin/theme names, local activation status and version, administrator login names, and cron hook/recurrence. They contain no file contents, passwords, API keys or database payloads. The private inventory workspace may temporarily contain raw WP-CLI stdout, which could include bootstrap diagnostics; it is removed on normal/catchable exit. Forced termination can leave private temporary data. This is not secure erasure.

The CSV reader validates exact headers, recognized plugin/theme states and delimiter-safe fields. Quoted commas/quotes are preserved. Supported repeated cron hooks are compared as sorted JSON arrays of recurrence strings (so embedded commas cannot collide with multiple schedules), not individual event instances: arguments, callback sources, event counts and next-run times are not captured. Reader limits are 8 MiB input/output per inventory, 50,000 rows, 64 KiB per record and 2,048 bytes per field. Exceeding a limit fails the capture; there is no silent truncation.

`meta.tsv` uses format 2 and includes SHA-256 values for `manifest.tsv`, `coverage.tsv` and `scope.tsv`. Hashes catch accidental inconsistency, not a same-user attacker who can replace both the manifest and metadata. File hashing checks metadata/identity before and after reading, but a capture is not an atomic filesystem/database snapshot. Simultaneous site updates, unreadable files and untrusted WordPress output can affect it. Stop maintenance before capturing a reference; the host account, interpreter, tools and filesystem ancestors must be trusted.

## Preservation and recovery

New captures/workspaces use private permissions in a scoped subprocess; the calling shell's umask and older directory/file permissions are not changed. Absolute, non-symlink baseline state paths are required. Historical reports and snapshots are never overwritten or pruned by these commands. New change TSV reports have unique random-suffixed names and no-replace publication; report writer failures return 2.

Readers and writers for the same root use `.baseline.lock`. A competing command refuses to proceed instead of reading half-activated state. On successful recreation the old directory is moved to a uniquely reserved `history/snapshot-TIMESTAMP.RANDOM/snapshot/`, then the staged new directory becomes `current`. Cooperating commands are locked during this two-rename sequence; it is not a single atomic directory replacement.

If activation fails with `current` absent, a catchable exit attempts to put the preserved prior snapshot back. If recovery fails, or activation is unconfirmed, the previous snapshot, staging workspace and lock are retained. A first-generation activation failure can also retain its staged capture and lock. No command silently removes a stale/recovery lock or guesses which historical baseline to use.

For manual recovery, first establish that no baseline command is still running. Preserve the retained workspace and history. Inspect the current/staged/prior directories; never overwrite an existing `current` or discard the only old snapshot. If `current` is absent, an administrator may restore the intended preserved snapshot to that empty location. Remove the empty lock directory only after reconciling state, then run `baseline status` to validate the selected snapshot. A surviving lock alone cannot distinguish an active process from forced termination. A power failure or uncatchable kill can leave unconfirmed state; there is no fsync/durability, signed-evidence or hostile-same-user race guarantee.

Exit 0 means the requested capture/status/comparison completed (for comparison, no deltas). Exit 1 from comparison means reviewable changes, not malware; `status` uses 1 when no baseline exists. Exit 2 means failure, incomplete or incomparable evidence. Missing baseline context remains optional in the incident/fleet checks as before; an existing but invalid baseline is an error.

## Regression tests

```bash
php -d memory_limit=64M tests/baseline-csv.php
bash tests/baseline-coverage.sh
bash tests/baseline-transactions.sh
bash tests/baseline.sh
bash tests/fleet-correlate.sh
bash tests/incident.sh
```

All fixtures are temporary. Tests simulate failed/malformed inventories, loss of dependencies, changed scope, nested/excluded sites, hash/identity errors, corrupted/legacy snapshots, concurrent commands, failed activation/restoration, interruptions, and report publication failure. No live client installation is used.
