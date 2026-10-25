# Evidence and explicit security remediation

In a terminal, a security scan asks `Remediate now? [y/N]` right after each section whose findings this workflow can handle, once those findings are printed and saved; default No. Without a terminal, or with `PRESSWARDEN_INTERACTIVE=0`, scans never prompt or remove files and print the `remediate files` command instead. `presswarden remediate files TARGET` enables interactive, default-skip prompts for eligible file findings from the PHP/upload threat checks and the public exposure check (`.env`/credential files, keys, database/config backup artifacts, VCS metadata and public logs). Exposed items are quarantined, so the copy is kept as evidence; key material may still be in use by the host or a plugin. It retains the original snapshot-based quarantine engine: selected scope and exclusions, protected files, bounded file/directory handling, private allocation, hashes, revalidation, write verification and failure journals. Link/special-file/race or incomplete-discovery conditions are not treated as permission to delete. Review findings require investigation; they are not automatic malware verdicts.

`quarantine list` and `quarantine verify CASE_ID` inspect generic evidence cases without changing website content. Verification checks the retained evidence and metadata, not whether a live website is fully recovered or free of malware. Do not publish private evidence or config/database backups. Toolkit state and evidence must be outside public webroots. Keep independent offline/site backups and the incident timeline.

## Retention

`quarantine prune --older-than=DAYS` is a manual retention step. Without `--apply` it only previews. A case is eligible only when its name is older than the cutoff, its stored objects match the manifest, and its removal is recorded complete. Every other case is kept and listed with the reason. With `--apply` in a terminal, the operator types `prune`; eligibility is recomputed and must equal the previewed set exactly. Each case is renamed to a `.pruning-` work name before removal, so a partial removal is never listed or verified as a case. Each removed case is appended to `prune-log.tsv`. Pruning never runs automatically and does not touch live sites, core-restore copies or reports. Keep an offline copy while an incident is open.

## Core files

`presswarden remediate core TARGET` is a separate terminal-only operation because generic quarantine protects core. It offers exact-version/locale restoration only for failed official core checksums, or evidence-first removal of extra files under `wp-admin` and `wp-includes` that are absent from the manifest. A host/plugin may intentionally add an extra file; the operator must judge it. `wp-content`, `wp-config.php` and unrelated paths are not replaced.

Every original is copied to a private directory and hash-verified before the first action. A per-site lock coordinates this tool's writers. Source identity is rechecked before replacement/removal; replacement is staged, published atomically where the local filesystem supports rename, then checksum-verified. Recovery and status manifests are in `state/backups/core-restore/` and `core-extras/`; they are not generic quarantine case IDs. A partial or unverified result keeps copies and fails; it does not claim an automatic rollback over a concurrent edit. Missing core directory trees are refused rather than reconstructed blindly. Preserve the recovery directory, inspect its manifest and restore deliberately after checking current file identities.

## No maintenance deletion

The former disposable-metadata quarantine mode has been removed. Routine file cleanup belongs to PressGarden's separate bounded preview/backup/execute workflow. PressGarden does not import this evidence engine, erase incident cases or treat maintenance as malware removal. Current logs and suspicious cleanup candidates are preserved.

## Limits

These are user-space administration tools, not a hostile-kernel or malicious-same-user isolation boundary. Cooperating writers are locked; WordPress, hosting jobs and other tools may still change files. Validation narrows races but cannot make a multi-file website transaction globally atomic. Interrupted or mixed-success remediation must be investigated, and followed by a fresh security scan.
