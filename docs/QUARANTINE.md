# Verified quarantine

Starting with 1.1.7, approved generic file actions and disposable-metadata cleanup use verified quarantine. Nothing is removed just because a detector matched. The existing interactive confirmation remains; skip is the default and non-interactive scans do not initiate removal. PHP CLI with the hash extension is required for these actions, not for every scanner check. There is no unverified-copy fallback.

## Before and after approval

Before offering removal, PressWarden records an ephemeral snapshot of the selected targets: SHA-256, sizes, file identities, ancestor directory identities and original metadata. This reads the targets without changing their contents. It is an **approval-time snapshot**, not the exact moment at which a detector first matched. A failed preflight refuses the whole selection. Skipping discards the temporary plan.

After approval, the action:

1. Revalidates the full selection against that snapshot, protected WordPress paths, exclusions and private scanner state.
2. Creates a unique private case, saves a manifest and copies the selected content into inertly named `.bin` objects. Symbolic links are saved as link-target **text**, never followed or recreated as live links.
3. Rereads and SHA-256-verifies every copy, rechecks the original selection, then saves a verification marker **before any source removal**.
4. Rechecks each source's identity/content and directory ancestors before removing that approved entry. Directory cleanup uses individual unlink operations and empty-directory removal, never recursive force deletion. An unexpected new child is left in place.
5. Records removal-started and removed events, with original-path mappings. A failed copy, verification, record write, changed source or removal stops the action. Available evidence is retained and the check returns INCOMPLETE (2).

If removal has already begun, a later failure can leave a partially removed selection. PressWarden does not automatically restore potentially malicious code to a website. It reports the retained case; its per-entry events and verified objects support investigation. An absent final event means the outcome is unconfirmed, not proof that a file remains or was removed.

## Read-only case inspection

```bash
./presswarden quarantine list
./presswarden quarantine verify CASE_ID
```

`list` shows up to 100 recent-format case IDs, without reading payloads. It counts legacy/unrecognized directories separately and does not rename, migrate or delete them. It inspects at most 10,000 directory entries and reports an error beyond that bound. Listing a case does not verify it.

`verify` reads only that case, never the original site or a stored link target. It checks that stored object bytes match the manifest and that the manifest matches the verification marker. Copy integrity and the recorded removal outcome are displayed separately. Exit 0 means the copies match their recorded hashes; removal may still be incomplete or unconfirmed. Missing/corrupted/unsafe case data returns 2. Old timestamp-only backups lack this manifest and cannot be verified by this command.

There is deliberately no `restore`, `purge` or `delete` subcommand. Do not execute quarantined content or restore it directly into a live site without investigating it. These commands do not discover sites, invoke WP-CLI, refresh feeds or create scan reports. The normal CLI still reads the administrator's trusted shell configuration.

## Evidence layout and privacy

```text
var/quarantine/
  case-YYYYMMDDTHHMMSSZ-random-id/
    manifest.json
    objects/00001.bin
    verified.json
    event-00001-remove-started.json
    event-00001-removed.json
    complete.json             # present only after all approved targets were removed
    incomplete.json           # best-effort failure record, when applicable
```

New cases/directories use 0700 and new files use 0600 (subject to stricter caller permissions). Files are not given source executable permissions. Original modes, owner/group IDs, timestamps and file identities are metadata in the manifest. ACLs, extended attributes and a complete forensic filesystem image are not captured. No global umask change, recursive permission change or historical-case overwrite occurs. Console output contains case IDs and counts, not source bodies. The private manifest contains original paths; the deletion report links the case and base64-encoded original paths. **Base64 is an encoding, not encryption.**

Use a quarantine location outside all served web directories. Known WordPress-site destinations and symlinked paths are refused, but PressWarden cannot infer every web-server alias or hosting route. Owner-only permissions do not protect against the same account, privileged access, ACLs or a web server intentionally serving the directory. Existing legacy quarantine permissions remain unchanged.

## Deliberate limits and trust

A selection is limited to 1,000 top-level targets, 10,000 total entries, 256 MiB of content and 64 nested levels. Manifests are bounded to 8 MiB. These are action-safety limits, not new detector limits or a guarantee of constant scan time/memory. Larger trees require smaller selections or manual handling. Generic directory actions remain restricted to VCS metadata; cleanup also recognizes its existing OS/development metadata directory names and rechecks live-Git/packaged-metadata protections. Arbitrary directories, protected WordPress files, nested WordPress roots, excluded targets, scanner state, special files and hard-linked regular files are refused. Symlink ancestors and control-character paths are refused for actions.

The source account, interpreter and filesystem ancestors must be trusted. Identity/hash checks narrow races but are **not a race-free filesystem transaction**; a hostile process with the same user can still race path operations. Reads may update access times. Forced termination can leave temporary plans or incomplete cases. Flushing and hash rereads are not an fsync/power-loss durability guarantee. Hash agreement is not a digital signature, proof of malware, or proof that the site is clean; someone who can rewrite both evidence and its manifest can forge matching hashes.

This change does not replace separate WordPress core/configuration/database repair workflows. Baseline completeness and discovery-cache hardening remain separate work, not part of this quarantine change.

## Tests

```bash
php -d memory_limit=64M tests/quarantine.php
bash tests/quarantine-runtime.sh
bash tests/quarantine-interruption.sh
```

All fixtures are temporary. Tests cover corrupted copies, changed source bytes/inodes/ancestors, partial and failed writes/removals, symlinks and special files, scope/protected paths, concurrent cases, legacy preservation and interrupted actions. No client websites or databases are modified by these tests.
