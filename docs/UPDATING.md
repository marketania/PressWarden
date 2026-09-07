# Updating PressWarden safely

## Normal upgrades

Finish running scans first, then run:

```bash
cd ~/PressWarden
./presswarden update
./presswarden --version
./presswarden doctor
```

Program code is updated first, followed by enabled threat-intelligence feeds. No API key, root access, PATH change, or system-wide directory is required. The updater needs PHP CLI with zlib, tar, and curl or wget. `doctor` reports readiness.

Your real `config/config`, reports, quarantine, baselines, and runtime state are not in the code replacement set. `config/config.example` is updated as a reference. Enabled intelligence caches can change during the subsequent feed refresh; a feed failure retains the new program and returns `1` so you can retry `./presswarden intel update`.

Custom configuration/state locations inside distribution-managed paths such as `lib/`, `checks/`, `intel/`, or `docs/` are refused rather than erased. Keep custom rules and evidence in `var/` or outside the program tree; `intel/` contains distributed native rules, while `var/intel/` contains local feed data. Symlinked managed directories or a symlinked program `config/` directory are refused. A private config file at an external path remains supported.

## New settings without overwriting your config

```bash
./presswarden config-new
```

This command lists template option names that are not explicitly assigned in the saved config. They are optional overrides, not necessarily options introduced in the last release or settings that need to be filled in. It never displays values, writes either file, or executes the config. A broken shell config can therefore still be compared. Use `PRESSWARDEN_CONFIG_FILE` in the environment to select another saved file.

The comparison recognizes simple assignment names, including `export NAME=value`. It does not evaluate shell conditionals, multiline values, sourced files, or environment overrides. Review the template and add only the overrides you need; do not copy it over your private config.

## What the updater validates

Starting with 1.1.3, the installed validator checks the entire archive before extraction into a private staging directory. It rejects traversal/absolute/control-character paths, multiple archive roots, duplicate/conflicting entries, symlinks, hardlinks, device/sparse files, privileged modes, unsafe PAX overrides, invalid headers, truncation, and nonzero trailing archive content. GitHub-style USTAR archives and non-overriding PAX time/comment metadata are supported; arbitrary tar extensions are not.

Limits are 32 MiB compressed, 128 MiB expanded, 16 MiB per member, and 10,000 headers. Required components and the public config template must be present. Distributed shell scripts and PHP helpers are syntax-checked before replacement and again after installation. Download clients enforce HTTPS and network timeouts.

These checks validate structure and installation safety, **not the trustworthiness of upstream code**. A trusted repository/ref and a trusted local installation remain prerequisites. There is no signature verification claim. The one-time bootstrap installer and older updater versions are separate: the new checks apply when the installed updater is 1.1.3 or later.

## Update locks and interruptions

An atomic `.presswarden-update.lock/` directory prevents overlapping updater processes. Its `pid` and `workspace` files describe the operation. New CLI scans refuse to start while a lock exists; scans already running are not stopped or protected from an update. Schedule updates between scans. Directly invoking individual check scripts bypasses this CLI guard.

A private `.presswarden-update.XXXXXX/` workspace is created beside the installation, not in a system temporary directory. Catchable HUP, INT, or TERM interruptions during replacement trigger an attempt to restore the complete old-code backup. A normal copy/validation failure uses the same recovery path. Successful rollback removes the workspace and lock.

If rollback fails, PressWarden reports **ROLLBACK INCOMPLETE** and keeps both the recovery workspace and lock. It never discards the only complete recovery copy merely because restoration failed. SIGKILL, power loss, disk failure, and concurrent changes by the same operating-system user cannot be made transactional by Bash; they may leave a partial installation and require manual recovery.

## Manual recovery

Do not immediately delete an update lock. First confirm that no updater is running; a PID alone can be stale or reused. Inspect the `workspace` path recorded in the lock and preserve that directory. A `backup/.complete` marker indicates that the old managed-code backup finished before replacement began.

When code restoration is necessary, restore only the distribution-managed paths from that complete backup after resolving disk/permission problems. Do not copy a downloaded `config/config` or `var/` into the live installation. After restoring and checking the code, remove the lock only when no updater is running. Run the restored CLI and `doctor` before deleting the retained backup/workspace; `doctor` is intentionally blocked while a lock remains. When the workspace never reached a complete backup or code replacement, verify the current code before clearing the lock and retrying.

Updates of Git development checkouts are refused by default; use your Git workflow there. A retained workspace is not a permanent version-history feature, and routine successful updates remove their rollback copies.
