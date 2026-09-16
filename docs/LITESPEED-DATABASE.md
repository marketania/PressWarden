# LiteSpeed Database Maintenance

PressWarden provides an explicit maintenance action for WordPress sites using the LiteSpeed Cache plugin.

## Commands

Check which discovered sites can use LiteSpeed database optimization:

```bash
presswarden litespeed-db status [target]
```

Run LiteSpeed Cache's full database cleanup/optimization:

```bash
presswarden litespeed-db optimize [target]
```

`target` follows the normal PressWarden targeting rules: a website name, nested website name, directory, `all`, or omit the target for the configured fleet.

## What PressWarden runs

For each eligible site, PressWarden changes into that WordPress installation's directory and runs exactly:

```bash
wp litespeed-database optimize_all
```

LiteSpeed documents the `litespeed-database` command family as not accepting normal WP-CLI default/global parameters. For that reason PressWarden intentionally does **not** append `--path`, `--skip-plugins`, `--skip-themes`, `--skip-packages`, or `--no-color` to the LiteSpeed command itself.

PressWarden may use ordinary WP-CLI commands with normal global parameters during preflight to verify that WordPress is readable and LiteSpeed Cache is installed and active.

## Safety behavior

Before changing a database, PressWarden performs a per-site preflight and reports one of these states:

- `READY` — WordPress is readable, LiteSpeed Cache is active, and `litespeed-database optimize_all` is available.
- `SKIP` — LiteSpeed Cache is not installed or is installed but inactive.
- `ERROR` — WordPress/WP-CLI could not bootstrap or LiteSpeed Cache is active but the expected CLI command is unavailable.

Interactive runs require one confirmation before any eligible database is changed. Fleet automation must be intentional by setting `PRESSWARDEN_INTERACTIVE=0`.

Optimization runs sequentially rather than in parallel to keep database load conservative on shared hosting and multi-site fleets.

This command is separate from PressWarden security scans. `fast`, `full`, and `incident` do not silently run LiteSpeed database cleanup.

It is also separate from PressWarden's native database maintenance. The native DB maintenance checks/repairs/optimizes SQL tables; LiteSpeed `optimize_all` additionally performs LiteSpeed Cache's configured cleanup operations such as WordPress revisions, drafts/trash, transients, and related database cleanup.

## Scheduled cleanup

For most maintained WordPress sites, weekly cleanup is a reasonable starting cadence. Do not run database cleanup every few minutes or unnecessarily every day.

Example weekly cron entry for Sunday at 3:00 AM:

```cron
0 3 * * 0 PATH="$HOME/.local/bin:/usr/local/bin:/usr/bin:/bin" PRESSWARDEN_INTERACTIVE=0 /path/to/presswarden litespeed-db optimize all >> "$HOME/.local/state/presswarden/litespeed-db-cron.log" 2>&1
```

Adjust the PressWarden path and `PATH` for the hosting account. WP-CLI must be available to the cron environment.

Before scheduling fleet-wide execution, run:

```bash
presswarden litespeed-db status all
```

and then perform one manual optimization run to confirm the hosting environment behaves as expected.

## WordPress multisite

LiteSpeed's database command supports an optional `blog <id>` argument. Without it, LiteSpeed uses its default blog behavior. PressWarden currently warns when multisite is detected and does not claim that one `optimize_all` invocation cleaned the entire network.

This conservative behavior avoids reporting network-wide maintenance that was not actually verified.
