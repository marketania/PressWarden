# LiteSpeed Database Maintenance

PressWarden supports both focused LiteSpeed database cleanup and automatic integration with its write-capable database-maintenance suites.

## Focused commands

Check which discovered sites can use LiteSpeed database optimization:

```bash
presswarden litespeed-db status [target]
```

Run LiteSpeed Cache's full database cleanup/optimization:

```bash
presswarden litespeed-db optimize [target]
```

`target` follows normal PressWarden targeting: a website name, nested website name, directory, `all`, or the configured fleet when omitted.

## DB and FULL suite integration

`presswarden db` and `presswarden full` now run the same `litespeed-db` maintenance implementation immediately before PressWarden's native SQL table check/repair/optimization step.

The automatic step:

- runs only where LiteSpeed Cache is installed, active, and exposes `litespeed-database optimize_all`;
- skips sites without an active LiteSpeed Cache plugin;
- runs installations sequentially to limit load;
- reports active-plugin/command/bootstrap failures as incomplete maintenance rather than false success;
- continues to native table maintenance even when one independent LiteSpeed site fails.

Disable only the automatic suite step with:

```bash
PRESSWARDEN_LITESPEED_DB_MAINTENANCE=0 presswarden db
```

The explicit `litespeed-db optimize` command remains available even when that suite setting is disabled.

## Exact command behavior

For a normal single-site installation, PressWarden changes into the WordPress directory and runs exactly:

```bash
wp litespeed-database optimize_all
```

LiteSpeed's database command family is the exception to its usual WP-CLI behavior and does not accept ordinary global parameters. PressWarden never appends `--path`, `--skip-plugins`, `--skip-themes`, `--skip-packages`, or `--no-color` to the real cleanup command.

`presswarden litespeed database status` is a PressWarden-only inventory action. It validates the real `optimize_all` subcommand and never tries to execute or request help for a nonexistent `litespeed-database status` command.

## Multisite

Before changing a multisite installation, PressWarden obtains all blog IDs with the built-in WP-CLI site inventory, validates the complete list, and then runs:

```bash
wp litespeed-database optimize_all blog ID
```

once for each validated ID. If the inventory is empty, malformed, or cannot be read, no blog cleanup starts and the installation is reported as an error. If one blog fails during execution, already-completed blog cleanups remain complete and the partial result is reported explicitly.

The lower-level umbrella command still permits a deliberately selected blog:

```bash
presswarden litespeed database optimize-all --blog=2 --target example.com
```

## Reporting

Preflight and execution display `[current/total]` progress. Successful runs show the number of completed blog scopes, elapsed time, bounded LiteSpeed output, and best-effort database allocation before and after cleanup.

Allocation figures are not deleted-row counts. MySQL may retain allocated space after rows are removed, and normal activity can make the measured database grow during maintenance. A successful cleanup may therefore report no size reduction.

## Safety behavior

Focused interactive optimization requires confirmation. `PRESSWARDEN_INTERACTIVE=0` is treated as intentional automation. The `db` and `full` commands are already explicit write-capable maintenance suites, so their internal LiteSpeed step does not prompt a second time.

An interrupted `litespeed-db` suite step is non-replayable through `presswarden continue`, just like `wp-db-maintenance`. Run a fresh `db` or `full` suite after reviewing the database state.

## Scheduled cleanup

Weekly maintenance is a reasonable starting point for many managed sites. A focused Sunday 3:00 AM example is:

```cron
0 3 * * 0 PATH="$HOME/.local/bin:/usr/local/bin:/usr/bin:/bin" PRESSWARDEN_INTERACTIVE=0 /path/to/presswarden litespeed-db optimize all >> "$HOME/.local/state/presswarden/litespeed-db-cron.log" 2>&1
```

To schedule the complete database security and maintenance workflow instead, substitute `presswarden db all`. Confirm WP-CLI and the desired PHP binary are available in the cron environment before enabling fleet execution.
