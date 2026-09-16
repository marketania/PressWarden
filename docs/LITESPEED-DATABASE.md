# LiteSpeed database maintenance

## Integrated DB maintenance (1.1.23+)

```bash
./presswarden db example.com
./presswarden db
```

The existing `db` suite still runs database security/isolation checks and stored-threat inspection. Its maintenance step now supports:

```text
CHECK TABLE → REPAIR proven failures only
            → authorized LiteSpeed optimize_all OR native OPTIMIZE TABLE
            → FINAL CHECK TABLE
```

The same maintenance step is part of `full`. `fast`, `incident` and focused intelligence inspections do not add LiteSpeed cleanup. Unresolved/unknown table health prevents the cleanup/optimization stage; an unsupported CHECK operation is informational, not corruption.

### Consent and backups

LiteSpeed `optimize_all` performs content cleanup in addition to table optimization. Depending on the plugin's version/settings, this includes revisions, drafts/trash, spam/trashed comments, trackbacks/pingbacks and transients. **Keep a current, restorable database backup. PressWarden does not create a database backup or promise rollback for this operation.**

`PRESSWARDEN_DB_LITESPEED` controls only cleanup inside `db`/`full`:

| Value | Behavior |
|---|---|
| `ask` (default) | One explicit prompt in an interactive terminal. No terminal, no answer or a declined prompt skips LiteSpeed but keeps native maintenance. |
| `on` | Explicit authorization to clean eligible sites, including unattended runs. |
| `off` | Native table maintenance only; no LiteSpeed content cleanup. |

Set it in your private config or for one invocation:

```bash
PRESSWARDEN_DB_LITESPEED=on ./presswarden db example.com
PRESSWARDEN_DB_LITESPEED=off ./presswarden db all
```

`PRESSWARDEN_INTERACTIVE=0` alone does not authorize the newly integrated cleanup. Existing unattended native-maintenance jobs therefore do not silently start deleting revisions/transients after an update. The direct `litespeed-db optimize` command remains an explicit cleanup request and preserves its existing noninteractive authorization convention.

### Eligibility and results

If LiteSpeed is active and `optimize_all` is available, authorized cleanup runs once. Successful LiteSpeed cleanup already includes table optimization; PressWarden does not repeat native OPTIMIZE afterward. If LiteSpeed is missing or inactive, native optimization remains available.

An active plugin with unavailable database CLI support is not silently treated as successful cleanup: native fallback may finish, but maintenance returns INCOMPLETE (2). A failed LiteSpeed execution can have partially cleaned data; it is not retried under another name, and final table verification still runs where possible. Native runtime/verification/optimization failures also return INCOMPLETE. Proven unresolved table errors remain actual findings, not generic tool failures.

Native SQL maintenance now selects tables matching the WordPress prefix (the network base prefix for native multisite maintenance), rather than every table in the database. Use distinct, non-overlapping prefixes for separate installations. Plugin-managed cleanup retains the installed LiteSpeed version's own table-selection behavior.

## Standalone commands and aliases

These status commands are equivalent and do not request cleanup:

```bash
./presswarden litespeed-db status example.com
./presswarden litespeed database status --target example.com
```

`status` belongs to PressWarden. It probes a real command, `optimize_all`, and never invokes `wp litespeed-database status`. Older/incompatible LiteSpeed versions can still correctly report the actual optimization command unavailable; PressWarden does not install, activate or update plugins automatically.

These default-blog cleanup commands share preflight, confirmation, progress and size reporting:

```bash
./presswarden litespeed-db optimize example.com
./presswarden litespeed database optimize-all --target example.com
```

Targets use normal website/directory/fleet discovery and exclusions. Preflight distinguishes READY, SKIP (missing/inactive plugin), and ERROR (bootstrap or command unavailable). Each slow stage announces its site and progress before running; execution shows OPTIMIZED/FAILED, elapsed time and bounded plugin output.

Actual cleanup is always invoked from the site's directory:

```bash
wp litespeed-database optimize_all
```

No `--path`, `--skip-plugins`, `--skip-themes` or other default globals are added to LiteSpeed's database family. Ordinary read-only preflight/measurement commands use normal WP-CLI globals. WordPress/plugin bootstrap can itself have side effects; a read-only PressWarden action means no cleanup was requested, not that unrelated application code cannot write anything.

## Statistics and interruptions

Size measurements use WordPress's existing database connection and `information_schema.tables`, limited to a matching table prefix. They do not require `wp db size`, an external MySQL client or PHP `proc_open`. Unavailable/ambiguous measurements are reported as unavailable, not zero. Unchanged or increased allocation after cleanup is possible: these figures are not exact deleted-row counts or guaranteed disk reclamation.

Ctrl+C during preflight reports that no LiteSpeed cleanup was started. During execution it warns that completed work remains and the current site may be partially cleaned. Database operations are not automatically rolled back or replayed.

## WordPress multisite

Integrated and standalone optimization enumerate active multisite blogs, validate the entire list before any cleanup, and pass each blog ID explicitly to LiteSpeed. A partial failure is not network-wide success. Native maintenance uses the network base prefix; allocation statistics are omitted for multisite.

For a deliberate blog-specific cleanup:

```bash
./presswarden litespeed database optimize-all --blog=2 --target example.com
```

PressWarden validates a positive, existing, active multisite blog ID before dispatch. Invalid, deleted, archived or spam blog IDs and single-site installations are refused. It does not promise protection against unrelated changes racing after the final validation.

## Scheduled maintenance

Example weekly integration after testing one site and arranging current backups:

```cron
0 3 * * 0 PATH="$HOME/.local/bin:/usr/local/bin:/usr/bin:/bin" PRESSWARDEN_INTERACTIVE=0 PRESSWARDEN_DB_LITESPEED=on /path/to/presswarden db all >> "$HOME/presswarden-db-cron.log" 2>&1
```

This is an example only; PressWarden does not install a cron job. Adjust the executable, cron timezone, PATH and private log destination for the hosting account. Native CHECK/REPAIR/OPTIMIZE and LiteSpeed cleanup can take locks; choose an appropriate maintenance window and do not overlap jobs. Omitting the LiteSpeed opt-in preserves native maintenance only.

Upstream references: [LiteSpeed CLI](https://docs.litespeedtech.com/lscache/lscwp/cli/) and [database operations](https://docs.litespeedtech.com/lscache/lscwp/database/).

## Compatibility with 1.1.22

The `PRESSWARDEN_LITESPEED_DB_MAINTENANCE=0` suite opt-out remains supported. In 1.1.23 the cleanup runs inside native maintenance after table health checks, rather than as a separate preceding suite step. `PRESSWARDEN_DB_LITESPEED=ask|on|off` controls consent; `ask` is the default. An explicit legacy opt-out overrides this policy.

Whole-network cleanup from 1.1.22 is retained: active blog IDs are enumerated and fully validated before the first cleanup, then revalidated before each `optimize_all blog ID`. Partial failures report the completed/failed blog scope; no network-wide success is claimed. Integrated cleanup uses the same path. Allocation statistics remain omitted for multisite.
