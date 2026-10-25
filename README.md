# PressWarden

<p align="center">
  <img src="docs/assets/press-tool-family.webp" alt="PressWarden blue security shield, PressHarden green policy shield, and PressGarden gold maintenance shield" width="700">
</p>

**WordPress security investigations from your terminal, with readable findings and preserved evidence.**

PressWarden helps you inspect one WordPress installation or a fleet for suspicious PHP and JavaScript, database threats, persistence, integrity changes and known vulnerabilities. Start with a narrow inspection, read its findings, and expand the investigation when you need more coverage. Ordinary scans preserve website files; deliberate recovery has its own interactive commands.

The Press family contains three independent applications. [PressHarden](https://github.com/marketania/PressHarden) manages desired-state WordPress/PHP security configuration. [PressGarden](https://github.com/marketania/PressGarden) handles maintenance and performance. Neither is a dependency of PressWarden.

**New here?** Follow [Install](#install), [Configuration, state and privacy](#configuration-state-and-privacy), then [Start with a read-only investigation](#start-with-a-read-only-investigation). Keep [the command guide](docs/CLI.md) nearby for topic help and a terminal preview.

**Version 2.0.3** asks `Remediate now? [y/N]` right after each scan step that finds removable items (default No; quarantine before removal), adds public exposure findings to `remediate files`, and adds `quarantine prune`. Version 2.0.2 added compact `scan` commands, topic help, color controls and clearer coverage reporting. See the [release notes](docs/releases/2.0.3.md). Existing installations can follow [Update, uninstall and migration](#update-uninstall-and-migration), then confirm `./presswarden version` reports `2.0.3` or newer.

## Other Press tools

PressWarden is part of the **Press Tool Family**. Other standalone tools are available for related WordPress administration tasks:

- **[PressHarden](https://github.com/marketania/PressHarden)** — WordPress hardening, security policy, `wp-config.php` controls, PHP posture, locking, and update preferences.
- **[PressGarden](https://github.com/marketania/PressGarden)** — WordPress maintenance, database health, cleanup, caching, LiteSpeed management, and performance operations.

Each tool has independent installation, configuration and state. Choose the tool for the task; none requires a sibling application.

## Install

### Requirements

Use Linux with Bash 4+, PHP CLI and standard GNU shell utilities. The installer also needs `tar`, PHP's zlib support and a download client when fetching remotely. The source-checkout example below uses Git. CI checks PHP 8.2–8.5 and retains PHP 7.4 syntax compatibility; choose an upstream-maintained, security-patched PHP runtime for actual administration. Legacy compatibility is not a recommendation to deploy PHP 7.4.

Run as the website's operating-system owner. Keep PressWarden, its private configuration, reports and evidence **outside served website directories**. Begin with a staging copy and review [the readiness and rollout guide](docs/PUBLIC-READINESS.md) before fleet-wide use. WP-CLI and optional scanners are covered [below](#optional-scanners-and-coverage); an API key is not required for the native checks.

### Recommended: install from source you selected

Choose a published tag from [Releases](https://github.com/marketania/PressWarden/releases). This example selects `v2.0.3` and installs a separate portable copy under your home directory:

```bash
mkdir -p "$HOME/src" "$HOME/tools"
git clone --branch v2.0.3 --depth 1 \
  https://github.com/marketania/PressWarden.git "$HOME/src/PressWarden"

# Review the selected source and install.sh before running it.
PRESSWARDEN_INSTALL_SOURCE="$HOME/src/PressWarden" \
PRESSWARDEN_INSTALL_PREFIX="$HOME/tools/PressWarden" \
bash "$HOME/src/PressWarden/install.sh"

cd "$HOME/tools/PressWarden"
./presswarden version
./presswarden help
```

Use new source/destination directories if those paths already exist. The installer refuses to overwrite an existing installation. Release downloads also provide `PressWarden-2.0.3.tar.gz`, `SHA256SUMS`, `SOURCE.json` and `RELEASE_NOTES.md`; an extracted, reviewed release directory can be used as `PRESSWARDEN_INSTALL_SOURCE` instead of a Git checkout.

### Alternative: follow the moving main branch

The bootstrap installer below fetches **the current `main` branch**. It does not select or pin a published release. Download and inspect the installer before executing it:

```bash
curl -fsSLo install-presswarden.sh https://raw.githubusercontent.com/marketania/PressWarden/main/install.sh
# Read install-presswarden.sh, then choose a new directory outside your websites.
PRESSWARDEN_INSTALL_PREFIX="$HOME/tools/PressWarden" bash install-presswarden.sh
```

Portable installation creates `config/config` and keeps private state under `var/`. For a user installation with separate XDG paths and a `presswarden` symlink under `~/.local/bin`, set `PRESSWARDEN_INSTALL_MODE=user`. See [updating and installation recovery](docs/UPDATING.md).

## Configuration, state and privacy

From the installed PressWarden directory, inspect the effective settings:

```bash
./presswarden config
./presswarden config-new
```

`config` displays paths and whether integrations are configured, without displaying token values. `config-new` lists template options missing from your saved configuration; it does not change the file or execute it. An ordinary Git checkout uses the user configuration path unless a portable marker or explicit override is present, so use the path printed by `config`.

Edit the **saved config file**, not `config/config.example`. For a portable installation, `config/config` already exists. Set the directory containing your WordPress sites, for example:

```bash
PRESSWARDEN_SCAN_ROOT="/home/account/domains"
PRESSWARDEN_DISCOVERY_DEPTH=8
PRESSWARDEN_EXCLUDE="example-to-skip.com example.com/old-shop"
```

Replace those example paths and labels with yours, then protect the saved file with `chmod 600 config/config`. Configuration is trusted shell code: use ordinary quoted assignments, keep credentials private, and correct syntax or loading errors before scanning. An existing unreadable, broken or invalid configuration is refused instead of silently selecting defaults. Exported `PRESSWARDEN_*` variables override saved values for that invocation.

| Data | Portable installation | User installation |
|---|---|---|
| Saved configuration | `config/config` | `${XDG_CONFIG_HOME:-~/.config}/presswarden/config` |
| State, reports, evidence and run history | `var/` | `${XDG_STATE_HOME:-~/.local/state}/presswarden` |
| Cache | `var/cache/` | `${XDG_CACHE_HOME:-~/.cache}/presswarden` |

[The configuration template](config/config.example) documents discovery limits, exclusions and integrations. `PRESSWARDEN_CONFIG_FILE`, `PRESSWARDEN_STATE_DIR` and `PRESSWARDEN_CACHE_DIR` select explicit private locations; `PRESSWARDEN_REPORTS_DIR` can move reports separately, and `config` shows its effective value. Do not put secrets, customer data, SQL dumps or findings into public issues.

## Start with a read-only investigation

### 1. Discover and inspect the intended scope

After setting your scan root, list the discovered installations:

```bash
./presswarden sites
./presswarden doctor /home/account/domains/example.com/public_html
```

Check the directory, selected installation count and any nested-site labels before scanning. A parent website can include nested WordPress installations. Select an exact nested label such as `example.com/shop`, or its explicit directory, when that is the intended scope. A directory argument is useful before configuring a fleet root:

```bash
./presswarden sites /home/account/domains
```

This lists that directory for this invocation; it does not save a new scan root. `doctor` checks local configuration, dependencies, discovery and available integration prerequisites. Its warnings explain what needs attention; it does not certify external API credentials, quota or the absence of malware.

### 2. Run a narrow first inspection

Replace this path with the intended staging WordPress directory:

```bash
./presswarden scan --runtime --target /home/account/domains/example.com/public_html
./presswarden status
./presswarden history
```

This inspection reads local PHP directive files as inert text for persistence indicators. It does not bootstrap WordPress, alter website settings or provide a complete malware assessment. The existing `./presswarden inspect runtime SITE` spelling remains supported.

### 3. Expand when the site and environment are understood

For a routine security audit, use `./presswarden scan SITE`. Use an explicit discovered label or directory first. The suite prints the selected scope, check progress, findings, run ID and report locations.

Ordinary scans are read-only **with respect to website maintenance, configuration and remediation**. They write private toolkit reports and caches. Some checks load WordPress through WP-CLI, including MU-plugin code; that bootstrap is trusted executable input, not a sandbox. For suspected compromise, start with static inspection or an isolated copy. Read-only also does not mean offline: integrity checks and enabled intelligence providers may contact external services.

## Everyday commands

Use these compact forms for everyday work. Existing spellings remain supported and are shown where useful.

| Task | Command |
|---|---|
| Routine security audit | `./presswarden scan SITE` — existing spelling: `fast SITE` |
| Deeper integrity and threat checks | `./presswarden scan --full SITE` — existing spelling: `full SITE` |
| Investigate a suspected compromise | `./presswarden scan --incident SITE` — existing spelling: `incident SITE` |
| Database threats and persistence | `./presswarden scan -db SITE` — existing spelling: `db SITE` |
| Focus on PHP, JavaScript or local PHP directives | `./presswarden scan --php SITE`, `--js SITE` or `--runtime SITE` |
| Review the latest run and finding changes | `./presswarden status` and `./presswarden history` |
| Check dependencies or list sites | `./presswarden doctor SITE` or `./presswarden sites` |
| Get task-specific instructions | `./presswarden help scan`, `help reports`, `help remediate` or `help all` |

Choose one scan mode. `--deep` aliases `--full`, and `-db` equals `--db`. Use `--target SITE` instead of a positional target when you prefer. Normal terminal output uses color; redirected output is plain. Use `--color=never`, `--color=always` or `NO_COLOR=1` as needed. [The command guide](docs/CLI.md) explains the remaining options.

## Target safety

A target is a discovered website name, a nested installation, a directory or `all`. **Omitting it selects the configured fleet.** Empty, unknown, excluded, ambiguous or duplicate targets fail rather than widening the scan. Color options cannot substitute for a missing `--target` value.

Parent selection retains intended nested installations and configured exclusions. Review `sites` output before using `all`. An explicit one-shot environment override applies only to that command unless you export it; it does not edit your saved configuration. See [target resolution](docs/SITE-TARGETS.md) for aliases, exclusions and directory rules.

## Exit codes and incomplete work

Check the scan's exit code immediately after it finishes, before running another command:

| Scan exit | Meaning | Next step |
|---|---|---|
| `0` | Selected executed checks completed without reportable findings | Read the scope and skipped-check messages before drawing conclusions. |
| `1` | Findings or review conditions | Inspect the saved details and assess applicability. A finding is an investigation lead. |
| `2` or higher | Invalid input, missing requirements, failed or incomplete work | Resolve the reported cause and repeat the affected inspection. Retained findings may still be useful. |

Operational commands have their own semantics: `doctor` returns `1` for readiness reviews, including zero discovered sites or a configured optional provider with missing tools; required dependency/syntax failures return `2`. A successful status/history display means the saved record was readable, not that the recorded scan was clean.

`SKIPPED` means that coverage was not obtained. `INCOMPLETE` means a selected operation could not establish complete coverage. Neither is a clean result. Linked, unreadable, changing or oversized core files and partial directory enumeration cannot produce a clean core-verification claim. See [scanner coverage](docs/SCANNER-COVERAGE.md) and [the refinement checkpoint](docs/REFINEMENT.md) for tested limits.

### Reports and run IDs

`./presswarden status` shows the latest suite run, its status and console-report path; `run-status` remains supported. Use the `RUN` identifier printed by the scan to select an earlier run:

```bash
./presswarden status RUN_ID
./presswarden history RUN_ID
./presswarden continue RUN_ID
```

Replace `RUN_ID` with the actual identifier. Omitting it selects the latest run; an explicitly empty, invalid or missing ID is an error. Before your first suite run, status/history explain that no record exists.

The reports directory holds console logs, detailed findings and optional JSON summaries. The state directory's `runs/RUN_ID/` holds the run journal and finalized `history.json`. Finding history distinguishes **NEW, RECURRING, CHANGED, RESOLVED and NOT RECHECKED**. Interrupted/running scans do not publish resolution history; skipped work does not establish that earlier evidence was resolved.

`continue` resumes a compatible interrupted run after checking version, scope, exclusions, inventory and the check plan. It does not restart arbitrary saved commands. Combined 1.x runs cannot resume into the security-only application; start a fresh scan after migration.

### Optional scanners and coverage

| Capability | What it needs | What to expect |
|---|---|---|
| Native PHP/JavaScript and local-file checks | Local filesystem access and the documented command dependencies | No API token is required; individual checks still have scope and resource limits. |
| WordPress database, accounts and runtime component inspection | Working WP-CLI and access to that site's database | These checks can load WordPress/MU-plugin code. Missing prerequisites do not imply a clean site. |
| Official core/plugin integrity | Relevant command dependencies and official checksum availability | Unregistered or unavailable plugin checksums leave coverage unknown. |
| External YARA | Your own readable rule file, compatible `yara`, GNU `timeout` and `realpath` | No signatures are bundled. Unconfigured rules are skipped; configured failures are incomplete. |
| WPScan | `wp`, `wpscan`, PHP, GNU `timeout`, a private token and an authorized reachable site URL | Passive remote enumeration is not a full installed-component inventory; API errors or exhausted quota are incomplete. |
| Wordfence / Patchstack / CISA intelligence | Provider-specific configuration and/or public/local feed cache | Feeds enrich investigations. Provider terms, credentials, freshness and coverage still apply. |

`doctor` checks local prerequisites without invoking those scanners or testing their APIs. `./presswarden intel status` shows feed state; `./presswarden intel update` explicitly refreshes enabled feeds. Some intelligence checks may also refresh feeds when `PRESSWARDEN_INTEL_AUTO_UPDATE=1`. Keep optional tokens in private configuration. Detailed limits and remedies are in [scanner coverage and troubleshooting](docs/SCANNER-COVERAGE.md).

## Mutations and evidence

Recovery is explicit and interactive:

```bash
./presswarden remediate files SITE
./presswarden remediate core SITE
./presswarden quarantine list
./presswarden quarantine verify CASE_ID
./presswarden quarantine prune --older-than=DAYS [--apply]
```

`remediate files` covers PHP/upload threat findings and public exposure findings: `.env` and credential files, keys, database/config backup artifacts, VCS metadata and public logs. Each section asks once; eligible items are copied to a private quarantine case and hash-verified before removal. In a terminal, `scan`, `fast`, `full`, `incident` and `db` ask the same `Remediate now? [y/N]` question right after each of those sections that has findings, once the findings are printed and saved, then continue with the next step. No or Enter changes nothing. With redirected input or `PRESSWARDEN_INTERACTIVE=0`, scans never prompt and only print the exact `remediate files` command.

`quarantine prune` previews cases older than the given number of days and deletes nothing. Only cases that verify and record a complete removal are eligible; tampered, incomplete or unrecognized cases are kept and listed. `--apply` asks for a typed `prune` in a terminal, refuses if the eligible set changed since the preview, and appends each removal to `prune-log.tsv` in the quarantine directory.

Remediation requires a terminal, and prompts default to skip. `PRESSWARDEN_INTERACTIVE=0` never approves changes. Generic file handling retains quarantine/evidence protections; critical configuration/core paths are not generic deletion targets. Core recovery verifies the exact official version/locale package and selected file identities, preserves recovery copies and reports partial outcomes.

Inspect the findings and recovery information, retain independent recoverable backups, then rescan after an approved repair. Quarantine verification is an integrity check, not an automatic restore. See [quarantine and recovery safety](docs/QUARANTINE.md). Routine cleanup belongs to PressGarden; preserve incident evidence before doing maintenance.

## Update, uninstall and migration

For a normal installed copy, finish current scans before updating:

```bash
./presswarden update
./presswarden version
./presswarden config-new
```

By default, `update` tracks **moving `main`**, then refreshes enabled security intelligence. A deliberately selected `PRESSWARDEN_REF` or `PRESSWARDEN_UPDATE_ARCHIVE` can choose another trusted distribution; see [updating and recovery](docs/UPDATING.md). An override pinned to an older tag or archive must be updated deliberately to obtain a newer release. Git development checkouts refuse the self-updater by default: manage the checkout with Git, or install a separate portable copy.

Updates preserve private configuration, reports and evidence. Uninstall removes managed program files and its own symlink while retaining private state. Moved commands print guidance and return `2`; no sibling is launched. Review [migration](docs/MIGRATION.md), [architecture](docs/ARCHITECTURE.md), and [source ownership](docs/OWNERSHIP.md) when moving from the combined 1.x product. [The old changelog](docs/CHANGELOG-1.x.md) preserves historical behavior.

### Troubleshooting the first run

| Symptom | Check next |
|---|---|
| No sites found | Confirm the root printed by `config`, directory permissions, discovery depth and exclusions. Run `sites /absolute/directory` to inspect the intended location. |
| Website label is unknown or ambiguous | Copy the exact label from `sites`, or select its explicit directory. Check nested installations. |
| Configuration error | Correct quoting and failed shell statements in the saved file. `config-new` still compares option names without executing it. |
| Configured scanner is unavailable | Follow the named dependency guidance in `doctor`; configure only integrations you intend to use. |
| Run is incomplete | Read its report and coverage messages; preserve partial findings and repeat the affected check after resolving the cause. |
| Update/recovery lock is present | Follow [the recovery procedure](docs/UPDATING.md); preserve its recorded workspace until the previous operation is understood. |
| A documented command is missing | Check `version` and `help`. Update to 2.0.2 or newer for the compact interface; check whether a saved ref or archive override pins an older source. |

## Advanced and legacy commands

Existing `fast`, `full`, `incident`, `db` and `inspect php|js|db|runtime` commands remain available. `inspect db` is the narrower database-malware recheck; `db`/`scan -db` selects the broader database security suite. Baselines and correlation remain separate tasks: `baseline create|status|diff`, `changes` and `correlate`. A full security scan does not perform database maintenance, cache purges, cleanup or policy changes. Use `help all` and [the command guide](docs/CLI.md) for the complete reference.

## Development and provenance

Review [GitHub collaboration](docs/GITHUB-COLLABORATION.md), the current [handoff](docs/HANDOFF.md), [contributing](CONTRIBUTING.md), and [provenance](PROVENANCE.md) before development. Run `bash scripts/check.sh` for required local validation; `bash tests/run.sh` runs benign-fixture coverage. Separate CI jobs exercise supported PHP contracts, upstream corpora and explicitly isolated WordPress/MySQL fixtures. Tests never target uncontrolled production sites.

[AI-assisted development](docs/AI-DEVELOPMENT.md) describes the development workflow. Its model settings do not create an OpenAI runtime dependency for the CLI.

MIT © 2026 Mustafa Sharif / Marketania. [License](LICENSE).
