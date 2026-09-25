# PressWarden

<p align="center">
  <img src="docs/assets/press-tool-family.webp" alt="PressWarden blue security shield, PressHarden green policy shield, and PressGarden gold maintenance shield" width="700">
</p>

**Fleet-scale WordPress security auditing, malware detection and incident investigation from the shell.**

PressWarden detects and investigates suspicious files, malicious PHP/JavaScript/database content, persistence, integrity failures and vulnerable components. It preserves reports and evidence. It is **not** a maintenance, cache, cleanup, update-policy or configuration-hardening tool.

The Press family contains three independent applications. [PressHarden](https://github.com/marketania/PressHarden) manages desired-state WordPress/PHP security configuration. [PressGarden](https://github.com/marketania/PressGarden) handles maintenance and performance. Neither is a dependency of PressWarden.

## Install

**Production runtime:** use an upstream-supported, security-patched PHP version. PHP 8.2–8.5 are supported at the September 2026 audit date; retained PHP 7.4 syntax tests are not a recommendation to deploy end-of-life PHP.

Read the [public-readiness audit and rollout checklist](docs/PUBLIC-READINESS.md) before fleet-wide use. Start on one staging site, verify recovery, and run as the site owner rather than root.

Linux with Bash 4+, PHP CLI 7.4+ and standard shell tools is the primary platform. WP-CLI is needed for runtime database/account/component inspections; optional vulnerability services and YARA have separate prerequisites. `doctor` reports actual availability instead of treating missing checks as clean.

Review the installer before running it:

```bash
curl -fsSLo install-presswarden.sh https://raw.githubusercontent.com/marketania/PressWarden/main/install.sh
bash install-presswarden.sh
cd PressWarden
./presswarden doctor
./presswarden sites
```

Portable installation keeps private configuration at `config/config` and data under `var/`. An independent user installation uses `PRESSWARDEN_INSTALL_MODE=user`, its own user-data prefix and a `presswarden` symlink under `~/.local/bin`. Existing installations should use `update`, not reinstall over their state. See [updating](docs/UPDATING.md).

For an unpublished branch or isolated fixture, use a validated local source tree:

```bash
PRESSWARDEN_INSTALL_SOURCE=/absolute/path/PressWarden \
PRESSWARDEN_INSTALL_PREFIX=/absolute/new/install/path bash install.sh
```

## Primary commands

```bash
./presswarden fast example.com
./presswarden full example.com
./presswarden incident example.com
./presswarden db example.com
./presswarden inspect php example.com
./presswarden inspect js example.com
./presswarden inspect db example.com
./presswarden inspect runtime example.com
./presswarden intel status
./presswarden intel update
./presswarden intel scan example.com
./presswarden baseline create example.com
./presswarden changes example.com
./presswarden correlate all
./presswarden quarantine list
./presswarden quarantine verify CASE_ID
./presswarden history
./presswarden run-status
./presswarden continue RUN_ID
```

`scan` is an alias for `fast`. `full` performs deep integrity and threat inspection, **never database repair, optimization, cache purges, cleanup, salt rotation or policy changes**. `db` is database threat and security inspection; ordinary health maintenance belongs to PressGarden.

`inspect runtime` reads local PHP directive files as inert text for auto-load/persistence indicators. It does not claim to measure the web-server PHP configuration. CLI/web configuration posture and supported deliberate `.user.ini` changes belong to PressHarden.

## Target safety

A target is a discovered website name, nested installation, explicit directory or `all`. Omission selects the configured fleet. A failed/ambiguous name, explicitly empty target, excluded target or unsafe directory path does not silently become the whole fleet. Named sites include intended nested installations while retaining exclusions. See [target resolution](docs/SITE-TARGETS.md).

```bash
PRESSWARDEN_SCAN_ROOT=/home/account/domains ./presswarden sites
./presswarden full example.com/shop
./presswarden incident /absolute/path/to/wordpress
```

## Mutations and evidence

Ordinary scans are read-only **with respect to website files and routine maintenance/configuration operations**. They still write toolkit reports, baselines, private caches and run state. Runtime checks can load WordPress/WP-CLI/plugin code; that code is trusted executable input, not a sandbox. A compromised bootstrap can have its own side effects, so use filesystem-only investigation or an isolated copy when necessary.

Security remediation is deliberately separate:

```bash
./presswarden remediate files example.com
./presswarden remediate core example.com
```

Both require an interactive terminal; the default at every remediation prompt is skip. `PRESSWARDEN_INTERACTIVE=0` never auto-approves remediation. Generic file removal retains the original evidence-first quarantine engine, protected-path rules, snapshot validation and recovery manifest. It does not remove critical configuration/core files via a generic prompt.

Core remediation uses the exact official WordPress version/locale package, verifies selected replacement files against the official checksum manifest, copies and verifies existing evidence, uses per-site writer locking, checks file identity immediately before action, and verifies the result. Extra-file removal is limited to files absent from the manifest under `wp-admin/` or `wp-includes/`. Links, traversal, unrelated files, bad package hashes and missing directory trees are refused. Partial results retain recovery information; concurrent changes are not blindly overwritten to force a rollback. Core recovery manifests live in `state/backups/core-restore/` or `core-extras/`; generic quarantine cases use `state/quarantine/` and the quarantine CLI. Rescan after remediation.

A finding is an investigation lead, not automatically proof of malware. Read [quarantine safety](docs/QUARANTINE.md) and keep independent recoverable backups. Never use PressGarden cleanup to conceal or repair an active incident.

## Configuration, state and privacy

Use `./presswarden config` for sanitized effective configuration and `./presswarden config-new` for template additions. Shell configuration is trusted code. Put secrets only in a private file; never paste real configuration, SQL dumps or evidence into public issues.

| Data | Portable | User installation |
|---|---|---|
| Configuration | `config/config` | `${XDG_CONFIG_HOME:-~/.config}/presswarden/config` |
| State, reports, evidence, run history | `var/` | `${XDG_STATE_HOME:-~/.local/state}/presswarden` |
| Cache | `var/cache/` | `${XDG_CACHE_HOME:-~/.cache}/presswarden` |

`PRESSWARDEN_CONFIG_FILE`, `PRESSWARDEN_STATE_DIR`, `PRESSWARDEN_CACHE_DIR`, discovery limits/exclusions and security integration options are documented in [the template](config/config.example). Keep state outside served website directories. Wordfence, Patchstack and WPScan credentials belong here, not in either sibling. CISA KEV correlation and optional administrator-provided YARA rules remain security-only.

## Exit codes and incomplete work

For scans, `0` means the selected checks completed without reportable findings; `1` means findings/review conditions; `2` or higher means an incomplete/invalid/failed operation or dependency problem. Individual operational commands have their documented semantics. An interrupted run is not clean. Use run status and finding history to distinguish NEW, RECURRING, CHANGED, RESOLVED and NOT RECHECKED.

Continuation verifies version, scope, exclusions, inventory and check plan. Runs from the combined 1.x product cannot resume into this release and replay maintenance commands; start a fresh security scan instead.

## Update, uninstall and migration

`./presswarden update` changes only PressWarden code and its security intelligence. It never updates a sibling. The updater validates archives/layout and preserves private state. `PRESSWARDEN_UPDATE_ARCHIVE=/absolute/distribution.tar.gz ./presswarden update` supports isolated validation. Stop ongoing operations before updating. Uninstall removes managed program files and its own symlink while retaining config, reports, evidence and backups; inspect the retained state before deliberate separate deletion.

Moved commands print instructions and return `2`; they never launch another application. See [migration](docs/MIGRATION.md), [architecture](docs/ARCHITECTURE.md), and [source ownership inventory](docs/OWNERSHIP.md). Historical 1.x behavior is preserved in [the old changelog](docs/CHANGELOG-1.x.md), not presented as current command guidance.

## Development and provenance

For AI-assisted repository work, see [AI-assisted development](docs/AI-DEVELOPMENT.md). The development configuration defaults trusted Codex projects to GPT-6 Astra; the CLI tool itself has no OpenAI runtime dependency.

Run `bash tests/run.sh` for local benign-fixture tests. Separate CI jobs run upstream package corpora, PHP 7.4 compatibility and isolated MySQL/WordPress integration. Tests never target uncontrolled production websites. See [contributing](CONTRIBUTING.md) and [provenance](PROVENANCE.md).

MIT © 2026 Mustafa Sharif / Marketania. [License](LICENSE).
