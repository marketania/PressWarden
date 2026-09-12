<div align="left">

```text
 ____                   __        __            _
|  _ \ _ __ ___  ___ ___\ \      / /_ _ _ __ __| | ___ _ __
| |_) | '__/ _ \/ __/ __|\ \ /\ / / _` | '__/ _` |/ _ \ '_ \
|  __/| | |  __/\__ \__ \ \ V  V / (_| | | | (_| |  __/ | | |
|_|   |_|  \___||___/___/  \_/\_/ \__,_|_|  \__,_|\___|_| |_|
```

# PressWarden

**Fleet-scale WordPress security auditing from the shell.**

![Version](https://img.shields.io/badge/version-1.1.19-2ea44f)
![Bash](https://img.shields.io/badge/bash-4%2B-4EAA25?logo=gnubash&logoColor=white)
![WordPress](https://img.shields.io/badge/WordPress-security-21759B?logo=wordpress&logoColor=white)
![Platform](https://img.shields.io/badge/platform-Linux-FCC624?logo=linux&logoColor=black)
![License](https://img.shields.io/badge/license-MIT-blue)
![Host](https://img.shields.io/badge/hosting-host--agnostic-8A2BE2)

PressWarden scans one WordPress site or an entire hosting account for malware, suspicious persistence, integrity problems, risky configuration, vulnerable components, database threats, and unexpected changes.

Created and maintained by Mustafa Sharif with support from [Marketania](https://marketania.com/).

</div>

---

## What PressWarden is for

PressWarden is designed for people who manage WordPress websites and want a practical security audit without a wall of noisy regex matches.

It can discover multiple WordPress installations automatically, including nested sites, and works across common Linux hosting environments such as:

- Hostinger
- cPanel
- Plesk
- DirectAdmin
- SiteGround
- VPS servers
- `/var/www`
- custom shared-hosting layouts

PressWarden focuses on **high-signal findings**. A PHP function such as `base64_decode()`, `file_get_contents()`, or `wp_enqueue_script()` is not considered malware by itself. Stronger findings require multiple suspicious behaviors to appear together.

### Highlights

- 🔎 **Automatic WordPress discovery** across one site or a hosting fleet
- 🦠 **PHP malware detection** including webshell behavior, remote loaders, credential theft, and obfuscated payloads
- 🌐 **JavaScript malware detection** including injected scripts and suspicious redirects
- 🗄️ **Database malware scanning** for stored scripts, PHP payloads, persistence, and suspicious administrator accounts
- 🧬 **WordPress integrity checks** for core and plugins
- 🧭 **Baseline + change detection** for security-relevant files, plugins, themes, administrators, and cron state
- 🚑 **Incident response mode** for evidence-first compromise and reinfection investigations
- 🔗 **Fleet correlation** for repeated new or changed artifacts appearing across multiple WordPress sites
- 🧠 **Threat Intelligence** with native rules and optional external providers
- 🚨 **CISA KEV correlation** for known-exploited vulnerabilities
- 🔄 **Safe self-update** for program code plus threat intelligence without replacing private state
- 🧳 **Portable shared-hosting install** with no sudo or PATH changes required
- ♻️ **Safe remediation** with quarantine-backed file actions
- 🔒 **Fleet lock/unlock** for `DISALLOW_FILE_MODS`
- 🧭 **WordPress policy dashboard** with one-site detail and fleet baseline differences
- 📊 **Human-readable and JSON reports**
- 🧾 **Persistent suite run state** so interrupted SSH scans are not mistaken for completed audits
- 🧭 **Structured finding history** with NEW, RECURRING, CHANGED, RESOLVED, and fail-closed NOT RECHECKED states

---

## Quick start

### 1. Install

From your hosting account home directory:

```bash
cd ~
curl -fsSL https://raw.githubusercontent.com/marketania/PressWarden/main/install.sh | bash
```

If `curl` is unavailable:

```bash
cd ~
wget -qO- https://raw.githubusercontent.com/marketania/PressWarden/main/install.sh | bash
```

### 2. Check the environment

```bash
cd ~/PressWarden
./presswarden doctor
```

### 3. Run your first scan

```bash
./presswarden fast
```

That is the recommended starting point for most users.

---

## Which scan should I run?

| Command | Best for |
|---|---|
| `./presswarden fast` | Regular security checks across your sites |
| `./presswarden full` | Deep periodic assurance including DB maintenance |
| `./presswarden incident` | Investigating a suspected compromise or reinfection |
| `./presswarden inspect js` | Rechecking JavaScript intelligence without other checks |
| `./presswarden intel scan` | Focused malware + threat-intelligence investigation |
| `./presswarden db` | Database security, stored malware, and DB maintenance |
| `./presswarden update` | Updating PressWarden code and refreshing threat intelligence |
| `./presswarden doctor` | Checking setup, dependencies, discovery, and integrations |
| `./presswarden cleanup` | Conservative log / disposable-file cleanup |
| `./presswarden wp-settings example.com` | WordPress policy, updates, cron, recovery, environment, debug, and config posture |
| `./presswarden last-run` | See whether the latest suite completed, was incomplete, or was interrupted and where it stopped |
| `./presswarden continue` | Safely continue an interrupted/failed suite from its first unfinished check after scope/version verification |
| `./presswarden history` | Compare the latest finalized suite findings with the previous trustworthy same-scope history snapshot |

For routine use, start with:

```bash
./presswarden fast
```

If you suspect a compromise:

```bash
./presswarden incident
```

---

## Choose a website by name

```bash
./presswarden scan example.com
./presswarden lock example.com
./presswarden unlock example.com
./presswarden lock-status example.com
./presswarden wp-settings example.com
```

Use the same website name with `full`, `incident`, `db`, `inspect`, `baseline`, `changes`, `cleanup`, and other site commands. No full hosting path needed.

**All websites:** omit the name or use `all`, such as `./presswarden lock all`.
**Nested website:** use `example.com/shop`. A parent website's directory still includes discovered nested installations, shown before lock/unlock approval.

`./presswarden sites` lists local names and directories. Unknown, excluded or ambiguous names stop without selecting anything. Existing directory arguments still work. [How local names are resolved](docs/SITE-TARGETS.md).

## WordPress policy dashboard

See the full normalized policy for one site:

```bash
./presswarden wp-settings example.com
```

For a fleet, PressWarden shows the unique most-common policy as a comparison baseline and then **only the websites that differ**. Tied values are reported as `MIXED`; differences are informational and do not replace dedicated security findings. Fast and Full include this read-only view automatically.

```bash
./presswarden wp-settings all
```

Supported settings can be changed with the same website-name or `all` targeting, with confirmation, backup, and verification. For example:

```bash
./presswarden wp-settings set cron disabled example.com
./presswarden wp-settings set environment production example.com
./presswarden wp-settings set editor disabled all
```

Core/plugin/theme automatic-update controls remain under `auto-updates`. `lock`/`unlock`, supported `wp-settings set` operations, and core auto-update policy now share a verified staged-copy transaction layer: PressWarden backs up the exact config, mutates and verifies a private copy with WP-CLI, revalidates the live source, then atomically publishes only verified bytes. See [WordPress policy details](docs/WP-SETTINGS.md) and [transaction safety](docs/CONFIG-TRANSACTIONS.md).

## Recheck one area

Run just the existing PHP, JavaScript, or database threat-intelligence check:

```bash
./presswarden inspect php example.com
./presswarden inspect js example.com
./presswarden inspect db example.com
```

The website name is optional. These commands reuse discovery, exclusions, and reports without refreshing feeds, offering file removal, or running database maintenance. They cover only the selected intelligence layer—not a complete security audit. Database inspection still loads WordPress through WP-CLI. Use `./presswarden inspect help` for scope details.

Long PHP/JavaScript checks now show a live file percentage; database inspection shows sites processed. The terminal line stays separate from saved reports. Disable with `PRESSWARDEN_PROGRESS=0`. See [progress details](docs/PROGRESS.md).

## Interrupted scans and last-run status

Suite runs now maintain a small private atomic state record while they execute. If SSH closes or the suite receives `HUP`, `INT`, or `TERM`, the latest run is marked `INTERRUPTED` with the active check instead of being left ambiguous.

```bash
./presswarden last-run
./presswarden run-status RUN_ID
```

A catchable interruption retains partial validated reports but never becomes a completed audit. `SIGKILL` cannot be trapped; when process liveness is available, `run-status` identifies a stale `RUNNING` record as an interrupted/abandoned run rather than inventing completion. Safe continuation is available with `./presswarden continue [RUN_ID]`. It carries only a completed prefix from the same PressWarden version and exact rediscovered scope, reruns the interrupted check from the beginning, and starts a new linked audit summary. Runs created before 1.1.17 do not contain the required scope snapshot. Automatic database maintenance is never replayed if it was the interrupted check. See [safe continuation](docs/CONTINUATION.md) and [suite run-state details](docs/RUN-STATE.md).

## Finding history

Finalized suite runs now correlate structured security findings with the previous trustworthy same-suite/same-scope snapshot:

```bash
./presswarden history
./presswarden history RUN_ID
```

History labels observations as **NEW**, **RECURRING**, **CHANGED**, **RESOLVED**, or **NOT RECHECKED**. These describe PressWarden observations, not compromise or remediation timestamps. A missing prior finding becomes RESOLVED only after complete discovery, internally complete history capture, a successful recheck of its owning check, non-overlapping runs, and a comparable scanner version. Otherwise it remains NOT RECHECKED. Interrupted runs never publish resolution history; continuation carries already-completed observation records into the new linked run. See [finding-history semantics](docs/FINDING-HISTORY.md).

---

## A smaller PHP environment report

Optional per-site PHP data now shows the common profile, consistency counts, and differences grouped by website. Shared custom settings and long domain lists stay in the private full report. Configuration differences are review items, not automatic vulnerabilities.

```bash
./presswarden inspect runtime example.com
./presswarden inspect runtime example.com --details
```

The second command shows full values. Hostinger remains optional; the local PHP checks work on other hosts too.

## Keep PressWarden updated

After installation, program and intelligence updates are handled together:

```bash
./presswarden update
```

PressWarden first downloads and validates the new program version, creates a rollback copy of its managed code, installs the validated code, and then refreshes enabled threat-intelligence feeds using the newly installed intelligence implementation.

The code updater does **not** replace your private configuration, reports, quarantine, baselines, caches, or existing intel state. The final intelligence-refresh step may intentionally update provider cache files under the intel state directory.

If an intelligence feed is temporarily unavailable, the validated program update remains installed and existing feed caches are preserved. The command reports the partial failure and exits `1` so automated maintenance can retry the intelligence refresh later.

Finish running scans before updating. Updates use a private staging directory, validate archive contents, and keep recovery files if rollback fails. See [Update safety and recovery](docs/UPDATING.md).

To review template settings without replacing your saved config or showing secret values:

```bash
./presswarden config-new
```

You can still refresh intelligence by itself when needed:

```bash
./presswarden intel update
```

---

## Understanding the results

PressWarden is exception-first, so healthy items are kept concise while important findings stand out.

```text
✖ ALERT       Strong evidence that needs investigation
⚠ REVIEW      Suspicious or unusual behavior that should be checked
ℹ INFO        Useful context that is not considered a security finding
✓ CLEAN       No reportable issue found within that check's scope
⚠ INCOMPLETE  A check could not finish; this is not a clean verdict
```

A finding is evidence for investigation, not automatic proof that a site is compromised. If WordPress discovery is incomplete, validated-site findings are retained but the run is INCOMPLETE and cannot be ALL CLEAR. For JavaScript, an encoded external URL with visitor targeting is `REVIEW`; the report identifies the rule, source line, and browser operation without offering bulk deletion.

Example:

```text
✖ ALERT  example.com  ›  wp-content/plugins/example/example.php
```

Threat-intelligence checks may also include a stable PressWarden rule ID such as:

```text
PW-PHP-003
PW-JS-002
PW-DB-001
```

These IDs make findings easier to identify across reports and future scanner versions. See [detection quality and scan completeness](docs/DETECTION-QUALITY.md) for evidence thresholds and analysis limitations.

---

## Track what changed

After you have validated a known-good state, create a security baseline:

```bash
./presswarden baseline create
```

Later, compare the current fleet with it:

```bash
./presswarden changes
```

PressWarden tracks hashes for security-relevant code and configuration plus plugin, theme, administrator, and cron state when WP-CLI is available. It does **not** save file contents, passwords, API keys, or database payloads in the baseline.

Uploads, caches, logs, backups, and other highly volatile directories are excluded from baseline change tracking to avoid routine noise. They remain covered by their normal security checks.

Useful baseline commands:

```bash
./presswarden baseline status
./presswarden baseline diff
```

Creating a new baseline preserves the previous one locally for future history and reinfection workflows. Failed captures never replace it. Comparisons require matching coverage: a failed inventory or missing site is **INCOMPLETE**, not a removal finding.

Baselines from before 1.1.8 have unknown coverage. After reviewing the current sites, explicitly recreate once to enable the safer comparisons; your older snapshot is archived. See [baseline coverage and recovery](docs/BASELINES.md).

---

## Incident response and fleet correlation

Use Incident Mode when a site may be compromised or keeps becoming reinfected:

```bash
./presswarden incident
```

Incident Mode combines baseline changes, fleet correlation, persistence checks, malware detection, administrator inspection, integrity verification, vulnerability intelligence, upload checks, and database threat inspection.

It is intentionally **evidence-first**: database repair and optimization are not run automatically during an incident investigation.

Fleet correlation can also be run by itself:

```bash
./presswarden correlate
```

PressWarden does not flag ordinary duplicate WordPress or plugin files merely because they exist on several sites. Correlation is limited to **new or changed baseline artifacts/state** that repeat across multiple WordPress installations, and those signals are shown as `REVIEW` until corroborated by other evidence.

---

## What PressWarden checks

### Malware and persistence

- request-controlled PHP execution
- webshell-like behavior
- remote payload download/write/include chains
- packed XOR / `chr()` / `ord()` loaders
- credential capture and exfiltration
- suspicious JavaScript loaders and redirects
- hidden external iframes
- executable files in unusual locations
- malicious or suspicious MU-plugin persistence
- cron, startup, SSH, and hosting-account persistence indicators
- known high-confidence WordPress malware markers

### WordPress integrity

- official WordPress core checksums
- missing or modified core files
- unexpected files in core locations
- WordPress.org plugin checksums in FULL and incident scans
- installed plugin provenance and lifecycle information

Plugin **activation state** and **package provenance** are kept separate. For example, a premium or custom plugin that is not listed on WordPress.org may appear as `EXTERNAL` while still being locally `ACTIVE` or `INACTIVE`.

### Database threats

PressWarden uses WordPress's existing database connection to inspect targeted areas such as:

- `wp_options`
- `wp_posts`
- administrator accounts and capabilities
- site-wide custom script storage

It looks for high-signal behavior such as stored external script loaders, obfuscated JavaScript, suspicious redirects, database-resident PHP payloads, and privileged persistence.

Stored database payloads are not dumped into normal reports. Findings identify the row, not its contents. Database failures and scan limits are reported as **INCOMPLETE**, never as a clean scan.

Widget and builder values are examined separately; unrelated scripts do not combine into malware evidence. See [`docs/DATABASE-SCANNING.md`](docs/DATABASE-SCANNING.md) for limits and WordPress bootstrap considerations.

### Configuration and hardening

- `wp-config.php`
- `.htaccess`
- `.user.ini` / `php.ini`
- WordPress salts and debug settings
- `FORCE_SSL_ADMIN`
- `DISALLOW_FILE_MODS`
- Wordfence WAF `auto_prepend_file`
- file and directory permissions
- PHP runtime security settings
- executable uploads

---

## Threat Intelligence

PressWarden v1.1 includes a native threat-intelligence layer that works with **zero API keys**.

```bash
./presswarden intel status
./presswarden intel update
./presswarden intel scan
```

The native catalog currently includes **22 stable rule IDs**, including behavioral rules and campaign knowledge covering PHP, JavaScript, database threats, and WordPress malware patterns.

Detailed rule metadata and research references are maintained separately:

- [`intel/README.md`](intel/README.md) — native rule architecture
- [`intel/native-rules.tsv`](intel/native-rules.tsv) — rule catalog
- [`intel/campaigns.tsv`](intel/campaigns.tsv) — campaign mappings
- [`intel/SOURCES.md`](intel/SOURCES.md) — research sources and licensing notes

### CISA Known Exploited Vulnerabilities

CISA KEV support is enabled by default for intelligence updates:

```bash
./presswarden intel update
```

When a vulnerability CVE also appears in CISA KEV, PressWarden can identify it as **known exploited** rather than treating it as an ordinary vulnerability match.

---

## Optional vulnerability intelligence

PressWarden's core scanner does not require any commercial service or API key.

Optional integrations can add more vulnerability context:

| Integration | Purpose | Configuration |
|---|---|---|
| Wordfence Intelligence | Installed-version vulnerability matching | `PRESSWARDEN_WORDFENCE_TOKEN` |
| Patchstack | Plugin/theme/core vulnerability intelligence | `PRESSWARDEN_PATCHSTACK_KEY` |
| WPScan | WPScan vulnerability checks | `WPSCAN_API_TOKEN` + WPScan CLI |
| Hostinger API | Optional PHP/account enrichment | `HOSTINGER_API_TOKEN` |

External vulnerability data is not bundled into the PressWarden repository. See [`intel/SOURCES.md`](intel/SOURCES.md) for provider-specific notes.

For persistent credentials, edit your private `config/config`. The examples below use exported environment variables for a single shell session; do not place real keys in public scripts or reports.

### Wordfence Intelligence

```bash
export PRESSWARDEN_WORDFENCE_TOKEN="your-token"
./presswarden intel update
./presswarden intel scan
```

Wordfence data is cached locally under the PressWarden runtime directory and matched against installed WordPress core, plugin, and theme versions.

### Patchstack

```bash
export PRESSWARDEN_PATCHSTACK_KEY="your-key"
./presswarden intel scan
```

Patchstack lookups are deduplicated and cached to reduce unnecessary API requests.

### WPScan

```bash
export WPSCAN_API_TOKEN="your-token"
./presswarden full
```

WPScan remains user-installed and user-token driven.

---

## Optional YARA scanning

If you already maintain or license YARA rules, PressWarden can run them during `full`, `incident`, or `intel scan`.

```bash
PRESSWARDEN_YARA_RULES="/home/example/security/wordpress.yar" ./presswarden intel scan
```

PressWarden does **not** ship third-party YARA signature collections.

External YARA matches are shown as `REVIEW` and are never automatically deleted or quarantined.

---

## Portable installation

The default installer keeps PressWarden self-contained:

```text
~/PressWarden/
├── presswarden
├── VERSION
├── config/
│   └── config
├── intel/
├── checks/
├── lib/
├── suites/
└── var/
    ├── reports/
    ├── cache/
    ├── quarantine/
    ├── baselines/
    └── intel/
```

You do not need:

- sudo
- `/usr/local/bin`
- `~/.local/bin`
- a PATH modification
- system-wide configuration

After installation, use `./presswarden update` for future program + threat-intelligence updates. Rerunning the installer remains safe and preserves your private `config/config` and `var/` data.

An optional user-wide install is also available:

```bash
PRESSWARDEN_INSTALL_MODE=user \
  bash -c "$(curl -fsSL https://raw.githubusercontent.com/marketania/PressWarden/main/install.sh)"
```

---

## Scan another directory

Pass a path after the scan command:

```bash
./presswarden fast /var/www
./presswarden full /home/example/websites
./presswarden incident /home/example/websites
./presswarden intel scan ~/domains
```

Portable installations also try to locate common sibling directories such as `domains/` and `public_html/` automatically.

---

## Lock or unlock WordPress changes

| Action | One website | All discovered websites |
|---|---|---|
| Lock | `./presswarden lock example.com` | `./presswarden lock all` |
| Unlock | `./presswarden unlock example.com` | `./presswarden unlock all` |
| Status | `./presswarden lock-status example.com` | `./presswarden lock-status all` |

Locking sets `DISALLOW_FILE_MODS=true`; unlock for trusted WordPress updates, then lock again. This is a WordPress restriction, not an operating-system file lock. Changes require confirmation unless intentionally running in noninteractive mode. Website names include nested installations beneath that directory; use `example.com/shop` for a nested site.

The legacy `file-mods status|on|off [target]` interface remains supported.

---

## Slow image-content scan

`./presswarden full` and `./presswarden incident` include an optional deep scan of image-like upload files for embedded PHP.

Because this can be slow on large hosting accounts, PressWarden asks before running it.

You can set a permanent preference in configuration:

```bash
PRESSWARDEN_UPLOADS_DEEP=1   # always run
PRESSWARDEN_UPLOADS_DEEP=0   # always skip
PRESSWARDEN_UPLOADS_DEEP=""  # ask interactively
```

Noninteractive FULL and incident scans skip this check unless it is explicitly enabled.

---

## Database maintenance note

Some WordPress database tables use storage engines that do not support `CHECK TABLE`.

A message such as:

```text
The storage engine for the table doesn't support check
```

is treated as an informational **SKIP**, not database corruption.

PressWarden does not attempt to repair these tables or count them as unhealthy.

---

## Safety by default

PressWarden is designed to detect first and remediate carefully.

- file-removal actions are interactive
- approved generic file actions verify quarantine copies against SHA-256 before removal
- critical WordPress files are protected from generic deletion prompts
- core repair verifies official replacements
- fleet lock/unlock backs up `wp-config.php`
- baseline changes and fleet correlations are review-only signals
- Incident Mode does not run database repair/optimization automatically
- threat-intelligence matches do not automatically delete plugins or themes
- JavaScript behavioral findings do not offer bulk deletion
- external YARA matches are review-only
- program self-update never replaces private config, reports, quarantine, baselines, or runtime history
- API failures do not become fake malware findings

Quarantine, baselines, and reports normally live under:

```text
PressWarden/var/
```

---

## Check quarantined evidence

Approved file removals now verify their quarantine copies before deleting originals. Each action has a unique private case; failed or interrupted actions retain available evidence.

```bash
./presswarden quarantine list
./presswarden quarantine verify CASE_ID
```

Verification checks stored hashes, not whether a file is safe. There is no automatic restore or purge, and older quarantine folders stay untouched. See [verified quarantine](docs/QUARANTINE.md) for scope, limits and recovery guidance.

---

## Configuration

Portable installs use:

```text
PressWarden/config/config
```

Common settings:

```bash
PRESSWARDEN_SCAN_ROOT=""
PRESSWARDEN_DISCOVERY_DEPTH=8
PRESSWARDEN_EXCLUDE=""
PRESSWARDEN_DISCOVERY_CACHE_TTL=300

PRESSWARDEN_INTERACTIVE=1
PRESSWARDEN_OUTPUT_JSON=1
PRESSWARDEN_BASELINE_MAX_CHANGES=100
PRESSWARDEN_UPLOADS_DEEP=""

PRESSWARDEN_INTEL_AUTO_UPDATE=1
PRESSWARDEN_INTEL_CISA=1
PRESSWARDEN_YARA_RULES=""

WPSCAN_API_TOKEN=""
PRESSWARDEN_WORDFENCE_TOKEN=""
PRESSWARDEN_PATCHSTACK_KEY=""
HOSTINGER_API_TOKEN=""
PRESSWARDEN_HOSTINGER_USERNAME=""
```

Environment variables override saved configuration values.

If your config contains API credentials:

```bash
chmod 600 config/config
```

Never commit real API keys to the repository.

---

## Requirements

### Required

- Linux / Unix-like environment
- Bash 4+
- PHP CLI
- common utilities such as `find`, `grep`, `sed`, `awk`, `sort`, and `stat`

### Recommended

- WP-CLI
- `curl` or `wget`

### Optional

- YARA for external YARA rules
- WPScan CLI for WPScan vulnerability checks
- Wordfence / Patchstack / Hostinger credentials for their optional integrations

Check your environment at any time:

```bash
./presswarden doctor
```

---

## Reports and exit codes

Reports are written under the PressWarden reports directory, normally:

```text
PressWarden/var/reports/
```

Suites can also generate JSON summaries for automation and downstream reporting. New runs have unique identifiers and private report files, so starting the same check twice in one second does not replace an earlier report. The existing `*-latest-summary.json` alias is published only after complete JSON is ready; failures are reported rather than ignored. No historical reports are deleted or migrated. See [`docs/REPORTS.md`](docs/REPORTS.md) for naming, permissions, and automation details.

Exit codes:

```text
0   completed checks have no findings; optional skips may remain
1   one or more ALERT / REVIEW findings were reported
2+  incomplete scan, missing/failed check, or scanner/reporting error
```

Suite JSON reports include `coverage_status` (`complete`, `partial`, or `incomplete`) plus counts of completed, skipped, and failed checks. A skipped optional check is not a completed check, and an unsuccessful scan is never an ALL CLEAR result.

For `./presswarden update`, exit `1` can also mean the program update succeeded but one or more threat-intelligence feeds could not refresh. The updater states this explicitly and preserves existing feed caches so `./presswarden intel update` can be retried later.

---

## For contributors and security researchers

The main README focuses on using PressWarden. More detailed implementation information lives in the project documentation:

- [`docs/PHP-DETECTION.md`](docs/PHP-DETECTION.md) — PHP evidence and coverage
- [`CONTRIBUTING.md`](CONTRIBUTING.md)
- [`SECURITY.md`](SECURITY.md)
- [`docs/DETECTION-QUALITY.md`](docs/DETECTION-QUALITY.md)
- [`intel/README.md`](intel/README.md)
- [`intel/SOURCES.md`](intel/SOURCES.md)
- [`CHANGELOG.md`](CHANGELOG.md)

New detection logic should continue to prioritize high confidence, benign lookalike testing, portability, safe remediation, and protection against false positives.

---

## Responsible use

Run PressWarden only against systems you own or are authorized to administer.

Security findings should be investigated in context. Legitimate WordPress plugins, themes, and hosting platforms can perform unusual operations, which is why PressWarden favors compound behavioral evidence over isolated suspicious-looking functions.

---

## About Marketania

PressWarden was created and is maintained by Mustafa Sharif with support from [Marketania](https://marketania.com/).

Marketania provides WordPress development, website maintenance, security, SEO, and digital technology services.

For professional WordPress or digital services, visit [Marketania.com](https://marketania.com/).

---

## License

MIT © 2026 Mustafa Sharif / [Marketania](https://marketania.com/).
