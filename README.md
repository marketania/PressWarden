<div align="center">

```text
 ____                    __        __            _            
|  _ \ _ __ ___  ___ ___\ \      / /_ _ _ __ __| | ___ _ __ 
| |_) | '__/ _ \/ __/ __|\ \ /\ / / _` | '__/ _` |/ _ \ '_ \
|  __/| | |  __/\__ \__ \\ V  V / (_| | | | (_| |  __/ | | |
|_|   |_|  \___||___/___/ \_/\_/ \__,_|_|  \__,_|\___|_| |_|
```

# PressWarden

**Fleet-scale WordPress security auditing from the shell.**

![Version](https://img.shields.io/badge/version-1.0.0-2ea44f)
![Bash](https://img.shields.io/badge/bash-4%2B-4EAA25?logo=gnubash&logoColor=white)
![WordPress](https://img.shields.io/badge/WordPress-security-21759B?logo=wordpress&logoColor=white)
![Platform](https://img.shields.io/badge/platform-Linux-FCC624?logo=linux&logoColor=black)
![License](https://img.shields.io/badge/license-MIT-blue)
![Host](https://img.shields.io/badge/hosting-host--agnostic-8A2BE2)

A high-signal, exception-first security and integrity auditor for one WordPress site or an entire hosting fleet.

</div>

---

## Why PressWarden?

WordPress incident response on a hosting account is rarely just "scan this one site." A compromised account may contain dozens of installations, nested WordPress copies, stale plugins, writable persistence points, database issues, modified core files, executable uploads, and legitimate plugin behavior that simplistic malware regexes misclassify.

PressWarden indexes the filesystem first, validates every WordPress root it finds, and then applies layered checks with **context-aware false-positive reduction**. It is designed for shared hosting, cPanel/Plesk/DirectAdmin layouts, VPS servers, `/var/www`, home directories, and custom filesystem structures. **Hostinger is not required.**

## Highlights

- 🔎 **Host-agnostic WordPress discovery** — finds validated WordPress roots and nested installations below any directory.
- ⚡ **Fast + Full profiles** — frequent high-signal audits or deeper incident-response sweeps.
- 🧬 **Official integrity checks** — WordPress core manifests and WordPress.org plugin checksums.
- 🛡️ **Context-aware malware detection** — compound evidence instead of noisy single-token regexes.
- 🧱 **Hardening review** — `.htaccess`, `wp-config.php`, PHP runtime, permissions, salts, debug settings, file modification controls, uploads, and persistence.
- 🗄️ **Database auditing + maintenance** — URL posture, registration, privilege/isolation visibility, salt reuse, table checks, conditional repair, optimize, verify.
- 🧹 **Inode cleanup** — quarantine-backed cleanup for logs and disposable OS/development metadata.
- ♻️ **Safe remediation** — destructive actions are interactive and backed up to quarantine first.
- 📦 **Cached discovery and network metadata** — avoids repeating expensive work across large fleets.
- 📊 **Human + JSON reporting** — clean terminal output and machine-readable suite summaries.
- 🔌 **Optional integrations** — WPScan vulnerability intelligence and Hostinger PHP-details enrichment.
- 🩺 **Doctor preflight** — validates dependencies, configuration, discovery, integration state, and portability.

## Quick install

### curl

```bash
curl -fsSL https://raw.githubusercontent.com/marketania/PressWarden/main/install.sh | bash
```

### wget

```bash
wget -qO- https://raw.githubusercontent.com/marketania/PressWarden/main/install.sh | bash
```

For security-sensitive environments, download and inspect the installer before executing it:

```bash
curl -fsSLO https://raw.githubusercontent.com/marketania/PressWarden/main/install.sh
less install.sh
bash install.sh
```

The installer places the project in `~/.local/share/presswarden`, creates `~/.local/bin/presswarden`, and creates a private config at `~/.config/presswarden/config` if one does not already exist.

## Usage

```bash
presswarden doctor
presswarden fast
presswarden full
presswarden db
presswarden cleanup
```

Scan an explicit filesystem tree:

```bash
presswarden fast /var/www
presswarden full /home/example/websites
presswarden fast ~/domains
```

Other commands:

```bash
presswarden config
presswarden file-mods status
presswarden file-mods on
presswarden file-mods off
presswarden --version
```

### Automatic root selection

If no path is supplied, PressWarden resolves the scan root in this order:

1. `PRESSWARDEN_SCAN_ROOT` from config/environment
2. `~/domains` when present
3. `~/public_html` when present
4. `/var/www` when present
5. current working directory

This preserves fast behavior on common shared-hosting accounts while remaining provider-independent.

## Scan profiles

| Profile | Intended use | Major checks |
|---|---|---|
| `fast` | Frequent fleet audit | persistence, targeted permissions, `.htaccess`, config, PHP runtime, high-signal PHP malware, sensitive files/cleanup, admin opt-in, core, root anomalies, plugins, themes, uploads, lean DB |
| `full` | Periodic assurance / incident response | everything in fast plus recursive permissions, deep PHP, WordPress.org plugin checksums, image-extension payload inspection, full DB isolation checks, DB maintenance |
| `db` | Database-only | database security/isolation plus conditional repair, optimize, final verification |
| `cleanup` | Inode housekeeping | public logs and conservative disposable metadata candidates, quarantine-backed |

## What PressWarden checks

### WordPress integrity

- Official WordPress core checksum verification keyed by exact version + locale.
- Cached official manifests for fleet-scale speed.
- Detects `MISMATCH`, `MISSING`, and core `EXTRA` files.
- Interactive targeted remediation can restore only failed core files from the exact official package and quarantine/remove extras.
- WordPress.org plugin checksum verification in the full suite with severity-aware classification of code mismatches, static-asset deviations, added files, and harmless OS metadata.

### Malware and persistence

- Request-controlled execution and filesystem primitives.
- Obfuscation/decode chains and dangerous sinks.
- Remote payload write/include behavior.
- Webshell primitives using compound evidence.
- Known redirect/cloaking campaign markers.
- Suspicious PHP in uploads with context-aware handling of legitimate plugin-generated files.
- Host cron/startup/SSH persistence indicators.

PressWarden intentionally avoids treating ordinary `base64_decode()`, `chmod(0777)`, upload handlers, importers, or plugin cache files as malware by location/token alone.

### Configuration and hardening

- `wp-config.php` malware/obfuscation indicators.
- `DISALLOW_FILE_MODS` and interactive enable/disable workflow.
- WordPress debug/query constants.
- placeholder/reused salts without printing secrets.
- `FORCE_SSL_ADMIN` posture.
- `.user.ini` / `php.ini` persistence.
- dangerous `.htaccess` directives and cloaked redirects.
- nested `.htaccess` handling that understands nested WordPress roots.
- Wordfence WAF `auto_prepend_file` validation and consolidation instead of false-positive spam.

### PHP environment

PressWarden audits the CLI/runtime layer for:

- PHP support lifecycle and patch currency
- loaded `php.ini` stack
- `allow_url_include`, `auto_prepend_file`, `auto_append_file`, `expose_php`, `enable_dl`
- FFI, PHAR, assertions, exception argument disclosure
- process-execution function surface
- `open_basedir`, temp paths, `.user.ini` behavior
- error/log disclosure defaults
- session hardening defaults

On Hostinger, an **optional** API integration can additionally compare exact per-domain PHP versions, every hPanel PHP option (memory, upload/post limits, execution/input limits, timezone and all returned settings), and extension drift. Without a Hostinger token, core PressWarden functionality is unchanged.

## Configuration

Edit:

```text
~/.config/presswarden/config
```

Example:

```bash
PRESSWARDEN_SCAN_ROOT=""
PRESSWARDEN_DISCOVERY_DEPTH=8
PRESSWARDEN_EXCLUDE=""
PRESSWARDEN_DISCOVERY_CACHE_TTL=300
PRESSWARDEN_INTERACTIVE=1
PRESSWARDEN_ADMINS_CHECK=""
PRESSWARDEN_OUTPUT_JSON=1

# Optional integrations
WPSCAN_API_TOKEN=""
HOSTINGER_API_TOKEN=""
PRESSWARDEN_HOSTINGER_USERNAME=""
```

If the file contains API credentials:

```bash
chmod 600 ~/.config/presswarden/config
```

**Never commit real API tokens.** PressWarden never intentionally prints configured token values.

## Optional integrations

### WPScan

Set `WPSCAN_API_TOKEN` to enable vulnerability intelligence:

```bash
WPSCAN_API_TOKEN="your-token"
```

The local integrity/malware scanner does not require WPScan.

### Hostinger

Set `HOSTINGER_API_TOKEN` to enrich `php-runtime` with exact per-site Hostinger PHP details. The scanner remains fully functional on non-Hostinger systems and with no Hostinger credential.

## Safety model

PressWarden defaults to **detect first, explain, then remediate interactively**.

- File deletion candidates are quarantined first.
- Critical WordPress files are protected from generic delete prompts.
- Core repair backs up the existing file, retrieves the exact official package, verifies the source file against the official manifest, replaces only the failed path, and verifies the result again.
- Database maintenance checks tables first and only attempts repair where appropriate before final verification.
- Non-interactive execution can disable remediation prompts with `PRESSWARDEN_INTERACTIVE=0`.

Quarantine and reports live outside the program directory under the user's state directory (normally `~/.local/state/presswarden`).

## Reports

Console logs and JSON summaries are written under:

```text
~/.local/state/presswarden/reports/
```

Example:

```text
fast-20260906-120000.log
fast-20260906-120000-summary.json
fast-latest-summary.json
```

## Performance design

PressWarden is intended to scale beyond a single site:

- WordPress discovery is cached and structurally revalidated.
- Recursive filesystem scans use outermost roots so nested installs are not double-scanned.
- Official core manifests are fetched once per version/locale and reused.
- WordPress.org plugin lifecycle metadata is deduplicated by slug and cached.
- Plugin checksums batch verification per site rather than launching WP-CLI for each plugin.
- Heavy/deep scans are separated from the frequent `fast` profile.
- No Bash process substitution is used in runtime scanner paths, avoiding `/dev/fd` issues seen on restricted shared hosting.

Force discovery refresh:

```bash
PRESSWARDEN_DISCOVERY_REFRESH=1 presswarden fast
```

## Requirements

Core requirements:

- Linux/Unix-like shell environment
- Bash 4+
- PHP CLI
- standard GNU/POSIX utilities (`find`, `grep`, `sed`, `awk`, `sort`, `stat`)

Strongly recommended:

- WP-CLI
- `curl` or `wget`

Run:

```bash
presswarden doctor
```

for an environment-specific readiness report.

## Project layout

```text
presswarden/
├── presswarden              # single user-facing CLI
├── install.sh               # curl/wget installer
├── uninstall.sh
├── config/
│   └── config.example
├── lib/
│   ├── _lib.sh              # discovery, UI, cache, safety helpers
│   └── _runner.sh           # suite driver + JSON summaries
├── suites/
│   ├── fast.sh
│   ├── full.sh
│   └── db.sh
├── checks/                  # focused WordPress/PHP/filesystem/DB scanners
├── integrations/            # optional provider/intelligence documentation/adapters
└── tests/
```

## Exit codes

- `0` — scan completed with no reportable findings
- `1` — findings/review items were reported
- `2+` — scanner/tooling error

## Responsible use

Run PressWarden only against systems you own or are authorized to administer. Security findings are evidence for investigation, not automatic proof of compromise. Legitimate plugins and hosting stacks can perform unusual operations; PressWarden deliberately favors contextual evidence and official integrity sources to reduce false positives.

## Contributing

Issues and pull requests are welcome. Before submitting scanner logic, prioritize:

1. high signal over broad regex matching,
2. reproducible evidence,
3. safe behavior on shared hosting,
4. no secret exposure,
5. no destructive default actions,
6. regression tests for false positives.

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

MIT © 2026 Mustafa Sharif / Marketania.
