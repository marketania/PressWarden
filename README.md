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

![Version](https://img.shields.io/badge/version-1.0.3-2ea44f)
![Bash](https://img.shields.io/badge/bash-4%2B-4EAA25?logo=gnubash&logoColor=white)
![WordPress](https://img.shields.io/badge/WordPress-security-21759B?logo=wordpress&logoColor=white)
![Platform](https://img.shields.io/badge/platform-Linux-FCC624?logo=linux&logoColor=black)
![License](https://img.shields.io/badge/license-MIT-blue)
![Host](https://img.shields.io/badge/hosting-host--agnostic-8A2BE2)

A high-signal, exception-first security and integrity auditor for one WordPress site or an entire hosting fleet.

Developed and maintained with support from [Marketania](https://marketania.com/).

</div>

---

## Why PressWarden?

WordPress incident response on a hosting account is rarely just "scan this one site." A compromised account may contain dozens of installations, nested WordPress copies, stale plugins, writable persistence points, database issues, modified core files, executable uploads, and legitimate plugin behavior that simplistic malware regexes misclassify.

PressWarden indexes the filesystem first, validates every WordPress root it finds, and then applies layered checks with **context-aware false-positive reduction**. It is designed for shared hosting, cPanel/Plesk/DirectAdmin layouts, VPS servers, `/var/www`, home directories, and custom filesystem structures. **Hostinger is not required.**

## Highlights

- 🔎 **Host-agnostic WordPress discovery** — finds validated WordPress roots and nested installations below any directory.
- 🧳 **Shared-host portable mode** — installs completely inside one local `PressWarden/` folder with no PATH or bin-directory requirement.
- ⚡ **Fast + Full profiles** — frequent high-signal audits or deeper incident-response sweeps.
- 🔒 **Fleet lock / unlock** — toggle `DISALLOW_FILE_MODS` across every discovered WordPress installation with one confirmation.
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

## Quick install — shared hosting / recommended

PressWarden v1.0.3 defaults to a **portable local installation**. It creates a `PressWarden` folder in your current directory and does **not** require access to `~/.local/bin`, symlinks, PATH changes, sudo, or system directories.

From your hosting account's home directory:

### curl

```bash
cd ~
curl -fsSL https://raw.githubusercontent.com/marketania/PressWarden/main/install.sh | bash
```

### wget

```bash
cd ~
wget -qO- https://raw.githubusercontent.com/marketania/PressWarden/main/install.sh | bash
```

Then:

```bash
cd PressWarden
./presswarden doctor
./presswarden fast
```

The installer prints the PressWarden logo plus a short confirmation and next steps:

```text
PressWarden v1.0.3 • portable shared-host install
No bin directory, symlink, PATH change, or system-wide access required.

✓ Installed: /home/example/PressWarden
✓ Config:    /home/example/PressWarden/config/config
✓ Data:      /home/example/PressWarden/var

Next steps:
  cd /home/example/PressWarden
  ./presswarden doctor
  ./presswarden fast

Tip: use ./presswarden full for the comprehensive audit.
```

### Inspect before installing

For security-sensitive environments:

```bash
cd ~
curl -fsSLO https://raw.githubusercontent.com/marketania/PressWarden/main/install.sh
less install.sh
bash install.sh
```

### Custom local folder

```bash
curl -fsSL https://raw.githubusercontent.com/marketania/PressWarden/main/install.sh \
  | PRESSWARDEN_INSTALL_DIR="$HOME/tools/PressWarden" bash
```

### Update an existing portable installation

You can rerun the installer from inside the existing folder:

```bash
cd ~/PressWarden
curl -fsSL https://raw.githubusercontent.com/marketania/PressWarden/main/install.sh | bash
```

PressWarden updates the program files while preserving:

```text
config/config
var/reports/
var/cache/
var/quarantine/
```

### Optional user-wide install

Users who do have a writable `~/.local/bin` and prefer a global-style command can still install the older user-level layout:

```bash
curl -fsSL https://raw.githubusercontent.com/marketania/PressWarden/main/install.sh \
  | PRESSWARDEN_INSTALL_MODE=user bash
```

That mode installs the `presswarden` command into `~/.local/bin`. Portable mode remains the default and recommended option for shared hosting.

## Portable folder layout

```text
PressWarden/
├── presswarden             # run this as ./presswarden
├── config/
│   ├── config.example
│   └── config              # private local settings / API tokens
├── var/
│   ├── reports/
│   ├── cache/
│   └── quarantine/
├── checks/
├── lib/
├── suites/
└── ...
```

Everything required by a portable installation stays inside that folder.

## Usage

Portable/shared-host installation:

```bash
cd PressWarden
./presswarden doctor
./presswarden fast
./presswarden full
./presswarden db
./presswarden cleanup
./presswarden lock-status
./presswarden lock
./presswarden unlock
```

Scan an explicit filesystem tree:

```bash
./presswarden fast /var/www
./presswarden full /home/example/websites
./presswarden fast ~/domains
./presswarden lock ~/domains
```

Other commands:

```bash
./presswarden config
./presswarden file-mods status
./presswarden file-mods on
./presswarden file-mods off
./presswarden --version
```

If PressWarden was installed in user mode, omit `./` and use `presswarden ...` normally.

### Automatic root selection

If no path is supplied, portable PressWarden deliberately scans **outside its own program folder**:

1. `PRESSWARDEN_SCAN_ROOT` from config/environment
2. `../domains` when present
3. `../public_html` when present
4. the parent directory containing `PressWarden/`

This matches common shared-hosting layouts such as:

```text
/home/account/
├── PressWarden/
└── domains/
    ├── site-one.com/public_html/
    ├── site-two.com/public_html/
    └── ...
```

User-wide mode retains the broader `~/domains` → `~/public_html` → `/var/www` → current-directory fallback.

### Fleet locking with DISALLOW_FILE_MODS

PressWarden can lock WordPress dashboard file modifications across every discovered installation by setting the WordPress `DISALLOW_FILE_MODS` constant.

```bash
./presswarden lock-status
./presswarden lock
./presswarden unlock
```

`./presswarden lock` sets:

```php
define('DISALLOW_FILE_MODS', true);
```

This prevents WordPress administrators from installing, updating, or editing plugins/themes from inside WordPress while the site is locked. `./presswarden unlock` sets the constant to `false` so normal update/maintenance workflows can run again.

A common maintenance workflow is:

```bash
./presswarden unlock
# run trusted WordPress/plugin/theme updates
./presswarden lock
./presswarden lock-status
```

For a large fleet, `lock` and `unlock` ask for **one fleet-level confirmation** and then apply the setting to all discovered WordPress installations. Before each `wp-config.php` change, PressWarden creates a quarantine-backed copy. If WP-CLI fails to update a site, the original config is restored automatically.

For automation, explicitly disable interactive mode:

```bash
PRESSWARDEN_INTERACTIVE=0 ./presswarden unlock /var/www
# maintenance automation
PRESSWARDEN_INTERACTIVE=0 ./presswarden lock /var/www
```

The older `file-mods status|on|off` interface remains available for compatibility and advanced workflows.

## Scan profiles

| Profile | Intended use | Major checks |
|---|---|---|
| `fast` | Frequent fleet audit | persistence, targeted permissions, `.htaccess`, config, PHP runtime, high-signal PHP malware, sensitive files/cleanup, admin opt-in, core, root anomalies, plugins, themes, uploads, lean DB |
| `full` | Periodic assurance / incident response | everything in fast plus recursive permissions, deep PHP, WordPress.org plugin checksums, **optional slow image-extension payload inspection**, full DB isolation checks, DB maintenance |
| `db` | Database-only | database security/isolation plus conditional repair, optimize, final verification |
| `cleanup` | Inode housekeeping | public logs and conservative disposable metadata candidates, quarantine-backed |

### Slow image-extension scan

The FULL profile contains a deliberately expensive check that reads image-like files in WordPress upload trees and looks for embedded PHP. On large fleets this can take a long time, so PressWarden **asks before running it**:

```text
SLOW CHECK  Scan image-like uploads for embedded PHP? This can take a long time on large fleets. [y/N]:
```

Press Enter or answer `n` to skip it. To set a permanent preference:

```bash
PRESSWARDEN_UPLOADS_DEEP=1   # always run in FULL
PRESSWARDEN_UPLOADS_DEEP=0   # always skip in FULL
```

Or force it for a single run:

```bash
PRESSWARDEN_UPLOADS_DEEP=1 ./presswarden full
```

Non-interactive FULL runs skip the slow scan unless `PRESSWARDEN_UPLOADS_DEEP=1` is explicitly set.

## What PressWarden checks

### WordPress integrity

- Official WordPress core checksum verification keyed by exact version + locale.
- Cached official manifests for fleet-scale speed.
- Detects `MISMATCH`, `MISSING`, and core `EXTRA` files.
- Interactive targeted remediation can restore only failed core files from the exact official package and quarantine/remove extras.
- WordPress.org plugin checksum verification with severity-aware classification of code mismatches, static-asset deviations, added files, and harmless OS metadata.

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
- `DISALLOW_FILE_MODS` detection and fleet-wide `lock` / `unlock` workflow.
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

On Hostinger, an **optional** API integration can additionally compare exact per-domain PHP versions, hPanel PHP options, and extension drift. Without a Hostinger token, core PressWarden functionality is unchanged.

## Configuration

Portable installation:

```text
PressWarden/config/config
```

User-wide installation:

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
PRESSWARDEN_UPLOADS_DEEP=""   # empty=ask, 1=always run, 0=always skip

# Optional integrations
WPSCAN_API_TOKEN=""
HOSTINGER_API_TOKEN=""
PRESSWARDEN_HOSTINGER_USERNAME=""
```

Exported environment variables override the same setting in the persistent config.

If the file contains API credentials:

```bash
chmod 600 config/config
```

**Never commit real API tokens.** PressWarden never intentionally prints configured token values.

## Optional integrations

### WPScan

Set `WPSCAN_API_TOKEN` to enable vulnerability intelligence. The local integrity/malware scanner does not require WPScan.

### Hostinger

Set `HOSTINGER_API_TOKEN` to enrich `php-runtime` with exact per-site Hostinger PHP details. The scanner remains fully functional on non-Hostinger systems and with no Hostinger credential.

## Safety model

PressWarden defaults to **detect first, explain, then remediate interactively**.

- File deletion candidates are quarantined first.
- Critical WordPress files are protected from generic delete prompts.
- Core repair backs up the existing file, retrieves the exact official package, verifies the source file against the official manifest, replaces only the failed path, and verifies the result again.
- Fleet lock/unlock creates a backup of each site's `wp-config.php` and restores the original automatically if WP-CLI fails.
- Database maintenance checks tables first and only attempts repair where appropriate before final verification.
- Slow or optional inventory checks can be skipped explicitly rather than silently consuming hours on large fleets.
- Non-interactive execution can disable remediation prompts with `PRESSWARDEN_INTERACTIVE=0`.

## Reports and runtime data

Portable mode keeps runtime data inside the PressWarden directory:

```text
PressWarden/var/reports/
PressWarden/var/cache/
PressWarden/var/quarantine/
```

Example reports:

```text
fast-20260906-120000.log
fast-20260906-120000-summary.json
fast-latest-summary.json
```

User-wide mode uses the normal XDG/home state directories instead.

## Performance design

PressWarden is intended to scale beyond a single site:

- WordPress discovery is cached and structurally revalidated.
- Recursive filesystem scans use outermost roots so nested installs are not double-scanned.
- Official core manifests are fetched once per version/locale and reused.
- WordPress.org plugin lifecycle metadata is deduplicated by slug and cached.
- Plugin checksums batch verification per site rather than launching WP-CLI for each plugin.
- Heavy/deep scans are separated from the frequent `fast` profile.
- The slow upload image-content scan is opt-in during FULL runs.
- No Bash process substitution is used in runtime scanner paths, avoiding `/dev/fd` issues seen on restricted shared hosting.

Force discovery refresh:

```bash
PRESSWARDEN_DISCOVERY_REFRESH=1 ./presswarden fast
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

Start with:

```bash
./presswarden doctor
```

for an environment-specific readiness report.

## Uninstall

Portable install:

```bash
cd PressWarden
./uninstall.sh
```

Because portable mode is self-contained, removing it also removes its local config and runtime data after confirmation.

## Project layout

```text
PressWarden/
├── presswarden              # single user-facing CLI
├── install.sh               # curl/wget installer
├── uninstall.sh
├── config/
│   └── config.example
├── lib/
├── suites/
├── checks/
├── integrations/
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

## About Marketania

PressWarden was created and is maintained by Mustafa Sharif with support from [Marketania](https://marketania.com/), a digital agency working across WordPress development, website maintenance, security, SEO, and business technology. PressWarden grew out of real-world fleet maintenance and WordPress security work across many client environments.

If your organization needs professional WordPress, web, or digital services, visit [Marketania.com](https://marketania.com/).

## License

MIT © 2026 Mustafa Sharif / [Marketania](https://marketania.com/).
