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

![Version](https://img.shields.io/badge/version-1.1.0-2ea44f)
![Bash](https://img.shields.io/badge/bash-4%2B-4EAA25?logo=gnubash&logoColor=white)
![WordPress](https://img.shields.io/badge/WordPress-security-21759B?logo=wordpress&logoColor=white)
![Platform](https://img.shields.io/badge/platform-Linux-FCC624?logo=linux&logoColor=black)
![License](https://img.shields.io/badge/license-MIT-blue)
![Host](https://img.shields.io/badge/hosting-host--agnostic-8A2BE2)

PressWarden scans one WordPress site or an entire hosting account for malware, suspicious persistence, integrity problems, risky configuration, vulnerable components, and database threats.

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
- 🧠 **Threat Intelligence** with native rules and optional external providers
- 🚨 **CISA KEV correlation** for known-exploited vulnerabilities
- 🧳 **Portable shared-hosting install** with no sudo or PATH changes required
- ♻️ **Safe remediation** with quarantine-backed file actions
- 🔒 **Fleet lock/unlock** for `DISALLOW_FILE_MODS`
- 📊 **Human-readable and JSON reports**

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
| `./presswarden full` | Deeper audits, incident response, and periodic assurance |
| `./presswarden intel scan` | Focused malware + threat-intelligence investigation |
| `./presswarden db` | Database security, stored malware, and DB maintenance |
| `./presswarden doctor` | Checking setup, dependencies, discovery, and integrations |
| `./presswarden cleanup` | Conservative log / disposable-file cleanup |

For routine use, start with:

```bash
./presswarden fast
```

If something looks suspicious or you want the deepest available scan:

```bash
./presswarden full
```

---

## Understanding the results

PressWarden is exception-first, so healthy items are kept concise while important findings stand out.

```text
✖ ALERT    Strong evidence that needs investigation
⚠ REVIEW   Suspicious or unusual behavior that should be checked
ℹ INFO     Useful context that is not considered a security finding
✓ CLEAN    No reportable issue found for that check
```

A finding is evidence for investigation, not automatic proof that a site is compromised.

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

These IDs make findings easier to identify across reports and future scanner versions.

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
- WordPress.org plugin checksums in FULL scans
- installed plugin provenance and lifecycle information

Plugin **activation state** and **package provenance** are kept separate. For example, a premium or custom plugin that is not listed on WordPress.org may appear as `EXTERNAL` while still being locally `ACTIVE` or `INACTIVE`.

### Database threats

PressWarden uses WordPress's existing database connection to inspect targeted areas such as:

- `wp_options`
- `wp_posts`
- administrator accounts and capabilities
- site-wide custom script storage

It looks for high-signal behavior such as stored external script loaders, obfuscated JavaScript, suspicious redirects, database-resident PHP payloads, and privileged persistence.

Stored database payloads are not dumped into normal reports.

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

### Wordfence Intelligence

```bash
PRESSWARDEN_WORDFENCE_TOKEN="your-token"
./presswarden intel update
./presswarden intel scan
```

Wordfence data is cached locally under the PressWarden runtime directory and matched against installed WordPress core, plugin, and theme versions.

### Patchstack

```bash
PRESSWARDEN_PATCHSTACK_KEY="your-key"
./presswarden intel scan
```

Patchstack lookups are deduplicated and cached to reduce unnecessary API requests.

### WPScan

```bash
WPSCAN_API_TOKEN="your-token"
./presswarden full
```

WPScan remains user-installed and user-token driven.

---

## Optional YARA scanning

If you already maintain or license YARA rules, PressWarden can run them during `full` or `intel scan`.

```bash
PRESSWARDEN_YARA_RULES="/home/example/security/wordpress.yar"
./presswarden intel scan
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
    └── intel/
```

You do not need:

- sudo
- `/usr/local/bin`
- `~/.local/bin`
- a PATH modification
- system-wide configuration

Rerunning the installer updates PressWarden while preserving your private `config/config` and `var/` data.

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
./presswarden intel scan ~/domains
```

Portable installations also try to locate common sibling directories such as `domains/` and `public_html/` automatically.

---

## Lock WordPress file modifications

PressWarden can manage:

```php
define('DISALLOW_FILE_MODS', true);
```

across all discovered WordPress installations.

Check status:

```bash
./presswarden lock-status
```

Temporarily unlock sites before trusted maintenance or updates:

```bash
./presswarden unlock
```

After updates are finished:

```bash
./presswarden lock
```

The older interface remains available for compatibility:

```bash
./presswarden file-mods status
./presswarden file-mods on
./presswarden file-mods off
```

---

## Slow image-content scan

`./presswarden full` includes an optional deep scan of image-like upload files for embedded PHP.

Because this can be slow on large hosting accounts, PressWarden asks before running it.

You can set a permanent preference in configuration:

```bash
PRESSWARDEN_UPLOADS_DEEP=1   # always run
PRESSWARDEN_UPLOADS_DEEP=0   # always skip
PRESSWARDEN_UPLOADS_DEEP=""  # ask interactively
```

Noninteractive FULL scans skip this check unless it is explicitly enabled.

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
- files are copied to quarantine before deletion
- critical WordPress files are protected from generic deletion prompts
- core repair verifies official replacements
- fleet lock/unlock backs up `wp-config.php`
- threat-intelligence matches do not automatically delete plugins or themes
- external YARA matches are review-only
- API failures do not become fake malware findings

Quarantine and reports normally live under:

```text
PressWarden/var/
```

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

Suites can also generate JSON summaries for automation and downstream reporting.

Exit codes:

```text
0   scan completed with no reportable findings
1   one or more ALERT / REVIEW findings were reported
2+  scanner or dependency error
```

---

## For contributors and security researchers

The main README focuses on using PressWarden. More detailed implementation information lives in the project documentation:

- [`CONTRIBUTING.md`](CONTRIBUTING.md)
- [`SECURITY.md`](SECURITY.md)
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
