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

A high-signal, exception-first security, integrity, hardening, and threat-intelligence auditor for one WordPress site or an entire hosting fleet.

Developed and maintained with support from [Marketania](https://marketania.com/).

</div>

---

## Why PressWarden?

WordPress incident response on a hosting account is rarely just “scan this one site.” A compromised account may contain dozens of installations, nested WordPress copies, stale plugins, writable persistence points, database injections, modified core files, executable uploads, malicious JavaScript, and legitimate plugin behavior that simplistic malware regexes misclassify.

PressWarden indexes the filesystem first, validates every WordPress root it finds, and then applies layered checks with **context-aware false-positive reduction**. It is designed for shared hosting, cPanel/Plesk/DirectAdmin layouts, VPS servers, `/var/www`, home directories, and custom filesystem structures. **Hostinger is not required.**

## Highlights

- 🔎 **Host-agnostic WordPress discovery** — validated roots and nested installations below any directory.
- 🧳 **Shared-host portable mode** — everything can live inside one local `PressWarden/` folder; no sudo, PATH, or bin access required.
- 🧠 **Threat Intelligence knowledge base** — named native rule IDs, campaign references, and focused `intel` workflows.
- 🦠 **PHP behavior detection** — request-controlled execution, packed loaders, credential exfiltration, remote payload behavior, and webshell primitives.
- 🌐 **JavaScript malware inspection** — decoded execution, obfuscated dynamic script loaders, and hidden external iframe behavior.
- 🗄️ **Database malware inspection** — targeted `wp_options` / `wp_posts` checks for injected browser payloads without dumping stored content.
- 🕵️ **Campaign markers** — high-specificity WP-VCD and SocGholish/NDSW markers plus Balada/Sign1-like behavioral rules.
- 🚨 **Known-exploitation prioritization** — optional CISA KEV correlation.
- 🛡️ **Optional vulnerability feeds** — Wordfence Intelligence, Patchstack, and WPScan remain user-configured and locally cached where appropriate.
- 🧬 **Official integrity checks** — WordPress core manifests and WordPress.org plugin checksums.
- 🔒 **Fleet lock / unlock** — toggle `DISALLOW_FILE_MODS` across every discovered installation with one confirmation.
- 🧱 **Hardening review** — `.htaccess`, `wp-config.php`, PHP runtime, permissions, salts, debug settings, uploads, persistence, and more.
- ♻️ **Safe remediation** — destructive actions are interactive and quarantine-backed.
- 📊 **Human + JSON reporting** — exception-first terminal output plus suite summaries.
- 🩺 **Doctor preflight** — dependency, discovery, config, threat-intel, integration, syntax, and portability readiness.

## Quick install — shared hosting

The default installer is **portable**. Run it from the directory where you want the `PressWarden/` folder created — usually your hosting account home:

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
cd ~/PressWarden
./presswarden doctor
./presswarden fast
```

Portable mode keeps everything local:

```text
PressWarden/
├── presswarden
├── VERSION
├── config/
│   └── config              # private configuration / API keys
├── intel/                  # native rule + campaign knowledge base
├── var/
│   ├── reports/
│   ├── cache/
│   ├── quarantine/
│   └── intel/              # downloaded/cached threat intelligence
├── checks/
├── lib/
└── suites/
```

No `~/.local/bin`, symlink, PATH change, sudo, or system-wide access is required. Rerunning the installer updates program files in place while preserving `config/config` and `var/`.

For security-sensitive environments, inspect the installer first:

```bash
curl -fsSLO https://raw.githubusercontent.com/marketania/PressWarden/main/install.sh
less install.sh
bash install.sh
```

An optional user-wide installation remains available:

```bash
PRESSWARDEN_INSTALL_MODE=user \
  bash -c "$(curl -fsSL https://raw.githubusercontent.com/marketania/PressWarden/main/install.sh)"
```

## Core usage

```bash
./presswarden doctor
./presswarden fast
./presswarden full
./presswarden db
./presswarden cleanup

./presswarden lock-status
./presswarden unlock
# perform trusted updates
./presswarden lock
```

Scan an explicit tree:

```bash
./presswarden fast /var/www
./presswarden full /home/example/websites
./presswarden fast ~/domains
```

Portable mode automatically looks outside the program folder, preferring sibling `domains/` or `public_html/` trees when present.

## Threat Intelligence — v1.1

PressWarden v1.1 adds a threat-oriented workflow that combines **native behavioral detections** with optional external vulnerability intelligence.

### Commands

```bash
./presswarden intel status
./presswarden intel update
./presswarden intel scan
```

`intel status` shows the native rule/campaign catalog, cached CISA KEV and Wordfence data, configured providers, and the local intelligence directory.

`intel update` refreshes external datasets that are designed to be downloaded as a feed. CISA KEV is enabled by default. Wordfence Intelligence is downloaded only when the user provides a token. Patchstack lookups happen during a scan and are deduplicated/cached by product/version.

`intel scan` runs a focused threat suite without the entire FULL maintenance sweep:

```text
PHP high-signal malware
packed/XOR remote loaders
dynamic request-controlled execution
credential capture + exfiltration
known campaign markers
JavaScript malware behaviors
database-stored browser malware
Wordfence vulnerability matching (optional)
Patchstack vulnerability matching (optional)
WPScan vulnerability intelligence (optional)
```

### Native rule model

PressWarden does **not** treat one suspicious function as malware. Native rules require compound evidence whenever practical.

Examples:

```text
PW-PHP-004
request-controlled function name
        +
dynamic invocation
        =
high-confidence execution backdoor
```

```text
PW-PHP-005
login + password POST capture
        +
outbound transmission
        +
TLS certificate verification disabled
        =
high-confidence credential exfiltration
```

```text
PW-JS-002
decode / character reconstruction
        +
dynamic <script> source creation
        +
DOM insertion
        =
obfuscated browser loader
```

```text
PW-DB-001
external/dynamic script stored in WordPress data
        +
decode/eval behavior
        =
high-confidence stored browser malware
```

The catalog lives in [`intel/native-rules.tsv`](intel/native-rules.tsv). Campaign references live in [`intel/campaigns.tsv`](intel/campaigns.tsv).

### Campaign knowledge

Current native intelligence includes high-specificity or behavior-based coverage informed by public research around:

- **WP-VCD** — controller/request markers documented by Wordfence.
- **SocGholish / NDSW** — documented NDSW-family JavaScript markers.
- **Balada Injector** — obfuscated/dynamic browser-loader behavior rather than fragile domain-only signatures.
- **Sign1** — database-stored obfuscated JavaScript behavior.

PressWarden deliberately says “campaign-like” when evidence is behavioral rather than using a specific attribution marker.

Research references and licensing notes are documented in [`intel/SOURCES.md`](intel/SOURCES.md).

## Vulnerability intelligence providers

All external providers are optional. The core scanner and native threat rules work with **zero API keys**.

### CISA KEV

```bash
PRESSWARDEN_INTEL_CISA=1
./presswarden intel update
```

PressWarden caches the public CISA Known Exploited Vulnerabilities catalog locally and uses CVE matches as a priority multiplier. A vulnerability that also appears in KEV is surfaced as **known exploited**.

### Wordfence Intelligence

Configure:

```bash
PRESSWARDEN_WORDFENCE_TOKEN="your-token"
```

Then:

```bash
./presswarden intel update
./presswarden intel scan
```

PressWarden matches installed WordPress core/plugin/theme versions against the locally cached Wordfence Intelligence V3 Production Feed, respecting affected version ranges and surfacing CVE/CVSS/remediation metadata. The feed itself is not redistributed by PressWarden.

Wordfence Intelligence documentation: https://www.wordfence.com/help/wordfence-intelligence/v3-accessing-and-consuming-the-vulnerability-data-feed/

### Patchstack

Configure:

```bash
PRESSWARDEN_PATCHSTACK_KEY="your-key"
```

PressWarden deduplicates installed component/version pairs across the fleet, caches responses, and caps uncached lookups by default:

```bash
PRESSWARDEN_PATCHSTACK_CACHE_TTL=21600
PRESSWARDEN_PATCHSTACK_MAX_LOOKUPS=250
```

Patchstack observations of exploitation and CISA KEV matches are elevated. API access, plan permissions, and rate limits remain controlled by Patchstack.

Patchstack Threat Intelligence API documentation: https://docs.patchstack.com/api-solutions/threat-intelligence-api/overview/

### WPScan

The existing WPScan integration remains user-token/user-install driven:

```bash
WPSCAN_API_TOKEN="your-token"
```

PressWarden does not redistribute the WPScan vulnerability database.

## Scan profiles

| Profile | Intended use | Major coverage |
|---|---|---|
| `fast` | Frequent fleet audit | persistence, targeted permissions, config, PHP, **native PHP/JS/campaign/DB threat intel**, core/plugin/theme/uploads, lean DB |
| `full` | Periodic assurance / incident response | FAST concepts plus recursive/deep scanning, official plugin checksums, **optional Wordfence/Patchstack/WPScan**, slow image scan, full DB isolation + maintenance |
| `intel scan` | Focused threat investigation | PHP/JS/campaign/DB malware + optional vulnerability intelligence |
| `db` | Database maintenance/security | DB security/isolation plus conditional repair, optimize, verify |
| `cleanup` | Inode housekeeping | conservative logs/disposable metadata cleanup, quarantine-backed |

### Slow image-extension scan

FULL contains a deliberately expensive check that reads image-like upload files looking for embedded PHP. PressWarden asks before running it:

```text
SLOW CHECK  Scan image-like uploads for embedded PHP? This can take a long time on large fleets. [y/N]:
```

Permanent preference:

```bash
PRESSWARDEN_UPLOADS_DEEP=1   # always run in FULL
PRESSWARDEN_UPLOADS_DEEP=0   # always skip in FULL
```

## What PressWarden checks

### Integrity

- official WordPress core checksums by exact version + locale
- missing/mismatched/extra core files
- quarantine-backed targeted core restore
- WordPress.org plugin checksum verification in FULL
- plugin repository lifecycle/provenance with local ACTIVE/INACTIVE state kept separate

### PHP / filesystem malware

- request-controlled execution sinks
- dynamic attacker-selected functions
- remote payload write/include behavior
- packed/XOR/`chr()`/`ord()` loaders
- credential capture + exfiltration chains
- obfuscation/decode chains
- executable uploads
- host cron/startup/SSH persistence indicators
- known high-specificity campaign markers

Standalone `base64_decode()`, `chmod(0777)`, upload handlers, XOR, numeric arrays, or `wp_enqueue_script()` are **not** automatically treated as malware.

### JavaScript / stored browser malware

- decoded code passed into execution
- dynamic script-loader construction with decoding + DOM insertion
- hidden external iframes with corroborating obfuscation
- targeted `wp_options` and `wp_posts` inspection
- stored payload content is not printed in reports

### Configuration / hardening

- `wp-config.php` malware/obfuscation indicators
- `DISALLOW_FILE_MODS` + fleet `lock` / `unlock`
- debug/query constants
- salts without printing secrets
- `FORCE_SSL_ADMIN`
- `.user.ini` / `php.ini` persistence
- dangerous `.htaccess` directives / cloaked redirects
- nested WordPress-aware `.htaccess` handling
- Wordfence WAF `auto_prepend_file` validation/consolidation

### PHP runtime

- PHP support lifecycle / patch currency
- loaded INI stack
- URL include / prepend / append
- FFI / PHAR / assertions / error disclosure
- process execution surface
- filesystem/temp/session posture
- optional Hostinger PHP-details enrichment when configured

### Database maintenance

PressWarden's DB maintenance uses WordPress's existing `$wpdb` connection and does not require `proc_open`, `mysqlcheck`, or the external MySQL client. Unsupported `CHECK TABLE` operations are informational — they are not treated as corruption.

## Configuration

Portable installs use:

```text
PressWarden/config/config
```

Example:

```bash
PRESSWARDEN_SCAN_ROOT=""
PRESSWARDEN_DISCOVERY_DEPTH=8
PRESSWARDEN_EXCLUDE=""
PRESSWARDEN_DISCOVERY_CACHE_TTL=300
PRESSWARDEN_INTERACTIVE=1
PRESSWARDEN_OUTPUT_JSON=1
PRESSWARDEN_UPLOADS_DEEP=""

# Threat intelligence
PRESSWARDEN_INTEL_AUTO_UPDATE=1
PRESSWARDEN_INTEL_CISA=1
PRESSWARDEN_PATCHSTACK_CACHE_TTL=21600
PRESSWARDEN_PATCHSTACK_MAX_LOOKUPS=250

# Optional providers
WPSCAN_API_TOKEN=""
PRESSWARDEN_WORDFENCE_TOKEN=""
PRESSWARDEN_PATCHSTACK_KEY=""
HOSTINGER_API_TOKEN=""
PRESSWARDEN_HOSTINGER_USERNAME=""
```

Environment variables override persistent config values. Keep configs containing credentials private:

```bash
chmod 600 config/config
```

**Never commit real API keys. PressWarden never intentionally prints configured token values.**

## Safety model

PressWarden defaults to **detect first, explain, then remediate interactively**.

- File deletion candidates are quarantined first.
- Critical WordPress files are protected from generic delete prompts.
- Core repair backs up the existing file and verifies the official replacement.
- Fleet lock/unlock backs up `wp-config.php` and rolls back on failure.
- DB maintenance repairs only genuine supported-table failures.
- Unsupported storage-engine maintenance operations remain informational.
- Threat-intelligence matches do not auto-delete plugins or themes.
- External intelligence failures do not turn into fake malware findings.
- Slow checks can be explicitly skipped.

Reports, cache, quarantine, and downloaded intelligence normally remain under:

```text
PressWarden/var/
```

## Performance design

PressWarden is built for fleets, not only one website:

- WordPress discovery is cached and structurally revalidated.
- Recursive scans use outermost roots so nested installs are not double-scanned.
- Core manifests and WordPress.org lifecycle metadata are cached.
- Plugin integrity verification is batched per site.
- Patchstack lookups are deduplicated by component/version and cached.
- Wordfence and CISA feeds are downloaded once and matched locally.
- JS/database scanners prefilter candidates before expensive validation.
- Heavy image inspection remains opt-in.
- Runtime scanner code avoids Bash process substitution to remain compatible with restricted shared hosting where `/dev/fd` may be unavailable.

## Requirements

Core:

- Linux/Unix-like shell environment
- Bash 4+
- PHP CLI
- standard GNU/POSIX utilities (`find`, `grep`, `sed`, `awk`, `sort`, `stat`)

Strongly recommended:

- WP-CLI
- `curl` or `wget`

Check the environment:

```bash
./presswarden doctor
```

## Project layout

```text
PressWarden/
├── presswarden
├── VERSION
├── install.sh
├── config/
├── intel/                   # native rules / campaign references / sources
├── lib/
├── suites/
│   ├── fast.sh
│   ├── full.sh
│   ├── db.sh
│   └── intel.sh
├── checks/
├── tests/
└── var/                     # portable runtime data, ignored by git
```

## Exit codes

- `0` — scan completed with no reportable findings
- `1` — findings/review items were reported
- `2+` — scanner/tooling error

## Responsible use

Run PressWarden only against systems you own or are authorized to administer. Security findings are evidence for investigation, not automatic proof of compromise. Legitimate plugins and hosting stacks can perform unusual operations; PressWarden deliberately favors compound behavior, official integrity sources, explicit confidence, and conservative remediation.

## Contributing

Issues and pull requests are welcome. Scanner logic should prioritize:

1. high signal over broad regex matching,
2. malicious + benign regression fixtures,
3. reproducible evidence,
4. shared-host portability,
5. no secret exposure,
6. no destructive defaults,
7. clear separation between behavior, provenance, vulnerability, and exploitation evidence.

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and [`intel/SOURCES.md`](intel/SOURCES.md).

## About Marketania

PressWarden was created and is maintained by Mustafa Sharif with support from [Marketania](https://marketania.com/), a digital agency working across WordPress development, website maintenance, security, SEO, and business technology. PressWarden grew out of real-world fleet maintenance and WordPress security work across many client environments.

If your organization needs professional WordPress, web, or digital services, visit [Marketania.com](https://marketania.com/).

## License

MIT © 2026 Mustafa Sharif / [Marketania](https://marketania.com/).
