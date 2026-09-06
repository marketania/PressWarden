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

A high-signal, exception-first WordPress security, integrity, hardening, and threat-intelligence auditor for one site or an entire hosting fleet.

Created and maintained by Mustafa Sharif with support from [Marketania](https://marketania.com/).

</div>

---

## Why PressWarden?

WordPress incident response on a hosting account is rarely just “scan this one site.” A compromised account may contain dozens of installations, nested WordPress copies, stale plugins, writable persistence points, database injections, modified core files, executable uploads, malicious JavaScript, and legitimate plugin behavior that simplistic malware regexes misclassify.

PressWarden indexes the filesystem first, validates every WordPress root it finds, and then applies layered checks with **context-aware false-positive reduction**. It works on shared hosting, cPanel/Plesk/DirectAdmin layouts, SiteGround, VPS servers, `/var/www`, home directories, and custom Linux hosting structures. **Hostinger is optional, not architectural.**

## Highlights

- 🔎 **Host-agnostic WordPress discovery** — validated roots plus nested installations below any directory.
- 🧳 **Portable shared-host mode** — the entire runtime can live inside one local `PressWarden/` folder; no sudo, PATH edits, or system directories required.
- 🧠 **Native Threat Intelligence** — 22 stable `PW-*` rules with category, severity, confidence, type, source/reference, and date metadata.
- 🦠 **PHP behavioral detection** — request-controlled execution, remote payload behavior, packed/XOR loaders, credential exfiltration, and admin-targeted browser payloads.
- 🌐 **JavaScript malware inspection** — decoded execution, decoded script-source injection, hidden external iframes, and reconstructed redirect targets.
- 🗄️ **Database malware + persistence inspection** — targeted `wp_options`, `wp_posts`, PHP payload, reinfector-option, and suspicious administrator checks without dumping stored payloads.
- 🕵️ **Campaign awareness** — WP-VCD, SocGholish/NDSW, Balada-like, Sign1-like, VexTrio/redirect-like, and admin-targeted fake-browser-update behavior.
- 🚨 **Known-exploitation prioritization** — CISA KEV correlation distinguishes known-exploited CVEs from ordinary vulnerability matches when evidence permits.
- 🛡️ **Optional vulnerability intelligence** — Wordfence Intelligence, Patchstack, and WPScan remain user-configured and are not bundled.
- 🧪 **Optional external YARA** — use administrator-supplied/licensed YARA rules; PressWarden ships no third-party YARA signatures and treats matches as review-only.
- 🧬 **Official integrity checks** — WordPress core manifests and WordPress.org plugin checksums.
- 🔒 **Fleet lock / unlock** — toggle `DISALLOW_FILE_MODS` across discovered WordPress installations with one confirmation.
- 🧱 **Hardening review** — `.htaccess`, `wp-config.php`, PHP runtime, permissions, salts, debug settings, uploads, persistence, and more.
- ♻️ **Safe remediation** — destructive actions are interactive and quarantine-backed.
- 📊 **Human + JSON reporting** — exception-first terminal output plus suite summaries.
- 🩺 **Doctor preflight** — dependencies, discovery, configuration, intelligence cache, integrations, syntax, and restricted-host portability readiness.

## Quick install — shared hosting

The default installer is portable. Run it from the hosting-account directory where you want the `PressWarden/` folder created, usually your home directory.

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

Portable mode keeps program data and private runtime data local:

```text
PressWarden/
├── presswarden
├── VERSION
├── config/
│   └── config              # private config / API keys
├── intel/                  # native metadata, campaign mappings, source docs
├── var/
│   ├── reports/
│   ├── cache/
│   ├── quarantine/
│   └── intel/              # locally cached optional external intelligence
├── checks/
├── lib/
└── suites/
```

No `~/.local/bin`, symlink, PATH change, sudo, or system-wide access is required. Rerunning the installer updates program files in place while preserving `config/config` and `var/`.

An optional user-wide install remains available:

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

./presswarden intel status
./presswarden intel update
./presswarden intel scan

./presswarden lock-status
./presswarden unlock
# perform trusted updates
./presswarden lock
```

The legacy/advanced file-mods interface remains available:

```bash
./presswarden file-mods status
./presswarden file-mods on
./presswarden file-mods off
```

Scan an explicit filesystem tree:

```bash
./presswarden fast /var/www
./presswarden full /home/example/websites
./presswarden intel scan ~/domains
```

Portable mode automatically looks outside the program folder, preferring sibling `domains/` or `public_html/` trees when present.

## Threat Intelligence — v1.1

PressWarden v1.1 combines **native behavioral detections** with optional external vulnerability intelligence. The core threat layer requires zero API keys.

### Intelligence commands

```bash
./presswarden intel status
./presswarden intel update
./presswarden intel scan
```

- `intel status` shows native rule/campaign counts, CISA KEV cache state, Wordfence Scanner/Production cache state, provider configuration, external YARA readiness, and the local intelligence directory.
- `intel update` refreshes download-style intelligence. CISA KEV is enabled by default; Wordfence is downloaded only when a user token is configured.
- `intel scan` runs a focused threat suite without the complete FULL maintenance workflow.

Focused coverage includes:

```text
PHP high-signal malware
packed/XOR remote loaders
dynamic request-controlled execution
credential capture + exfiltration
admin-targeted remote browser payloads
known campaign markers
JavaScript decoded execution and script loaders
decoded browser redirects
database-stored browser/PHP malware
database persistence and suspicious admin identities
external administrator-supplied YARA rules (optional)
Wordfence vulnerability matching (optional)
Patchstack vulnerability matching (optional)
WPScan vulnerability intelligence (optional)
```

## Native rule architecture

PressWarden does **not** equate one suspicious function with malware. Native rules require compound evidence whenever practical.

For example:

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
login/password POST capture
        +
outbound transmission
        +
TLS certificate verification disabled
        =
high-confidence credential exfiltration
```

```text
PW-JS-002
decoder / character reconstruction
        +
decoded value reaches <script> source
        +
dynamic script creation + DOM insertion
        =
obfuscated browser loader
```

```text
PW-DB-005
stored PHP tag
        +
execution primitive
        +
request-controlled input or decoding
        =
database-resident PHP payload review
```

The native catalog lives in [`intel/native-rules.tsv`](intel/native-rules.tsv). Its metadata includes:

```text
ID • category • severity • confidence • type • name • owner
source • reference • date added • date updated
```

The design and contribution contract are documented in [`intel/README.md`](intel/README.md). Executable logic remains in `checks/` and small helpers under `lib/` so tokenization, WordPress context, data-flow approximations, and false-positive protections can be tested directly instead of being reduced to noisy one-function regex rules.

## Campaign knowledge

Current native intelligence includes high-specificity or behavior-based coverage informed by public research around:

- **WP-VCD** — high-specificity controller/request markers.
- **SocGholish / NDSW** — documented NDSW-family JavaScript marker families.
- **Balada Injector** — decoded/obfuscated dynamic browser-loader behavior rather than fragile domain-only IOCs.
- **Sign1** — database-stored obfuscated JavaScript behavior.
- **VexTrio / redirect malware** — reconstructed browser redirect behavior and encoded/URL-rich option persistence.
- **Admin-targeted fake browser updates** — WordPress administrator + capability + Windows User-Agent gating combined with remote encoded browser payload behavior.

PressWarden deliberately says **campaign-like** when evidence is behavioral rather than claiming attribution from a generic technique. Research references and licensing notes are in [`intel/SOURCES.md`](intel/SOURCES.md).

## Vulnerability intelligence providers

All external providers are optional. PressWarden does not copy third-party vulnerability databases into the MIT repository.

### CISA KEV

```bash
PRESSWARDEN_INTEL_CISA=1
./presswarden intel update
```

PressWarden caches CISA's public Known Exploited Vulnerabilities catalog locally and correlates CVE IDs from vulnerability providers. A matching CVE is surfaced as **known exploited**; KEV is a prioritization signal, not a WordPress-specific vulnerability database.

### Wordfence Intelligence

Configure:

```bash
PRESSWARDEN_WORDFENCE_TOKEN="your-token"
./presswarden intel update
./presswarden intel scan
```

PressWarden uses the two Wordfence Intelligence V3 feeds for different roles:

```text
Wordfence Scanner Feed
        ↓
installed-version detection
        ↓
matching vulnerability UUID
        ↓
Wordfence Production Feed
        ↓
CVE / CVSS enrichment when available
        ↓
CISA KEV correlation
        ↓
known-exploited priority elevation
```

The **Scanner Feed** is the primary detection source. The **Production Feed** enriches matching UUIDs. Large feeds are validated and matched with bounded-memory streaming rather than whole-feed `json_decode()` so they remain practical on constrained shared hosting.

Both feeds remain in the user's local `var/intel/` cache. PressWarden does not redistribute them and displays available record attribution for matched entries. See [`intel/SOURCES.md`](intel/SOURCES.md) for current licensing notes.

### Patchstack

Configure:

```bash
PRESSWARDEN_PATCHSTACK_KEY="your-key"
PRESSWARDEN_PATCHSTACK_CACHE_TTL=21600
PRESSWARDEN_PATCHSTACK_MAX_LOOKUPS=250
```

PressWarden deduplicates installed component/version pairs across the fleet, performs user-keyed product/version lookups, and maintains an operational TTL cache to avoid repeated API calls. Patchstack exploitation observations and CISA KEV matches can elevate priority. Use remains subject to the user's Patchstack plan and current terms.

### WPScan

The existing WPScan integration remains user-token/user-install driven:

```bash
WPSCAN_API_TOKEN="your-token"
```

PressWarden invokes the user's WPScan CLI and does **not** build or cache a local WPScan vulnerability database. WPScan licensing/API limits remain the token holder's responsibility.

## Optional external YARA

PressWarden ships no third-party `.yar` / `.yara` collections. If an administrator already maintains or licenses YARA signatures, point PressWarden at one rules file:

```bash
PRESSWARDEN_YARA_RULES="/home/example/security/wordpress.yar"
./presswarden intel scan
```

YARA is included only in `full` and `intel scan`, never `fast`. Matches are always **REVIEW** inside PressWarden because external rule severity, licensing, and false-positive characteristics are outside the native `PW-*` contract. A YARA match does not trigger automatic quarantine/deletion.

## Scan profiles

| Profile | Intended use | Major coverage |
|---|---|---|
| `fast` | Frequent fleet audit | persistence, targeted permissions, config, PHP, native PHP/JS/campaign/DB threat intelligence, core/plugin/theme/uploads, lean DB |
| `full` | Periodic assurance / incident response | FAST concepts plus recursive/deep scanning, optional external YARA, official plugin checksums, optional Wordfence/Patchstack/WPScan, slow image scan, full DB isolation + maintenance |
| `intel scan` | Focused threat investigation | PHP/JS/campaign/DB malware + optional YARA + optional vulnerability intelligence |
| `db` | Database security/threat/maintenance | DB isolation/security, stored malware + privileged persistence, conditional repair, optimize, verify |
| `cleanup` | Inode housekeeping | conservative logs/disposable metadata cleanup, quarantine-backed |

### Slow image-extension scan

FULL contains a deliberately expensive check that reads image-like upload files looking for embedded PHP. PressWarden asks before running it:

```text
SLOW CHECK  Scan image-like uploads for embedded PHP? This can take a long time on large fleets. [y/N]:
```

Set a permanent preference if desired:

```bash
PRESSWARDEN_UPLOADS_DEEP=1   # always run in FULL
PRESSWARDEN_UPLOADS_DEEP=0   # always skip in FULL
```

Empty means ask interactively. Noninteractive FULL runs skip it unless explicitly enabled.

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
- admin-targeted remote encoded browser payload chains
- obfuscation/decode chains
- executable uploads
- host cron/startup/SSH persistence indicators
- high-specificity campaign markers

Standalone `base64_decode()`, `chmod(0777)`, upload handlers, XOR, numeric arrays, `file_get_contents()`, or `wp_enqueue_script()` are **not** automatically treated as malware.

### JavaScript / stored browser malware

- decoded code passed into `eval` / `Function`
- decoded values reaching dynamic script sources plus DOM insertion
- reconstructed targets reaching `location`, `location.assign`, or `location.replace`
- hidden external iframes with corroborating obfuscation
- targeted `wp_options` / `wp_posts` inspection
- stored PHP execution payload review when multiple behaviors corroborate it
- suspicious privileged-account persistence identities
- encoded redirect/reinfector-style option persistence
- stored payload bodies are not printed in reports

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

PressWarden uses WordPress's existing `$wpdb` connection and does not require `proc_open`, `mysqlcheck`, or an external MySQL client for database maintenance/threat inspection.

`CHECK TABLE` messages such as:

```text
The storage engine for the table doesn't support check
```

are informational unsupported operations. They are **not** treated as corruption, repaired, counted as unhealthy, or reported as unresolved.

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
PRESSWARDEN_YARA_RULES=""

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
- Threat-intelligence matches do not automatically delete plugins or themes.
- External YARA matches are review-only and never auto-remediated.
- External-intelligence failures do not become fake malware findings.
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
- Patchstack lookups are deduplicated by component/version.
- Wordfence Scanner/Production and CISA feeds are downloaded once and matched locally.
- Wordfence matching streams records with bounded memory.
- JavaScript/database scanners prefilter candidates before expensive validation.
- Heavy image inspection remains opt-in.
- Runtime scanner code avoids Bash process substitution to remain compatible with restricted shared hosting where `/dev/fd` may be unavailable.

## Requirements

Core:

- Linux/Unix-like shell environment
- Bash 4+
- PHP CLI
- standard GNU/POSIX utilities such as `find`, `grep`, `sed`, `awk`, `sort`, `stat`

Strongly recommended:

- WP-CLI
- `curl` or `wget`

Optional:

- `yara` only when `PRESSWARDEN_YARA_RULES` is configured
- WPScan CLI/token for WPScan intelligence
- provider tokens for Wordfence/Patchstack/Hostinger integrations

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
├── intel/
│   ├── README.md             # native rule architecture / contract
│   ├── native-rules.tsv      # stable rule metadata
│   ├── campaigns.tsv         # campaign knowledge mappings
│   └── SOURCES.md            # research + licensing boundaries
├── lib/
├── suites/
│   ├── fast.sh
│   ├── full.sh
│   ├── db.sh
│   └── intel.sh
├── checks/
├── tests/
└── var/                      # portable runtime data, ignored by git
```

## CI / regression philosophy

New threat logic should include both:

1. a malicious fixture that **must trigger**, and
2. a benign lookalike that **must not trigger**.

GitHub Actions also enforces Bash/PHP syntax, host-agnostic discovery, portable shared-host behavior, bounded-memory Wordfence parsing, intelligence credential safety, external-only YARA behavior, no runtime process substitution, no legacy branding, and no hard-coded API credentials.

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
7. clear separation between behavior, provenance, vulnerability, exploitation, and external-signature evidence.

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), [`intel/README.md`](intel/README.md), and [`intel/SOURCES.md`](intel/SOURCES.md).

## About Marketania

PressWarden was created and is maintained by Mustafa Sharif with support from [Marketania](https://marketania.com/), a digital agency working across WordPress development, website maintenance, security, SEO, and business technology. PressWarden grew out of real-world fleet maintenance and WordPress security work across many client environments.

If your organization needs professional WordPress, web, or digital services, visit [Marketania.com](https://marketania.com/).

## License

MIT © 2026 Mustafa Sharif / [Marketania](https://marketania.com/).
