# Optional scanner coverage and troubleshooting

This checkpoint covers external YARA, active-plugin checksums and remote WPScan.
The integrated candidate also includes the static-core verifier from PR #33. Native
security detection and site mutations are not combined with maintenance.

## Start safely

Read `help`, then inspect the exact staging directory with `sites`. A normal
`full` scan never authorizes remediation, but some checks execute WordPress code.
Do not bootstrap a suspected compromised installation merely to investigate it;
use an isolated copy and filesystem-only checks first.

## External YARA

Set `PRESSWARDEN_YARA_RULES` in private administrator configuration only when you
have a trusted, licensed rules file. No signatures or YARA binary are installed
for you. GNU `timeout` and a YARA engine advertising `--no-follow-symlinks` are
required. `PRESSWARDEN_YARA_TIMEOUT` is a positive integer from 1 to 3600 seconds,
default 120, per recursive root. The capability probe is limited to 5 seconds.
Output files are capped at 16 MiB each (8 MiB in POSIX mode), and at most 10,000
output records are interpreted per root. Hitting a limit is incomplete.

The scanner does not follow symlinks. Its recursive interface cannot express
PressWarden subtree exclusions, so a root containing an excluded installation
is **not scanned by YARA**. Choose a narrower eligible root or use native scoped
checks. Filtering matches after scanning would not protect excluded data.

| Result | Meaning | Exit |
|---|---|---:|
| SKIPPED | No rules configured; no YARA coverage obtained | 0 |
| CLEAN, limited scope | Engine completed with no matches in the stated regular-file scope | 0 |
| REVIEW | External rules matched; not automatically confirmed malware | 1 |
| INCOMPLETE | Missing capability, failed/refused root, warning, malformed output, timeout or limit | 2 |

Valid partial matches survive an engine failure. Diagnostic text and paths have
ASCII terminal controls neutralized; this is not a guarantee about every other
PressWarden output surface. The display limit is not a complete raw-match archive.
Administrator-supplied engines/rules remain trusted executable inputs, and
no-follow behavior does not make a changing filesystem an atomic snapshot.

## Active plugin checksums

The check inventories active and network-active plugins. WordPress.org lifecycle
metadata determines eligibility, but an unknown or unsupported vendor package is
a **coverage gap**, not a clean or malicious verdict. Obtain original vendor
packages/checksums for premium or custom components. Inactive plugins, MU-plugins,
themes and other components need their own checks.

Provider stdout and stderr are kept separate. JSON shape, plugin identifiers and
relative paths are validated before use. Each WP-CLI call has a 120-second limit
and bounded output. Missing/malformed inventory, upstream skip warnings and engine
failures produce INCOMPLETE (2), while ordinary package deviations remain findings
(1). An expected upstream failure summary is accepted only alongside valid finding
records. Unrecognized diagnostic formats conservatively require review of coverage.

An added `.DS_Store` or similar filename alone does not establish benign contents.
It is a package deviation for review, not a recommendation to delete it. No
cleanup, quarantine or configuration mutation is added by this checkpoint.

The bounded parser is inert PHP. The provider commands themselves still bootstrap
WordPress; `--skip-plugins` does **not** suppress MU-plugins. They are not safe
sandboxes for a compromised site. Existing availability caches are not publisher
signatures or a complete vulnerability assessment.

## Remote WPScan

A configured `WPSCAN_API_TOKEN` enables the optional external check. With no token,
this check reports SKIPPED and does not bootstrap WordPress or claim coverage.
Configured but missing `wp`, `wpscan`, PHP or GNU `timeout` is INCOMPLETE (2).
`PRESSWARDEN_WPSCAN_TIMEOUT` is 1–3600 seconds, default 180, per home-resolution
or remote-scan invocation. Provider output is capped at 8 MiB for interpretation;
process output limits and timeouts bound incomplete runs.

Home resolution keeps stdout separate from diagnostics and validates one HTTP(S)
URL without embedded credentials, queries or fragments. Failure never guesses a
URL from a directory name. This resolution **executes trusted WordPress and MU-plugin
code**; it is not static investigation. Do not use it on an untrusted compromised
installation. Only run remote scans against URLs you are authorized to assess.
PressWarden is not a network sandbox: operator-owned HOME/XDG WPScan settings,
WordPress home settings, provider redirects and DNS remain trust boundaries.
WPScan runs from a new private directory rather than loading site-local `.wpscan`
options. Review administrator scanner configuration and use an isolated snapshot
when origin or ownership is uncertain.

Only structured vulnerability records become findings. A record is provider evidence
requiring version/applicability review, not proof of compromise. Core, main-theme,
plugin and theme records are checked, bounded and deduplicated. Exit 5 is WPScan's
normal vulnerability-found code and maps to REVIEW (1) only with valid records;
actual failed/interrupted scans retain valid findings and report INCOMPLETE (2).
Malformed data, unknown component versions, missing completion markers, changed
target URLs, warnings and absent/failed/exhausted API coverage are not clean.
Quota zero is conservatively incomplete even when the last successful lookup may
have consumed the final request. An empty valid result means only no records in
**remote passive enumeration**, never that every installed component was inspected.

No API token is added to process arguments. Raw diagnostics and PoC content are
not copied into reports; configured token values and terminal controls are removed
from bounded finding text. Environment variables and administrator scanner code
are trusted, not a secret vault. Private temporary provider files are removed after
normal completion; interruption may leave a private directory for administrator
cleanup. Valid partial matches survive normal error reports; malformed/oversized
JSON cannot be safely interpreted as evidence. No database, plugin or site file
is changed by the wrapper, but remote HTTP requests and WordPress bootstrap can
have their own effects. Existing local threat-intelligence alternatives remain
independent from this optional API-backed scan.

## Findings display and original evidence

The shared `report` path treats finding text as untrusted. Terminal escape/control
bytes and Unicode directional controls are shown as visible escapes, while ordinary
Unicode is retained. Invalid UTF-8 bytes are represented rather than passed through
to the terminal. Each displayed record is bounded to a 4,096-byte prefix plus a
truncation marker; the configured line cap does not truncate the original evidence
saved by the existing private findings-log path. Do not `cat` raw evidence into a
terminal: it can still contain malicious terminal controls and sensitive site data.

A readable, single-link regular findings file is required. Missing, linked, unreadable,
nonregular, changing, or over-128-MiB input is INCOMPLETE (2), never CLEAN. Display
caps are integers from 0 to 10,000. Failure to render or save evidence disables generic
file actions; an unsaved temporary source is retained instead of intentionally removed
by `report`. No recovery persistence across process/system crashes is promised.
A valid empty file still means no findings in that specific check, not a complete
security assessment. A last record without a newline is counted and shown.

Display escaping does not change original finding paths used by the separate guarded
remediation logic. These checks are bounded best-effort identity checks, not an atomic
filesystem snapshot. This improvement covers shared finding rows, not every direct
provider message, banner, metadata field, or HTML output surface in the project.

### Excluded findings and byte preservation

Exclusion handling now validates the original single-link regular source before
reading it and creates a separate private projection. It does not rewrite the
original with a shell line reader: that reader can remove NUL bytes, append a
newline to the last record, and conceal an oversized or hardlinked source before
subsequent validation. Retained rows keep their exact bytes and last-line ending.
Long excluded rows remain excluded across read chunks; a similarly named sibling
path is not excluded by prefix alone.

Both source size and identity are checked before and after bounded streaming.
The 128-MiB source limit is enforced before filtering, even when all records would
be excluded. Invalid exclusions (more than 10,000 roots, over 4,096 bytes per root,
control bytes, or filesystem root) refuse the projection. If display or evidence
saving fails, the original source, including excluded records, is retained. The
projection is disposable; it is not an independent recovery archive. Normal
successful reporting keeps the existing temporary-source cleanup behavior.

This is best-effort filesystem identity checking, not a snapshot against every
same-account concurrent writer. Inspect retained raw evidence with a byte-safe
viewer rather than displaying it directly in a terminal. The binary-safe bounded
read and exclusive output mode follow the PHP [fgets](https://www.php.net/manual/en/function.fgets.php)
and [fopen](https://www.php.net/manual/en/function.fopen.php) contracts.

## Validation and remaining scope

Baseline main `d7867965a9b9d759568ef1a2503e394b4baa8e99` passed 50 local test
scripts despite the reproduced failures. New tests call the real shell checks
with recording, inert provider adapters. They cover exclusion refusal, real
process timeout, retained partial findings, malformed records, wrong JSON shapes,
option-like plugin names, coverage gaps and neutralized terminal controls.
Attribution tests preserve the exact original credits, link markup, license,
provenance and approved artwork. Run `bash tests/run.sh` and inspect the PR's CI
for current results; mock-provider tests do not establish every upstream version.

This is a focused completed repair, not closure of every item in the full
refinement brief. Real credentialed feeds, every hosting/WordPress variation,
concurrent filesystem races and comprehensive terminal/HTML surfaces still need
separate review. No version bump, tag, release, merge or production operation is
part of this checkpoint. PR #33 remains independently reviewable; its implementation is included in this combined candidate.

## Primary references and decisions

- [YARA CLI](https://yara.readthedocs.io/en/latest/commandline.html): recursive scans follow links unless explicitly disabled; require the advertised no-follow capability.
- [WP-CLI plugin checksums](https://developer.wordpress.org/cli/commands/plugin/verify-checksums/): preserve its JSON and package-deviation contract without TLS bypass.
- [WP-CLI plugin list](https://developer.wordpress.org/cli/commands/plugin/list/): active versus network-active scope and WordPress.org metadata.
- [WordPress hardening](https://developer.wordpress.org/advanced-administration/security/hardening/): least privilege and independent recovery.
- [GitHub secure use](https://docs.github.com/en/actions/reference/security/secure-use): preserve read-only PR jobs and separate release authority.
- [SSDF publications](https://csrc.nist.gov/projects/ssdf/publications): use SSDF 1.1 final as guidance; 1.2 is listed as an initial public draft, not an adopted certification.
- [OpenSSF Scorecard checks](https://github.com/ossf/scorecard/blob/main/docs/checks.md): review pinned dependencies and workflow boundaries; no Scorecard score or certification is claimed.

- [WPScan README](https://github.com/wpscanteam/wpscan#optional-wordpress-vulnerability-database-api): quota exhaustion can remove vulnerability coverage; environment token and current-directory configuration behavior.
- [WPScan JSON templates](https://github.com/wpscanteam/wpscan/tree/master/app/views/json): parse structured vulnerability/API/completion fields, not English output phrases.
- [WPScan exit codes](https://github.com/wpscanteam/wpscan/blob/master/lib/wpscan/exit_code.rb): preserve exit 5 as vulnerability findings, not a failed engine.
