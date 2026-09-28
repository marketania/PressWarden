# Optional scanner coverage and troubleshooting

This checkpoint changes external YARA and active-plugin checksum reporting. It
is separate from the unmerged static-core verification work in PR #33. Native
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
part of this checkpoint. Existing static-core PR #33 remains separately reviewable.

## Primary references and decisions

- [YARA CLI](https://yara.readthedocs.io/en/latest/commandline.html): recursive scans follow links unless explicitly disabled; require the advertised no-follow capability.
- [WP-CLI plugin checksums](https://developer.wordpress.org/cli/commands/plugin/verify-checksums/): preserve its JSON and package-deviation contract without TLS bypass.
- [WP-CLI plugin list](https://developer.wordpress.org/cli/commands/plugin/list/): active versus network-active scope and WordPress.org metadata.
- [WordPress hardening](https://developer.wordpress.org/advanced-administration/security/hardening/): least privilege and independent recovery.
- [GitHub secure use](https://docs.github.com/en/actions/reference/security/secure-use): preserve read-only PR jobs and separate release authority.
- [SSDF publications](https://csrc.nist.gov/projects/ssdf/publications): use SSDF 1.1 final as guidance; 1.2 is listed as an initial public draft, not an adopted certification.
- [OpenSSF Scorecard checks](https://github.com/ossf/scorecard/blob/main/docs/checks.md): review pinned dependencies and workflow boundaries; no Scorecard score or certification is claimed.
