# Architecture

PressWarden is the security member of three independent shell applications. The CLI resolves scope once, then invokes focused checks or ordered security suites. `lib/` contains its own discovery, targeting, output, bounded PHP/JavaScript/database analysis, intelligence, evidence, reporting, baseline and continuation helpers. `intel/` contains security rules and provider handling. `integrations/` documents optional security services. There is no runtime import from a sibling repository.

## Ownership

| Responsibility | Owner | Boundary |
|---|---|---|
| Malware, suspicious redirects, PHP/JavaScript/database threats, persistence | PressWarden | Detect/investigate; never routine cleanup |
| Core/plugin integrity, vulnerability intelligence, Wordfence/Patchstack/WPScan/CISA/YARA | PressWarden | No configuration or maintenance mutation |
| Baselines, reinfection analysis, correlation, evidence, history, continuation | PressWarden | Existing evidence protections retained |
| wp-config, locking, update policy, explicit auth/cache salt rotation, PHP policy | PressHarden | Desired-state configuration, not malware remediation |
| Native DB checks/engine-aware repair/optimization, cleanup, LiteSpeed/cache/CDN | PressGarden | Explicit operational intent and recovery, not incident remediation |
| Discovery, targeting, private path handling, update validation | Independent copies | Adapted into each product; no fourth shared runtime |

Configuration evidence can legitimately overlap: PressWarden detects suspicious auto-load directives or exposed debug state; PressHarden evaluates/configures the intended state. Only the latter owns those setters. Read-only account/DB credential-isolation checks remain security work; salt rotation moved to an explicit Harden transaction. Inactive-theme and cache coverage moved to Garden, while plugin/MU-plugin threat inspection remains here.

Ordinary scan entry points reset the remediation gate. Explicit terminal-only `remediate` entry points enable existing bounded evidence workflows with default-skip prompts. `full`, `db`, `fast`, `incident`, `intel` and `inspect` do not run maintenance or hardening checks. Version/check-plan validation prevents 1.x mixed run continuation.

See [full source inventory](OWNERSHIP.md) and [migration](MIGRATION.md). The inventory records the pinned source and every tracked file, including mixed responsibilities, migrated tests and owner-specific workflow decisions.
