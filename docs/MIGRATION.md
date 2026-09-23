# Migration from PressWarden 1.1.24

Source commit: `63adec182b4d3a20dbd5e24daa9b9fa0e98510b8`.

| Old interface / side effect | New owner and interface |
|---|---|
| `presswarden lock/unlock/lock-status TARGET` | `pressharden lock/unlock/lock-status TARGET` |
| `presswarden file-mods ACTION TARGET` | `pressharden file-mods ACTION TARGET` |
| `presswarden wp-settings ...` | `pressharden wp-settings ...` |
| `presswarden auto-updates ...` | `pressharden auto-updates ...` |
| Implicit debug-setting mutation from configuration checks | Explicit `pressharden wp-settings set debug/debug-display/debug-log disabled TARGET` |
| Authentication/cache salt-rotation prompts inside DB inspection | `pressharden salts rotate auth/cache TARGET` |
| Detailed PHP/provider comparison | `pressharden php inspect TARGET --details` |
| `presswarden litespeed-db status/optimize TARGET` | `pressgarden litespeed-db status/optimize TARGET` |
| `presswarden litespeed AREA ACTION ...` | `pressgarden litespeed AREA ACTION ...` |
| Native DB maintenance mixed into `full` or `db` | Explicit `pressgarden db check/repair/optimize/cleanup TARGET` |
| `presswarden cleanup TARGET` | `pressgarden cleanup preview/execute TARGET`; default is preview |
| Implicit file/core remediation from ordinary scans | Explicit `presswarden remediate files/core TARGET`, terminal-only/default skip |

Slash-separated verbs above indicate alternatives, not literal CLI arguments. Run each tool's help for complete syntax. Former commands in PressWarden give migration guidance and exit `2`, without invoking any sibling. This is a transition aid, not a permanent wrapper or runtime dependency.

Each tool has its own configuration, state, cache, reports, backups, update target and portable marker. Copy only relevant configuration values, renaming the intended namespace. Never copy vulnerability keys to a maintenance/policy tool. No program automatically migrates, deletes or imports old private state. Old security reports/evidence stay in PressWarden's state; old policy/maintenance backups remain recoverable at their original path until deliberately archived or migrated.

Saved runs from 1.x are not resumed by this release. Original history is still available, but a fresh security scan is required after the split.

Safety tightening is deliberate: original automatic DB maintenance is removed; current/live logs, VCS history and unknown cleanup candidates are not blindly deleted; failed target resolution is fatal; operations retain private verified recovery data; on-disk PHP settings are not labeled web-effective. These restrictions are not hidden loss of a capability.
