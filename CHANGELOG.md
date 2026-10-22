# Changelog

## 2.0.2 — 2026-10-21

- Add a newcomer walkthrough for selected-source installation, configuration,
  discovery, first inspection, optional scanner limits, saved results and recovery;
  explain versioned source installation and moving-main updates.
- Refuse unusable, syntactically invalid or unsuccessful saved configuration
  before dispatch. Preserve exact exported values, including multiline exclusion
  lists, and stop when a readonly saved value blocks an explicit override.
- Keep presentation flags from replacing a missing named target; propagate config
  root-validation errors and display the effective reports directory.
- Explain empty saved-run history without creating state, and reject explicitly
  empty, invalid or unrecorded run IDs instead of quietly selecting the latest run.
- Report missing local prerequisites for configured WPScan/YARA providers in
  doctor without invoking those scanners or testing external credentials.
- Add one `scan` entrypoint with full/incident/database/PHP/JavaScript/runtime selectors,
  strict `--target` support and compatibility with all existing scan verbs.
- Add short grouped help, topic help, a complete `help all` reference and `status`
  as an alias for saved run status.
- Honor `NO_COLOR`, avoid ANSI output in redirected stdout when only stderr is a
  terminal, and support `--color=auto|always|never` / `--no-color` consistently.
- Make `update --help` read-only and reject ignored extra arguments before update,
  intelligence refresh, configuration advice or version dispatch.
- Include the scanner/evidence fixes from #34 (which
  includes #33), preserving their regression tests and original attribution.


- Preserve exact finding bytes during excluded-site projection, reject unsafe original sources before filtering, and retain original evidence on failure. Refuse cleanup of a projection directory replaced by a link. Add ten exclusion/report regression methods.

- Escape untrusted terminal/bidi controls in shared findings display, bound long rows without truncating saved evidence, and retain final unterminated findings.
- Report unreadable/missing/unsafe findings sources as incomplete; retain unsaved temporary evidence and disable generic file actions after report failures. Add inert byte-level reporting regressions.

- Combine static-core linked-path/manifest validation with optional-scanner coverage safeguards.
- Interpret bounded WPScan JSON, preserve upstream vulnerability exit 5, refuse guessed/invalid URLs, and report API/timeout/coverage failures without leaking raw diagnostics.

- Preserve YARA partial matches, require no-follow support, refuse excluded recursive subtrees and bound execution/output; report failures as incomplete.
- Separate checksum provider diagnostics from JSON, validate plugin identities and paths, and report unavailable vendor coverage honestly. Added metadata names are review conditions, not a claim of harmless contents.
- Add regression tests and exact attribution/link/artwork preservation checks. The tools remain independently installable with no sibling runtime dependency.

## 2.0.1 — 2026-09-24

- Explicitly empty or invalid `sites` directory arguments now stop with exit 2 instead of falling back to fleet inventory.
- Directory targets retain exclusions relative to the original fleet root; discovery cache keys include that scope.
- Uninstall refuses update/recovery markers, including dangling symlinks, before changing managed files.

Add approved README artwork, distribution regressions, supported-PHP CI, pinned Actions and corrected project Codex defaults.

## 2.0.0 — Press family split

- Fix downloaded portable/user installation: validate the single-root archive, extract its contents without assuming validator output, and ignore inherited tar/gzip options. Add offline download-path, identity, archive/link and transport-failure regression tests.
- Security-only suites; no maintenance or policy mutations.
- Hardening moved to PressHarden, maintenance/performance to PressGarden.
- Explicit interactive security remediation is separated from scans.
- Pre-split continuation cannot replay a mixed command plan.
- Independent discovery, evidence, reports, intelligence and update behavior retained.

Historical releases: [1.x changelog](docs/CHANGELOG-1.x.md).
