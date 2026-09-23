# Changelog

## 2.0.0 — Press family split

- Fix downloaded portable/user installation: validate the single-root archive, extract its contents without assuming validator output, and ignore inherited tar/gzip options. Add offline download-path, identity, archive/link and transport-failure regression tests.
- Security-only suites; no maintenance or policy mutations.
- Hardening moved to PressHarden, maintenance/performance to PressGarden.
- Explicit interactive security remediation is separated from scans.
- Pre-split continuation cannot replay a mixed command plan.
- Independent discovery, evidence, reports, intelligence and update behavior retained.

Historical releases: [1.x changelog](docs/CHANGELOG-1.x.md).
