# AGENTS.md

## Product mission

Security detection, malware and vulnerability investigation, integrity, threat intelligence, incident response, evidence, quarantine, baselines, and security reporting.

## Engineering rules

- Read only the documentation relevant to the task. Use `docs/AI-DEVELOPMENT.md` for model/effort guidance and the repository architecture/migration docs when a change touches those boundaries.
- Keep ordinary scans evidence-first and read-only with respect to website maintenance and configuration. Never reintroduce routine DB optimization, cache management, cleanup, or hardening-policy mutations. Invalid or ambiguous targets must fail closed and must never broaden to the fleet.
- Treat repository edits, pull requests, releases, and production website operations as distinct actions. Report only actions actually confirmed by tools.
- Keep this repository independently installable and runnable. Do not add a runtime dependency on either sibling tool.
- Keep secrets, client data, SQL dumps, evidence, and private state out of prompts, commits, issues, and test fixtures.
- Prefer small, reviewable changes. Preserve historical examples and changelogs unless the task explicitly updates history.

## Validation

Use `bash tests/run.sh` for local benign-fixture coverage. Run the smallest relevant checks first, then required repository CI for merge. Security-remediation changes require focused target/evidence/recovery tests.

For reversible documentation-only changes, use focused validation rather than unrelated exhaustive testing unless repository policy or CI requires more.
