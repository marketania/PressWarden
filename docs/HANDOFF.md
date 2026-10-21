# Handoff

Check this file and open pull requests before starting work. Record one branch and
owned area per agent/task. Resolve overlap through comments on the owning PR;
never push that agent's branch. Remove the entry when the PR is merged.

| Agent | Branch | Owned area | Status |
|---|---|---|---|
| Codex | `codex/cli-usability-audit-2026-10-21` | Reviewable consolidation of existing scanner safety candidate #34 (includes #33), command usability, terminal output, newcomer README and configuration/scope/readiness/result regressions | PR #40 review candidate; follow-up usability audit; unmerged and unreleased |

The follow-up audit preserves exported scope values exactly, refuses unusable or
failed configuration, keeps color flags from consuming a target value, improves
first-run status/history and local optional-provider diagnostics, and adds an
actionable newcomer README. Published v2.0.1 predates the compact candidate CLI;
no version bump, main merge, release or production deployment is part of this work.

This is PressWarden, an independent Bash/PHP application. Runtime changes, client sites,
production credentials and deployment infrastructure are outside this setup.

Read [the 2026-10-11 build/deployment decision](DEPLOYMENT-DECISION.md) before any build/release planning.
