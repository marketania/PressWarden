# Handoff

Check this file and open pull requests before starting work. Record one branch and
owned area per agent/task. Resolve overlap through comments on the owning PR;
never push that agent's branch. Remove the entry when the PR is merged.

## Active work

- `claude/project-thread-kwdhal` (Claude): exposure findings in `remediate files`,
  post-scan remediation offer and `quarantine prune`. Owns `checks/sensitive-files.sh`,
  `lib/remediation.sh`, quarantine prune code and related docs/tests.

## Publication handoff — 2.0.2

The owner authorized publication on 2026-10-21. PR #40 includes the command
usability, scanner coverage, configuration and newcomer-guide work in version
2.0.2, including the reviewed safety fixes from PR #34/#33. The task ownership
entry is removed with this merge.

The existing verified source-release workflow publishes only after the required
checks pass on the exact main commit. See [release notes](releases/2.0.2.md) for
operator changes and update instructions. Production website operations are
separate from source publication.

This is PressWarden, an independent Bash/PHP application. Runtime changes, client sites,
production credentials and deployment infrastructure are outside this setup.

Read [the 2026-10-11 build/deployment decision](DEPLOYMENT-DECISION.md) before any build/release planning.
