# Contributing to PressWarden

Thanks for helping improve PressWarden.

## Principles

- Prefer compound/contextual evidence over single-token malware signatures.
- Add a regression case for every false-positive fix.
- Never log secrets, salts, passwords, API tokens, or database credentials.
- Destructive changes must be explicit, reversible where practical, and quarantine/backup-backed.
- Keep provider-specific enrichment optional.
- Maintain compatibility with restricted shared-hosting shells; runtime scanner code must not rely on Bash process substitution.

## Before a pull request

```bash
find . -type f -name '*.sh' -exec bash -n {} \;
bash -n presswarden
./tests/smoke.sh
```

Describe what changed, why it is high-signal, expected false-positive behavior, and how it was tested.
