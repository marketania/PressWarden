# Optional integrations

PressWarden core scanning requires no hosting-provider API. Integrations only enrich local findings.

- **WPScan API** — vulnerability intelligence when `WPSCAN_API_TOKEN` is configured.
- **Hostinger API** — exact per-site PHP version/options/extensions when `HOSTINGER_API_TOKEN` is configured. Without it, `php-runtime` continues with local/CLI and file-level override checks.

Tokens belong in `~/.config/presswarden/config` (mode `600`) or the environment. Never commit real tokens.
