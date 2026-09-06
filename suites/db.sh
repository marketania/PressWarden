#!/usr/bin/env bash
RUN_NAME=db
RUN_DESC="database only • security/isolation audit → conditional repair → optimize → verify"
RUN_DOES="Runs only the database security audit followed by conditional repair, optimization, and final verification."
RUN_WHY="Use when you want database posture and health without scanning the WordPress filesystem."
unset PRESSWARDEN_SKIP_DB_PRIV_SCOPE PRESSWARDEN_SKIP_DB_CRED_REUSE 2>/dev/null || true
CHECKS="wp-db wp-db-maintenance"
. "$(cd "$(dirname "$0")/.." && pwd)/lib/_runner.sh"
run_all
