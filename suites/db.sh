#!/usr/bin/env bash
RUN_NAME=db
RUN_DESC="database only • security/isolation audit → targeted malware intelligence → conditional repair → optimize → verify"
RUN_DOES="Runs the database security audit and targeted malware/persistence intelligence before conditional repair, optimization, and final verification."
RUN_WHY="Use when you want database security posture, stored-malware intelligence, and health without scanning the WordPress filesystem."
unset PRESSWARDEN_SKIP_DB_PRIV_SCOPE PRESSWARDEN_SKIP_DB_CRED_REUSE 2>/dev/null || true
CHECKS="wp-db wp-db-malware wp-db-maintenance"
. "$(cd "$(dirname "$0")/.." && pwd)/lib/_runner.sh"
run_all
