#!/usr/bin/env bash
RUN_NAME=db
RUN_DESC="database only • security/isolation + malware persistence audit → conditional repair → optimize → verify"
RUN_DOES="Runs database security/isolation checks, targeted stored-malware and suspicious administrator-persistence intelligence, then conditional repair, optimization, and final verification."
RUN_WHY="Use when you want database posture, stored-threat inspection, and health without scanning the WordPress filesystem."
unset PRESSWARDEN_SKIP_DB_PRIV_SCOPE PRESSWARDEN_SKIP_DB_CRED_REUSE 2>/dev/null || true
CHECKS="wp-db wp-db-malware wp-db-maintenance"
. "$(cd "$(dirname "$0")/.." && pwd)/lib/_runner.sh"
run_all
