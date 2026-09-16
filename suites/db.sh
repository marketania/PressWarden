#!/usr/bin/env bash
RUN_NAME=db
RUN_DESC="database only • security/isolation + malware persistence audit → LiteSpeed cleanup → conditional repair → optimize → verify"
RUN_DOES="Runs database security/isolation checks, targeted stored-malware and suspicious administrator-persistence intelligence, LiteSpeed Cache cleanup where active, then conditional native table repair, optimization, and final verification."
RUN_WHY="Use when you want database posture, stored-threat inspection, cleanup, and health without scanning the WordPress filesystem."
unset PRESSWARDEN_SKIP_DB_PRIV_SCOPE PRESSWARDEN_SKIP_DB_CRED_REUSE 2>/dev/null || true
PW_LITESPEED_DB_SUITE=1
export PW_LITESPEED_DB_SUITE
CHECKS="wp-db wp-db-malware litespeed-db wp-db-maintenance"
. "$(cd "$(dirname "$0")/.." && pwd)/lib/_runner.sh"
run_all
