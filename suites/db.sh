#!/usr/bin/env bash
export _PW_EXPLICIT_REMEDIATION=0
RUN_NAME=db
RUN_DESC="database security, stored threats and credential isolation; no maintenance"
RUN_DOES="Inspects stored malicious payloads, administrator persistence, URL tampering, grants and cross-site credential/salt reuse."
RUN_WHY="Use for database security investigation; PressGarden independently owns database health and maintenance."
unset PRESSWARDEN_SKIP_DB_PRIV_SCOPE PRESSWARDEN_SKIP_DB_CRED_REUSE 2>/dev/null || true
CHECKS="wp-db wp-db-malware"
. "$(cd "$(dirname "$0")/.." && pwd)/lib/_runner.sh"
run_all
