#!/usr/bin/env bash
export _PW_EXPLICIT_REMEDIATION=0
RUN_NAME=full
RUN_DESC="comprehensive WordPress security audit, deep integrity and threat inspection"
RUN_DOES="Runs the complete security suite: persistence, filesystem evidence, deep PHP/JavaScript/upload inspection, database malware, integrity and optional vulnerability intelligence."
RUN_WHY="Use for thorough security investigation. It never performs ordinary cleanup, database repair, optimization or configuration changes."
unset PRESSWARDEN_SKIP_DB_PRIV_SCOPE PRESSWARDEN_SKIP_DB_CRED_REUSE 2>/dev/null || true
CHECKS="host-persistence filesystem-security-full htcheck confcheck php-runtime phpcheck sensitive-files wp-access wp-core wp-root wp-plugins wp-uploads phpdeep php-obfuscated-loader php-threat-intel wp-campaign-intel js-threat-intel external-yara wp-plugin-integrity wp-wordfence-intel wp-patchstack-intel wp-vulnerabilities wp-uploads-deep wp-db wp-db-malware"
. "$(cd "$(dirname "$0")/.." && pwd)/lib/_runner.sh"
run_all
