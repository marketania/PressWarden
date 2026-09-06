#!/usr/bin/env bash
RUN_NAME=full
RUN_DESC="comprehensive sweep • hardening + deep PHP/image scans + threat intelligence + official integrity + DB maintenance"
RUN_DOES="Runs the complete local security suite, including recursive permissions, deep PHP/image inspection, JavaScript/campaign/database-malware intelligence, official integrity checks, optional Wordfence/Patchstack/WPScan vulnerability intelligence, and database maintenance."
RUN_WHY="Use periodically or after an incident when slower exhaustive checks, network-backed intelligence, and repair operations are justified."
unset PRESSWARDEN_SKIP_DB_PRIV_SCOPE PRESSWARDEN_SKIP_DB_CRED_REUSE 2>/dev/null || true
CHECKS="host-persistence filesystem-security-full htcheck confcheck php-runtime phpcheck sensitive-files wp-access wp-core wp-root wp-plugins wp-themes wp-uploads phpdeep php-obfuscated-loader wp-campaign-intel js-threat-intel wp-plugin-integrity wp-wordfence-intel wp-patchstack-intel wp-vulnerabilities wp-uploads-deep wp-db wp-db-malware wp-db-maintenance"
. "$(cd "$(dirname "$0")/.." && pwd)/lib/_runner.sh"
run_all
