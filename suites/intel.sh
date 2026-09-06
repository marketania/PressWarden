#!/usr/bin/env bash
RUN_NAME=intel
RUN_DESC="focused PHP/JavaScript/campaign/database + vulnerability intelligence"
RUN_DOES="Runs PressWarden's native behavior/campaign intelligence plus optional Wordfence, Patchstack and WPScan vulnerability intelligence without the full filesystem/database-maintenance sweep."
RUN_WHY="Use when investigating suspicious behavior or after refreshing intelligence data and you want a focused threat-oriented pass."
PRESSWARDEN_SKIP_DB_PRIV_SCOPE=1
PRESSWARDEN_SKIP_DB_CRED_REUSE=1
export PRESSWARDEN_SKIP_DB_PRIV_SCOPE PRESSWARDEN_SKIP_DB_CRED_REUSE
CHECKS="phpquick php-obfuscated-loader php-threat-intel wp-campaign-intel js-threat-intel wp-db-malware wp-wordfence-intel wp-patchstack-intel wp-vulnerabilities"
. "$(cd "$(dirname "$0")/.." && pwd)/lib/_runner.sh"
run_all
