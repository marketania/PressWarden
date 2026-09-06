#!/usr/bin/env bash
RUN_NAME=fast
RUN_DESC="high-signal routine security + hardening + native threat intelligence • no deep PHP/image scan • lean DB audit"
RUN_DOES="Runs routine persistence, filesystem, configuration, PHP, malware, JavaScript/campaign intelligence, integrity, plugin/theme, upload, access, and lean database checks."
RUN_WHY="Use frequently for broad high-signal coverage; deep content scans, external vulnerability feeds, plugin package checksums, and database maintenance are reserved for full/intel workflows."
PRESSWARDEN_SKIP_DB_PRIV_SCOPE=1
PRESSWARDEN_SKIP_DB_CRED_REUSE=1
export PRESSWARDEN_SKIP_DB_PRIV_SCOPE PRESSWARDEN_SKIP_DB_CRED_REUSE
CHECKS="host-persistence filesystem-security htcheck confcheck php-runtime phpcheck phpquick php-obfuscated-loader php-threat-intel wp-campaign-intel js-threat-intel sensitive-files wp-access wp-core wp-root wp-plugins wp-themes wp-uploads wp-db wp-db-malware"
. "$(cd "$(dirname "$0")/.." && pwd)/lib/_runner.sh"
run_all
