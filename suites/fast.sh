#!/usr/bin/env bash
export _PW_EXPLICIT_REMEDIATION=0
RUN_NAME=fast
RUN_DESC="high-signal routine security and native threat intelligence; lean database inspection"
RUN_DOES="Runs persistence, filesystem/configuration exposure, malware, core integrity, plugin, upload, account and lean database threat checks."
RUN_WHY="Use frequently for high-signal investigation; deep scans and optional external vulnerability feeds belong to full/intel."
PRESSWARDEN_SKIP_DB_PRIV_SCOPE=1
PRESSWARDEN_SKIP_DB_CRED_REUSE=1
export PRESSWARDEN_SKIP_DB_PRIV_SCOPE PRESSWARDEN_SKIP_DB_CRED_REUSE
CHECKS="host-persistence filesystem-security htcheck confcheck php-runtime phpcheck phpquick php-obfuscated-loader php-threat-intel wp-campaign-intel js-threat-intel sensitive-files wp-access wp-core wp-root wp-plugins wp-uploads wp-db wp-db-malware"
. "$(cd "$(dirname "$0")/.." && pwd)/lib/_runner.sh"
run_all
