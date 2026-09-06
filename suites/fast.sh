#!/usr/bin/env bash
RUN_NAME=fast
RUN_DESC="high-signal routine security + hardening • no deep PHP/image scan • lean DB audit"
RUN_DOES="Runs routine persistence, filesystem, configuration, PHP, malware, integrity, plugin/theme, upload, access, and lean database checks."
RUN_WHY="Use frequently for broad coverage with lower runtime; deep content scans, plugin package checksums, and database maintenance are reserved for full."
PRESSWARDEN_SKIP_DB_PRIV_SCOPE=1
PRESSWARDEN_SKIP_DB_CRED_REUSE=1
export PRESSWARDEN_SKIP_DB_PRIV_SCOPE PRESSWARDEN_SKIP_DB_CRED_REUSE
CHECKS="host-persistence filesystem-security htcheck confcheck php-runtime phpcheck phpquick sensitive-files wp-access wp-core wp-root wp-plugins wp-themes wp-uploads wp-db"
. "$(cd "$(dirname "$0")/.." && pwd)/lib/_runner.sh"
run_all
