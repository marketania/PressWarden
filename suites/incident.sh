#!/usr/bin/env bash
RUN_NAME=incident
RUN_DESC="evidence-first WordPress compromise investigation • persistence + malware + integrity + accounts + database threats"
RUN_DOES="Runs security-relevant change detection when a baseline exists, host and WordPress persistence checks, deep PHP/JavaScript malware inspection, administrator inventory, official integrity verification, vulnerability intelligence, upload inspection, and database threat checks."
RUN_WHY="Use when a site may be compromised or reinfected. Incident mode prioritizes evidence collection and correlation and intentionally excludes database repair/optimization so investigation does not alter database state unnecessarily."

# Administrator and application-password inventory is always relevant during an incident.
PRESSWARDEN_ADMINS_CHECK=1; export PRESSWARDEN_ADMINS_CHECK
# Preserve the existing deep-upload contract: empty asks interactively, 1 runs,
# 0 skips, and noninteractive execution skips unless explicitly enabled.

unset PRESSWARDEN_SKIP_DB_PRIV_SCOPE PRESSWARDEN_SKIP_DB_CRED_REUSE 2>/dev/null || true
CHECKS="baseline-changes host-persistence filesystem-security-full htcheck confcheck php-runtime phpcheck sensitive-files wp-access wp-core wp-root wp-plugins wp-themes wp-uploads phpdeep php-obfuscated-loader php-threat-intel wp-campaign-intel js-threat-intel external-yara wp-plugin-integrity wp-wordfence-intel wp-patchstack-intel wp-vulnerabilities wp-uploads-deep wp-db wp-db-malware"
. "$(cd "$(dirname "$0")/.." && pwd)/lib/_runner.sh"
run_all
