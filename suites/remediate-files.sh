#!/usr/bin/env bash
# Explicit interactive file-threat remediation; never maintenance or policy.
[ "${_PW_EXPLICIT_REMEDIATION:-0}" = 1 ] && [ -t 0 ] || exit 2
RUN_NAME=remediate-files
RUN_DESC='explicit interactive file-threat review; each removal requires separate approval'
RUN_DOES='Runs existing PHP/upload threat checks with evidence-first quarantine prompts for eligible unprotected files.'
RUN_WHY='Use only after preserving incident evidence and validating provenance. Review findings are not proof of malware.'
CHECKS='phpcheck phpquick phpdeep wp-uploads'
. "$(cd "$(dirname "$0")/.." && pwd)/lib/_runner.sh"
run_all
