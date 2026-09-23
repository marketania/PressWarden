#!/usr/bin/env bash
set -euo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
for file in checks/wp-settings.sh checks/file-mods.sh checks/wp-auto-updates.sh checks/litespeed.sh checks/litespeed-db.sh checks/wp-db-maintenance.sh lib/config-transaction.sh lib/php-environment.php; do [ ! -e "$REPO/$file" ]; done
for suite in fast full db incident; do
  line=$(grep '^CHECKS=' "$REPO/suites/$suite.sh")
  ! printf '%s' "$line" | grep -Eq 'wp-settings|file-mods|auto-updates|litespeed|wp-db-maintenance|wp-themes'
  grep -q 'export _PW_EXPLICIT_REMEDIATION=0' "$REPO/suites/$suite.sh"
done
! grep -E 'wp config (set|shuffle-salts)|_prompt_cleanup|_prompt_disable_debug' "$REPO/checks/wp-db.sh" "$REPO/checks/confcheck.sh" "$REPO/checks/sensitive-files.sh"
mkdir -p "$T/bin" "$T/home" "$T/site/wp-admin" "$T/site/wp-content" "$T/site/wp-includes"
printf '<?php $wp_version="7.1";\n' > "$T/site/wp-includes/version.php"
printf '<?php\ndefine("WP_DEBUG",true);\n' > "$T/site/wp-config.php"
touch "$T/site/wp-load.php" "$T/site/wp-settings.php"
printf 'auto_prepend_file = /tmp/legitimate-or-suspicious.php\n' > "$T/site/.user.ini"
printf '<?php /* inert evidence */\n' > "$T/site/suspicious.php"
for b in wp curl wget pressharden pressgarden; do printf '#!/bin/sh\necho unexpected >> "$TEST_CALLS"\nexit 99\n' > "$T/bin/$b"; chmod +x "$T/bin/$b"; done
export PATH="$T/bin:$PATH" HOME="$T/home" TEST_CALLS="$T/calls" PRESSWARDEN_CONFIG_FILE="$T/no-config" PRESSWARDEN_SCAN_ROOT="$T/site" PRESSWARDEN_STATE_DIR="$T/state" PRESSWARDEN_CACHE_DIR="$T/cache" PRESSWARDEN_INTERACTIVE=0 PRESSWARDEN_PROGRESS=0 PRESSWARDEN_NOCOLOR=1
before=$(sha256sum "$T/site/wp-config.php" "$T/site/.user.ini" "$T/site/suspicious.php")
for cmd in lock unlock lock-status wp-settings auto-updates file-mods cleanup litespeed litespeed-db; do
 rc=0; bash "$REPO/presswarden" "$cmd" example.com > "$T/out" 2>&1 || rc=$?
 [ "$rc" -eq 2 ]; grep -q 'moved to Press' "$T/out"
done
[ ! -e "$T/calls" ]
rc=0; bash "$REPO/presswarden" inspect runtime "$T/site" > "$T/runtime" 2>&1 || rc=$?
[ "$rc" -eq 1 ] || { cat "$T/runtime"; exit 1; }
grep -q auto_prepend_file "$T/runtime"; ! grep -q '/tmp/legitimate-or-suspicious.php' "$T/runtime"
[ ! -e "$T/calls" ]
# Inherited remediation variables cannot change a read-only CLI invocation.
rc=0; _PW_EXPLICIT_REMEDIATION=1 bash "$REPO/presswarden" inspect runtime "$T/site" > /dev/null 2>&1 || rc=$?; [ "$rc" -eq 1 ]
[ "$(sha256sum "$T/site/wp-config.php" "$T/site/.user.ini" "$T/site/suspicious.php")" = "$before" ]
rc=0; bash "$REPO/presswarden" remediate core "$T/site" > "$T/no-tty" 2>&1 || rc=$?; [ "$rc" -eq 2 ]
for cmd in fast full db incident; do rc=0; bash "$REPO/presswarden" "$cmd" '' > /dev/null 2>&1 || rc=$?; [ "$rc" -eq 2 ]; done
printf 'Security-only suites, moved-command non-execution, inert persistence visibility, empty target and remediation gates PASS\n'
