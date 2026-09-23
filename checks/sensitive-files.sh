#!/usr/bin/env bash
# sensitive-files — exposed secrets, dumps, VCS metadata, logs
NAME=sensitive-files; DESC="public-web secret/backup/VCS exposure"
SCAN_DOES="Searches public web trees for environment files, private keys, database dumps, backups, VCS metadata, exposed logs."
SCAN_WHY="Accidentally published secrets or backups can expose credentials or source history; read-only exposure inventory preserves files and logs as potential incident evidence."
. "$(cd "$(dirname "$0")/.." && pwd)/lib/_lib.sh"

main() {
  banner
  local L s f size

  sec "Environment/config secrets under public_html"
  L=$(tmpf)
  for s in "${TREE_ROOTS[@]}"; do
    find "$s" -type f \
      \( -name '.env' -o -name '.env.*' -o -name 'id_rsa' -o -name 'id_ed25519' -o -name 'auth.json' -o -name 'composer-auth.json' \) \
      -not -name '.env.example' -not -name '.env.sample' \
      -not -path '*/vendor/*' -not -path '*/node_modules/*' -not -path '*/.private/*' -print 2>/dev/null >> "$L"
  done
  report "$L" issue "no obvious environment/private credential files under public_html" noaction

  sec "Database/config backup artifacts"
  L=$(tmpf)
  for s in "${TREE_ROOTS[@]}"; do
    find "$s" -type f \
      \( -iname '*.sql' -o -iname '*.sql.gz' -o -iname '*.sql.zip' \
         -o -name 'wp-config.php.*' -o -name 'wp-config.bak*' -o -name 'wp-config.old' -o -name 'wp-config.txt' \) \
      -not -path '*/.private/*' \
      -not -path '*/wp-content/plugins/litespeed-cache/src/data_structure/*.sql' \
      -not -path '*/wp-content/plugins/modern-events-calendar/assets/sql/*.sql' \
      -not -path '*/wp-content/plugins/modern-events-calendar-lite/assets/sql/*.sql' \
      -print 2>/dev/null >> "$L"
  done
  report "$L" issue "no unexpected database/config backup artifacts exposed in the web tree" noaction
  note "known plugin schema SQL is suppressed only at verified paths: LiteSpeed Cache src/data_structure/*.sql; Modern Events Calendar assets/sql/*.sql"

  sec "Private key material in high-risk web locations"
  L=$(tmpf)
  for s in "${SCAN_ROOTS[@]}"; do
    find "$s" -maxdepth 2 -type f \( -iname '*.key' -o -iname '*.pem' \) -print 2>/dev/null >> "$L"
    [ -d "$s/wp-content/uploads" ] && find "$s/wp-content/uploads" -type f \( -iname '*.key' -o -iname '*.pem' \) -print 2>/dev/null >> "$L"
  done
  report "$L" review "no key/PEM material in root, shallow web paths, or uploads" noaction

  sec "Version-control metadata under public_html"
  L=$(tmpf)
  for s in "${TREE_ROOTS[@]}"; do
    find "$s" -type d \( -name '.git' -o -name '.svn' -o -name '.hg' \) \
      -not -path '*/.private/*' -print 2>/dev/null >> "$L"
  done
  report "$L" review "no VCS metadata directories found under public_html" noaction

  sec "Public log files" "non-empty logs under public_html • evidence inventory only"
  L=$(tmpf)
  for s in "${TREE_ROOTS[@]}"; do
    find "$s" \
      \( -type d \( -name vendor -o -name node_modules -o -name .git -o -name .svn -o -name .hg -o -name .private \) -prune \) -o \
      \( -type f -size +0c \
         \( -iname '*.log' -o -iname '*.log.*' -o -name 'error_log' -o -name 'php_errorlog' \) -print \) \
      2>/dev/null >> "$L"
  done
  sort -u -o "$L" "$L" 2>/dev/null || true
  local logs logbytes=0 b
  logs=$(grep -c . "$L" 2>/dev/null); logs=${logs:-0}
  if [ "$logs" -gt 0 ]; then
    while IFS= read -r f; do
      b=$(stat -c '%s' -- "$f" 2>/dev/null || echo 0)
      case "$b" in ''|*[!0-9]*) b=0 ;; esac
      logbytes=$((logbytes+b))
    done < "$L"
    note "log storage found: $logs file(s), $(human_bytes "$logbytes") total; live logs are retained as potential evidence"
  fi
  report "$L" review "no non-empty public .log/error_log/php_errorlog files found" noaction

  finish
}
run_logged sensitive-files
