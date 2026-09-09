#!/usr/bin/env bash
# sensitive-files — exposed secrets, dumps, VCS metadata, logs and conservative inode cleanup
NAME=sensitive-files; DESC="public-web secret/backup/VCS exposure + conservative inode cleanup"
SCAN_DOES="Searches public web trees for environment files, private keys, database dumps, backups, VCS metadata, exposed logs, and disposable OS/development metadata that can waste inodes."
SCAN_WHY="Accidentally published secrets or backups can expose credentials or source history; removing verified disposable metadata and stale logs reduces inode usage without deleting WordPress/runtime assets."
. "$(cd "$(dirname "$0")/.." && pwd)/lib/_lib.sh"

_inside_live_git_tree() {
  local p="$1" d
  d=$(dirname "$p")
  while [ "$d" != "/" ]; do
    case "$d" in "$ROOT"|"$ROOT"/*) : ;; *) break ;; esac
    [ -e "$d/.git" ] && return 0
    [ "$d" = "$ROOT" ] && break
    d=$(dirname "$d")
  done
  return 1
}

_cleanup_metrics() {
  local list="$1" p n b inodes=0 bytes=0
  while IFS= read -r p; do
    [ -n "$p" ] || continue
    [ -e "$p" ] || [ -L "$p" ] || continue
    if [ -d "$p" ] && [ ! -L "$p" ]; then
      n=$(find "$p" -xdev -print 2>/dev/null | wc -l | tr -d '[:space:]')
      b=$(du -sb -- "$p" 2>/dev/null | awk '{print $1}')
      case "$n" in ''|*[!0-9]*) n=1 ;; esac
      case "$b" in ''|*[!0-9]*) b=0 ;; esac
      inodes=$((inodes+n)); bytes=$((bytes+b))
    else
      b=$(stat -c '%s' -- "$p" 2>/dev/null || echo 0)
      case "$b" in ''|*[!0-9]*) b=0 ;; esac
      inodes=$((inodes+1)); bytes=$((bytes+b))
    fi
  done < "$list"
  printf '%s|%s\n' "$inodes" "$bytes"
}

_prompt_cleanup_action() {
  local list="$1" top metrics inodes bytes ans
  top=$(grep -c . "$list" 2>/dev/null); top=${top:-0}
  [ "$top" -gt 0 ] || return 0
  metrics=$(_cleanup_metrics "$list")
  inodes=${metrics%%|*}; bytes=${metrics#*|}

  printf '\n    %s%sCLEANUP ACTION%s  %s top-level candidate(s) • ~%s inode(s) • %s\n' "$B" "$BL" "$X" "$top" "$inodes" "$(human_bytes "$bytes")"
  printf '    %sℹ%s  candidates are quarantined before removal; plugin/theme updates may recreate packaged metadata\n' "$C" "$X"

  [ "$PRESSWARDEN_INTERACTIVE" != 0 ] || { printf '    %sℹ%s  non-interactive session — cleanup skipped\n' "$C" "$X"; return 0; }
  [ -t 0 ] || { printf '    %sℹ%s  non-interactive session — cleanup skipped\n' "$C" "$X"; return 0; }

  _pw_quarantine_prepare "$list" cleanup || return 2
  printf '    %s[c]%s cleanup + quarantine   %s[s]%s skip %s(default)%s : ' "$B$R" "$X" "$B$G" "$X" "$D" "$X"
  IFS= read -r ans || ans='s'
  case "$ans" in
    c|C|clean|cleanup|CLEAN|CLEANUP)
      printf '    %sℹ%s  backing up cleanup candidates to quarantine before removal...\n' "$C" "$X"
      _quarantine_delete "$list" "$PW_Q_WORK/plan.json" cleanup || true
      ;;
    *) printf '    %s%s↷ SKIPPED%s  no cleanup files changed\n' "$B" "$Y" "$X" ;;
  esac
  _pw_quarantine_discard_plan
}

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
  report "$L" issue "no obvious environment/private credential files under public_html"

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
  report "$L" issue "no unexpected database/config backup artifacts exposed in the web tree"
  note "known plugin schema SQL is suppressed only at verified paths: LiteSpeed Cache src/data_structure/*.sql; Modern Events Calendar assets/sql/*.sql"

  sec "Private key material in high-risk web locations"
  L=$(tmpf)
  for s in "${SCAN_ROOTS[@]}"; do
    find "$s" -maxdepth 2 -type f \( -iname '*.key' -o -iname '*.pem' \) -print 2>/dev/null >> "$L"
    [ -d "$s/wp-content/uploads" ] && find "$s/wp-content/uploads" -type f \( -iname '*.key' -o -iname '*.pem' \) -print 2>/dev/null >> "$L"
  done
  report "$L" review "no key/PEM material in root, shallow web paths, or uploads"

  sec "Version-control metadata under public_html"
  L=$(tmpf)
  for s in "${TREE_ROOTS[@]}"; do
    find "$s" -type d \( -name '.git' -o -name '.svn' -o -name '.hg' \) \
      -not -path '*/.private/*' -print 2>/dev/null >> "$L"
  done
  report "$L" review "no VCS metadata directories found under public_html"

  sec "Public log files" "non-empty logs under public_html • optional cleanup"
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
    note "log storage found: $logs file(s), $(human_bytes "$logbytes") total; applications may recreate logs after deletion"
  fi
  report "$L" review "no non-empty public .log/error_log/php_errorlog files found"

  sec "Disposable OS/development metadata" "inode cleanup • INFO only • runtime-safe candidates"
  L=$(tmpf); local RAW CAND metrics inodes bytes
  RAW=$(tmpf); CAND=$(tmpf)
  : > "$L"; : > "$RAW"; : > "$CAND"

  for s in "${TREE_ROOTS[@]}"; do
    find "$s" \
      \( -type d \( -name vendor -o -name node_modules -o -name .git -o -name .svn -o -name .hg -o -name .private \) -prune \) -o \
      \( -type d \( -name '__MACOSX' -o -name '.AppleDouble' \) -print -prune \) \
      2>/dev/null >> "$L"

    find "$s" \
      \( -type d \( -name vendor -o -name node_modules -o -name .git -o -name .svn -o -name .hg -o -name .private -o -name __MACOSX -o -name .AppleDouble \) -prune \) -o \
      \( -type f \
         \( -name '.DS_Store' -o -name 'Thumbs.db' -o -name 'desktop.ini' -o -name '._*' -o -name '.LSOverride' \) \
         -print \) 2>/dev/null >> "$L"

    find "$s" \
      \( -type d \( -name vendor -o -name node_modules -o -name .git -o -name .svn -o -name .hg -o -name .private -o -name __MACOSX -o -name .AppleDouble \) -prune \) -o \
      \( -type d \
         \( -name '.idea' -o -name '.vscode' -o -name '.pytest_cache' -o -name '.mypy_cache' -o -name '.sass-cache' \) \
         -not -path '*/wp-content/plugins/*' \
         -not -path '*/wp-content/themes/*' \
         -print -prune \) 2>/dev/null >> "$RAW"

    find "$s" \
      \( -type d \( -name vendor -o -name node_modules -o -name .git -o -name .svn -o -name .hg -o -name .private -o -name __MACOSX -o -name .AppleDouble \) -prune \) -o \
      \( -type f \
         \( -name '.gitignore' -o -name '.gitattributes' -o -name '.gitkeep' \
            -o -name '.editorconfig' -o -name '.eslintignore' -o -name '.stylelintignore' \
            -o -name '.prettierignore' -o -name '.npmignore' \
            -o -name 'phpcs.xml' -o -name 'phpcs.xml.dist' -o -name '.phpcs.xml' -o -name '.phpcs.xml.dist' \
            -o -name 'phpstan.neon' -o -name 'phpstan.neon.dist' \
            -o -name 'phpunit.xml' -o -name 'phpunit.xml.dist' \
            -o -name '.eslintcache' -o -name '.stylelintcache' -o -name '.phpunit.result.cache' \) \
         -not -path '*/wp-content/plugins/*' \
         -not -path '*/wp-content/themes/*' \
         -print \) 2>/dev/null >> "$RAW"
  done

  sort -u -o "$RAW" "$RAW" 2>/dev/null || true
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    _inside_live_git_tree "$f" && continue
    printf '%s\n' "$f" >> "$L"
  done < "$RAW"

  sort -u -o "$L" "$L" 2>/dev/null || true
  cp -f "$L" "$CAND" 2>/dev/null || true

  if [ -s "$CAND" ]; then
    metrics=$(_cleanup_metrics "$CAND")
    inodes=${metrics%%|*}; bytes=${metrics#*|}
    note "cleanup candidates: $(grep -c . "$CAND" 2>/dev/null) top-level item(s) • approximately $inodes inode(s) • $(human_bytes "$bytes")"
    note ".gitignore/.gitattributes/.gitkeep and development metadata are included only when no live .git ancestor exists"
    note "plugin/theme packaged development metadata is preserved so cleanup does not manufacture checksum failures"
    note "not included: wp-content/cache, uploads/media, vendor, node_modules, .well-known, Hostinger .private, PHP configs, or application/runtime data"
  fi

  report "$L" info "no disposable OS/development metadata cleanup candidates found" noaction
  _prompt_cleanup_action "$CAND"
  rm -f "$RAW" "$CAND"

  finish
}
run_logged sensitive-files
