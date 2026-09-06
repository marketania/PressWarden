# Extract a real file path from either a plain path or grep -Hn style output:
#   /path/file.php
#   /path/file.php:123:matching text
_finding_path() {
  local line="$1" p
  # Findings can be files, symlinks, or narrowly-approved removable directories
  # such as VCS metadata.  The protection layer decides whether a directory is
  # actually eligible for one-key remediation.
  if [ -e "$line" ] || [ -L "$line" ]; then
    p="$line"
  else
    p=${line%%:*}
    [ -e "$p" ] || [ -L "$p" ] || return 1
  fi
  case "$p" in
    "$ROOT"/*) printf '%s\n' "$p" ;;
    *) return 1 ;;
  esac
}

# Files that are too dangerous to remove with a one-key remediation action.
# They remain visible in the report and can be repaired/replaced manually.
_is_protected_file() {
  local p="$1" root rel base
  root=$(_site_root_for_path "$p" 2>/dev/null || true)
  [ -n "$root" ] || return 1
  rel=${p#"$root"/}

  # Directory deletion is intentionally much stricter than file deletion.
  # Only VCS metadata directories are eligible here; every other directory is
  # protected even if some future report happens to list it.
  if [ -d "$p" ] && [ ! -L "$p" ]; then
    base=${p##*/}
    case "$base" in .git|.svn|.hg) return 1 ;; *) return 0 ;; esac
  fi

  case "$rel" in
    wp-config.php|.htaccess|.user.ini|php.ini) return 0 ;;
    wp-admin|wp-admin/*|wp-includes|wp-includes/*) return 0 ;;
    index.php|wp-load.php|wp-blog-header.php|wp-settings.php|wp-cron.php|wp-login.php|wp-mail.php|wp-activate.php|wp-signup.php|wp-trackback.php|wp-comments-post.php|xmlrpc.php) return 0 ;;
    wp-content/themes/*/functions.php) return 0 ;;
    *) return 1 ;;
  esac
}

_build_action_lists() {
  local findings="$1" deletable="$2" protected="$3" line p
  : > "$deletable"; : > "$protected"
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    p=$(_finding_path "$line" 2>/dev/null) || continue
    if _is_protected_file "$p"; then
      printf '%s\n' "$p" >> "$protected"
    else
      printf '%s\n' "$p" >> "$deletable"
    fi
  done < "$findings"
  sort -u -o "$deletable" "$deletable" 2>/dev/null || true
  sort -u -o "$protected" "$protected" 2>/dev/null || true
}

_quarantine_delete() {
  local list="$1" stamp qroot p rel dest okn=0 failn=0
  stamp=$(date +%Y%m%d-%H%M%S)
  qroot="$QUARANTINE/$stamp"
  mkdir -p "$qroot" 2>/dev/null || { printf '    %s✖ could not create quarantine: %s%s\n' "$R" "$qroot" "$X"; return 1; }

  while IFS= read -r p; do
    [ -n "$p" ] || continue
    [ -e "$p" ] || [ -L "$p" ] || continue
    rel=${p#"$ROOT"/}
    dest="$qroot/$rel"
    mkdir -p "$(dirname "$dest")" 2>/dev/null || { failn=$((failn+1)); continue; }
    if cp -a -- "$p" "$dest" 2>/dev/null && {
         if [ -d "$p" ] && [ ! -L "$p" ]; then rm -rf -- "$p" 2>/dev/null; else rm -f -- "$p" 2>/dev/null; fi
       }; then
      okn=$((okn+1)); DELETED=$((DELETED+1))
      printf '    %s%s✓ DELETED%s  ' "$B" "$G" "$X"; compact_line "$p"; printf '\n'
      [ -n "${DELETE_LOG:-}" ] && printf '%s | deleted=%s | quarantine=%s\n' "$(date '+%F %T')" "$p" "$dest" >> "$DELETE_LOG"
    else
      failn=$((failn+1))
      printf '    %s%s✖ FAILED%s   ' "$B" "$R" "$X"; compact_line "$p"; printf '\n'
    fi
  done < "$list"

  printf '    %sℹ%s  quarantine: %s\n' "$C" "$X" "$qroot"
  [ "$failn" -eq 0 ] || printf '    %s⚠%s  %s file(s) could not be removed\n' "$Y" "$X" "$failn"
  [ "$okn" -gt 0 ]
}

# Ask for remediation after a section with file findings.
# Default is always SKIP. In non-interactive use, nothing is deleted.
_prompt_file_action() {
  local findings="$1" sev="$2" del prot nd np ans
  [ "$sev" != info ] || return 0
  [ "$PRESSWARDEN_INTERACTIVE" != 0 ] || return 0
  [ -t 0 ] || { printf '    %sℹ%s  non-interactive session — remediation skipped\n' "$C" "$X"; return 0; }

  del=$(tmpf); prot=$(tmpf)
  _build_action_lists "$findings" "$del" "$prot"
  nd=$(grep -c . "$del" 2>/dev/null); nd=${nd:-0}
  np=$(grep -c . "$prot" 2>/dev/null); np=${np:-0}
  [ "$nd" -gt 0 ] || [ "$np" -gt 0 ] || { rm -f "$del" "$prot"; return 0; }

  printf '\n    %s%sACTION%s  ' "$B" "$BL" "$X"
  if [ "$nd" -gt 0 ]; then
    printf '%s%s%s deletable item(s)' "$B" "$nd" "$X"
  else
    printf '%s0 deletable items%s' "$D" "$X"
  fi
  [ "$np" -gt 0 ] && printf '  %s• %s protected%s' "$D" "$np" "$X"
  printf '\n'
  [ "$np" -gt 0 ] && printf '    %s⚠ Protected files will NOT be deleted by this prompt.%s\n' "$Y" "$X"

  if [ "$nd" -gt 0 ]; then
    printf '    %s[d]%s delete + quarantine   %s[s]%s skip %s(default)%s : ' "$B$R" "$X" "$B$G" "$X" "$D" "$X"
    IFS= read -r ans || ans='s'
    case "$ans" in
      d|D|delete|DELETE)
        printf '    %sℹ%s  backing up to quarantine before removal...\n' "$C" "$X"
        _quarantine_delete "$del" || true
        ;;
      *) printf '    %s%s↷ SKIPPED%s  no files changed\n' "$B" "$Y" "$X" ;;
    esac
  else
    printf '    %s%s↷ SKIPPED%s  only protected critical files were matched\n' "$B" "$Y" "$X"
  fi

  PROTECTED_SKIPPED=$((PROTECTED_SKIPPED+np))
  rm -f "$del" "$prot"
}

# report <listfile> [issue|review|info] [clean-message] [noaction]
# noaction suppresses the generic delete/quarantine prompt when a section has
# its own safer configuration-specific remediation workflow.
report() {
  local f="$1" sev="${2:-issue}" clean_msg="${3:-no matches}" action_mode="${4:-}" n label mark col cap shown line elapsed x
  cap="$PRESSWARDEN_MAX"
  # Defense in depth: suppress findings under explicitly excluded WordPress roots,
  # including nested targets such as domain.com/special.
  if [ "${#MANUAL_EXCLUDED_ROOTS[@]}" -gt 0 ] && [ -s "$f" ]; then
    local filt line er skip
    filt="$f.filtered"; : > "$filt"
    while IFS= read -r line; do
      skip=0
      for er in "${MANUAL_EXCLUDED_ROOTS[@]}"; do
        case "$line" in "$er"|"$er"/*) skip=1; break ;; esac
      done
      [ "$skip" -eq 1 ] || printf '%s\n' "$line" >> "$filt"
    done < "$f"
    mv -f "$filt" "$f" 2>/dev/null || true
  fi
  n=$(grep -c . "$f" 2>/dev/null); n=${n:-0}
  elapsed=$(( $(date +%s) - SEC_T0 ))

  case "$sev" in
    review) label='REVIEW'; mark='⚠'; col="$Y" ;;
    info)   label='INFO';   mark='ℹ'; col="$C" ;;
    *)      label='ALERT';  mark='✖'; col="$R"; sev='issue' ;;
  esac

  if [ "$n" -eq 0 ]; then
    printf '    %s%s✓ CLEAN%s  %s%s%s  %s(%s)%s\n' \
      "$B" "$G" "$X" "$D" "$clean_msg" "$X" "$D" "$(human_time "$elapsed")" "$X"
    rm -f "$f"; return 0
  fi

  _save_details "$f" "$sev"
  shown=0
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    shown=$((shown+1)); [ "$shown" -gt "$cap" ] && break
    printf '    %s%s%s %-6s%s  ' "$B" "$col" "$mark" "$label" "$X"
    compact_line "$line"
    printf '\n'
  done < "$f"

  [ "$n" -gt "$cap" ] && printf '    %s… %s more hidden; full list is in the findings log%s\n' \
    "$D" "$((n-cap))" "$X"
  printf '    %s%s%s %s match(es)%s  %s(%s)%s\n' \
    "$B" "$col" "$label" "$n" "$X" "$D" "$(human_time "$elapsed")" "$X"

  case "$sev" in
    review) REVIEWS=$((REVIEWS+n)) ;;
    info) : ;;
    *) ALERTS=$((ALERTS+n)) ;;
  esac
  [ "$sev" != info ] && TOTAL=$((TOTAL+n))

  # Remediation happens only after the report is printed and fully logged.
  [ "$action_mode" = noaction ] || _prompt_file_action "$f" "$sev"
  rm -f "$f"
}

finish() {
  local el=$(( $(date +%s) - T0 )) col status
  printf '\n'; _rule
  if [ "$ALERTS" -gt 0 ]; then col="$R"; status='ATTENTION REQUIRED'
  elif [ "$REVIEWS" -gt 0 ]; then col="$Y"; status='REVIEW RECOMMENDED'
  else col="$G"; status='CLEAN'; fi
  printf '  %s%s%s%s  %s%s%s\n' "$B" "$col" "$status" "$X" "$D" "$NAME" "$X"
  printf '  %salerts:%s %s%s%s   %sreview:%s %s%s%s   %sfindings:%s %s\n' \
    "$D" "$X" "$R" "$ALERTS" "$X" "$D" "$X" "$Y" "$REVIEWS" "$X" "$D" "$X" "$TOTAL"
  printf '  %sdeleted:%s %s%s%s   %sprotected:%s %s%s%s\n' \
    "$D" "$X" "$G" "$DELETED" "$X" "$D" "$X" "$Y" "$PROTECTED_SKIPPED" "$X"
  printf '  %selapsed:%s %s   %sconsole log:%s %s\n' \
    "$D" "$X" "$(human_time "$el")" "$D" "$X" "${LOG:-none}"
  [ -s "${DETAIL_LOG:-/dev/null}" ] && printf '  %sfull findings:%s %s\n' "$D" "$X" "$DETAIL_LOG"
  _rule
  printf '\n'
  [ "$TOTAL" -eq 0 ] && return 0 || return 1
}

run_logged() {
  mkdir -p "$REPORTS" 2>/dev/null || die "cannot create $REPORTS"
  local stamp; stamp=$(date +%Y%m%d-%H%M%S)
  LOG="$REPORTS/$1-$stamp.log"
  DETAIL_LOG="$REPORTS/$1-$stamp-findings.log"
  DELETE_LOG="$REPORTS/$1-$stamp-deletions.log"
  : > "$DETAIL_LOG"; : > "$DELETE_LOG"
  main 2>&1 | tee "$LOG"
  local rc=${PIPESTATUS[0]}
  [ -s "$DETAIL_LOG" ] || rm -f "$DETAIL_LOG"
  [ -s "$DELETE_LOG" ] || rm -f "$DELETE_LOG"
  return "$rc"
}
