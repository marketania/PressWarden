# Complete-or-refuse baseline captures. Sources are read, never included as code.
_pw_sha256() {
  local f="$1" hash
  if command -v sha256sum >/dev/null 2>&1; then
    hash=$(sha256sum < "$f" 2>/dev/null | awk '{print $1}') || return 2
  elif command -v shasum >/dev/null 2>&1; then
    hash=$(shasum -a 256 < "$f" 2>/dev/null | awk '{print $1}') || return 2
  elif command -v openssl >/dev/null 2>&1; then
    hash=$(openssl dgst -sha256 < "$f" 2>/dev/null | awk '{print $NF}') || return 2
  else
    return 2
  fi
  [[ "$hash" =~ ^[a-fA-F0-9]{64}$ ]] || return 2
  printf '%s' "$hash"
}

_pw_baseline_identity() {
  local identity
  identity=$(stat -c '%d:%i:%s:%Y:%Z' -- "$1" 2>/dev/null || stat -f '%d:%i:%z:%m:%c' "$1" 2>/dev/null) || return 2
  [[ "$identity" =~ ^[0-9]+:[0-9]+:[0-9]+:-?[0-9]+:-?[0-9]+$ ]] || return 2
  printf '%s' "$identity"
}

_pw_baseline_text_safe() { case "$1" in *[[:cntrl:]]*) return 1 ;; esac; }

_pw_baseline_capture_files() {
  local site="$1" label="$2" target="$3" list f rel hash before after size p literal failed=0
  local -a prune=()
  list="$target/files.nul"
  # Do not attribute nested installations to their parents or read excluded sites
  # and scanner evidence. Escape find's pattern metacharacters in literal paths.
  for p in "${SCAN_ROOTS[@]}" "${MANUAL_EXCLUDED_ROOTS[@]}" "$PRESSWARDEN_DIR" "$PRESSWARDEN_STATE_DIR" "$PRESSWARDEN_CACHE_DIR" "$REPORTS" "$QUARANTINE"; do
    case "$p" in "$site"/*)
      literal=${p//\\/\\\\}; literal=${literal//\*/\\*}; literal=${literal//\?/\\?}; literal=${literal//\[/\\[}
      prune+=(-o -path "$literal") ;;
    esac
  done
  if ! find "$site" \
    \( -type d \( -name uploads -o -name cache -o -name caches -o -name wflogs -o -name upgrade -o -name backups -o -name backup -o -name ai1wm-backups -o -name updraft -o -name logs -o -name tmp -o -name node_modules -o -name .git -o -name .svn -o -name .hg "${prune[@]}" \) -prune \) -o \
    \( -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.pht' -o -name '*.phar' -o -name '*.inc' -o -name '*.js' -o -name '*.mjs' -o -name '*.cjs' -o -name '.htaccess' -o -name '.user.ini' -o -name 'php.ini' -o -name 'wp-config.php' \) -print0 \) \
    > "$list" 2>/dev/null; then failed=1; fi
  while IFS= read -r -d '' f; do
    if ! _pw_baseline_text_safe "$f" || [ ! -f "$f" ] || [ -L "$f" ]; then failed=1; continue; fi
    rel=${f#"$site"/}
    before=$(_pw_baseline_identity "$f") || { failed=1; continue; }
    hash=$(_pw_sha256 "$f") || { failed=1; continue; }
    after=$(_pw_baseline_identity "$f") || { failed=1; continue; }
    if [ "$before" != "$after" ] || [ -L "$f" ] || [ ! -f "$f" ]; then failed=1; continue; fi
    size=${before#*:*:}; size=${size%%:*}
    case "$size" in ''|*[!0-9]*) failed=1; continue ;; esac
    printf 'F\t%s\t%s\t%s:%s\n' "$label" "$rel" "$hash" "$size" >> "$target/manifest.tsv" || return 2
  done < "$list"
  rm -f -- "$list"
  if [ "$failed" -ne 0 ]; then
    printf 'INCOMPLETE: file traversal/hash/identity capture failed for %s; no comparison or baseline replacement.\n' "$label" >&2
    printf 'F\t%s\tFAILED\n' "$label" >> "$target/coverage.tsv"
    return 2
  fi
  printf 'F\t%s\tCAPTURED\n' "$label" >> "$target/coverage.tsv"
}

_pw_baseline_capture_wp_state() {
  local site="$1" label="$2" target="$3" type out parsed state failed=0
  local -a args
  out="$target/inventory.csv"; parsed="$target/inventory.tsv"
  for type in P T A C; do
    state=UNAVAILABLE
    if command -v wp >/dev/null 2>&1; then
      state=FAILED
      case "$type" in
        P) args=(plugin list --fields=name,status,version --skip-update-check) ;;
        T) args=(theme list --fields=name,status,version) ;;
        A) args=(user list --role=administrator --fields=user_login) ;;
        C) args=(cron event list --fields=hook,recurrence) ;;
      esac
      # Captured stdout is private and transient. Never forward raw WP-CLI errors.
      if command -v php >/dev/null 2>&1 \
        && wp "${args[@]}" --format=csv --path="$site" "${WPQ[@]}" > "$out" 2>/dev/null \
        && php "$PRESSWARDEN_DIR/lib/baseline-csv.php" "$out" "$type" "$label" > "$parsed" 2>/dev/null \
        && cat "$parsed" >> "$target/manifest.tsv"; then state=CAPTURED; fi
      if [ "$state" = FAILED ]; then
        failed=1
        printf 'INCOMPLETE: %s inventory failed for %s; missing records are not removals.\n' "$type" "$label" >&2
      fi
    fi
    printf '%s\t%s\t%s\n' "$type" "$label" "$state" >> "$target/coverage.tsv" || return 2
    rm -f -- "$out" "$parsed"
  done
  [ "$failed" -eq 0 ]
}

_pw_baseline_capture() {
  local target="$1" site label created records files wpstate name hash failed=0 wpcli=0
  mkdir -m 700 -- "$target" || return 2
  : > "$target/manifest.tsv" || return 2
  : > "$target/coverage.tsv" || return 2
  : > "$target/scope.tsv" || return 2
  # A baseline must be based on fresh discovery, never a stale cached site set.
  PRESSWARDEN_DISCOVERY_REFRESH=1 refresh_scan_roots
  if [ "${PW_DISCOVERY_FAILED:-0}" -ne 0 ] || [ "${#SCAN_ROOTS[@]}" -eq 0 ]; then
    printf 'INCOMPLETE: fresh WordPress discovery failed or selected no sites.\n' >&2; return 2
  fi
  for site in "${SCAN_ROOTS[@]}"; do
    _pw_baseline_text_safe "$site" || return 2
    case "$site" in "$ROOT"|"$ROOT"/*) : ;; *) return 2 ;; esac
    label=$(site_label_from_root "$site"); _pw_baseline_text_safe "$label" || return 2
    printf 'SITE\t%s\t%s\n' "$label" "$site" >> "$target/scope.tsv" || return 2
    _pw_baseline_capture_files "$site" "$label" "$target" || failed=1
    _pw_baseline_capture_wp_state "$site" "$label" "$target" || failed=1
  done
  # Explicit policy identity makes scope changes incomparable, not mass removals.
  for name in ROOT PRESSWARDEN_DISCOVERY_DEPTH PRESSWARDEN_EXCLUDE PRESSWARDEN_DIR PRESSWARDEN_STATE_DIR PRESSWARDEN_CACHE_DIR REPORTS QUARANTINE; do
    _pw_baseline_text_safe "${!name}" || return 2
    printf 'POLICY\t%s\t%s\n' "$name" "${!name}" >> "$target/scope.tsv" || return 2
  done
  for name in manifest coverage scope; do sort -u "$target/$name.tsv" -o "$target/$name.tsv" || return 2; done
  if [ "$failed" -ne 0 ]; then return 2; fi
  created=$(date -u '+%Y-%m-%dT%H:%M:%SZ') || return 2
  records=$(wc -l < "$target/manifest.tsv") || return 2
  files=$(awk -F '\t' '$1=="F"{n++} END{print n+0}' "$target/manifest.tsv") || return 2
  wpstate=$((records-files)); command -v wp >/dev/null 2>&1 && wpcli=1
  {
    printf 'format\t2\nroot\t%s\ncreated\t%s\npresswarden_version\t%s\n' "$ROOT" "$created" "$PRESSWARDEN_VERSION"
    printf 'sites\t%s\nrecords\t%s\nfiles\t%s\nwp_state\t%s\nwp_cli\t%s\n' "${#SCAN_ROOTS[@]}" "$records" "$files" "$wpstate" "$wpcli"
    printf 'coverage\t%s\n' "$([ "$wpcli" -eq 1 ] && printf complete || printf files-only)"
  } > "$target/meta.tsv" || return 2
  for name in manifest coverage scope; do
    hash=$(_pw_sha256 "$target/$name.tsv") || return 2
    printf '%s_sha256\t%s\n' "$name" "$hash" >> "$target/meta.tsv" || return 2
  done
  return 0
}
