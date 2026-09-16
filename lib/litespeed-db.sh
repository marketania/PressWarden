# Shared LiteSpeed database adapter. Never execute a cleanup to probe support.
pw_lsdb_builtin() {
  local site="$1"; shift
  wp "$@" --path="$site" --skip-plugins --skip-themes --skip-packages --no-color
}
pw_lsdb_is_multisite() { pw_lsdb_builtin "$1" core is-installed --network >/dev/null 2>&1; }
pw_lsdb_command_available() {
  local site="$1" action="${2:-optimize_all}"
  # These are real LiteSpeed subcommands. `status` belongs to PressWarden only.
  case "$action" in
    clear_posts|clear_comments|clear_trackbacks|clear_transients|optimize_tables|optimize_all) ;;
    *) return 1 ;;
  esac
  (cd "$site" && PAGER=cat WP_CLI_PAGER=cat wp help litespeed-database "$action" >/dev/null 2>&1)
}
pw_lsdb_preflight() {
  local site="$1" action="${2:-optimize_all}" ids count
  if ! pw_lsdb_builtin "$site" core is-installed >/dev/null 2>&1; then
    printf 'ERROR\tWordPress/WP-CLI bootstrap failed\n'
  elif ! pw_lsdb_builtin "$site" plugin is-installed litespeed-cache >/dev/null 2>&1; then
    printf 'SKIP\tLiteSpeed Cache is not installed\n'
  elif ! pw_lsdb_builtin "$site" plugin is-active litespeed-cache >/dev/null 2>&1; then
    printf 'SKIP\tLiteSpeed Cache is installed but inactive\n'
  elif ! pw_lsdb_command_available "$site" "$action"; then
    printf 'ERROR\tLiteSpeed Cache is active but litespeed-database %s is unavailable\n' "$action"
  elif pw_lsdb_is_multisite "$site"; then
    ids=$(pw_lsdb_blog_ids "$site") || { printf 'ERROR\tmultisite blog-ID inventory failed; no cleanup will be attempted\n'; return 0; }
    count=$(printf '%s\n' "$ids" | awk 'NF {n++} END {print n+0}')
    printf 'READY\tmultisite detected; %s validated blog(s) will be cleaned\n' "$count"
  else
    printf 'READY\tLiteSpeed %s available\n' "$action"
  fi
}
pw_lsdb_validate_blog() {
  local site="$1" id="$2" out
  [[ "$id" =~ ^[1-9][0-9]{0,9}$ ]] || return 1
  out=$(pw_lsdb_builtin "$site" eval-file "$PRESSWARDEN_DIR/lib/db-blog.php" "$id" 2>/dev/null) || return 1
  [ "$out" = "PWDBBLOG1"$'\t'"$id" ]
}
pw_lsdb_run() {
  local site="$1" action="$2"; shift 2
  case "$action" in
    clear_posts|clear_comments|clear_trackbacks|clear_transients|optimize_tables|optimize_all) ;;
    *) printf 'Unsupported LiteSpeed database action.\n' >&2; return 2 ;;
  esac
  if [ "$#" -ne 0 ]; then
    if [ "$#" -ne 2 ] || [ "${1:-}" != blog ] || ! pw_lsdb_validate_blog "$site" "${2:-}"; then
      printf 'Refusing LiteSpeed cleanup: blog ID is invalid, unavailable or not an active multisite blog.\n' >&2
      return 2
    fi
  fi
  # Do not add globals: LiteSpeed's database family does not support them.
  (cd "$site" && wp litespeed-database "$action" "$@")
}
pw_lsdb_size_bytes() {
  local out n
  # No wp db size/mysql/proc_open dependency on restricted shared hosting.
  out=$(pw_lsdb_builtin "$1" eval-file "$PRESSWARDEN_DIR/lib/db-size.php" 2>/dev/null) || return 1
  [[ "$out" == PWDBSIZE1$'\t'* ]] || return 1
  n=${out#*$'\t'}
  # Reject ambiguous output, signs, leading zeroes and arithmetic overflow.
  [[ "$n" =~ ^(0|[1-9][0-9]{0,14})$ ]] || return 1
  printf '%s' "$n"
}
pw_lsdb_format_bytes() {
  awk -v n="${1:-0}" 'BEGIN {
    split("B KiB MiB GiB TiB", u, " "); i=1;
    while (n >= 1024 && i < 5) { n/=1024; i++ }
    if (i == 1) printf "%.0f %s", n, u[i]; else printf "%.2f %s", n, u[i];
  }'
}
pw_lsdb_show_output() {
  local file="$1"
  [ -s "$file" ] || return 0
  # Bounded output; strip terminal controls and redact common credential fields.
  # awk consumes input fully (unlike head in a pipefail pipeline).
  LC_ALL=C sed -E $'s/\033\\[[0-9;]*[[:alpha:]]//g' < "$file" |
    LC_ALL=C tr -cd '\11\12\15\40-\176' |
    sed -E 's/((api[-_ ]?key|token|secret|password|passwd|credential)[^:=]{0,30}[:=][[:space:]]*)[^[:space:],}]+/\1[REDACTED]/Ig' |
    awk 'NR <= 12 {sub(/\r$/, ""); print "        " substr($0,1,300)} NR == 13 {print "        [additional command output omitted]"}'
}

# Validate the entire active-blog inventory before the first mutation. A blog is
# validated again by pw_lsdb_run immediately before its individual cleanup.
pw_lsdb_blog_ids() {
  local site="$1" raw id seen='|' result='' count=0
  raw=$(pw_lsdb_builtin "$site" site list --field=blog_id --deleted=0 --archived=0 --spam=0 2>/dev/null) || return 1
  while IFS= read -r id; do
    [[ "$id" =~ ^[1-9][0-9]{0,9}$ ]] || return 1
    [[ "$seen" != *"|$id|"* ]] || continue
    pw_lsdb_validate_blog "$site" "$id" || return 1
    seen+="$id|"; result+="$id"$'\n'; count=$((count+1))
    [ "$count" -le 10000 ] || return 1
  done <<< "$raw"
  [ "$count" -gt 0 ] || return 1
  printf '%s' "$result"
}
# Result globals for one installation.
LSDB_RUN_BLOG_TOTAL=1
LSDB_RUN_BLOG_DONE=0
LSDB_RUN_FAILED_BLOG=''
LSDB_RUN_ENUM_FAILED=0

pw_lsdb_run_all() {
  local site="$1" out="$2" ids blog rc multisite=0
  pw_lsdb_is_multisite "$site" && multisite=1
  local -a blogs=()
  LSDB_RUN_BLOG_TOTAL=1
  LSDB_RUN_BLOG_DONE=0
  LSDB_RUN_FAILED_BLOG=''
  LSDB_RUN_ENUM_FAILED=0

  if [ "$multisite" = 1 ]; then
    ids=$(pw_lsdb_blog_ids "$site") || {
      printf 'Multisite blog-ID inventory failed before cleanup; no blog was changed.\n' > "$out"
      LSDB_RUN_ENUM_FAILED=1
      return 96
    }
    while IFS= read -r blog; do [ -n "$blog" ] && blogs+=("$blog"); done <<< "$ids"
    [ "${#blogs[@]}" -gt 0 ] || {
      printf 'Multisite blog-ID inventory was empty; no blog was changed.\n' > "$out"
      LSDB_RUN_ENUM_FAILED=1
      return 96
    }
    LSDB_RUN_BLOG_TOTAL=${#blogs[@]}
    : > "$out" || return 97
    for blog in "${blogs[@]}"; do
      printf 'Blog %s:\n' "$blog" >> "$out"
      # Do not add WP-CLI global parameters here.
      pw_lsdb_run "$site" optimize_all blog "$blog" >> "$out" 2>&1
      rc=$?
      if [ "$rc" -ne 0 ]; then
        LSDB_RUN_FAILED_BLOG="$blog"
        return "$rc"
      fi
      LSDB_RUN_BLOG_DONE=$((LSDB_RUN_BLOG_DONE+1))
    done
    return 0
  fi

  # Do not add WP-CLI global parameters here.
  pw_lsdb_run "$site" optimize_all > "$out" 2>&1
  rc=$?
  [ "$rc" -ne 0 ] || LSDB_RUN_BLOG_DONE=1
  return "$rc"
}
