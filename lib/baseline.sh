#!/usr/bin/env bash
# PressWarden baseline/change-detection engine.
# Stores only local hashes and low-sensitivity WordPress state metadata.
set -uo pipefail

PRESSWARDEN_DIR="${PRESSWARDEN_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
# shellcheck source=lib/_lib.sh
. "$PRESSWARDEN_DIR/lib/_lib.sh"

PRESSWARDEN_BASELINE_MAX_CHANGES="${PRESSWARDEN_BASELINE_MAX_CHANGES:-100}"
case "$PRESSWARDEN_BASELINE_MAX_CHANGES" in ''|*[!0-9]*) PRESSWARDEN_BASELINE_MAX_CHANGES=100 ;; esac

_pw_baseline_key() {
  printf '%s\n' "$ROOT" | cksum | awk '{printf "%s-%s", $1, $2}'
}

_pw_baseline_scope_dir() {
  printf '%s/baselines/%s' "$PRESSWARDEN_STATE_DIR" "$(_pw_baseline_key)"
}

_pw_sha256() {
  local f="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$f" 2>/dev/null | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$f" 2>/dev/null | awk '{print $1}'
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "$f" 2>/dev/null | awk '{print $NF}'
  else
    die "baseline requires sha256sum, shasum, or openssl"
  fi
}

_pw_file_size() {
  local f="$1" s
  s=$(stat -c %s "$f" 2>/dev/null || true)
  case "$s" in ''|*[!0-9]*) s=$(wc -c < "$f" 2>/dev/null | tr -d '[:space:]' || printf '0') ;; esac
  case "$s" in ''|*[!0-9]*) s=0 ;; esac
  printf '%s' "$s"
}

_pw_csv_field() {
  local v="$1"
  v=${v%$'\r'}
  case "$v" in \"*\") v=${v#\"}; v=${v%\"} ;; esac
  v=${v//\"\"/\"}
  v=${v//$'\t'/ }
  v=${v//$'\n'/ }
  printf '%s' "$v"
}

_pw_baseline_capture_files() {
  local site="$1" label="$2" manifest="$3" list f rel hash size
  list=$(tmpf); : > "$list"

  # Baseline security-relevant executable/configuration content. Volatile media,
  # caches, backups, logs and temporary trees are intentionally excluded from
  # change tracking; normal malware scans continue to inspect their own scopes.
  find "$site" \
    \( -type d \( -name uploads -o -name cache -o -name caches -o -name wflogs -o -name upgrade -o -name backups -o -name backup -o -name ai1wm-backups -o -name updraft -o -name logs -o -name tmp -o -name node_modules -o -name .git -o -name .svn -o -name .hg \) -prune \) -o \
    \( -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.pht' -o -name '*.phar' -o -name '*.inc' -o -name '*.js' -o -name '*.mjs' -o -name '*.cjs' -o -name '.htaccess' -o -name '.user.ini' -o -name 'php.ini' -o -name 'wp-config.php' \) -print \) \
    2>/dev/null > "$list"

  sort -u "$list" -o "$list" 2>/dev/null || true
  while IFS= read -r f; do
    [ -f "$f" ] || continue
    rel=${f#"$site"/}
    case "$rel" in *$'\t'*|*$'\n'*) continue ;; esac
    hash=$(_pw_sha256 "$f"); [ -n "$hash" ] || continue
    size=$(_pw_file_size "$f")
    printf 'F\t%s\t%s\t%s:%s\n' "$label" "$rel" "$hash" "$size" >> "$manifest"
  done < "$list"
  rm -f "$list"
}

_pw_baseline_capture_wp_state() {
  local site="$1" label="$2" manifest="$3" out first a b c rest
  command -v wp >/dev/null 2>&1 || return 0

  out=$(tmpf)
  if wp plugin list --fields=name,status,version --format=csv --path="$site" "${WPQ[@]}" > "$out" 2>/dev/null; then
    first=1
    while IFS=',' read -r a b c rest; do
      if [ "$first" -eq 1 ]; then first=0; continue; fi
      a=$(_pw_csv_field "$a"); b=$(_pw_csv_field "$b"); c=$(_pw_csv_field "$c")
      [ -n "$a" ] && printf 'P\t%s\t%s\t%s|%s\n' "$label" "$a" "$b" "$c" >> "$manifest"
    done < "$out"
  fi

  : > "$out"
  if wp theme list --fields=name,status,version --format=csv --path="$site" "${WPQ[@]}" > "$out" 2>/dev/null; then
    first=1
    while IFS=',' read -r a b c rest; do
      if [ "$first" -eq 1 ]; then first=0; continue; fi
      a=$(_pw_csv_field "$a"); b=$(_pw_csv_field "$b"); c=$(_pw_csv_field "$c")
      [ -n "$a" ] && printf 'T\t%s\t%s\t%s|%s\n' "$label" "$a" "$b" "$c" >> "$manifest"
    done < "$out"
  fi

  : > "$out"
  if wp user list --role=administrator --fields=user_login --format=csv --path="$site" "${WPQ[@]}" > "$out" 2>/dev/null; then
    first=1
    while IFS=',' read -r a rest; do
      if [ "$first" -eq 1 ]; then first=0; continue; fi
      a=$(_pw_csv_field "$a")
      [ -n "$a" ] && printf 'A\t%s\t%s\tadministrator\n' "$label" "$a" >> "$manifest"
    done < "$out"
  fi

  : > "$out"
  if wp cron event list --fields=hook,recurrence --format=csv --path="$site" "${WPQ[@]}" > "$out" 2>/dev/null; then
    first=1
    while IFS=',' read -r a b rest; do
      if [ "$first" -eq 1 ]; then first=0; continue; fi
      a=$(_pw_csv_field "$a"); b=$(_pw_csv_field "$b")
      [ -n "$a" ] && printf 'C\t%s\t%s\t%s\n' "$label" "$a" "$b" >> "$manifest"
    done < "$out"
  fi
  rm -f "$out"
}

_pw_baseline_capture() {
  local target="$1" manifest meta site label created records files wpstate
  mkdir -p "$target" || die "cannot create baseline capture directory: $target"
  manifest="$target/manifest.tsv"; meta="$target/meta.tsv"; : > "$manifest"

  refresh_scan_roots
  [ "${#SCAN_ROOTS[@]}" -gt 0 ] || die "no non-excluded WordPress installs found under $ROOT"

  for site in "${SCAN_ROOTS[@]}"; do
    label=$(site_label_from_root "$site")
    _pw_baseline_capture_files "$site" "$label" "$manifest"
    _pw_baseline_capture_wp_state "$site" "$label" "$manifest"
  done

  sort -u "$manifest" -o "$manifest" 2>/dev/null || true
  created=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
  records=$(wc -l < "$manifest" | tr -d '[:space:]'); case "$records" in ''|*[!0-9]*) records=0 ;; esac
  files=$(awk -F '\t' '$1=="F"{n++} END{print n+0}' "$manifest")
  wpstate=$((records-files))
  {
    printf 'format\t1\n'
    printf 'root\t%s\n' "$ROOT"
    printf 'created\t%s\n' "$created"
    printf 'presswarden_version\t%s\n' "$PRESSWARDEN_VERSION"
    printf 'sites\t%s\n' "${#SCAN_ROOTS[@]}"
    printf 'records\t%s\n' "$records"
    printf 'files\t%s\n' "$files"
    printf 'wp_state\t%s\n' "$wpstate"
    printf 'wp_cli\t%s\n' "$([ -x "$(command -v wp 2>/dev/null || true)" ] && printf 1 || printf 0)"
  } > "$meta"
  chmod 600 "$manifest" "$meta" 2>/dev/null || true
}

_pw_meta_value() {
  local file="$1" key="$2"
  awk -F '\t' -v k="$key" '$1==k{print $2; exit}' "$file" 2>/dev/null
}

pw_baseline_create() {
  local scope parent new current history stamp oldcreated
  scope=$(_pw_baseline_scope_dir); parent="$PRESSWARDEN_STATE_DIR/baselines"
  mkdir -p "$scope/history" "$parent" 2>/dev/null || die "cannot create baseline state directory"
  new="$scope/.new.$$"; rm -rf "$new"; mkdir -p "$new" || die "cannot create temporary baseline"
  trap 'rm -rf "${new:-}"' EXIT

  printf 'Creating security baseline for %s\n' "$ROOT"
  printf 'Baseline records the current state; it does not by itself prove that state is clean.\n\n'
  _pw_baseline_capture "$new"

  current="$scope/current"; history="$scope/history"
  if [ -d "$current" ]; then
    oldcreated=$(_pw_meta_value "$current/meta.tsv" created)
    stamp=${oldcreated//[-:]/}; stamp=${stamp//T/-}; stamp=${stamp//Z/}
    [ -n "$stamp" ] || stamp=$(date -u '+%Y%m%d-%H%M%S')
    [ ! -e "$history/$stamp" ] || stamp="$stamp-$$"
    mv "$current" "$history/$stamp" || die "could not preserve previous baseline"
  fi
  mv "$new" "$current" || die "could not activate new baseline"
  trap - EXIT
  chmod -R go-rwx "$scope" 2>/dev/null || true

  printf '✓ Baseline created\n'
  printf '  Sites:       %s\n' "$(_pw_meta_value "$current/meta.tsv" sites)"
  printf '  Files:       %s\n' "$(_pw_meta_value "$current/meta.tsv" files)"
  printf '  WP state:    %s\n' "$(_pw_meta_value "$current/meta.tsv" wp_state)"
  printf '  Created:     %s\n' "$(_pw_meta_value "$current/meta.tsv" created)"
  printf '  Stored:      %s\n' "$current"
}

pw_baseline_status() {
  local scope current histories=0
  scope=$(_pw_baseline_scope_dir); current="$scope/current"
  printf 'PressWarden baseline\n\n'
  printf 'Scan root:    %s\n' "$ROOT"
  if [ ! -s "$current/manifest.tsv" ] || [ ! -s "$current/meta.tsv" ]; then
    printf 'Status:       not created\n'
    printf '\nCreate one with: ./presswarden baseline create%s\n' "$([ "$ROOT" != "$PWD" ] && printf ' <path>' || true)"
    return 1
  fi
  if [ -d "$scope/history" ]; then
    histories=$(find "$scope/history" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l | tr -d '[:space:]')
    case "$histories" in ''|*[!0-9]*) histories=0 ;; esac
  fi
  printf 'Status:       ready\n'
  printf 'Created:      %s\n' "$(_pw_meta_value "$current/meta.tsv" created)"
  printf 'Sites:        %s\n' "$(_pw_meta_value "$current/meta.tsv" sites)"
  printf 'Files:        %s\n' "$(_pw_meta_value "$current/meta.tsv" files)"
  printf 'WP state:     %s\n' "$(_pw_meta_value "$current/meta.tsv" wp_state)"
  printf 'WP-CLI state: %s\n' "$([ "$(_pw_meta_value "$current/meta.tsv" wp_cli)" = 1 ] && printf captured || printf 'not available')"
  printf 'History:      %s previous baseline(s)\n' "$histories"
  printf 'Stored:       %s\n' "$current"
}

_pw_baseline_build_diff() {
  local old="$1" new="$2" out="$3"
  awk -F '\t' 'BEGIN{OFS="\t"}
    NR==FNR { k=$1 FS $2 FS $3; old[k]=$4; oldtype[k]=$1; oldsite[k]=$2; oldkey[k]=$3; next }
    { k=$1 FS $2 FS $3; seen[k]=1;
      if (!(k in old)) print "ADD",$1,$2,$3,$4,"";
      else if (old[k] != $4) print "CHANGE",$1,$2,$3,$4,old[k];
    }
    END { for (k in old) if (!(k in seen)) print "REMOVE",oldtype[k],oldsite[k],oldkey[k],"",old[k] }
  ' "$old" "$new" | sort > "$out"
}

_pw_baseline_print_change() {
  local action="$1" type="$2" site="$3" key="$4" newv="$5" oldv="$6" label
  case "$type" in
    F)
      case "$action" in ADD) label='+ NEW FILE' ;; CHANGE) label='~ CHANGED' ;; REMOVE) label='- REMOVED' ;; esac
      printf '  %-12s %s › %s\n' "$label" "$site" "$key"
      ;;
    P)
      case "$action" in ADD) label='+ PLUGIN' ;; CHANGE) label='~ PLUGIN' ;; REMOVE) label='- PLUGIN' ;; esac
      printf '  %-12s %s › %s' "$label" "$site" "$key"
      [ "$action" = CHANGE ] && printf '  (%s → %s)' "$oldv" "$newv"
      printf '\n'
      ;;
    T)
      case "$action" in ADD) label='+ THEME' ;; CHANGE) label='~ THEME' ;; REMOVE) label='- THEME' ;; esac
      printf '  %-12s %s › %s' "$label" "$site" "$key"
      [ "$action" = CHANGE ] && printf '  (%s → %s)' "$oldv" "$newv"
      printf '\n'
      ;;
    A)
      case "$action" in ADD) label='+ ADMIN' ;; CHANGE) label='~ ADMIN' ;; REMOVE) label='- ADMIN' ;; esac
      printf '  %-12s %s › %s\n' "$label" "$site" "$key"
      ;;
    C)
      case "$action" in ADD) label='+ CRON' ;; CHANGE) label='~ CRON' ;; REMOVE) label='- CRON' ;; esac
      printf '  %-12s %s › %s' "$label" "$site" "$key"
      [ "$action" = CHANGE ] && printf '  (%s → %s)' "$oldv" "$newv"
      printf '\n'
      ;;
    *) printf '  %-12s %s › %s\n' "$action" "$site" "$key" ;;
  esac
}

pw_baseline_diff() {
  local scope current capture diff report changes added changed removed shown=0 action type site key newv oldv max
  scope=$(_pw_baseline_scope_dir); current="$scope/current"
  [ -s "$current/manifest.tsv" ] && [ -s "$current/meta.tsv" ] || {
    printf 'No baseline exists for %s. Create one first with ./presswarden baseline create [path].\n' "$ROOT" >&2
    return 2
  }
  [ "$(_pw_meta_value "$current/meta.tsv" root)" = "$ROOT" ] || die "baseline root does not match current scan root"

  capture="$scope/.compare.$$"; diff=$(tmpf); rm -rf "$capture"; mkdir -p "$capture" || die "cannot create comparison capture"
  trap 'rm -rf "${capture:-}" "${diff:-}"' EXIT
  printf 'Comparing current state with baseline from %s...\n\n' "$(_pw_meta_value "$current/meta.tsv" created)"
  _pw_baseline_capture "$capture"
  _pw_baseline_build_diff "$current/manifest.tsv" "$capture/manifest.tsv" "$diff"

  changes=$(wc -l < "$diff" | tr -d '[:space:]'); case "$changes" in ''|*[!0-9]*) changes=0 ;; esac
  added=$(awk -F '\t' '$1=="ADD"{n++} END{print n+0}' "$diff")
  changed=$(awk -F '\t' '$1=="CHANGE"{n++} END{print n+0}' "$diff")
  removed=$(awk -F '\t' '$1=="REMOVE"{n++} END{print n+0}' "$diff")

  if [ "$changes" -eq 0 ]; then
    printf '✓ No security-baseline changes detected.\n'
    rm -rf "$capture"; rm -f "$diff"; trap - EXIT
    return 0
  fi

  printf 'BASELINE CHANGES\n'
  printf '  Added: %s  Changed: %s  Removed: %s\n\n' "$added" "$changed" "$removed"
  max="$PRESSWARDEN_BASELINE_MAX_CHANGES"
  while IFS=$'\t' read -r action type site key newv oldv; do
    [ -n "$action" ] || continue
    shown=$((shown+1)); [ "$shown" -le "$max" ] || continue
    _pw_baseline_print_change "$action" "$type" "$site" "$key" "$newv" "$oldv"
  done < "$diff"
  if [ "$changes" -gt "$max" ]; then printf '\n  ... %s additional change(s) omitted from terminal output.\n' "$((changes-max))"; fi

  mkdir -p "$REPORTS" 2>/dev/null || true
  report="$REPORTS/baseline-changes-$(date -u '+%Y%m%dT%H%M%SZ').tsv"
  cp "$diff" "$report" 2>/dev/null || report=''
  [ -n "$report" ] && { chmod 600 "$report" 2>/dev/null || true; printf '\nChange report: %s\n' "$report"; }
  printf '\nReview changes before accepting a new baseline. A change is not automatically malware.\n'

  rm -rf "$capture"; rm -f "$diff"; trap - EXIT
  return 1
}
