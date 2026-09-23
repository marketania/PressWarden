#!/usr/bin/env bash
# Baselines record observed state, never certify that a site is clean.
set -uo pipefail
PRESSWARDEN_DIR="${PRESSWARDEN_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
. "$PRESSWARDEN_DIR/lib/_lib.sh"
. "$PRESSWARDEN_DIR/lib/baseline-capture.sh"
PRESSWARDEN_BASELINE_MAX_CHANGES="${PRESSWARDEN_BASELINE_MAX_CHANGES:-100}"
case "$PRESSWARDEN_BASELINE_MAX_CHANGES" in ''|*[!0-9]*) PRESSWARDEN_BASELINE_MAX_CHANGES=100 ;; esac

_pw_baseline_key() { printf '%s\n' "$ROOT" | cksum | awk '{printf "%s-%s", $1, $2}'; }
_pw_baseline_scope_dir() { printf '%s/baselines/%s' "$PRESSWARDEN_STATE_DIR" "$(_pw_baseline_key)"; }
_pw_meta_value() { awk -F '\t' -v k="$2" '$1==k{print $2; exit}' "$1" 2>/dev/null; }

_pw_baseline_safe_path() {
  local p="$1"
  _pw_baseline_text_safe "$p" || return 2
  case "$p" in /*) : ;; *) return 2 ;; esac
  case "/$p/" in */../*|*/./*) return 2 ;; esac
  while [ "$p" != / ]; do
    [ ! -L "$p" ] || return 2
    p=${p%/*}; [ -n "$p" ] || p=/
  done
}

_pw_baseline_cleanup() {
  local rc=$?
  trap - EXIT
  if [ -n "${PW_BASELINE_PREVIOUS:-}" ] && [ -d "$PW_BASELINE_PREVIOUS" ]; then
    if [ ! -e "$PW_BASELINE_SCOPE/current" ] && [ ! -L "$PW_BASELINE_SCOPE/current" ]; then
      if mv -- "$PW_BASELINE_PREVIOUS" "$PW_BASELINE_SCOPE/current"; then PW_BASELINE_KEEP_LOCK=0;
      else PW_BASELINE_KEEP_LOCK=1; fi
    fi
  fi
  if [ "${PW_BASELINE_KEEP_LOCK:-0}" -ne 0 ]; then
    printf 'INCOMPLETE: baseline activation/recovery is unconfirmed. Previous evidence, workspace and lock retained under %s; see docs/BASELINES.md.\n' "$PW_BASELINE_SCOPE" >&2
    return 2
  fi
  [ -z "${PW_BASELINE_WORK:-}" ] || rm -rf -- "$PW_BASELINE_WORK"
  [ -z "${PW_BASELINE_LOCK:-}" ] || rmdir -- "$PW_BASELINE_LOCK" 2>/dev/null || true
  return "$rc"
}

# Call only inside this command/check's private subshell. The lock covers readers
# too, so cooperating commands never observe the activation's two-rename gap.
_pw_baseline_begin() {
  _pw_baseline_text_safe "$ROOT" || { printf 'INCOMPLETE: unsupported scan-root characters.\n' >&2; return 2; }
  PW_BASELINE_SCOPE=$(_pw_baseline_scope_dir)
  _pw_baseline_safe_path "$PW_BASELINE_SCOPE/history" || { printf 'INCOMPLETE: unsafe baseline state path.\n' >&2; return 2; }
  _pw_baseline_safe_path "$PW_BASELINE_SCOPE/current" || { printf 'INCOMPLETE: unsafe baseline snapshot path.\n' >&2; return 2; }
  umask 077
  mkdir -p -- "$PW_BASELINE_SCOPE/history" || return 2
  PW_BASELINE_LOCK="$PW_BASELINE_SCOPE/.baseline.lock"
  if ! mkdir -- "$PW_BASELINE_LOCK" 2>/dev/null; then
    printf 'INCOMPLETE: baseline is busy or recovery is pending; see docs/BASELINES.md.\n' >&2; return 2
  fi
  PW_BASELINE_WORK=''; PW_BASELINE_PREVIOUS=''; PW_BASELINE_KEEP_LOCK=0
  trap '_pw_baseline_cleanup' EXIT
  trap 'exit 2' HUP INT TERM
  PW_BASELINE_WORK=$(mktemp -d "$PW_BASELINE_SCOPE/.work.XXXXXX") || return 2
  PW_BASELINE_CURRENT="$PW_BASELINE_SCOPE/current"
  PW_BASELINE_CAPTURE="$PW_BASELINE_WORK/capture"
  PW_BASELINE_DIFF="$PW_BASELINE_WORK/diff.tsv"
}

_pw_baseline_validate() {
  local dir="$1" name expected actual
  _pw_baseline_safe_path "$dir" || return 2
  for name in meta manifest coverage scope; do
    [ -f "$dir/$name.tsv" ] && [ ! -L "$dir/$name.tsv" ] && [ -r "$dir/$name.tsv" ] || {
      printf 'INCOMPLETE: baseline has missing/unsafe files or legacy coverage. Explicitly recreate after review; the old snapshot is preserved.\n' >&2; return 2;
    }
  done
  if [ "$(_pw_meta_value "$dir/meta.tsv" format)" != 2 ]; then
    printf 'INCOMPLETE: legacy baseline coverage is unknown; recreate after review to enable comparisons.\n' >&2; return 2
  fi
  [ "$(_pw_meta_value "$dir/meta.tsv" root)" = "$ROOT" ] || { printf 'INCOMPLETE: baseline scan root differs.\n' >&2; return 2; }
  for name in manifest coverage scope; do
    expected=$(_pw_meta_value "$dir/meta.tsv" "${name}_sha256")
    actual=$(_pw_sha256 "$dir/$name.tsv") || return 2
    if [ "$expected" != "$actual" ]; then printf 'INCOMPLETE: baseline %s integrity mismatch.\n' "$name" >&2; return 2; fi
  done
  # TSV contents remain inert. Refuse malformed/colliding record identities.
  awk -F '\t' '
    NF!=4 || $1 !~ /^[FPTAC]$/ || $2=="" || $3=="" {exit 2}
    {for(i=1;i<=NF;i++) if($i ~ /[[:cntrl:]]/) exit 2; k=$1 FS $2 FS $3; if(k in seen) exit 2; seen[k]=1}
    $1=="F" {split($4,h,":"); if(length(h[1])!=64 || h[1] !~ /^[a-fA-F0-9]+$/ || h[2] !~ /^[0-9]+$/) exit 2}
  ' "$dir/manifest.tsv" || { printf 'INCOMPLETE: malformed baseline records.\n' >&2; return 2; }
  case "$(_pw_meta_value "$dir/meta.tsv" coverage)" in complete|files-only) : ;; *) return 2 ;; esac
  # Coverage must describe every selected site, with one row per category.
  awk -F '\t' '
    FILENAME==ARGV[1] {if(NF!=2 || $1=="" || ($1 in meta)) exit 2; meta[$1]=$2; next}
    FILENAME==ARGV[2] {if($1=="SITE"){if(NF!=3 || $2=="" || $3=="" || ($2 in sites)) exit 2; sites[$2]=1; n++} next}
    FILENAME==ARGV[3] {if(!($2 in sites)) exit 2; cov[$1 FS $2]=$3; c++; next}
    FILENAME==ARGV[4] {if(!($2 in sites) || cov[$1 FS $2]!="CAPTURED") exit 2; records++; if($1=="F") files++; next}
    END{
      if(n<1 || c!=5*n || meta["sites"]!=n || meta["records"]!=records || meta["files"]!=files || files<1 || meta["wp_state"]!=records-files) exit 2;
      if(meta["wp_cli"]!="0" && meta["wp_cli"]!="1") exit 2;
      state=(meta["wp_cli"]=="1" ? "CAPTURED" : "UNAVAILABLE");
      if(meta["coverage"]!=(meta["wp_cli"]=="1" ? "complete" : "files-only")) exit 2;
      split("P T A C",types," "); for(site in sites){if(cov["F" FS site]!="CAPTURED") exit 2; for(t in types) if(cov[types[t] FS site]!=state) exit 2}
    }
  ' "$dir/meta.tsv" "$dir/scope.tsv" "$dir/coverage.tsv" "$dir/manifest.tsv" || {
    printf 'INCOMPLETE: inconsistent baseline coverage metadata.\n' >&2; return 2;
  }
  awk -F '\t' 'NF!=3 || $1 !~ /^[FPTAC]$/ || $2=="" || $3 !~ /^(CAPTURED|UNAVAILABLE)$/ {exit 2}
    $1=="F" && $3!="CAPTURED" {exit 2}
    {k=$1 FS $2; if(k in seen) exit 2; seen[k]=1}
  ' "$dir/coverage.tsv" || return 2
}

pw_baseline_create() (
  _pw_baseline_begin || exit 2
  printf 'Creating security baseline for %s\n' "$ROOT"
  printf 'This records observed state, not proof of cleanliness. Failed captures never replace current.\n\n'
  _pw_baseline_capture "$PW_BASELINE_CAPTURE" || { printf 'INCOMPLETE: baseline capture rejected; current baseline unchanged.\n' >&2; exit 2; }
  _pw_baseline_validate "$PW_BASELINE_CAPTURE" || exit 2
  if [ -e "$PW_BASELINE_CURRENT" ]; then
    [ -d "$PW_BASELINE_CURRENT" ] && [ ! -L "$PW_BASELINE_CURRENT" ] || exit 2
    # Losing WP-CLI must never silently replace previously captured runtime state.
    if [ "$(_pw_meta_value "$PW_BASELINE_CAPTURE/meta.tsv" wp_cli)" = 0 ] \
      && { [ "$(_pw_meta_value "$PW_BASELINE_CURRENT/meta.tsv" wp_cli)" = 1 ] \
           || grep -qE '^[PTAC][[:space:]]' "$PW_BASELINE_CURRENT/manifest.tsv" 2>/dev/null; }; then
      printf 'INCOMPLETE: WP-CLI is unavailable; refusing to downgrade the existing baseline.\n' >&2; exit 2
    fi
    stamp=$(date -u '+%Y%m%dT%H%M%SZ') || exit 2
    archive=$(mktemp -d "$PW_BASELINE_SCOPE/history/snapshot-$stamp.XXXXXX") || exit 2
    PW_BASELINE_PREVIOUS="$archive/snapshot"
    mv -- "$PW_BASELINE_CURRENT" "$PW_BASELINE_PREVIOUS" || exit 2
  fi
  PW_BASELINE_KEEP_LOCK=1
  mv -- "$PW_BASELINE_CAPTURE" "$PW_BASELINE_CURRENT" || exit 2
  PW_BASELINE_KEEP_LOCK=0; PW_BASELINE_PREVIOUS=''
  printf '✓ Baseline created\n'
  printf '  Sites:       %s\n' "$(_pw_meta_value "$PW_BASELINE_CURRENT/meta.tsv" sites)"
  printf '  Files:       %s\n' "$(_pw_meta_value "$PW_BASELINE_CURRENT/meta.tsv" files)"
  printf '  WP state:    %s\n' "$(_pw_meta_value "$PW_BASELINE_CURRENT/meta.tsv" wp_state)"
  printf '  Coverage:    %s\n' "$(_pw_meta_value "$PW_BASELINE_CURRENT/meta.tsv" coverage)"
  printf '  Created:     %s\n' "$(_pw_meta_value "$PW_BASELINE_CURRENT/meta.tsv" created)"
  printf '  Stored:      %s\n' "$PW_BASELINE_CURRENT"
)

pw_baseline_status() (
  scope=$(_pw_baseline_scope_dir); current="$scope/current"
  printf 'PressWarden baseline\n\nScan root:    %s\n' "$ROOT"
  if [ ! -e "$current" ] && [ ! -L "$current" ] && [ ! -e "$scope/.baseline.lock" ]; then
    printf 'Status:       not created\n\nCreate one with: ./presswarden baseline create [path]\n'; exit 1
  fi
  _pw_baseline_begin || exit 2
  _pw_baseline_validate "$current" || exit 2
  printf 'Status:       ready\nCreated:      %s\n' "$(_pw_meta_value "$current/meta.tsv" created)"
  printf 'Sites:        %s\nFiles:        %s\n' "$(_pw_meta_value "$current/meta.tsv" sites)" "$(_pw_meta_value "$current/meta.tsv" files)"
  printf 'Coverage:     %s (observed, not certified clean)\n' "$(_pw_meta_value "$current/meta.tsv" coverage)"
  awk -F '\t' '{count[$1 FS $3]++} END{for(k in count){split(k,a,FS); printf "  %-2s %-12s %d site(s)\n",a[1],a[2],count[k]}}' "$current/coverage.tsv" | sort
  printf '  F=files; P=plugins; T=themes; A=administrators; C=cron\nStored:       %s\n' "$current"
  histories=$(find "$scope/history" -type f -name meta.tsv 2>/dev/null | wc -l) || exit 2
  printf 'History:      %s preserved snapshot(s)\n' "$histories"
)

_pw_baseline_build_diff() {
  awk -F '\t' 'BEGIN{OFS="\t"}
    FILENAME==ARGV[1] {k=$1 FS $2 FS $3; old[k]=$4; ot[k]=$1; os[k]=$2; ok[k]=$3; next}
    {k=$1 FS $2 FS $3; seen[k]=1; if(!(k in old)) print "ADD",$1,$2,$3,$4,""; else if(old[k]!=$4) print "CHANGE",$1,$2,$3,$4,old[k]}
    END{for(k in old) if(!(k in seen)) print "REMOVE",ot[k],os[k],ok[k],"",old[k]}
  ' "$1" "$2" | sort > "$3"
}

_pw_baseline_prepare_comparison() {
  _pw_baseline_begin || return 2
  _pw_baseline_validate "$PW_BASELINE_CURRENT" || return 2
  _pw_baseline_capture "$PW_BASELINE_CAPTURE" || return 2
  _pw_baseline_validate "$PW_BASELINE_CAPTURE" || return 2
  if ! cmp -s "$PW_BASELINE_CURRENT/scope.tsv" "$PW_BASELINE_CAPTURE/scope.tsv"; then
    printf 'INCOMPLETE: selected sites, exclusions or capture policy changed; not comparable. Review scope before recreating a baseline.\n' >&2; return 2
  fi
  if ! cmp -s "$PW_BASELINE_CURRENT/coverage.tsv" "$PW_BASELINE_CAPTURE/coverage.tsv"; then
    printf 'INCOMPLETE: file/WordPress inventory coverage changed; missing inventories are not removals.\n' >&2; return 2
  fi
  if [ "$(_pw_meta_value "$PW_BASELINE_CURRENT/meta.tsv" coverage)" = files-only ]; then
    printf 'Coverage: files only; WordPress inventories unavailable in both snapshots.\n'
  fi
  _pw_baseline_build_diff "$PW_BASELINE_CURRENT/manifest.tsv" "$PW_BASELINE_CAPTURE/manifest.tsv" "$PW_BASELINE_DIFF" || return 2
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

pw_baseline_diff() (
  _pw_baseline_prepare_comparison || exit 2
  diff="$PW_BASELINE_DIFF"
  changes=$(wc -l < "$diff") || exit 2
  if [ "$changes" -eq 0 ]; then printf '✓ No security-baseline changes detected in comparable captured categories.\n'; exit 0; fi
  added=$(awk -F '\t' '$1=="ADD"{n++} END{print n+0}' "$diff") || exit 2
  changed=$(awk -F '\t' '$1=="CHANGE"{n++} END{print n+0}' "$diff") || exit 2
  removed=$(awk -F '\t' '$1=="REMOVE"{n++} END{print n+0}' "$diff") || exit 2
  # Private, no-replace TSV publication; preserve all older change reports.
  reservation=$(mktemp -d "$REPORTS/.baseline-changes-$(date -u '+%Y%m%dT%H%M%SZ').XXXXXX") || exit 2
  report="$REPORTS/${reservation##*/}.tsv"; report=${report/\/\.baseline-changes-/\/baseline-changes-}
  if ! cp -- "$diff" "$reservation/data" || ! ln -- "$reservation/data" "$report"; then
    printf 'INCOMPLETE: change report publication failed; baseline unchanged.\n' >&2; exit 2
  fi
  rm -f -- "$reservation/data"; rmdir -- "$reservation"
  printf 'BASELINE CHANGES\n  Added: %s  Changed: %s  Removed: %s\n\n' "$added" "$changed" "$removed"
  shown=0
  # Preserve empty TSV fields: Bash collapses IFS whitespace, so translate tabs
  # to a non-whitespace delimiter only after reading each complete record.
  while IFS= read -r row; do
    shown=$((shown+1)); [ "$shown" -le "$PRESSWARDEN_BASELINE_MAX_CHANGES" ] || continue
    IFS=$'\034' read -r action type site key newv oldv <<< "${row//$'\t'/$'\034'}"
    _pw_baseline_print_change "$action" "$type" "$site" "$key" "$newv" "$oldv"
  done < "$diff"
  if [ "$changes" -gt "$PRESSWARDEN_BASELINE_MAX_CHANGES" ]; then printf '\n  ... %s additional changes in the saved report.\n' "$((changes-PRESSWARDEN_BASELINE_MAX_CHANGES))"; fi
  printf '\nChange report: %s\nReview changes before creating a new baseline. Change alone is not malware.\n' "$report"
  exit 1
)
