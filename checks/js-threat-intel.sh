#!/usr/bin/env bash
# Read-only browser-code intelligence. Native helpers never execute site code.
NAME=js-threat-intel; DESC="JavaScript loader / redirect / decoded-execution analysis"
SCAN_DOES="Examines JavaScript and inline HTML scripts using bounded lexical analysis and ordered source-to-sink recognition."
SCAN_WHY="Separates suspicious code relationships from unrelated functions, minification, comments, and normal application routing."
. "$(cd "$(dirname "$0")/.." && pwd)/lib/_lib.sh"

main() {
  banner
  if ! command -v php >/dev/null 2>&1; then
    printf '    INCOMPLETE: PHP is required for JavaScript validation; no clean verdict.\n' >&2
    return 2
  fi
  if [ "${#TREE_ROOTS[@]}" -eq 0 ]; then
    printf '    INCOMPLETE: no validated WordPress installations found; no JavaScript scan performed.\n' >&2
    return 2
  fi
  local candidates results errors s rc=0 kind rule finding alert review id title stats roots_visited=0
  candidates=$(tmpf); results=$(tmpf); errors=$(tmpf)
  : > "$candidates"; : > "$results"; : > "$errors"
  pw_progress_init
  for s in "${TREE_ROOTS[@]}"; do
    if [ "${PW_PROGRESS_ACTIVE:-0}" = 1 ]; then
      pw_progress_collect "$roots_visited" "${#TREE_ROOTS[@]}" "$(site_label_from_root "$s")"
    fi
    find "$s" -xdev \
      \( -type d \( -name vendor -o -name node_modules -o -name cache -o -name caches -o -name wflogs -o -name .git -o -name .private \) -prune \) -o \
      \( -type f \( -name '*.js' -o -name '*.mjs' -o -name '*.cjs' -o -name '*.html' -o -name '*.htm' \) -size -6291457c -print0 \) \
      >> "$candidates" 2>> "$errors" || rc=2
    roots_visited=$((roots_visited+1))
  done
  PW_PROGRESS_LIST_COMPLETE=1; [ "$rc" -eq 0 ] || PW_PROGRESS_LIST_COMPLETE=0
  export PW_PROGRESS_LIST_COMPLETE
  pw_progress_count_paths "$candidates"
  pw_progress_clear
  php "$PRESSWARDEN_DIR/lib/js-threat-cli.php" < "$candidates" > "$results" 2>> "$errors" || rc=2
  pw_progress_end

  stats=$(grep '^JS ANALYSIS:' "$errors" | tail -1)
  [ -z "$stats" ] || note "$stats"

  for id in PW-JS-001 PW-JS-002 PW-JS-004 PW-JS-003; do
    alert=$(tmpf); review=$(tmpf); : > "$alert"; : > "$review"
    while IFS=$'\t' read -r kind rule finding; do
      [ "$rule" = "$id" ] || continue
      case "$kind" in
        ALERT) printf '%s\n' "$finding" >> "$alert" ;;
        REVIEW) printf '%s\n' "$finding" >> "$review" ;;
      esac
    done < "$results"
    sort -u "$alert" -o "$alert"; sort -u "$review" -o "$review"
    case "$id" in
      PW-JS-001) title='decoded code passed to execution' ;;
      PW-JS-002) title='obfuscated browser script loading' ;;
      PW-JS-004) title='obfuscated browser redirect' ;;
      PW-JS-003) title='hidden remote iframe with decoded event handler' ;;
    esac
    sec "$id • $title" "read-only evidence; no automatic removal"
    if [ -s "$alert" ] || [ -s "$review" ]; then
      [ ! -s "$alert" ] || report "$alert" issue '' noaction
      [ ! -s "$review" ] || report "$review" review '' noaction
    elif [ "$rc" -eq 0 ]; then
      report "$alert" issue 'no matching high-signal chain in analyzed scope' noaction
    else
      note 'Incomplete analysis — no clean verdict for this rule.'
    fi
    rm -f "$alert" "$review"
  done
  note 'Visitor-gated encoded HTTP URLs are REVIEW, not confirmed malware. Evidence includes the rule, source line, sink, and hostname; URL credentials/query strings are not printed.'
  rm -f "$candidates" "$results"
  if [ "$rc" -ne 0 ]; then
    printf '    INCOMPLETE: one or more paths could not be analyzed; check PHP and read permissions.\n' >&2
    # The PHP helper emits escaped, payload-free diagnostics. Directory errors
    # are not echoed because filenames may contain terminal control characters.
    grep '^INCOMPLETE:' "$errors" | head -n 5 >&2 || true
    rm -f "$errors"
    return 2
  fi
  rm -f "$errors"
  finish
}
run_logged js-threat-intel
