#!/usr/bin/env bash
# external-yara — optional administrator-supplied YARA compatibility.
NAME=external-yara; DESC="optional external YARA rule scan"
SCAN_DOES="Runs a user-supplied YARA rules file recursively against validated outermost WordPress roots and reports matches as review items without automatic remediation."
SCAN_WHY="Organizations may already license or maintain YARA signatures that complement PressWarden's native behavior rules; keeping them external avoids redistributing incompatible third-party signature sets."
. "$(cd "$(dirname "$0")/.." && pwd)/lib/_lib.sh"

main() {
  banner
  local rules="${PRESSWARDEN_YARA_RULES:-}" s d out err rc line rule path shown cap hidden total_matches=0
  sec "External YARA rules" "optional • user-supplied rules only • review-only matches"
  if [ -z "$rules" ]; then
    note "SKIPPED: PRESSWARDEN_YARA_RULES is not configured."
    finish; return 0
  fi
  if ! command -v yara >/dev/null 2>&1; then
    flag "YARA" "PRESSWARDEN_YARA_RULES is configured but the yara command is not available"
    finish; return 1
  fi
  if [ ! -r "$rules" ] || [ ! -f "$rules" ]; then
    flag "YARA" "configured rules file is not a readable regular file: $rules"
    finish; return 1
  fi

  cap="${PRESSWARDEN_MAX:-60}"
  case "$cap" in ''|*[!0-9]*) cap=60 ;; esac
  for s in "${TREE_ROOTS[@]}"; do
    d=$(site_label_from_root "$s"); out=$(tmpf); err=$(tmpf); : > "$out"; : > "$err"
    yara -r "$rules" "$s" > "$out" 2> "$err"; rc=$?
    if [ "$rc" -ne 0 ]; then
      flag "$d" "external YARA scan failed (rc=$rc)" "$(tail -n 4 "$err" 2>/dev/null)"
      rm -f "$out" "$err"; continue
    fi
    [ -s "$err" ] && note "$d: YARA reported warnings; review the scanner log if rule compilation/runtime behavior is unexpected."
    shown=0
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      total_matches=$((total_matches+1)); shown=$((shown+1))
      if [ "$shown" -le "$cap" ]; then
        rule=${line%% *}; path=${line#* }
        if [ "$path" = "$line" ]; then
          flag "$d" "external YARA match — $line"
        else
          flag "$d" "external YARA match — $rule" "$path"
        fi
      fi
    done < "$out"
    if [ "$shown" -gt "$cap" ]; then
      hidden=$((shown-cap)); TOTAL=$((TOTAL+hidden)); REVIEWS=$((REVIEWS+hidden))
      note "$d: $hidden additional YARA match(es) hidden; rerun the YARA tool directly for its complete output."
    fi
    rm -f "$out" "$err"
  done

  [ "$total_matches" -eq 0 ] && printf '    %s✓ CLEAN%s  no external YARA rule matches reported\n' "$G" "$X"
  note "External YARA matches are always review-only in PressWarden because third-party rule severity, licensing and false-positive characteristics are outside the native rule contract."
  note "PressWarden does not bundle or redistribute YARA signatures; configure only rules you are authorized to use."
  finish
}
run_logged external-yara
