#!/usr/bin/env bash
# external-yara — optional administrator-supplied YARA compatibility.
NAME=external-yara; DESC="optional external YARA rule scan"
SCAN_DOES="Runs administrator-supplied YARA rules with bounded execution against eligible outermost WordPress roots. Links are not followed; roots containing excluded installations are refused. Matches are review-only and failed coverage is incomplete."
SCAN_WHY="External rules can complement native checks, but missing capabilities, engine failures and skipped scope must never become malware-clearance claims."
. "$(cd "$(dirname "$0")/.." && pwd)/lib/_lib.sh"

# Engine output is untrusted terminal data, not formatting or shell input.
_yara_text() { printf '%s' "$1" | LC_ALL=C tr '\000-\010\013-\037\177' '?'; }
_yara_incomplete() { PW_CHECK_INCOMPLETE=1; note "INCOMPLETE: $(_yara_text "$1")"; }
_yara_has_exclusion() {
  local root="$1" excluded
  for excluded in "${MANUAL_EXCLUDED_ROOTS[@]}"; do
    case "$excluded" in "$root"|"$root"/*) return 0 ;; esac
  done
  return 1
}

main() {
  banner
  local rules="${PRESSWARDEN_YARA_RULES:-}" seconds="${PRESSWARDEN_YARA_TIMEOUT:-120}"
  local s d out err rc line rule path shown processed cap hidden help completed=0 total_matches=0
  sec "External YARA rules" "optional • administrator-supplied • review-only matches"
  if [ -z "$rules" ]; then
    note "SKIPPED: PRESSWARDEN_YARA_RULES is not configured. No YARA coverage was obtained."
    return 0
  fi
  if [[ ! "$seconds" =~ ^[1-9][0-9]{0,3}$ ]] || [ "$seconds" -gt 3600 ]; then
    _yara_incomplete 'PRESSWARDEN_YARA_TIMEOUT must be an integer from 1 to 3600 seconds.'
    finish; return 2
  fi
  if ! command -v yara >/dev/null 2>&1 || ! command -v timeout >/dev/null 2>&1; then
    _yara_incomplete 'Configured external YARA requires yara and GNU timeout. Install dependencies or deliberately disable this optional check.'
    finish; return 2
  fi
  if [ ! -r "$rules" ] || [ ! -f "$rules" ]; then
    _yara_incomplete 'Configured rules file is not a readable regular file; check PRESSWARDEN_YARA_RULES. Nothing was scanned.'
    finish; return 2
  fi
  rules=$(realpath -- "$rules" 2>/dev/null) || { _yara_incomplete 'Cannot resolve rules path.'; finish; return 2; }
  # A finite timeout and output-file size limit also protect the capability probe.
  help=$(tmpf) || return 2
  (ulimit -f 16384; timeout --kill-after=2s 5s yara --help) > "$help" 2>&1; rc=$?
  if [ "$rc" -ne 0 ] || ! grep -q -- '--no-follow-symlinks' "$help"; then
    rm -f -- "$help"
    _yara_incomplete 'YARA must advertise --no-follow-symlinks; this engine cannot safely perform the requested recursive scan.'
    finish; return 2
  fi
  rm -f -- "$help"
  cap="${PRESSWARDEN_MAX:-60}"
  if [[ ! "$cap" =~ ^[1-9][0-9]{0,3}$ ]]; then cap=60; fi
  for s in "${TREE_ROOTS[@]}"; do
    d=$(_yara_text "$(site_label_from_root "$s")")
    if [ ! -d "$s" ] || [ -L "$s" ]; then
      _yara_incomplete "$d: selected root changed or became unavailable; not scanned."
      continue
    fi
    # YARA cannot exclude arbitrary subtrees. Filtering its output afterward
    # would still read excluded data, so refuse instead of overstating coverage.
    if _yara_has_exclusion "$s"; then
      _yara_incomplete "$d: recursive root contains an excluded installation. Select a narrower eligible root or use native scoped checks; YARA was not run for this root."
      continue
    fi
    out=$(tmpf) || { _yara_incomplete 'Cannot reserve scanner output.'; continue; }
    err=$(tmpf) || { rm -f -- "$out"; _yara_incomplete 'Cannot reserve scanner diagnostics.'; continue; }
    # No WP-CLI, WordPress bootstrap, shell eval, or automatic remediation.
    # Each output file is bounded to at most 16 MiB (8 MiB in POSIX mode).
    (ulimit -f 16384; timeout --kill-after=5s "${seconds}s" yara -r --no-follow-symlinks "$rules" "$s") > "$out" 2> "$err"; rc=$?
    shown=0; processed=0
    # Retain valid partial matches even when the engine failed or timed out.
    while IFS= read -r line || [ -n "$line" ]; do
      processed=$((processed+1))
      if [ "$processed" -gt 10000 ]; then
        _yara_incomplete "$d: scanner output exceeded 10000 records; remaining records were not interpreted."
        break
      fi
      [ -n "$line" ] || continue
      rule=${line%% *}; path=${line#* }
      if [[ ! "$rule" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || [[ "$path" != "$s/"* ]]; then
        _yara_incomplete "$d: scanner emitted an invalid or out-of-scope result."
        continue
      fi
      case "/${path#"$s"/}/" in */../*|*/./*) _yara_incomplete "$d: scanner emitted an unsafe path."; continue ;; esac
      total_matches=$((total_matches+1)); shown=$((shown+1))
      if [ "$shown" -le "$cap" ]; then
        flag "$d" "external YARA match — $rule" "$(_yara_text "$path")"
      fi
    done < "$out"
    if [ "$shown" -gt "$cap" ]; then
      hidden=$((shown-cap)); TOTAL=$((TOTAL+hidden)); REVIEWS=$((REVIEWS+hidden))
      note "$d: $hidden additional matches not displayed; this report is not a full raw-match archive."
    fi
    if [ "$rc" -ne 0 ]; then
      _yara_incomplete "$d: YARA failed or exceeded its execution/output limit (rc=$rc). Valid partial matches above were retained."
    fi
    if [ -s "$err" ]; then
      _yara_incomplete "$d: scanner diagnostics prevent a complete-coverage claim. Review rules, permissions and engine compatibility."
      note "$(_yara_text "$(head -c 2048 "$err")")"
    fi
    if [ "$rc" -eq 0 ] && [ ! -s "$err" ]; then completed=$((completed+1)); fi
    rm -f -- "$out" "$err"
  done
  if [ "$completed" -eq 0 ]; then
    _yara_incomplete 'No eligible root completed external YARA scanning.'
  elif [ "$total_matches" -eq 0 ] && [ "${PW_CHECK_INCOMPLETE:-0}" -eq 0 ] && [ "${PW_DISCOVERY_FAILED:-0}" -eq 0 ]; then
    note 'no external YARA rule matches reported in the completed regular-file scope; links were not followed.'
  fi
  note 'External matches are review-only, not confirmed malware. No signatures are bundled and no remediation is performed.'
  finish
}
run_logged external-yara
