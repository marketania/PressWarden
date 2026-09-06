#!/usr/bin/env bash
# wp-campaign-intel — high-specificity public-research campaign markers.
NAME=wp-campaign-intel; DESC="known WordPress malware campaign markers"
SCAN_DOES="Looks for high-specificity markers associated with documented WordPress malware campaigns while keeping broader behavioral detections in separate scanners."
SCAN_WHY="Known campaign markers provide very high-signal evidence when present, but PressWarden avoids claiming attribution from generic obfuscation alone."
. "$(cd "$(dirname "$0")/.." && pwd)/lib/_lib.sh"

main() {
  banner
  local L s

  sec "PW-CAMP-001 • WP-VCD controller marker" "wp_vcd + request action/password controller • Wordfence-documented pattern"
  L=$(tmpf); : > "$L"
  for s in "${TREE_ROOTS[@]}"; do
    find "$s" -xdev \
      \( -type d \( -name vendor -o -name node_modules -o -name cache -o -name caches -o -name uploads -o -name wflogs -o -name .git -o -name .private \) -prune \) -o \
      \( -type f \( -name '*.php' -o -name '*.phtml' \) -print0 \) 2>/dev/null \
      | xargs -0 -r grep -IlE '(wp_vcd|2f3ad13e4908141130e292bf8aa67474)' 2>/dev/null >> "$L"
  done
  sort -u "$L" -o "$L"
  report "$L" issue "no WP-VCD controller markers found"
  note "Rule PW-CAMP-001 is based on highly specific WP-VCD controller markers documented by Wordfence; a match should be investigated immediately."

  sec "PW-CAMP-002 • SocGholish / NDSW markers" "ndsw/ndsj/ndsx and documented evolved marker families"
  L=$(tmpf); : > "$L"
  for s in "${TREE_ROOTS[@]}"; do
    find "$s" -xdev \
      \( -type d \( -name vendor -o -name node_modules -o -name cache -o -name caches -o -name uploads -o -name wflogs -o -name .git -o -name .private \) -prune \) -o \
      \( -type f \( -name '*.js' -o -name '*.php' -o -name '*.html' -o -name '*.htm' \) -print0 \) 2>/dev/null \
      | xargs -0 -r grep -IlE '(^|[^A-Za-z0-9_])(ndsw|ndsj|ndsx|zqxw|zqxq|qwzx)([^A-Za-z0-9_]|$)' 2>/dev/null >> "$L"
  done
  sort -u "$L" -o "$L"
  report "$L" issue "no high-specificity SocGholish/NDSW markers found"
  note "Rule PW-CAMP-002 uses marker families documented in Sucuri research; the generic JavaScript scanner separately detects campaign-like behavior without requiring these names."

  finish
}
run_logged wp-campaign-intel
