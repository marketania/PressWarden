#!/usr/bin/env bash
# wp-uploads-deep — slow content inspection for PHP hidden inside image extensions
NAME=wp-uploads-deep; DESC="uploads image-content scan (slow • full only)"
SCAN_DOES="Reads image-like upload files and checks whether PHP code has been hidden behind an image extension."
SCAN_WHY="Extension-only checks can miss a backdoor named .jpg or .png, so this slower content scan is optional during FULL runs."
. "$(cd "$(dirname "$0")/.." && pwd)/lib/_lib.sh"
main() {
  banner
  local L n

  n=0
  for p in "${SCAN_ROOTS[@]}"; do
    [ -d "$p/wp-content/uploads" ] || continue
    n=$((n+1))
  done

  sec "PHP disguised with an image extension" "$n site upload tree(s) • slow content scan"
  note "Slow check: FULL asks before running it. Set PRESSWARDEN_UPLOADS_DEEP=1 to always run or =0 to always skip."
  L=$(tmpf)
  find "${SCAN_ROOTS[@]/%//wp-content/uploads}" -type f \
    \( -iname '*.jpg' -o -iname '*.jpeg' -o -iname '*.png' -o -iname '*.gif' \
       -o -iname '*.ico' -o -iname '*.webp' \) \
    -size +1k -exec grep -lI -m1 '<?php' {} + 2>/dev/null > "$L"
  report "$L"

  finish
}
run_logged wp-uploads-deep
