#!/usr/bin/env bash
# phpcheck — fast local PHP placement anomalies
NAME=phpcheck; DESC="high-signal PHP placement anomalies"
SCAN_DOES="Looks for executable PHP in locations where WordPress normally ships none, plus genuinely executable extensionless files at the WordPress root."
SCAN_WHY="This keeps the FAST pass focused on strong local indicators. MU-plugin inventory, generic core-file anomalies, and root archives are handled by dedicated WP/plugin/root checks instead of being scanned twice."
. "$(cd "$(dirname "$0")/.." && pwd)/lib/_lib.sh"

main() {
  banner
  local L d s found_lang lang_n lang_sites lang_total

  sec "PHP where WordPress ships none"
  L=$(tmpf)
  for d in wp-admin/images wp-includes/images wp-content/upgrade; do
    find "${SCAN_ROOTS[@]/%//$d}" -type f \
      \( -name '*.php' -o -name '*.php[57]' -o -name '*.phtml' -o -name '*.phar' \) \
      2>/dev/null
  done > "$L"
  report "$L" issue "no unexpected PHP outside wp-content/languages"

  found_lang=0; lang_sites=0; lang_total=0
  for s in "${SCAN_ROOTS[@]}"; do
    [ -d "$s/wp-content/languages" ] || continue
    lang_n=$(find "$s/wp-content/languages" -type f \
      \( -name '*.php' -o -name '*.php[57]' -o -name '*.phtml' \) \
      2>/dev/null | grep -c .)
    lang_n=${lang_n:-0}
    [ "$lang_n" -gt 0 ] || continue
    found_lang=1
    lang_sites=$((lang_sites+1)); lang_total=$((lang_total+lang_n))
    printf '    %s%sℹ MULTILANGUAGE%s  %s%s%s  %s›%s  %s%s PHP file(s)%s in wp-content/languages\n' \
      "$B" "$C" "$X" "$B$M" "$(site_domain "$s")" "$X" "$D" "$X" "$B" "$lang_n" "$X"
  done
  if [ "$found_lang" -eq 1 ]; then
    printf '    %sℹ%s  language scope total: %s%s site(s)%s • %s%s PHP file(s)%s\n' \
      "$C" "$X" "$B" "$lang_sites" "$X" "$B" "$lang_total" "$X"
  else
    note "language scope: no PHP translation files found"
  fi

  sec "Extensionless executable files at WordPress roots"
  L=$(tmpf)
  find "${SCAN_ROOTS[@]}" -maxdepth 1 -type f ! -name '*.*' -perm /111 \
    ! -name 'LICENSE' ! -name 'README' ! -name 'Dockerfile' ! -name 'Makefile' \
    ! -name 'CHANGELOG' 2>/dev/null > "$L"
  report "$L" review "no executable extensionless root files"

  note "Duplicate scans removed: MU-plugin inventory is owned by wp-plugins; generic wp-admin/wp-includes anomalies are owned by wp-core checksums; root archives are owned by wp-root/sensitive-files."
  finish
}
run_logged phpcheck
