#!/usr/bin/env bash
# confcheck — wp-config.php + per-directory PHP configuration
NAME=confcheck; DESC="WordPress/PHP configuration integrity + hardening"
SCAN_DOES="Reviews wp-config.php and per-directory PHP settings for obfuscation, dangerous directives, debug exposure, and hardening gaps."
SCAN_WHY="These files load very early and can silently prepend attacker code or weaken WordPress and PHP protections. This check never changes configuration; desired-state changes belong to PressHarden."
. "$(cd "$(dirname "$0")/.." && pwd)/lib/_lib.sh"

main() {
  banner
  local L f s cfglist sites site

  sec "Obfuscation inside wp-config.php"
  L=$(tmpf)
  grep -HnE 'eval\(|base64_decode|gzinflate|gzuncompress|str_rot13|\$\{"\\x|assert\(|preg_replace\([^,]*/e' \
    "${SCAN_ROOTS[@]/%//wp-config.php}" 2>/dev/null > "$L"
  report "$L"

  sec "Nested PHP configuration persistence" "all .user.ini/php.ini under WordPress roots"
  cfglist=$(tmpf); L=$(tmpf)
  : > "$cfglist"
  for s in "${TREE_ROOTS[@]}"; do
    find "$s" -type f \( -name '.user.ini' -o -name 'php.ini' \) \
      -not -path '*/.private/*' -print 2>/dev/null >> "$cfglist"
  done
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    grep -HnEi \
      '^[[:space:]]*(auto_prepend_file|auto_append_file)[[:space:]]*=[[:space:]]*[^;#[:space:]]+|^[[:space:]]*allow_url_include[[:space:]]*=[[:space:]]*(on|1|yes|true)' \
      "$f" 2>/dev/null | grep -v 'wordfence-waf.php' >> "$L" || true
  done < "$cfglist"
  rm -f "$cfglist"
  report "$L" issue "no dangerous nested PHP configuration overrides"

  sec "Production PHP overrides worth reviewing"
  cfglist=$(tmpf); L=$(tmpf)
  : > "$cfglist"
  for s in "${TREE_ROOTS[@]}"; do
    find "$s" -type f \( -name '.user.ini' -o -name 'php.ini' \) \
      -not -path '*/.private/*' -print 2>/dev/null >> "$cfglist"
  done
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    grep -HnEi \
      '^[[:space:]]*(display_errors|display_startup_errors)[[:space:]]*=[[:space:]]*(on|1|yes|true)' \
      "$f" 2>/dev/null >> "$L" || true
  done < "$cfglist"
  rm -f "$cfglist"
  report "$L" review "no explicit display_errors/display_startup_errors enabled"

  sec "Dangerous WordPress constants"
  L=$(tmpf)
  grep -HnEi \
    "define\\([[:space:]]*['\"](WP_ALLOW_REPAIR|ALLOW_UNFILTERED_UPLOADS)['\"][[:space:]]*,[[:space:]]*true" \
    "${SCAN_ROOTS[@]/%//wp-config.php}" 2>/dev/null > "$L"
  report "$L" issue "WP_ALLOW_REPAIR and ALLOW_UNFILTERED_UPLOADS are not enabled"

  sec "WordPress debug/query instrumentation"
  L=$(tmpf); sites=$(tmpf); : > "$sites"
  for site in "${SCAN_ROOTS[@]}"; do
    f="$site/wp-config.php"; [ -f "$f" ] || continue
    if grep -HnEi \
      "define\\([[:space:]]*['\"](WP_DEBUG|WP_DEBUG_DISPLAY|WP_DEBUG_LOG|SCRIPT_DEBUG|SAVEQUERIES)['\"][[:space:]]*,[[:space:]]*true[[:space:]]*\\)" \
      "$f" 2>/dev/null >> "$L"; then
      printf '%s\n' "$site" >> "$sites"
    fi
  done
  sort -u -o "$sites" "$sites" 2>/dev/null || true
  report "$L" review "WordPress debug/query instrumentation is not explicitly enabled" noaction
  note "Debug exposure is read-only here. Use PressHarden for deliberate configuration changes."
  rm -f "$sites"

  sec "Placeholder authentication salts"
  L=$(tmpf)
  grep -Hn "put your unique phrase here" "${SCAN_ROOTS[@]/%//wp-config.php}" 2>/dev/null > "$L"
  report "$L" review

  finish
}
run_logged confcheck
