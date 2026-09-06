#!/usr/bin/env bash
# confcheck — wp-config.php + per-directory PHP configuration
NAME=confcheck; DESC="WordPress/PHP configuration integrity + hardening"
SCAN_DOES="Reviews wp-config.php and per-directory PHP settings for obfuscation, dangerous directives, debug exposure, and hardening gaps."
SCAN_WHY="These files load very early and can silently prepend attacker code or weaken WordPress and PHP protections. Interactive prompts can safely harden wp-config.php when you choose to do so."
. "$(cd "$(dirname "$0")/.." && pwd)/lib/_lib.sh"

# Back up wp-config.php before a configuration remediation. Backups live outside
# public_html under the toolkit quarantine directory and are mode 600 where possible.
_cfg_backup() {
  local site="$1" tag="$2" cfg="$site/wp-config.php" stamp dest rel
  [ -f "$cfg" ] || return 1
  stamp=$(date +%Y%m%d-%H%M%S)
  rel=${cfg#"$ROOT"/}
  dest="$QUARANTINE/config-$tag-$stamp/$rel"
  mkdir -p "$(dirname "$dest")" 2>/dev/null || return 1
  cp -p -- "$cfg" "$dest" 2>/dev/null || return 1
  chmod 600 "$dest" 2>/dev/null || true
  printf '%s' "$dest"
}

# Use WP-CLI's config editor rather than sed so existing constants are updated
# correctly and missing constants can be inserted without brittle text matching.
_cfg_set_raw() {
  local site="$1" key="$2" value="$3"
  command -v wp >/dev/null 2>&1 || return 127
  wp config set "$key" "$value" --raw --path="$site" --no-color >/dev/null 2>&1
}

_prompt_enable_file_mods_lockdown() {
  local sites="$1" n ans site backup okn=0 failn=0
  n=$(grep -c . "$sites" 2>/dev/null); n=${n:-0}
  [ "$n" -gt 0 ] || return 0
  [ "$PRESSWARDEN_INTERACTIVE" != 0 ] || return 0
  [ -t 0 ] || { note "non-interactive session — DISALLOW_FILE_MODS remediation skipped"; return 0; }

  printf '\n    %s%sACTION%s  %s%s%s site(s) can be hardened with DISALLOW_FILE_MODS=true.\n' "$B" "$BL" "$X" "$B" "$n" "$X"
  printf '    %sThis blocks plugin/theme installs, updates, deletion and dashboard file editing until you turn it off.%s\n' "$D" "$X"
  printf '    %s[a]%s add/enable DISALLOW_FILE_MODS=true   %s[s]%s skip %s(default)%s : ' "$B$C" "$X" "$B$G" "$X" "$D" "$X"
  IFS= read -r ans || ans='s'
  case "$ans" in
    a|A|add|ADD|enable|ENABLE)
      if ! command -v wp >/dev/null 2>&1; then
        printf '    %s✖ WP-CLI is unavailable; no configuration files were changed.%s\n' "$R" "$X"
        return 0
      fi
      while IFS= read -r site; do
        [ -n "$site" ] || continue
        backup=$(_cfg_backup "$site" filemods) || { printf '    %s✖ FAILED%s   %s — backup failed\n' "$R" "$X" "$(site_label_from_root "$site")"; failn=$((failn+1)); continue; }
        if _cfg_set_raw "$site" DISALLOW_FILE_MODS true; then
          printf '    %s✓ HARDENED%s %s — DISALLOW_FILE_MODS=true\n' "$G" "$X" "$(site_label_from_root "$site")"
          printf '      %sbackup: %s%s\n' "$D" "$backup" "$X"
          okn=$((okn+1))
        else
          cp -p -- "$backup" "$site/wp-config.php" 2>/dev/null || true
          printf '    %s✖ FAILED%s   %s — restored backup\n' "$R" "$X" "$(site_label_from_root "$site")"
          failn=$((failn+1))
        fi
      done < "$sites"
      printf '    %sℹ%s  file-modification lockdown: %s changed • %s failed\n' "$C" "$X" "$okn" "$failn"
      ;;
    *) printf '    %s↷ SKIPPED%s  wp-config.php was not changed\n' "$Y" "$X" ;;
  esac
}

_debug_constant_true() {
  local cfg="$1" key="$2"
  grep -Eiq "define\\([[:space:]]*['\"]${key}['\"][[:space:]]*,[[:space:]]*true[[:space:]]*\\)" "$cfg" 2>/dev/null
}

_prompt_disable_debug() {
  local sites="$1" n ans site cfg backup key okn=0 failn=0 changed
  n=$(grep -c . "$sites" 2>/dev/null); n=${n:-0}
  [ "$n" -gt 0 ] || return 0
  [ "$PRESSWARDEN_INTERACTIVE" != 0 ] || return 0
  [ -t 0 ] || { note "non-interactive session — debug remediation skipped"; return 0; }

  printf '\n    %s%sACTION%s  %s%s%s site(s) have WordPress debug/query instrumentation enabled.\n' "$B" "$BL" "$X" "$B" "$n" "$X"
  printf '    %s[d]%s disable enabled debug constants   %s[s]%s skip %s(default)%s : ' "$B$C" "$X" "$B$G" "$X" "$D" "$X"
  IFS= read -r ans || ans='s'
  case "$ans" in
    d|D|disable|DISABLE)
      if ! command -v wp >/dev/null 2>&1; then
        printf '    %s✖ WP-CLI is unavailable; no configuration files were changed.%s\n' "$R" "$X"
        return 0
      fi
      while IFS= read -r site; do
        [ -n "$site" ] || continue
        cfg="$site/wp-config.php"; [ -f "$cfg" ] || continue
        backup=$(_cfg_backup "$site" debugoff) || { printf '    %s✖ FAILED%s   %s — backup failed\n' "$R" "$X" "$(site_label_from_root "$site")"; failn=$((failn+1)); continue; }
        changed=0
        for key in WP_DEBUG WP_DEBUG_DISPLAY WP_DEBUG_LOG SCRIPT_DEBUG SAVEQUERIES; do
          if _debug_constant_true "$cfg" "$key"; then
            if _cfg_set_raw "$site" "$key" false; then
              changed=$((changed+1))
            else
              cp -p -- "$backup" "$cfg" 2>/dev/null || true
              printf '    %s✖ FAILED%s   %s — could not set %s=false; restored backup\n' "$R" "$X" "$(site_label_from_root "$site")" "$key"
              failn=$((failn+1)); changed=-1; break
            fi
          fi
        done
        if [ "$changed" -ge 0 ]; then
          printf '    %s✓ DEBUG OFF%s %s — %s enabled constant(s) set to false\n' "$G" "$X" "$(site_label_from_root "$site")" "$changed"
          printf '      %sbackup: %s%s\n' "$D" "$backup" "$X"
          okn=$((okn+1))
        fi
      done < "$sites"
      printf '    %sℹ%s  debug hardening: %s changed • %s failed\n' "$C" "$X" "$okn" "$failn"
      ;;
    *) printf '    %s↷ SKIPPED%s  debug settings were not changed\n' "$Y" "$X" ;;
  esac
}

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
  _prompt_disable_debug "$sites"
  rm -f "$sites"

  sec "WordPress file modification lockdown"
  L=$(tmpf); sites=$(tmpf); : > "$sites"
  for site in "${SCAN_ROOTS[@]}"; do
    f="$site/wp-config.php"; [ -f "$f" ] || continue
    if ! grep -Eiq "define\\([[:space:]]*['\"]DISALLOW_FILE_MODS['\"][[:space:]]*,[[:space:]]*true[[:space:]]*\\)" "$f"; then
      echo "$f: DISALLOW_FILE_MODS is not explicitly true" >> "$L"
      printf '%s\n' "$site" >> "$sites"
    fi
  done
  report "$L" review "DISALLOW_FILE_MODS is explicitly true on all discovered WordPress installs" noaction
  _prompt_enable_file_mods_lockdown "$sites"
  rm -f "$sites"

  sec "Dashboard file editor hardening"
  L=$(tmpf)
  for f in "${SCAN_ROOTS[@]/%//wp-config.php}"; do
    [ -f "$f" ] || continue
    if grep -Eiq "define\\([[:space:]]*['\"]DISALLOW_FILE_MODS['\"][[:space:]]*,[[:space:]]*true[[:space:]]*\\)" "$f"; then continue; fi
    if grep -Eiq "define\\([[:space:]]*['\"]DISALLOW_FILE_EDIT['\"][[:space:]]*,[[:space:]]*true[[:space:]]*\\)" "$f"; then continue; fi
    echo "$f: neither DISALLOW_FILE_MODS nor DISALLOW_FILE_EDIT is explicitly true"
  done > "$L"
  report "$L" review

  sec "Placeholder authentication salts"
  L=$(tmpf)
  grep -Hn "put your unique phrase here" "${SCAN_ROOTS[@]/%//wp-config.php}" 2>/dev/null > "$L"
  report "$L" review

  sec "FORCE_SSL_ADMIN posture" "inventory only"
  local forced=0 implicit=0
  for f in "${SCAN_ROOTS[@]/%//wp-config.php}"; do
    [ -f "$f" ] || continue
    if grep -Eiq "define\\([[:space:]]*['\"]FORCE_SSL_ADMIN['\"][[:space:]]*,[[:space:]]*true" "$f"; then
      forced=$((forced+1))
    else
      implicit=$((implicit+1))
    fi
  done
  printf '    %s✓ EXPLICIT%s %s site(s) FORCE_SSL_ADMIN=true  •  %sℹ IMPLICIT%s %s site(s) rely on normal HTTPS/proxy enforcement\n' \
    "$G" "$X" "$forced" "$C" "$X" "$implicit"
  note "FORCE_SSL_ADMIN is reported as posture, not a finding; HTTPS may already be enforced by the host/CDN."

  finish
}
run_logged confcheck
