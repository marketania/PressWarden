#!/usr/bin/env bash
NAME=wp-auto-updates; DESC="WordPress core, plugin, and theme automatic-update policy"
SCAN_DOES="Reports configured core auto-update level plus plugin/theme auto-update coverage, and identifies global blockers without changing site state."
SCAN_WHY="Automatic-update policy affects how quickly WordPress receives maintenance and security fixes; visibility helps operators make deliberate fleet-wide choices."
. "$(cd "$(dirname "$0")/.." && pwd)/lib/_lib.sh"

ACTION="${1:-status}"; VALUE="${2:-}"

_wpcmd() { local site="$1"; shift; wp "$@" --path="$site" "${WPQ[@]}"; }
_cfg_has() { _wpcmd "$1" config has "$2" --type=constant >/dev/null 2>&1; }
_cfg_json() { _wpcmd "$1" config get "$2" --type=constant --format=json 2>/dev/null; }
_cfg_true() { _cfg_has "$1" "$2" && _wpcmd "$1" config is-true "$2" --type=constant >/dev/null 2>&1; }

_core_policy() {
  local site="$1" v major minor
  if _cfg_has "$site" WP_AUTO_UPDATE_CORE; then
    v=$(_cfg_json "$site" WP_AUTO_UPDATE_CORE) || return 2
    case "$v" in
      true) printf 'MAJOR' ;;
      false) printf 'DISABLED' ;;
      '"minor"') printf 'MINOR' ;;
      '"beta"'|'"rc"'|'"development"'|'"branch-development"') printf 'MAJOR' ;;
      *) printf 'CUSTOM' ;;
    esac
    return 0
  fi
  major=$(_wpcmd "$site" option get auto_update_core_major --format=json 2>/dev/null || printf '"unset"')
  minor=$(_wpcmd "$site" option get auto_update_core_minor --format=json 2>/dev/null || printf '"enabled"')
  case "$major" in '"enabled"') printf 'MAJOR'; return 0 ;; esac
  case "$minor" in '"disabled"') printf 'DISABLED' ;; *) printf 'MINOR' ;; esac
}

_item_counts() {
  local site="$1" type="$2" total enabled
  total=$(_wpcmd "$site" "$type" auto-updates status --all --format=count 2>/dev/null) || return 2
  enabled=$(_wpcmd "$site" "$type" auto-updates status --all --enabled-only --format=count 2>/dev/null) || return 2
  case "$total:$enabled" in *[!0-9:]*|:*|*:) return 2 ;; esac
  printf '%s\t%s\n' "$total" "$enabled"
}

_item_state() {
  local total="$1" enabled="$2"
  if [ "$total" -eq 0 ]; then printf 'N/A'
  elif [ "$enabled" -eq 0 ]; then printf 'DISABLED'
  elif [ "$enabled" -eq "$total" ]; then printf 'ENABLED'
  else printf 'PARTIAL'
  fi
}

_blocker() {
  local site="$1" out=''
  _cfg_true "$site" AUTOMATIC_UPDATER_DISABLED && out='AUTOMATIC_UPDATER_DISABLED'
  if _cfg_true "$site" DISALLOW_FILE_MODS; then
    [ -z "$out" ] || out+=','
    out+='DISALLOW_FILE_MODS'
  fi
  printf '%s' "$out"
}

_status_row() {
  local site="$1" label core pc tc pt pe tt te ps ts block
  label=$(site_label_from_root "$site")
  core=$(_core_policy "$site") || return 2
  pc=$(_item_counts "$site" plugin) || return 2; IFS=$'\t' read -r pt pe <<< "$pc"
  tc=$(_item_counts "$site" theme) || return 2; IFS=$'\t' read -r tt te <<< "$tc"
  ps=$(_item_state "$pt" "$pe"); ts=$(_item_state "$tt" "$te"); block=$(_blocker "$site")
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$label" "$core" "$ps" "$pe" "$pt" "$ts" "$te" "$tt" "$block"
}

_save_status_details() {
  local rows="$1"
  [ -n "${DETAIL_LOG:-}" ] || return 0
  {
    printf '\n[AUTO-UPDATES] per-site configured policy\n'
    printf 'site\tcore\tplugins\tplugins_enabled\tplugins_total\tthemes\tthemes_enabled\tthemes_total\tglobal_blocker\n'
    cat "$rows"
  } >> "$DETAIL_LOG" || return 1
}

_status() {
  local rows site failed=0 n label core ps pe pt ts te tt block
  local minor=0 major=0 disabled=0 custom=0 p_on=0 p_partial=0 p_off=0 p_na=0 t_on=0 t_partial=0 t_off=0 t_na=0 blocked=0
  require_wp; discover_sites; banner
  sec "WordPress automatic-update policy" "core • plugins • themes • global blockers"
  rows=$(tmpf); : > "$rows"
  for site in "${WP_SITES[@]}"; do
    if ! _status_row "$site" >> "$rows"; then
      printf '    INCOMPLETE: %s auto-update policy could not be read.\n' "$(site_label_from_root "$site")" >&2
      failed=1
    fi
  done
  [ "$failed" -eq 0 ] || { rm -f "$rows"; return 2; }
  _save_status_details "$rows" || { rm -f "$rows"; printf '    INCOMPLETE: auto-update detail evidence could not be saved.\n' >&2; return 2; }
  n=$(grep -c . "$rows" 2>/dev/null); n=${n:-0}
  if [ "$n" -le 3 ]; then
    while IFS=$'\t' read -r label core ps pe pt ts te tt block; do
      printf '    %s✓%s  %s%s%s  Core %s%s%s • Plugins %s %s/%s • Themes %s %s/%s' "$G" "$X" "$B$M" "$label" "$X" "$B" "$core" "$X" "$ps" "$pe" "$pt" "$ts" "$te" "$tt"
      [ -z "$block" ] || printf ' • %sBLOCKED by %s%s' "$Y" "$block" "$X"
      printf '\n'
    done < "$rows"
  else
    while IFS=$'\t' read -r label core ps pe pt ts te tt block; do
      case "$core" in MINOR) minor=$((minor+1));; MAJOR) major=$((major+1));; DISABLED) disabled=$((disabled+1));; *) custom=$((custom+1));; esac
      case "$ps" in ENABLED) p_on=$((p_on+1));; PARTIAL) p_partial=$((p_partial+1));; DISABLED) p_off=$((p_off+1));; *) p_na=$((p_na+1));; esac
      case "$ts" in ENABLED) t_on=$((t_on+1));; PARTIAL) t_partial=$((t_partial+1));; DISABLED) t_off=$((t_off+1));; *) t_na=$((t_na+1));; esac
      [ -z "$block" ] || blocked=$((blocked+1))
    done < "$rows"
    printf '    %s✓ CORE%s     MINOR %s • MAJOR %s • DISABLED %s • CUSTOM %s\n' "$G" "$X" "$minor" "$major" "$disabled" "$custom"
    printf '    %sℹ PLUGINS%s  ENABLED %s • PARTIAL %s • DISABLED %s • N/A %s\n' "$C" "$X" "$p_on" "$p_partial" "$p_off" "$p_na"
    printf '    %sℹ THEMES%s   ENABLED %s • PARTIAL %s • DISABLED %s • N/A %s\n' "$C" "$X" "$t_on" "$t_partial" "$t_off" "$t_na"
    [ "$blocked" -eq 0 ] || printf '    %sℹ BLOCKED%s  %s/%s site(s) have a global updater blocker; use auto-updates status <site> for detail\n' "$Y" "$X" "$blocked" "$n"
  fi
  note "Core policy uses WP_AUTO_UPDATE_CORE when explicitly defined; plugin/theme counts reflect installed-item preferences. Global blockers are reported separately."
  rm -f "$rows"
  finish
}

_backup_config() {
  local site="$1" label="$2" root="$3" dest
  dest="$root/$label/wp-config.php"
  mkdir -p "$(dirname "$dest")" 2>/dev/null || return 1
  cp -p "$site/wp-config.php" "$dest" 2>/dev/null || return 1
  chmod 600 "$dest" 2>/dev/null || true
  printf '%s' "$dest"
}

_set_core() {
  local site label backup_root backup desired now block rc fail=0
  require_wp; discover_sites
  backup_root="$QUARANTINE/auto-updates-core-$(date -u +%Y%m%dT%H%M%SZ)-$$"; mkdir -p "$backup_root" || return 2; chmod 700 "$backup_root" 2>/dev/null || true
  for site in "${WP_SITES[@]}"; do
    label=$(site_label_from_root "$site"); backup=$(_backup_config "$site" "$label" "$backup_root") || { printf '✖ %s: could not back up wp-config.php\n' "$label"; fail=1; continue; }
    case "$VALUE" in
      minor) _wpcmd "$site" config set WP_AUTO_UPDATE_CORE minor --type=constant >/dev/null 2>&1; rc=$?; desired=MINOR ;;
      major) _wpcmd "$site" config set WP_AUTO_UPDATE_CORE true --raw --type=constant >/dev/null 2>&1; rc=$?; desired=MAJOR ;;
      disabled) _wpcmd "$site" config set WP_AUTO_UPDATE_CORE false --raw --type=constant >/dev/null 2>&1; rc=$?; desired=DISABLED ;;
    esac
    if [ "${rc:-2}" -ne 0 ]; then cp -p "$backup" "$site/wp-config.php" 2>/dev/null || true; printf '✖ %s: core policy update failed; wp-config.php restored\n' "$label"; fail=1; continue; fi
    now=$(_core_policy "$site" 2>/dev/null || true)
    if [ "$now" != "$desired" ]; then cp -p "$backup" "$site/wp-config.php" 2>/dev/null || true; printf '✖ %s: verification failed; wp-config.php restored\n' "$label"; fail=1; continue; fi
    block=$(_blocker "$site")
    printf '✓ %s: core auto-updates %s' "$label" "$desired"; [ -z "$block" ] || printf ' (configured, but blocked by %s)' "$block"; printf '\n'
  done
  [ "$fail" -eq 0 ] || return 2
}

_enabled_names() { _wpcmd "$1" "$2" auto-updates status --all --enabled-only --field=name 2>/dev/null; }
_restore_items() {
  local site="$1" type="$2" saved="$3" name
  _wpcmd "$site" "$type" auto-updates disable --all >/dev/null 2>&1 || return 1
  while IFS= read -r name; do [ -n "$name" ] || continue; _wpcmd "$site" "$type" auto-updates enable "$name" >/dev/null 2>&1 || return 1; done < "$saved"
}

_set_items() {
  local type singular site label root saved counts total enabled want fail=0 block
  case "$ACTION" in plugins) type=plugin; singular=Plugins ;; themes) type=theme; singular=Themes ;; esac
  require_wp; discover_sites
  root="$QUARANTINE/auto-updates-${type}-$(date -u +%Y%m%dT%H%M%SZ)-$$"; mkdir -p "$root" || return 2; chmod 700 "$root" 2>/dev/null || true
  for site in "${WP_SITES[@]}"; do
    label=$(site_label_from_root "$site"); saved="$root/$label-enabled.txt"; mkdir -p "$(dirname "$saved")" || { fail=1; continue; }
    _enabled_names "$site" "$type" > "$saved" || { printf '✖ %s: could not snapshot %s auto-update preferences\n' "$label" "${singular,,}"; fail=1; continue; }; chmod 600 "$saved" 2>/dev/null || true
    _wpcmd "$site" "$type" auto-updates "$VALUE" --all >/dev/null 2>&1 || { _restore_items "$site" "$type" "$saved" >/dev/null 2>&1 || true; printf '✖ %s: %s auto-update change failed; previous preference list restored where possible\n' "$label" "$singular"; fail=1; continue; }
    counts=$(_item_counts "$site" "$type" 2>/dev/null) || { _restore_items "$site" "$type" "$saved" >/dev/null 2>&1 || true; printf '✖ %s: %s verification failed; previous preference list restored where possible\n' "$label" "$singular"; fail=1; continue; }
    IFS=$'\t' read -r total enabled <<< "$counts"
    want=0; [ "$VALUE" = enable ] && want=$total
    if [ "$enabled" -ne "$want" ]; then _restore_items "$site" "$type" "$saved" >/dev/null 2>&1 || true; printf '✖ %s: %s verification mismatch; previous preference list restored where possible\n' "$label" "$singular"; fail=1; continue; fi
    block=$(_blocker "$site")
    printf '✓ %s: %s auto-updates %s (%s/%s enabled)' "$label" "$singular" "${VALUE^^}D" "$enabled" "$total"; [ -z "$block" ] || printf ' (configured, but blocked by %s)' "$block"; printf '\n'
  done
  [ "$fail" -eq 0 ] || return 2
}

main() {
  case "$ACTION" in
    status) _status ;;
    core) _set_core ;;
    plugins|themes) _set_items ;;
    *) printf 'Unknown auto-update action.\n' >&2; return 2 ;;
  esac
}

if [ "$ACTION" = status ]; then run_logged wp-auto-updates; else main; fi
