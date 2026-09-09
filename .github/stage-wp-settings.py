from pathlib import Path

p=Path('presswarden'); s=p.read_text()
old="  ./presswarden auto-updates themes enable|disable [target]\n  ./presswarden file-mods ACTION [target]  Legacy/advanced status|on|off interface\n"
new="  ./presswarden auto-updates themes enable|disable [target]\n  ./presswarden wp-settings [target]       WordPress policy dashboard / fleet baseline differences\n  ./presswarden wp-settings set SETTING VALUE [target]  Change supported wp-config policy\n  ./presswarden file-mods ACTION [target]  Legacy/advanced status|on|off interface\n"
assert old in s; s=s.replace(old,new,1)
old="Examples: ./presswarden scan example.com   ./presswarden lock example.com   ./presswarden auto-updates core minor example.com\n"
new="Examples: ./presswarden scan example.com   ./presswarden lock example.com   ./presswarden wp-settings example.com\n"
assert old in s; s=s.replace(old,new,1)
marker='cmd="${1:-help}"; shift || true\n'
confirm=r'''confirm_wp_setting_change() {
  local setting="$1" value="$2" root="$3" ans=''
  if [ "${PRESSWARDEN_INTERACTIVE:-1}" = "0" ]; then return 0; fi
  if [ -r /dev/tty ] && [ -w /dev/tty ]; then
    if [ -n "${TARGET_NAME:-}" ]; then
      printf '\n  Set %s=%s for %s (%s installation(s))? [y/N]: ' "$setting" "$value" "$TARGET_NAME" "${TARGET_COUNT:-1}" > /dev/tty
    else
      printf '\n  Set %s=%s for all discovered websites under %s? [y/N]: ' "$setting" "$value" "$root" > /dev/tty
    fi
    IFS= read -r ans < /dev/tty || ans=''
    case "$ans" in y|Y|yes|YES) return 0 ;; *) printf 'Cancelled.\n'; return 1 ;; esac
  fi
  printf 'Refusing fleet wp-settings change without an interactive terminal. Set PRESSWARDEN_INTERACTIVE=0 to run intentionally in automation.\n' >&2
  return 1
}

'''
assert marker in s; s=s.replace(marker,confirm+marker,1)
route=r'''  wp-settings)
    sub="${1:-status}"
    if [ "$sub" = status ]; then
      shift || true
      [ "$#" -le 1 ] || { printf 'Usage: ./presswarden wp-settings [website|directory|all]\n' >&2; exit 2; }
      select_target "$@" || exit 2
      exec bash "$PRESSWARDEN_DIR/checks/wp-settings.sh" status
    elif [ "$sub" = set ]; then
      shift || true
      setting="${1:-}"; value="${2:-}"; target="${3:-}"
      [ "$#" -ge 2 ] && [ "$#" -le 3 ] || { printf 'Usage: ./presswarden wp-settings set SETTING VALUE [website|directory|all]\n' >&2; exit 2; }
      case "$setting" in
        editor|cron|recovery|debug|force-ssl-admin|alternate-cron)
          case "$value" in enabled|disabled) : ;; *) printf '%s must be enabled or disabled.\n' "$setting" >&2; exit 2 ;; esac ;;
        environment)
          case "$value" in production|staging|development|local) : ;; *) printf 'environment must be production, staging, development, or local.\n' >&2; exit 2 ;; esac ;;
        development)
          case "$value" in disabled|core|plugin|theme|all) : ;; *) printf 'development must be disabled, core, plugin, theme, or all.\n' >&2; exit 2 ;; esac ;;
        *) printf 'Supported wp-settings setters: editor, cron, recovery, environment, development, debug, force-ssl-admin, alternate-cron.\n' >&2; exit 2 ;;
      esac
      if [ -n "$target" ]; then select_target "$target" || exit 2; else select_target || exit 2; fi
      confirm_wp_setting_change "$setting" "$value" "$ROOT" || exit 1
      export PRESSWARDEN_POLICY_APPLY=1 PRESSWARDEN_INTERACTIVE=0
      exec bash "$PRESSWARDEN_DIR/checks/wp-settings.sh" set "$setting" "$value"
    else
      [ "$#" -le 1 ] || { printf 'Usage: ./presswarden wp-settings [website|directory|all]\n' >&2; exit 2; }
      select_target "$@" || exit 2
      exec bash "$PRESSWARDEN_DIR/checks/wp-settings.sh" status
    fi
    ;;
'''
needle='  auto-updates)\n'
assert needle in s; s=s.replace(needle,route+needle,1)
p.write_text(s)

p=Path('CHANGELOG.md'); s=p.read_text()
marker='All notable changes to PressWarden are documented here.\n\n'
entry='''## 1.1.12 — 2026-09-09

Unified WordPress policy dashboard and fleet baseline differences.

- Add `wp-settings` for a full one-site policy view and a compact fleet baseline with only differing sites. Tied values are reported as MIXED rather than selecting an arbitrary baseline.
- Replace the separate Fast/Full auto-update inventory step with the unified `wp-settings` check; existing `auto-updates` mutation commands remain available. Policy differences are informational and do not replace dedicated security findings.
- Collect one allowlisted normalized policy record per site, covering file/editor controls, core/plugin/theme updates, updater blockers, cron/recovery, environment/development, debug/cache, retention/resources and selected configuration posture. Never emit arbitrary wp-config values, credentials, salts, API keys or source bodies.
- Add confirmed, backed-up and verified setters for editor, cron, Recovery Mode, environment, development mode, debug, FORCE_SSL_ADMIN and alternate cron. Hosting/plugin-sensitive values remain inventory-only.
- Preserve website-name targeting, exclusions, verified quarantine, baseline semantics, updater recovery, scan progress and detector thresholds.

'''
assert marker in s; s=s.replace(marker,marker+entry,1); p.write_text(s)
