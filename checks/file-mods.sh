#!/usr/bin/env bash
. "$(cd "$(dirname "$0")/.." && pwd)/lib/_lib.sh"
action="${1:-status}"
case "$action" in status|on|off) ;; *) printf 'Usage: presswarden file-mods status|on|off [path]\n' >&2; exit 2 ;; esac
command -v wp >/dev/null 2>&1 || die "WP-CLI is required for file-mods"
for s in "${SCAN_ROOTS[@]}"; do
  label=$(site_label_from_root "$s")
  cur=$(wpq "$s" config get DISALLOW_FILE_MODS --type=constant 2>/dev/null || printf '')
  if [ "$action" = status ]; then
    case "${cur,,}" in 1|true) ok "$label" "DISALLOW_FILE_MODS=true" ;; *) flag "$label" "DISALLOW_FILE_MODS is not true" ;; esac
    continue
  fi
  want=true; [ "$action" = off ] && want=false
  if [ "$PRESSWARDEN_INTERACTIVE" != 0 ] && [ -t 0 ]; then
    printf '  %s%s%s%s DISALLOW_FILE_MODS=%s? [y/N]: ' "$B" "$Y" "$label" "$X" "$want"
    read -r ans || ans=''; case "$ans" in y|Y|yes|YES) ;; *) continue ;; esac
  fi
  backup="$QUARANTINE/file-mods-$(date +%Y%m%d-%H%M%S)/$label/wp-config.php"
  mkdir -p "$(dirname "$backup")" && cp -p "$s/wp-config.php" "$backup" || { flag "$label" "could not back up wp-config.php"; continue; }
  if wpq "$s" config set DISALLOW_FILE_MODS "$want" --raw >/dev/null 2>&1; then
    ok "$label" "DISALLOW_FILE_MODS=$want"
  else
    cp -p "$backup" "$s/wp-config.php" 2>/dev/null || true
    issue "$label" "WP-CLI update failed; original wp-config.php restored"
  fi
done
