#!/usr/bin/env bash
set -euo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin"
for name in example.com other.com; do
  p="$T/sites/$name/public_html"; mkdir -p "$p/wp-admin" "$p/wp-content" "$p/wp-includes"
  touch "$p/wp-load.php" "$p/wp-settings.php"; printf '<?php $wp_version="7.1";\n' > "$p/wp-includes/version.php"
  printf '<?php define("WP_AUTO_UPDATE_CORE", "minor");\n' > "$p/wp-config.php"
  printf 'minor\n' > "$p/.core"; printf '4\n' > "$p/.plugins-total"; printf '2\n' > "$p/.plugins-enabled"; printf '3\n' > "$p/.themes-total"; printf '0\n' > "$p/.themes-enabled"
done
touch "$T/sites/other.com/public_html/.DISALLOW_FILE_MODS"
cat > "$T/bin/wp" <<'WP'
#!/usr/bin/env bash
set -eu
p=''; args=(); for a in "$@"; do case "$a" in --path=*) p=${a#--path=} ;; --skip-*|--no-color) ;; *) args+=("$a") ;; esac; done
set -- "${args[@]}"; [ -n "$p" ] || exit 90
case "$1" in
 config)
   case "$2" in
    has) case "$3" in WP_AUTO_UPDATE_CORE) exit 0 ;; AUTOMATIC_UPDATER_DISABLED|DISALLOW_FILE_MODS) [ -f "$p/.${3}" ] ;; *) exit 1 ;; esac ;;
    get) case "$3" in WP_AUTO_UPDATE_CORE) case "$(cat "$p/.core")" in minor) echo '"minor"';; major) echo true;; disabled) echo false;; esac ;; *) exit 1;; esac ;;
    is-true) [ -f "$p/.${3}" ] ;;
    set) case "$3" in WP_AUTO_UPDATE_CORE) case "$4" in minor) echo minor > "$p/.core"; printf '<?php define("WP_AUTO_UPDATE_CORE", "minor");\n' > "$p/wp-config.php" ;; true) echo major > "$p/.core"; printf '<?php define("WP_AUTO_UPDATE_CORE", true);\n' > "$p/wp-config.php" ;; false) echo disabled > "$p/.core"; printf '<?php define("WP_AUTO_UPDATE_CORE", false);\n' > "$p/wp-config.php" ;; esac ;; esac ;;
   esac ;;
 option) case "$3" in auto_update_core_major) echo '"unset"';; auto_update_core_minor) echo '"enabled"';; *) exit 1;; esac ;;
 plugin|theme)
   type=$1; total=$(cat "$p/.${type}s-total"); enabled=$(cat "$p/.${type}s-enabled")
   [ "$2" = auto-updates ] || exit 91
   case "$3" in
    status)
      case " $* " in *' --field=name '*) i=1; while [ "$i" -le "$enabled" ]; do echo "$type$i"; i=$((i+1)); done ;; *' --enabled-only '*) echo "$enabled" ;; *) echo "$total" ;; esac ;;
    enable) if [ "${4:-}" = --all ]; then echo "$total" > "$p/.${type}s-enabled"; else cur=$(cat "$p/.${type}s-enabled"); [ "$cur" -lt "$total" ] && echo $((cur+1)) > "$p/.${type}s-enabled"; fi ;;
    disable) if [ "${4:-}" = --all ]; then echo 0 > "$p/.${type}s-enabled"; fi ;;
    *) exit 92 ;;
   esac ;;
 *) exit 93 ;;
esac
WP
chmod +x "$T/bin/wp"
export PATH="$T/bin:$PATH" PRESSWARDEN_SCAN_ROOT="$T/sites" PRESSWARDEN_CONFIG_FILE="$T/no-config" PRESSWARDEN_STATE_DIR="$T/state" PRESSWARDEN_CACHE_DIR="$T/cache" PRESSWARDEN_INTERACTIVE=0 PRESSWARDEN_NOCOLOR=1 PRESSWARDEN_PROGRESS=0
run(){ bash "$REPO/presswarden" "$@"; }
run auto-updates status example.com > "$T/status"
grep -q 'Core .*MINOR' "$T/status"; grep -q 'Plugins PARTIAL 2/4' "$T/status"; grep -q 'Themes DISABLED 0/3' "$T/status"
run auto-updates status other.com > "$T/blocked"
grep -q 'BLOCKED by DISALLOW_FILE_MODS' "$T/blocked"
run auto-updates core major example.com > "$T/out"; [ "$(cat "$T/sites/example.com/public_html/.core")" = major ]; [ "$(cat "$T/sites/other.com/public_html/.core")" = minor ]
run auto-updates plugins enable example.com > "$T/out"; [ "$(cat "$T/sites/example.com/public_html/.plugins-enabled")" = 4 ]; [ "$(cat "$T/sites/other.com/public_html/.plugins-enabled")" = 2 ]
run auto-updates themes enable all > "$T/out"; [ "$(cat "$T/sites/example.com/public_html/.themes-enabled")" = 3 ]; [ "$(cat "$T/sites/other.com/public_html/.themes-enabled")" = 3 ]
run auto-updates themes disable other.com > "$T/out"; [ "$(cat "$T/sites/other.com/public_html/.themes-enabled")" = 0 ]
run auto-updates core disabled other.com > "$T/out"; [ "$(cat "$T/sites/other.com/public_html/.core")" = disabled ]
run auto-updates status all > "$T/fleet"; grep -q 'Core .*MAJOR' "$T/fleet"; grep -q 'Core .*DISABLED' "$T/fleet"
# Standalone mutation/status commands remain; Fast/Full now use the unified policy dashboard.
grep -q 'wp-settings' "$REPO/suites/fast.sh"; grep -q 'wp-settings' "$REPO/suites/full.sh"
! grep -q 'wp-auto-updates' "$REPO/suites/fast.sh"; ! grep -q 'wp-auto-updates' "$REPO/suites/full.sh"
find "$T/state/quarantine" -type f | grep -q .
printf 'WordPress automatic-update policy: named/fleet status, core/plugin/theme changes and backups PASS\n'
