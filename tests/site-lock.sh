#!/usr/bin/env bash
set -euo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin"
for name in example.com other.com; do
  p="$T/sites/$name/public_html"; mkdir -p "$p/wp-admin" "$p/wp-content" "$p/wp-includes"
  touch "$p/wp-load.php" "$p/wp-settings.php"; printf '<?php $wp_version="7.1";\n' > "$p/wp-includes/version.php"
  printf '<?php define("DISALLOW_FILE_MODS",false);\n' > "$p/wp-config.php"
done
cat > "$T/bin/wp" <<'WP'
#!/usr/bin/env bash
set -eu
p=''; for a in "$@"; do case "$a" in --path=*) p=${a#--path=} ;; esac; done
[ "$1" = config ] && [ -f "$p/wp-config.php" ] || exit 95
case "$2" in
  get) if grep -q 'true' "$p/wp-config.php"; then echo true; else echo false; fi ;;
  set) printf '<?php define("DISALLOW_FILE_MODS",%s);\n' "$4" > "$p/wp-config.php" ;;
  *) exit 96 ;;
esac
WP
chmod +x "$T/bin/wp"
export PATH="$T/bin:$PATH" PRESSWARDEN_SCAN_ROOT="$T/sites" PRESSWARDEN_CONFIG_FILE="$T/no-config" PRESSWARDEN_STATE_DIR="$T/state" PRESSWARDEN_CACHE_DIR="$T/cache" PRESSWARDEN_INTERACTIVE=0 PRESSWARDEN_NOCOLOR=1
run(){ bash "$REPO/presswarden" "$@"; }
old=$(sha256sum "$T/sites/other.com/public_html/wp-config.php")
run lock example.com > "$T/out"; grep -q 'file changes locked' "$T/out"
grep -q true "$T/sites/example.com/public_html/wp-config.php"
[ "$(sha256sum "$T/sites/other.com/public_html/wp-config.php")" = "$old" ]
run lock-status example.com > "$T/status"; grep -q 'LOCKED.*example.com' "$T/status"; ! grep -q other.com "$T/status"
# Existing config backup path remains in use.
find "$T/state/quarantine" -name wp-config.php | grep -q .
run unlock example.com > "$T/out"; grep -q false "$T/sites/example.com/public_html/wp-config.php"
run lock-status example.com > "$T/status"; grep -q 'UNLOCKED.*example.com' "$T/status"
PRESSWARDEN_EXCLUDE=other.com run lock all > "$T/out"
[ "$(sha256sum "$T/sites/other.com/public_html/wp-config.php")" = "$old" ]
run lock all > "$T/out"; grep -q true "$T/sites/other.com/public_html/wp-config.php"
run unlock all > "$T/out"; grep -q false "$T/sites/other.com/public_html/wp-config.php"
printf 'Named/fleet lock actions: selected config, existing backups, exclusions and readable status PASS\n'
