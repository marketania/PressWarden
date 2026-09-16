#!/usr/bin/env bash
set -euo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin"

make_site() {
  local name="$1" p
  p="$T/sites/$name/public_html"
  mkdir -p "$p/wp-admin" "$p/wp-content" "$p/wp-includes"
  touch "$p/wp-load.php" "$p/wp-settings.php"
  printf '<?php $wp_version="7.1";\n' > "$p/wp-includes/version.php"
  printf '<?php\n' > "$p/wp-config.php"
}
make_site example.com
make_site other.com
make_site broken.com

touch "$T/sites/example.com/public_html/.litespeed-installed"
touch "$T/sites/example.com/public_html/.litespeed-active"
touch "$T/sites/broken.com/public_html/.bootstrap-fail"

cat > "$T/bin/wp" <<'WP'
#!/usr/bin/env bash
set -eu
orig=("$@")
p=''; args=()
for a in "$@"; do
  case "$a" in
    --path=*) p=${a#--path=} ;;
    --skip-plugins|--skip-themes|--skip-packages|--no-color) ;;
    *) args+=("$a") ;;
  esac
done
set -- "${args[@]}"
[ -n "$p" ] || p="$PWD"

# LiteSpeed explicitly rejects ordinary WP-CLI global parameters. Fail the test
# if PressWarden ever starts appending one to the actual plugin command.
if [ "${1:-}" = litespeed-database ]; then
  for a in "${orig[@]}"; do
    case "$a" in --*) echo 'unexpected WP-CLI global parameter' >&2; exit 96 ;; esac
  done
fi

case "${1:-}" in
  core)
    [ "${2:-}" = is-installed ] || exit 90
    [ ! -f "$p/.bootstrap-fail" ] || exit 91
    if [ "${3:-}" = --network ]; then [ -f "$p/.multisite" ]; else exit 0; fi
    ;;
  plugin)
    [ ! -f "$p/.bootstrap-fail" ] || exit 91
    case "${2:-}" in
      is-installed) [ "${3:-}" = litespeed-cache ] && [ -f "$p/.litespeed-installed" ] ;;
      is-active) [ "${3:-}" = litespeed-cache ] && [ -f "$p/.litespeed-active" ] ;;
      *) exit 92 ;;
    esac
    ;;
  help)
    [ "${2:-}" = litespeed-database ] && [ "${3:-}" = optimize_all ] || exit 93
    [ -f "$p/.litespeed-active" ] || exit 94
    [ ! -f "$p/.no-litespeed-command" ] || exit 95
    ;;
  db)
    [ "${2:-}" = size ] || exit 89
    # Simulate measurable allocation reduction after LiteSpeed optimization.
    if [ -f "$p/.optimized" ]; then echo 900000; else echo 1000000; fi
    ;;
  litespeed-database)
    [ "${2:-}" = optimize_all ] || exit 97
    [ -f "$p/.litespeed-active" ] || exit 98
    [ ! -f "$p/.optimize-fail" ] || { echo 'simulated LiteSpeed optimization failure' >&2; exit 41; }
    touch "$p/.optimized"
    echo 'Success: LiteSpeed database optimized.'
    ;;
  *) exit 99 ;;
esac
WP
chmod +x "$T/bin/wp"

export PATH="$T/bin:$PATH"
export PRESSWARDEN_SCAN_ROOT="$T/sites"
export PRESSWARDEN_CONFIG_FILE="$T/no-config"
export PRESSWARDEN_STATE_DIR="$T/state"
export PRESSWARDEN_CACHE_DIR="$T/cache"
export PRESSWARDEN_INTERACTIVE=0
export PRESSWARDEN_NOCOLOR=1
export PRESSWARDEN_PROGRESS=0
run(){ bash "$REPO/presswarden" "$@"; }

# Status must distinguish eligible, non-LiteSpeed, and actual WP-CLI/bootstrap
# errors rather than falsely classifying everything nonzero as "inactive".
if run litespeed-db status all > "$T/status" 2>&1; then
  echo 'status unexpectedly succeeded despite a bootstrap-broken site' >&2; exit 1
fi
grep -q 'example.com.*READY' "$T/status"
grep -q 'other.com.*SKIP.*not installed' "$T/status"
grep -q 'broken.com.*ERROR.*bootstrap failed' "$T/status"

# Narrowing to one site must run the exact LiteSpeed command from that site's
# working directory and must never append --path/--skip-* global parameters.
# It should also report clear progress and before/after database size when the
# built-in WP-CLI db size command is available.
run litespeed-db optimize example.com > "$T/optimized" 2>&1
[ -f "$T/sites/example.com/public_html/.optimized" ]
[ ! -f "$T/sites/other.com/public_html/.optimized" ]
grep -q 'example.com.*OPTIMIZED' "$T/optimized"
grep -q 'Preflight complete: ready 1' "$T/optimized"
grep -q 'reported reduction' "$T/optimized"
grep -q 'Measured database size (1 site(s))' "$T/optimized"
grep -q 'Success: LiteSpeed database optimized' "$T/optimized"

# An active plugin with a missing LiteSpeed CLI command is a preflight error and
# must not be reported as a successful skip.
touch "$T/sites/other.com/public_html/.litespeed-installed" "$T/sites/other.com/public_html/.litespeed-active" "$T/sites/other.com/public_html/.no-litespeed-command"
if run litespeed-db status other.com > "$T/unavailable" 2>&1; then
  echo 'missing LiteSpeed CLI command unexpectedly returned success' >&2; exit 1
fi
grep -q 'ERROR.*litespeed-database optimize_all is unavailable' "$T/unavailable"

# Runtime failure from optimize_all must propagate as exit 2 and leave a clear
# per-site FAILED result.
rm -f "$T/sites/example.com/public_html/.optimized"
touch "$T/sites/example.com/public_html/.optimize-fail"
set +e
run litespeed-db optimize example.com > "$T/failure" 2>&1
rc=$?
set -e
[ "$rc" -eq 2 ] || { echo "expected exit 2 for LiteSpeed execution failure, got $rc" >&2; exit 1; }
grep -q 'example.com.*FAILED.*exit 41' "$T/failure"
[ ! -f "$T/sites/example.com/public_html/.optimized" ]

# Multisite is permitted but explicitly warned because optimize_all without
# `blog <id>` does not establish network-wide cleanup coverage. Size savings are
# also deliberately not claimed for the whole shared multisite database.
rm -f "$T/sites/example.com/public_html/.optimize-fail"
touch "$T/sites/example.com/public_html/.multisite"
run litespeed-db status example.com > "$T/multisite" 2>&1
grep -q 'multisite detected' "$T/multisite"
grep -q 'does not claim full multisite-network cleanup' "$T/multisite"
run litespeed-db optimize example.com > "$T/multisite-optimize" 2>&1
grep -q 'size statistics skipped for multisite' "$T/multisite-optimize"

printf 'LiteSpeed database maintenance: targeting, exact CLI invocation, progress, size statistics, failures and multisite warning PASS\n'
