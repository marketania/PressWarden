#!/usr/bin/env bash
set -euo pipefail
ROOTDIR="$(cd "$(dirname "$0")/.." && pwd)"
EXPECTED_VERSION=$(cat "$ROOTDIR/VERSION")
TMP="${TMPDIR:-/tmp}/presswarden-smoke.$$"; trap 'rm -rf "$TMP"' EXIT
stage() { printf 'SMOKE: %s\n' "$1"; }
mkdir -p "$TMP/sites/example.com/public_html/wp-admin" "$TMP/sites/example.com/public_html/wp-content/plugins/white-engine" "$TMP/sites/example.com/public_html/wp-content/plugins/normal-plugin" "$TMP/sites/example.com/public_html/wp-includes"
touch "$TMP/sites/example.com/public_html/wp-settings.php" "$TMP/sites/example.com/public_html/wp-load.php"
printf '<?php $wp_version = "7.1";\n' > "$TMP/sites/example.com/public_html/wp-includes/version.php"

cat > "$TMP/sites/example.com/public_html/wp-content/plugins/white-engine/white-engine.php" <<'PHP'
<?php
final class Test_Packed_Loader {
    private static function unpack_bytes($bytes, $key) {
        $out = '';
        $m = strlen($key);
        foreach ($bytes as $i => $value) {
            $out .= chr($value ^ ord($key[$i % $m]));
        }
        return $out;
    }
    private static function hidden_source() {
        $key = implode('', array_map('chr', [8,236,224,129,47,94,245,219,207,206]));
        $rows = [[96,152,148,241,92,100,218,244,161,161,122,137,132,232,78,51,219,184,160,163,39,162,133,246,112,14,135,180,163,167,126,195,129,241,70]];
        return self::unpack_bytes($rows[0], $key);
    }
    public static function boot() {
        $src = self::hidden_source();
        wp_enqueue_script('test-packed-loader', $src, [], '1.0.0', true);
    }
}
PHP

cat > "$TMP/sites/example.com/public_html/wp-content/plugins/normal-plugin/normal-plugin.php" <<'PHP'
<?php
function normal_plugin_assets() {
    wp_enqueue_script('normal-plugin', plugin_dir_url(__FILE__) . 'assets/app.js', [], '1.0.0', true);
}
PHP

stage 'syntax'
for f in "$ROOTDIR/presswarden" "$ROOTDIR/install.sh" "$ROOTDIR/uninstall.sh" "$ROOTDIR"/lib/*.sh "$ROOTDIR"/checks/*.sh "$ROOTDIR"/suites/*.sh; do bash -n "$f"; done

stage 'explicit discovery'
ROOT="$TMP/sites" \
PRESSWARDEN_CONFIG_FILE="$TMP/no-config" \
PRESSWARDEN_STATE_DIR="$TMP/state" \
PRESSWARDEN_CACHE_DIR="$TMP/cache" \
PRESSWARDEN_NOCOLOR=1 \
bash -c '
  set -euo pipefail
  . "$1/lib/_lib.sh"
  [ "${#SCAN_ROOTS[@]}" -eq 1 ]
  [ "$(site_label_from_root "${SCAN_ROOTS[0]}")" = "example.com" ]
  [ "$PRESSWARDEN_VERSION" = "$2" ]
' _ "$ROOTDIR" "$EXPECTED_VERSION"

stage 'obfuscated loader regression'
loader_out=$(ROOT="$TMP/sites" PRESSWARDEN_CONFIG_FILE="$TMP/no-config" PRESSWARDEN_STATE_DIR="$TMP/state-loader" PRESSWARDEN_CACHE_DIR="$TMP/cache-loader" PRESSWARDEN_NOCOLOR=1 bash "$ROOTDIR/checks/php-obfuscated-loader.sh" 2>&1 || true)
printf '%s\n' "$loader_out" | grep -q 'white-engine.php' || { printf '%s\n' "$loader_out" >&2; printf 'White-Engine-style fixture was not detected\n' >&2; exit 1; }
if printf '%s\n' "$loader_out" | grep -q 'normal-plugin.php'; then
  printf '%s\n' "$loader_out" >&2
  printf 'normal wp_enqueue_script fixture was falsely flagged\n' >&2
  exit 1
fi

stage 'DB unsupported CHECK regression'
# The exact Granada/Wordfence-style response must remain an informational SKIP path,
# never a BAD/unresolved table path.
grep -q "doesn't support check" "$ROOTDIR/checks/wp-db-maintenance.sh"
grep -q 'return \[.unsupported.' "$ROOTDIR/checks/wp-db-maintenance.sh"
grep -q 'echo "SKIP\\t"' "$ROOTDIR/checks/wp-db-maintenance.sh"
grep -q 'Unsupported CHECK TABLE operations are informational' "$ROOTDIR/checks/wp-db-maintenance.sh"

stage 'output wording regression'
if grep -R -nE 'runall-(fast|full)\.sh' "$ROOTDIR/checks" "$ROOTDIR/lib" "$ROOTDIR/suites" "$ROOTDIR/README.md" >/dev/null 2>&1; then
  printf 'stale pre-PressWarden command wording found\n' >&2
  exit 1
fi
grep -q 'local activation is shown separately' "$ROOTDIR/checks/wp-plugins.sh"
grep -q 'recognized provider/service MU summarized' "$ROOTDIR/checks/wp-plugins.sh"

stage 'environment precedence'
cat > "$TMP/config" <<'EOF'
PRESSWARDEN_UPLOADS_DEEP=0
EOF
cfg=$(PRESSWARDEN_CONFIG_FILE="$TMP/config" PRESSWARDEN_UPLOADS_DEEP=1 "$ROOTDIR/presswarden" config)
printf '%s\n' "$cfg" | grep -qE 'Deep upload scan:[[:space:]]+1$'

stage 'CLI aliases/version'
[ "$($ROOTDIR/presswarden --version)" = "PressWarden $EXPECTED_VERSION" ]
help=$($ROOTDIR/presswarden help)
printf '%s\n' "$help" | grep -q '\./presswarden lock \[path\]'
printf '%s\n' "$help" | grep -q '\./presswarden unlock \[path\]'
printf '%s\n' "$help" | grep -q '\./presswarden lock-status \[path\]'

stage 'portable shared-host mode'
HOST="$TMP/hosting-home"
PORTABLE="$HOST/PressWarden"
mkdir -p "$HOST/domains/example.com/public_html/wp-admin" "$HOST/domains/example.com/public_html/wp-content" "$HOST/domains/example.com/public_html/wp-includes" "$PORTABLE/config"
touch "$HOST/domains/example.com/public_html/wp-settings.php" "$HOST/domains/example.com/public_html/wp-load.php"
printf '<?php $wp_version = "7.1";\n' > "$HOST/domains/example.com/public_html/wp-includes/version.php"
cp "$ROOTDIR/presswarden" "$ROOTDIR/VERSION" "$PORTABLE/"
cp -a "$ROOTDIR/lib" "$ROOTDIR/checks" "$ROOTDIR/suites" "$PORTABLE/"
cp "$ROOTDIR/config/config.example" "$PORTABLE/config/config"
touch "$PORTABLE/.presswarden-portable"
chmod +x "$PORTABLE/presswarden" "$PORTABLE"/checks/*.sh "$PORTABLE"/suites/*.sh

portable_cfg=$(cd "$PORTABLE" && ./presswarden config)
printf '%s\n' "$portable_cfg" | grep -qE 'Install mode:[[:space:]]+portable/local$'
printf '%s\n' "$portable_cfg" | grep -Fq "Config:             $PORTABLE/config/config"
printf '%s\n' "$portable_cfg" | grep -Fq "Scan root:          $HOST/domains"
printf '%s\n' "$portable_cfg" | grep -Fq "State directory:    $PORTABLE/var"
printf '%s\n' "$portable_cfg" | grep -Fq "Cache directory:    $PORTABLE/var/cache"

(
  cd "$PORTABLE"
  PRESSWARDEN_NOCOLOR=1 bash -c '
    set -euo pipefail
    . ./lib/_lib.sh
    [ "$ROOT" = "$1/domains" ]
    [ "${#SCAN_ROOTS[@]}" -eq 1 ]
    [ "$(site_label_from_root "${SCAN_ROOTS[0]}")" = "example.com" ]
    [ "$REPORTS" = "$2/var/reports" ]
    [ "$PRESSWARDEN_CACHE_DIR" = "$2/var/cache" ]
    [ "$QUARANTINE" = "$2/var/quarantine" ]
    [ "$PRESSWARDEN_VERSION" = "$3" ]
  ' _ "$HOST" "$PORTABLE" "$EXPECTED_VERSION"
)

stage 'runtime portability'
if grep -R -nE '<[[:space:]]*<\(|>[[:space:]]*>\(' "$ROOTDIR/checks" "$ROOTDIR/lib" "$ROOTDIR/suites" >/dev/null 2>&1; then
  printf 'runtime process substitution found\n' >&2; exit 1
fi
printf 'PressWarden smoke test: PASS\n'
