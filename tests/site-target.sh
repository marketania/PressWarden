#!/usr/bin/env bash
set -euo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
cp -a "$REPO" "$T/repo"; rm -rf "$T/repo/.git"
S="$T/sites"; mkdir -p "$T/bin" "$T/state" "$T/cache"
site(){ mkdir -p "$1/wp-admin" "$1/wp-content" "$1/wp-includes"; touch "$1/wp-settings.php" "$1/wp-load.php"; printf '<?php $wp_version="7.1";\n' > "$1/wp-includes/version.php"; }
site "$S/example.com/public_html"; site "$S/example.com/public_html/shop"; site "$S/other.com/httpdocs"; site "$S/opaque"
cat > "$S/opaque/wp-config.php" <<'PHP'
<?php
define('WP_HOME','https://opaque.example/');
file_put_contents(getenv('SHOULD_NOT_EXECUTE'), 'executed');
PHP
export SHOULD_NOT_EXECUTE="$T/unsafe" PRESSWARDEN_SCAN_ROOT="$S" PRESSWARDEN_STATE_DIR="$T/state" PRESSWARDEN_CACHE_DIR="$T/cache" PRESSWARDEN_CONFIG_FILE="$T/config" PRESSWARDEN_INTERACTIVE=0 PRESSWARDEN_NOCOLOR=1
printf 'PRESSWARDEN_SCAN_ROOT="%s"\n' "$S" > "$T/config"; chmod 600 "$T/config"
printf '#!/usr/bin/env bash\nexit 97\n' > "$T/bin/wp"; chmod +x "$T/bin/wp"; export PATH="$T/bin:$PATH"
run(){ bash "$T/repo/presswarden" "$@"; }
run sites > "$T/list"; grep -q 'example.com ' "$T/list"; grep -q 'example.com/shop' "$T/list"; grep -q 'other.com ' "$T/list"; grep -q 'opaque.example' "$T/list"; [ ! -e "$T/unsafe" ]
# Stubs preserve genuine shared discovery, recording scope but never scanning clients.
cat > "$T/stub" <<'STUB'
#!/usr/bin/env bash
. "$PRESSWARDEN_DIR/lib/_lib.sh"
printf 'ROOT=%s\n' "$ROOT"
for p in "${SCAN_ROOTS[@]}"; do printf 'SITE=%s\n' "$p"; done
STUB
for c in fast full incident db inspect intel; do cp "$T/stub" "$T/repo/suites/$c.sh"; chmod +x "$T/repo/suites/$c.sh"; done
for c in file-mods sensitive-files doctor fleet-correlate; do cp "$T/stub" "$T/repo/checks/$c.sh"; chmod +x "$T/repo/checks/$c.sh"; done
cat > "$T/repo/lib/baseline.sh" <<'STUB'
pw_baseline_create(){ bash "$PRESSWARDEN_DIR/suites/fast.sh"; }
pw_baseline_status(){ pw_baseline_create; }
pw_baseline_diff(){ pw_baseline_create; }
STUB
for cmd in scan fast full incident db doctor cleanup lock unlock lock-status changes correlate; do
  run "$cmd" example.com > "$T/out" 2>&1
  grep -Fxq "ROOT=$S/example.com/public_html" "$T/out"
  grep -Fxq "SITE=$S/example.com/public_html/shop" "$T/out"
  ! grep -q "SITE=$S/other.com" "$T/out"
done
for kind in php js db runtime; do run inspect "$kind" other.com > "$T/out" 2>&1; grep -Fxq "ROOT=$S/other.com/httpdocs" "$T/out"; done
for action in create status diff; do run baseline "$action" example.com/shop > "$T/out" 2>&1; grep -Fxq "ROOT=$S/example.com/public_html/shop" "$T/out"; done
for action in on off status; do run file-mods "$action" other.com > "$T/out" 2>&1; grep -Fxq "ROOT=$S/other.com/httpdocs" "$T/out"; done
run intel scan opaque.example > "$T/out" 2>&1; grep -Fxq "ROOT=$S/opaque" "$T/out"; [ ! -e "$T/unsafe" ]
run scan 'https://EXAMPLE.com/shop/' > "$T/out" 2>&1; grep -Fxq "ROOT=$S/example.com/public_html/shop" "$T/out"
run scan all > "$T/out"; [ "$(grep -c '^SITE=' "$T/out")" -eq 4 ]
run scan > "$T/out"; grep -Fxq "ROOT=$S" "$T/out"
run scan "$S/other.com/httpdocs" > "$T/out"; grep -Fxq "ROOT=$S/other.com/httpdocs" "$T/out"
# Never fall back to all sites for an unknown/unsafe/excluded name.
for name in missing.com 'example.com/../other.com' 'https://user@example.com' 'example.com;id'; do
  set +e; run lock "$name" > "$T/out" 2>&1; rc=$?; set -e
  [ "$rc" -eq 2 ]; ! grep -q '^ROOT=' "$T/out"
done
set +e; PRESSWARDEN_EXCLUDE=example.com run unlock example.com > "$T/out" 2>&1; rc=$?; set -e
[ "$rc" -eq 2 ]; ! grep -q '^ROOT=' "$T/out"
# A nested exclusion expressed relative to the fleet survives narrowed ROOT.
PRESSWARDEN_EXCLUDE=example.com/shop run scan example.com > "$T/out" 2>&1
! grep -q "SITE=$S/example.com/public_html/shop" "$T/out"
grep -q '^SITE=' "$T/out"
# Duplicated local names are errors, not first-match wins.
site "$S/a/duplicate.com/public_html"; site "$S/b/duplicate.com/httpdocs"
set +e; run lock duplicate.com > "$T/out" 2>&1; rc=$?; set -e
[ "$rc" -eq 2 ]; grep -q ambiguous "$T/out"; ! grep -q '^ROOT=' "$T/out"
# Optional alias resolves only discovered, non-excluded roots; no shell evaluation.
printf 'custom.example=%s\n' "$S/other.com/httpdocs" > "$T/aliases"
PRESSWARDEN_SITE_ALIASES_FILE="$T/aliases" run scan custom.example > "$T/out" 2>&1; grep -Fxq "ROOT=$S/other.com/httpdocs" "$T/out"
printf 'external.example=%s\n' "$T/outside" >> "$T/aliases"
set +e; PRESSWARDEN_SITE_ALIASES_FILE="$T/aliases" run lock external.example > "$T/out" 2>&1; rc=$?; set -e
[ "$rc" -eq 2 ]; ! grep -q '^ROOT=' "$T/out"
set +e; PRESSWARDEN_SITE_ALIASES_FILE="$T/aliases" PRESSWARDEN_EXCLUDE=other.com run lock custom.example > "$T/out" 2>&1; rc=$?; set -e
[ "$rc" -eq 2 ]
# Even a local relative folder named missing.com is not guessed as the target.
mkdir "$T/missing.com"
set +e; (cd "$T" && run lock missing.com) > "$T/out" 2>&1; rc=$?; set -e
[ "$rc" -eq 2 ]
# Broken discovery refuses names before any operation.
printf '#!/usr/bin/env bash\nexit 2\n' > "$T/bin/find"; chmod +x "$T/bin/find"
set +e; run lock example.com > "$T/out" 2>&1; rc=$?; set -e
[ "$rc" -eq 2 ]; ! grep -q '^ROOT=' "$T/out"; rm "$T/bin/find"
# Details flag only applies to runtime, invalid argument counts remain errors.
run inspect runtime example.com --details > "$T/out" 2>&1; grep -Fxq "ROOT=$S/example.com/public_html" "$T/out"
for args in 'scan example.com extra' 'inspect js example.com --details' 'lock example.com other.com'; do
  set +e; run $args > "$T/out" 2>&1; rc=$?; set -e
  [ "$rc" -eq 2 ]; ! grep -q '^ROOT=' "$T/out"
done
[ ! -e "$T/unsafe" ]
printf 'Website targeting: command routing, layouts, nested scope, exclusions, ambiguity, no bootstrap and failures PASS\n'
