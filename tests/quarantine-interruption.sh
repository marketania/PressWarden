#!/usr/bin/env bash
set -euo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d "${TMPDIR:-/tmp}/presswarden-quarantine-signal.XXXXXX")
pid=''
cleanup(){ [ -z "$pid" ] || { kill -TERM "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; }; rm -rf "$TMP"; }
trap cleanup EXIT
cat > "$TMP/worker.php" <<'PHP'
<?php
require $argv[1].'/lib/quarantine.php';
class PausingQuarantine extends PressWardenQuarantine {
    protected function copyObject($s,$d,$e) {
        parent::copyObject($s,$d,$e);
        if (getenv('PW_TEST_PAUSE') === 'copy') { touch(getenv('PW_TEST_READY')); sleep(30); }
    }
    protected function removeEntry($p,$dir) {
        $ok = parent::removeEntry($p,$dir);
        if (getenv('PW_TEST_PAUSE') === 'remove') { touch(getenv('PW_TEST_READY')); sleep(30); }
        return $ok;
    }
}
$root=$argv[2]; $site="$root/site";
mkdir("$site/wp-admin",0700,true);mkdir("$site/wp-includes",0700,true);mkdir("$site/wp-content",0700,true);
foreach(['wp-load.php','wp-settings.php','wp-includes/version.php'] as $p)file_put_contents("$site/$p",'<?php // inert');
file_put_contents("$site/a.php",'a');file_put_contents("$site/b.php",'b');
$q=new PausingQuarantine();$policy=['root'=>$root,'quarantine'=>"$root/evidence",'sites'=>[$site],'blocked'=>[],'mode'=>'generic'];
$q->apply($q->plan($policy,["$site/a.php","$site/b.php"]));
PHP
for phase in copy remove; do
  root="$TMP/$phase"; mkdir "$root"
  PW_TEST_PAUSE="$phase" PW_TEST_READY="$root/ready" php "$TMP/worker.php" "$REPO" "$root" > "$root/out" 2>&1 & pid=$!
  ready=0
  for i in $(seq 1 250); do
    if [ -e "$root/ready" ]; then ready=1; break; fi
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.02
  done
  [ "$ready" -eq 1 ] || { cat "$root/out" >&2; exit 1; }
  kill -TERM "$pid"
  set +e; wait "$pid"; rc=$?; set -e; pid=''
  [ "$rc" -ne 0 ]; [ -f "$root/site/b.php" ]
  casepath=$(find "$root/evidence" -mindepth 1 -maxdepth 1 -type d -name 'case-*'); [ -n "$casepath" ]
  [ -f "$casepath/manifest.json" ]; [ ! -e "$casepath/complete.json" ]
  if [ "$phase" = copy ]; then
    [ -f "$root/site/a.php" ]; [ ! -e "$casepath/verified.json" ]
    set +e; php "$REPO/lib/quarantine-cli.php" verify "$root/evidence" "${casepath##*/}" > "$root/verify" 2>&1; rc=$?; set -e
    [ "$rc" -eq 2 ]
  else
    [ ! -e "$root/site/a.php" ]; [ -f "$casepath/verified.json" ]
    php "$REPO/lib/quarantine-cli.php" verify "$root/evidence" "${casepath##*/}" > "$root/verify"
    grep -q 'incomplete or unconfirmed' "$root/verify"
    [ "$(cat "$casepath/objects/00001.bin")" = a ]; [ "$(cat "$casepath/objects/00002.bin")" = b ]
  fi
done
printf 'Quarantine interruption before/after removal retains evidence: PASS\n'
