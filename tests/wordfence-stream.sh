#!/usr/bin/env bash
set -euo pipefail
ROOTDIR="$(cd "$(dirname "$0")/.." && pwd)"
TMP="${TMPDIR:-/tmp}/presswarden-wordfence-stream.$$"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP"
feed="$TMP/feed.json"
inv="$TMP/inventory.tsv"
empty="$TMP/empty.json"
printf '{}\n' > "$empty"

# Build a feed larger than the PHP memory limit used for validation. A whole-
# feed json_decode would exhaust memory; the streaming parser must succeed.
php -r '
  $f=fopen($argv[1],"wb");fwrite($f,"{");
  for($i=0;$i<420;$i++){
    if($i)fwrite($f,",");$id=sprintf("00000000-0000-0000-0000-%012d",$i);
    $slug=$i===419?"target-plugin":"plugin-".$i;
    $rec=["id"=>$id,"software"=>[["type"=>"plugin","slug"=>$slug,"affected_versions"=>[["from_version"=>"*","to_version"=>"9.9.9","from_inclusive"=>true,"to_inclusive"=>true]],"patched_versions"=>["10.0.0"]]],"references"=>["https://example.invalid/ref"],"padding"=>str_repeat("x",30000)];
    fwrite($f,json_encode($id).":".json_encode($rec));
  }
  fwrite($f,"}\n");fclose($f);
' "$feed"

size=$(stat -c %s "$feed")
[ "$size" -gt 12000000 ]
count=$(php -d memory_limit=12M "$ROOTDIR/lib/json-object-stream.php" validate-wordfence "$feed")
[ "$count" = 420 ]

printf 'example.com|plugin|target-plugin|1.2.3|active\n' > "$inv"
out=$(php -d memory_limit=12M "$ROOTDIR/lib/wordfence-match.php" "$feed" "$empty" "$inv" "$empty")
printf '%s\n' "$out" | grep -q 'target-plugin|1.2.3|active'
printf '%s\n' "$out" | grep -q '00000000-0000-0000-0000-000000000419'

# The large Wordfence files must never be decoded wholesale by the matcher or
# status/update helper.
if grep -nE 'json_decode\(\(string\)@?file_get_contents\(\$(scannerFile|productionFile)' "$ROOTDIR/lib/wordfence-match.php"; then
  printf 'whole Wordfence feed decode detected\n' >&2
  exit 1
fi

printf 'PressWarden Wordfence streaming test: PASS\n'
