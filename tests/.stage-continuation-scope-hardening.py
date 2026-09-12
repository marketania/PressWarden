#!/usr/bin/env python3
from pathlib import Path
root=Path(__file__).resolve().parents[1]

def rep(path, old, new):
    p=root/path; s=p.read_text()
    if old not in s: raise SystemExit(f'anchor missing: {path}: {old[:100]!r}')
    p.write_text(s.replace(old,new,1))

rep('lib/run-continuation.sh',
'''  local out="$1" p depth="${PRESSWARDEN_DISCOVERY_DEPTH:-8}"
  : > "$out" || return 2
''',
'''  local out="$1" p depth="${PRESSWARDEN_DISCOVERY_DEPTH:-8}"
  case "$depth" in ''|*[!0-9]*) depth=8 ;; esac
  [ "$depth" -ge 1 ] 2>/dev/null || depth=8
  : > "$out" || return 2
''')
rep('lib/run-continuation.php',
"""        elseif($k==='DEPTH'){if($depth!==''||!preg_match('/^[0-9]{1,3}$/D',$v))pwc_fail('invalid scope depth');$depth=$v;}
""",
"""        elseif($k==='DEPTH'){if($depth!==''||!preg_match('/^[0-9]{1,10}$/D',$v)||(int)$v<1||(int)$v>2147483647)pwc_fail('invalid scope depth');$depth=$v;}
""")
rep('lib/run-continuation.php',
"""function pwc_scope_read($runDir){$path=$runDir.'/scope.json';if(!file_exists($path)&&!is_link($path))pwc_fail('run predates safe continuation scope metadata; rerun the suite before using continue');$j=pwc_read_json($path);if(($j['format']??null)!==1||($j['tool']??null)!=='PressWarden'||!isset($j['fingerprint'],$j['scan_roots'],$j['root'],$j['discovery_depth'],$j['target_exclusions']))pwc_fail('run predates safe continuation scope metadata; rerun the suite before using continue');return $j;}
""",
"""function pwc_scope_read($runDir){
    $path=$runDir.'/scope.json';
    if(!file_exists($path)&&!is_link($path))pwc_fail('run predates safe continuation scope metadata; rerun the suite before using continue');
    $j=pwc_read_json($path);
    if(($j['format']??null)!==1||($j['tool']??null)!=='PressWarden'||!isset($j['fingerprint'],$j['scan_roots'],$j['root'],$j['discovery_depth'],$j['target_exclusions']))pwc_fail('run predates safe continuation scope metadata; rerun the suite before using continue');
    $root=pwc_text($j['root'],false,8192); $depth=$j['discovery_depth'];
    if(!is_int($depth)||$depth<1||$depth>2147483647||!is_array($j['scan_roots'])||!is_array($j['target_exclusions']))pwc_fail('invalid stored continuation scope');
    if(count($j['scan_roots'])<1||count($j['scan_roots'])>PWC_MAX_SITES||count($j['target_exclusions'])>PWC_MAX_SITES)pwc_fail('invalid stored continuation scope');
    $sites=[]; foreach($j['scan_roots'] as $v)$sites[]=pwc_text($v,false,8192);
    $ex=[]; foreach($j['target_exclusions'] as $v)$ex[]=pwc_text($v,false,8192);
    $sites=array_values(array_unique($sites)); $ex=array_values(array_unique($ex)); sort($sites,SORT_STRING); sort($ex,SORT_STRING);
    if(count($sites)!==count($j['scan_roots'])||count($ex)!==count($j['target_exclusions']))pwc_fail('duplicate stored continuation scope');
    $base=['root'=>$root,'discovery_depth'=>$depth,'scan_roots'=>$sites,'target_exclusions'=>$ex];
    $canon=json_encode($base,JSON_UNESCAPED_SLASHES); if($canon===false)pwc_fail('scope encoding failed');
    $fingerprint=pwc_text($j['fingerprint'],false,64); if(!preg_match('/^[a-f0-9]{64}$/D',$fingerprint)||!hash_equals(hash('sha256',$canon),$fingerprint))pwc_fail('continuation scope fingerprint mismatch');
    $base['fingerprint']=$fingerprint; return $base;
}
""")
# Add stored-scope corruption and discovery-depth normalization regressions before mismatch tests.
rep('tests/run-continuation.sh',
'''grep -q $'^one\\t2\\tfindings\\t4$' "$CARRY"

# Scope/version/check-plan changes must refuse continuation rather than mixing audits.
''',
'''grep -q $'^one\\t2\\tfindings\\t4$' "$CARRY"

# Stored scope is internally authenticated against its own canonical fields so
# accidental corruption cannot silently redirect a continuation.
cp "$RUNS/$ID/scope.json" "$TMP/scope-good.json"
php -r '$p=$argv[1]; $j=json_decode(file_get_contents($p),true); $j["root"].="/corrupt"; file_put_contents($p,json_encode($j,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES)."\\n");' "$RUNS/$ID/scope.json"
set +e; php "$CONT" plan "$RUNS" "$ID" 1.1.17 > "$TMP/corrupt.out" 2>&1; rc=$?; set -e
[ "$rc" -eq 2 ]; grep -q 'scope fingerprint mismatch' "$TMP/corrupt.out"
cp "$TMP/scope-good.json" "$RUNS/$ID/scope.json"; chmod 600 "$RUNS/$ID/scope.json"

# Scope recording follows the same invalid/zero discovery-depth fallback used by discovery.
DEPTH_OUT="$TMP/depth.tsv"
PW_DEPTH_REPO="$REPO" PW_DEPTH_ROOT="$TMP/root" PW_DEPTH_OUT="$DEPTH_OUT" bash -c 'ROOT="$PW_DEPTH_ROOT"; PRESSWARDEN_DISCOVERY_DEPTH=bogus; SCAN_ROOTS=("$ROOT/site-a"); _PW_TARGET_EXCLUSIONS=""; . "$PW_DEPTH_REPO/lib/run-continuation.sh"; _pw_continue_scope_file "$PW_DEPTH_OUT"'
grep -q $'^DEPTH\\t8$' "$DEPTH_OUT"
PW_DEPTH_REPO="$REPO" PW_DEPTH_ROOT="$TMP/root" PW_DEPTH_OUT="$DEPTH_OUT" bash -c 'ROOT="$PW_DEPTH_ROOT"; PRESSWARDEN_DISCOVERY_DEPTH=0; SCAN_ROOTS=("$ROOT/site-a"); _PW_TARGET_EXCLUSIONS=""; . "$PW_DEPTH_REPO/lib/run-continuation.sh"; _pw_continue_scope_file "$PW_DEPTH_OUT"'
grep -q $'^DEPTH\\t8$' "$DEPTH_OUT"

# Scope/version/check-plan changes must refuse continuation rather than mixing audits.
''')
