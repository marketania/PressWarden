#!/usr/bin/env python3
from pathlib import Path
p=Path(__file__).resolve().parents[1]/'lib/run-continuation.php'
s=p.read_text()
old="function pwc_scope_read($runDir){$j=pwc_read_json($runDir.'/scope.json');if(($j['format']??null)!==1||($j['tool']??null)!=='PressWarden'||!isset($j['fingerprint'],$j['scan_roots'],$j['root'],$j['discovery_depth'],$j['target_exclusions']))pwc_fail('run predates safe continuation scope metadata; rerun the suite before using continue');return $j;}"
new="function pwc_scope_read($runDir){$path=$runDir.'/scope.json';if(!file_exists($path)&&!is_link($path))pwc_fail('run predates safe continuation scope metadata; rerun the suite before using continue');$j=pwc_read_json($path);if(($j['format']??null)!==1||($j['tool']??null)!=='PressWarden'||!isset($j['fingerprint'],$j['scan_roots'],$j['root'],$j['discovery_depth'],$j['target_exclusions']))pwc_fail('run predates safe continuation scope metadata; rerun the suite before using continue');return $j;}"
if old not in s: raise SystemExit('scope-read anchor missing')
p.write_text(s.replace(old,new,1))
