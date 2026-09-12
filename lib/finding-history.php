<?php
// PressWarden structured finding history. PHP 7.4 compatible; never bootstraps WordPress.
const PWFH_FORMAT = 1;
const PWFH_MAX_JSON = 8388608;
const PWFH_MAX_INPUT = 8388608;
const PWFH_MAX_FINDINGS = 10000;
const PWFH_MAX_OBS_FILES = 2048;
const PWFH_MAX_SITES = 4096;
const PWFH_HASH_FILE_MAX = 33554432;

final class PressWardenFindingHistoryError extends RuntimeException {}
function pwfh_fail($m) { throw new PressWardenFindingHistoryError($m); }
function pwfh_now() { return gmdate('c'); }
function pwfh_text($v, $allowEmpty=false, $max=8192) {
    $v=(string)$v;
    if ((!$allowEmpty && $v==='') || strlen($v)>$max || preg_match('/[\x00-\x1F\x7F]/', $v)) pwfh_fail('invalid history metadata');
    return $v;
}
function pwfh_id($v) { $v=(string)$v; if(!preg_match('/^[A-Za-z0-9][A-Za-z0-9._-]{0,159}$/D',$v))pwfh_fail('invalid run id'); return $v; }
function pwfh_check($v) { $v=pwfh_text($v,false,96); if(!preg_match('/^[A-Za-z0-9_-]+$/D',$v))pwfh_fail('invalid check name'); return $v; }
function pwfh_plain_dir($p,$create=false) {
    $p=rtrim(pwfh_text($p,false,8192),'/'); if($p==='')$p='/';
    if(is_link($p))pwfh_fail('unsafe history directory');
    if(!file_exists($p)){
        if(!$create)pwfh_fail('history directory missing');
        $old=umask(0077); try{$ok=@mkdir($p,0700,true);}finally{umask($old);} if(!$ok&&!is_dir($p))pwfh_fail('cannot create history directory');
    }
    $s=@lstat($p); if(!$s||(($s['mode']&0170000)!==0040000)||is_link($p))pwfh_fail('unsafe history directory'); return $p;
}
function pwfh_regular($p,$max=PWFH_MAX_JSON) {
    if(is_link($p))pwfh_fail('unsafe history file'); $s=@lstat($p);
    if(!$s||(($s['mode']&0170000)!==0100000)||$s['nlink']!==1||$s['size']<0||$s['size']>$max)pwfh_fail('unsafe history file'); return $s;
}
function pwfh_read_file($p,$max=PWFH_MAX_JSON){pwfh_regular($p,$max);$r=@file_get_contents($p,false,null,0,$max+1);if($r===false||strlen($r)>$max)pwfh_fail('cannot read history file');return $r;}
function pwfh_read_json($p,$max=PWFH_MAX_JSON){$j=json_decode(pwfh_read_file($p,$max),true,96);if(!is_array($j))pwfh_fail('invalid history json');return $j;}
function pwfh_write_all($h,$d){$o=0;$l=strlen($d);while($o<$l){$n=@fwrite($h,substr($d,$o));if($n===false||$n===0)pwfh_fail('history write failed');$o+=$n;}if(!@fflush($h))pwfh_fail('history flush failed');}
function pwfh_encode($j){$d=json_encode($j,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES|JSON_INVALID_UTF8_SUBSTITUTE);if($d===false)pwfh_fail('history encoding failed');$d.="\n";if(strlen($d)>PWFH_MAX_JSON)pwfh_fail('history size limit');return $d;}
function pwfh_atomic_write($path,$data,$createOnly=false){
    $dir=pwfh_plain_dir(dirname($path),false);
    if(file_exists($path)||is_link($path)){if($createOnly)pwfh_fail('history destination exists');pwfh_regular($path);}
    $tmp=$dir.'/.history.'.bin2hex(random_bytes(8)).'.tmp';$old=umask(0077);try{$h=@fopen($tmp,'xb');}finally{umask($old);}if($h===false)pwfh_fail('cannot stage history');
    try{pwfh_write_all($h,$data);}finally{if(!@fclose($h)){@unlink($tmp);pwfh_fail('history close failed');}}
    if($createOnly){if(!@link($tmp,$path)){@unlink($tmp);pwfh_fail('cannot publish history');}@unlink($tmp);return;}
    if(is_link($path)){@unlink($tmp);pwfh_fail('unsafe history destination');}
    if(!@rename($tmp,$path)){@unlink($tmp);pwfh_fail('cannot publish history');}
}
function pwfh_atomic_json($p,$j,$createOnly=false){pwfh_atomic_write($p,pwfh_encode($j),$createOnly);}
function pwfh_atomic_text($p,$s){if(file_exists($p)||is_link($p))pwfh_regular($p,4096);pwfh_atomic_write($p,$s,false);}
function pwfh_create_dir($p){if(file_exists($p)||is_link($p)){pwfh_plain_dir($p,false);return;} $old=umask(0077);try{$ok=@mkdir($p,0700);}finally{umask($old);}if(!$ok)pwfh_fail('cannot create history directory');pwfh_plain_dir($p,false);}
function pwfh_create_lock($p){if(file_exists($p)||is_link($p)){pwfh_regular($p,4096);return;} $old=umask(0077);try{$h=@fopen($p,'xb');}finally{umask($old);}if($h===false)pwfh_fail('cannot create history lock');if(!@fclose($h))pwfh_fail('history lock close failed');pwfh_regular($p,4096);}
function pwfh_lock($p){pwfh_create_lock($p);$expected=pwfh_regular($p,4096);$h=@fopen($p,'r+');if($h===false)pwfh_fail('cannot open history lock');$a=@fstat($h);if(!$a||$a['dev']!==$expected['dev']||$a['ino']!==$expected['ino']||($a['mode']&0170000)!==0100000||$a['nlink']!==1){@fclose($h);pwfh_fail('history lock changed');}if(!@flock($h,LOCK_EX)){@fclose($h);pwfh_fail('cannot lock history');}return $h;}
function pwfh_unlock($h){@flock($h,LOCK_UN);@fclose($h);}
function pwfh_scope($runDir){
    $j=pwfh_read_json($runDir.'/scope.json');$fp=pwfh_text($j['fingerprint']??'',false,64);
    if(($j['format']??null)!==1||($j['tool']??null)!=='PressWarden'||!preg_match('/^[a-f0-9]{64}$/D',$fp))pwfh_fail('invalid scope history metadata');
    $root=pwfh_text($j['root']??'',false,8192);$depth=$j['discovery_depth']??null;$sites=$j['scan_roots']??null;$ex=$j['target_exclusions']??null;
    if(!is_int($depth)||$depth<1||$depth>2147483647||!is_array($sites)||!is_array($ex)||count($sites)<1||count($sites)>PWFH_MAX_SITES||count($ex)>PWFH_MAX_SITES)pwfh_fail('invalid scope history metadata');
    $sv=[];foreach($sites as $v)$sv[]=pwfh_text($v,false,8192);$ev=[];foreach($ex as $v)$ev[]=pwfh_text($v,false,8192);$sv=array_values(array_unique($sv));$ev=array_values(array_unique($ev));sort($sv,SORT_STRING);sort($ev,SORT_STRING);
    if(count($sv)!==count($sites)||count($ev)!==count($ex))pwfh_fail('duplicate scope history metadata');
    $base=['root'=>$root,'discovery_depth'=>$depth,'scan_roots'=>$sv,'target_exclusions'=>$ev];$canon=json_encode($base,JSON_UNESCAPED_SLASHES);if($canon===false||!hash_equals(hash('sha256',$canon),$fp))pwfh_fail('scope history fingerprint mismatch');
    return $j;
}
function pwfh_state($runDir){$j=pwfh_read_json($runDir.'/state.json',262144);if(($j['tool']??null)!=='PressWarden'||!isset($j['run_id'],$j['suite'],$j['version'],$j['started_epoch'],$j['results']))pwfh_fail('invalid run state for history');return $j;}
function pwfh_site_map_from_tsv($path){
    $raw=pwfh_read_file($path,1048576);$rows=[];$seen=[];
    foreach(preg_split('/\n/',$raw) as $line){if($line==='')continue;$p=explode("\t",$line,2);if(count($p)!==2)pwfh_fail('invalid site map');$root=pwfh_text($p[0],false,8192);$label=pwfh_text($p[1],false,512);if(isset($seen[$root]))pwfh_fail('duplicate site root');$seen[$root]=1;$rows[]=['root'=>$root,'label'=>$label];}
    if(count($rows)<1||count($rows)>PWFH_MAX_SITES)pwfh_fail('invalid site map size');
    usort($rows,function($a,$b){$la=strlen($a['root']);$lb=strlen($b['root']);if($la===$lb)return strcmp($a['root'],$b['root']);return $la>$lb?-1:1;});return $rows;
}
function pwfh_site_map($runDir){$j=pwfh_read_json($runDir.'/site-map.json',1048576);if(($j['format']??null)!==PWFH_FORMAT||($j['tool']??null)!=='PressWarden'||!is_array($j['sites']??null))pwfh_fail('invalid site map');$out=[];$seen=[];foreach($j['sites'] as $r){if(!is_array($r))pwfh_fail('invalid site map');$root=pwfh_text($r['root']??'',false,8192);$label=pwfh_text($r['label']??'',false,512);if(isset($seen[$root]))pwfh_fail('duplicate site root');$seen[$root]=1;$out[]=['root'=>$root,'label'=>$label];}if(count($out)<1||count($out)>PWFH_MAX_SITES)pwfh_fail('invalid site map size');usort($out,function($a,$b){return strlen($a['root'])===strlen($b['root'])?strcmp($a['root'],$b['root']):(strlen($a['root'])>strlen($b['root'])?-1:1);});return $out;}
function pwfh_rule($section){if(preg_match('/\b(PW-[A-Z0-9]+(?:-[A-Z0-9]+)*)\b/',$section,$m))return $m[1];return '';}
function pwfh_section_key($section){$r=pwfh_rule($section);return $r!==''?$r:'SECTION-'.substr(hash('sha256',strtolower(trim($section))),0,24);}
function pwfh_under_site($path,$sites){foreach($sites as $s){$r=$s['root'];if($path===$r||strpos($path,$r.'/')===0)return [$s,$path===$r?'':substr($path,strlen($r)+1)];}return null;}
function pwfh_path_candidate($line,$sites){
    $candidates=[$line];
    if(preg_match('/^(.+):([0-9]+):(.*)$/D',$line,$m))$candidates[]=$m[1];
    if(preg_match('/^(.+) mode=[0-7]{3,4}(?: |$)/D',$line,$m))$candidates[]=$m[1];
    if(preg_match('/^(.+) -> .+$/D',$line,$m))$candidates[]=$m[1];
    foreach($candidates as $c){$m=pwfh_under_site($c,$sites);if($m!==null)return [$c,$m[0],$m[1]];}
    return null;
}
function pwfh_fingerprint_path($path,$line,$severity){
    $s=@lstat($path);$e=hash('sha256',$line);
    if(!$s)return ['fingerprint'=>hash('sha256',"missing\0$severity\0$e"),'basis'=>'evidence'];
    $mode=sprintf('%o',$s['mode']&07777);
    if(($s['mode']&0170000)===0120000){$t=@readlink($path);if($t!==false&&strlen($t)<=8192&&!preg_match('/[\x00-\x1F\x7F]/',$t))return ['fingerprint'=>hash('sha256',"symlink\0$t\0$mode\0$severity"),'basis'=>'symlink-target'];return ['fingerprint'=>hash('sha256',"symlink\0$mode\0$severity\0$e"),'basis'=>'evidence'];}
    if(($s['mode']&0170000)===0100000){if($s['size']<=PWFH_HASH_FILE_MAX){$h=@hash_file('sha256',$path);if(is_string($h)&&preg_match('/^[a-f0-9]{64}$/D',$h))return ['fingerprint'=>hash('sha256',"file\0$h\0$mode\0$severity"),'basis'=>'content-sha256'];}return ['fingerprint'=>hash('sha256',"filemeta\0{$s['size']}\0{$s['mtime']}\0$mode\0$severity\0$e"),'basis'=>'metadata+evidence'];}
    if(($s['mode']&0170000)===0040000)return ['fingerprint'=>hash('sha256',"dir\0{$s['mtime']}\0$mode\0$severity\0$e"),'basis'=>'metadata+evidence'];
    return ['fingerprint'=>hash('sha256',"other\0$mode\0$severity\0$e"),'basis'=>'evidence'];
}
function pwfh_record_from_line($check,$section,$severity,$line,$sites){
    $sectionKey=pwfh_section_key($section);$rule=pwfh_rule($section);$pathMatch=pwfh_path_candidate($line,$sites);
    if($pathMatch!==null){[$path,$site,$rel]=$pathMatch;$identity=hash('sha256',implode("\0",[$check,$sectionKey,$site['label'],$rel]));$fp=pwfh_fingerprint_path($path,$line,$severity);return ['identity'=>$identity,'check'=>$check,'section'=>$section,'rule'=>$rule,'severity'=>$severity==='issue'?'ALERT':'REVIEW','site'=>$site['label'],'path'=>$rel,'locator'=>'file','locator_id'=>'','fingerprint'=>$fp['fingerprint'],'fingerprint_basis'=>$fp['basis'],'occurrences'=>1];}
    if(preg_match('/^(.+) \[(PW-DB-00[1-6]); (option|post|admin) row ([1-9][0-9]{0,17})\]$/D',$line,$m)){$siteMatch=pwfh_under_site($m[1],$sites);if($siteMatch!==null){$site=$siteMatch[0];$loc='db:'.$m[3].':'.$m[4];$identity=hash('sha256',implode("\0",[$check,$m[2],$site['label'],$loc]));$fingerprint=hash('sha256',implode("\0",[$severity,$m[2],$loc]));return ['identity'=>$identity,'check'=>$check,'section'=>$section,'rule'=>$m[2],'severity'=>$severity==='issue'?'ALERT':'REVIEW','site'=>$site['label'],'path'=>'','locator'=>'database-row','locator_id'=>$loc,'fingerprint'=>$fingerprint,'fingerprint_basis'=>'controlled-db-locator','occurrences'=>1];}}
    $e=hash('sha256',$line);$identity=hash('sha256',implode("\0",[$check,$sectionKey,$e]));return ['identity'=>$identity,'check'=>$check,'section'=>$section,'rule'=>$rule,'severity'=>$severity==='issue'?'ALERT':'REVIEW','site'=>'','path'=>'','locator'=>'evidence','locator_id'=>'evidence:'.substr($e,0,16),'fingerprint'=>hash('sha256',"evidence\0$severity\0$e"),'fingerprint_basis'=>'evidence','occurrences'=>1];
}
function pwfh_merge_record(&$map,$r){$id=$r['identity'];if(!isset($map[$id])){$map[$id]=$r;return;} $old=$map[$id];if((string)$old['fingerprint']!==(string)$r['fingerprint']||(string)$old['severity']!==(string)$r['severity'])pwfh_fail('conflicting observation identity');$old['occurrences']=(int)$old['occurrences']+(int)$r['occurrences'];$map[$id]=$old;}
function pwfh_capture($runDir,$check,$section,$severity,$file){
    $runDir=pwfh_plain_dir($runDir,false);$check=pwfh_check($check);$section=pwfh_text($section,false,512);if($severity!=='issue'&&$severity!=='review')pwfh_fail('invalid severity');$sites=pwfh_site_map($runDir);$raw=pwfh_read_file($file,PWFH_MAX_INPUT);$lines=preg_split('/\n/',$raw);$map=[];$matches=0;
    foreach($lines as $line){$line=rtrim($line,"\r");if($line==='')continue;if(strlen($line)>8192||preg_match('/[\x00-\x1F\x7F]/',$line))pwfh_fail('unrepresentable finding');++$matches;if($matches>PWFH_MAX_FINDINGS)pwfh_fail('finding history limit');$r=pwfh_record_from_line($check,$section,$severity,$line,$sites);pwfh_merge_record($map,$r);}
    if($matches===0)return;
    $obs=pwfh_plain_dir($runDir.'/observations',false);$doc=['format'=>PWFH_FORMAT,'tool'=>'PressWarden','check'=>$check,'section'=>$section,'severity'=>$severity,'matches'=>$matches,'records'=>array_values($map)];$path=$obs.'/obs-'.bin2hex(random_bytes(12)).'.json';pwfh_atomic_json($path,$doc,true);
}
function pwfh_capture_error($runDir,$check){$runDir=pwfh_plain_dir($runDir,false);$check=pwfh_check($check);$d=pwfh_plain_dir($runDir.'/capture-errors',false);$p=$d.'/'.$check; if(file_exists($p)||is_link($p)){pwfh_regular($p,32);return;} $old=umask(0077);try{$h=@fopen($p,'xb');}finally{umask($old);}if($h!==false){pwfh_write_all($h,"1\n");@fclose($h);} }
function pwfh_observations($runDir,$onlyCheck=''){
    $dir=pwfh_plain_dir($runDir.'/observations',false);$names=@scandir($dir);if(!is_array($names))pwfh_fail('cannot list observations');$files=0;$map=[];$matchesBy=[];
    foreach($names as $n){if($n==='.'||$n==='..')continue;if(!preg_match('/^obs-[a-f0-9]{24}\.json$/D',$n))pwfh_fail('unexpected observation entry');if(++$files>PWFH_MAX_OBS_FILES)pwfh_fail('observation file limit');$j=pwfh_read_json($dir.'/'.$n,1048576);if(($j['format']??null)!==PWFH_FORMAT||($j['tool']??null)!=='PressWarden'||!is_array($j['records']??null))pwfh_fail('invalid observation');$check=pwfh_check($j['check']??'');if($onlyCheck!==''&&$check!==$onlyCheck)continue;$m=$j['matches']??null;if(!is_int($m)||$m<1||$m>PWFH_MAX_FINDINGS)pwfh_fail('invalid observation matches');$matchesBy[$check]=($matchesBy[$check]??0)+$m;foreach($j['records'] as $r){if(!is_array($r))pwfh_fail('invalid observation record');foreach(['identity','check','section','severity','site','path','locator','locator_id','fingerprint','fingerprint_basis','occurrences'] as $k)if(!array_key_exists($k,$r))pwfh_fail('incomplete observation record');$id=pwfh_text($r['identity'],false,64);$fp=pwfh_text($r['fingerprint'],false,64);if(!preg_match('/^[a-f0-9]{64}$/D',$id)||!preg_match('/^[a-f0-9]{64}$/D',$fp))pwfh_fail('invalid observation hash');if(pwfh_check($r['check'])!==$check)pwfh_fail('observation check mismatch');$r['section']=pwfh_text($r['section'],false,512);$r['severity']=pwfh_text($r['severity'],false,16);if($r['severity']!=='ALERT'&&$r['severity']!=='REVIEW')pwfh_fail('invalid observation severity');$r['site']=pwfh_text($r['site'],true,512);$r['path']=pwfh_text($r['path'],true,8192);$r['locator']=pwfh_text($r['locator'],false,32);$r['locator_id']=pwfh_text($r['locator_id'],true,128);$r['fingerprint_basis']=pwfh_text($r['fingerprint_basis'],false,64);if(!is_int($r['occurrences'])||$r['occurrences']<1)pwfh_fail('invalid occurrence count');pwfh_merge_record($map,$r);if(count($map)>PWFH_MAX_FINDINGS)pwfh_fail('active history finding limit');}}
    return [$map,$matchesBy];
}
function pwfh_results($state){$out=[];$r=$state['results']??null;if(!is_array($r))pwfh_fail('invalid run results');foreach($r as $k=>$v){if(!is_array($v))pwfh_fail('invalid run result');$check=isset($v['check'])?pwfh_check($v['check']):pwfh_check((string)$k);$status=(string)($v['status']??'');$n=$v['findings']??null;if($n!==null&&!is_int($n)&&!is_numeric($n))pwfh_fail('invalid run finding count');$out[$check]=['status'=>$status,'findings'=>$n===null?null:(int)$n];}return $out;}
function pwfh_capture_error_checks($runDir){$d=pwfh_plain_dir($runDir.'/capture-errors',false);$names=@scandir($d);if(!is_array($names))pwfh_fail('cannot list capture errors');$out=[];foreach($names as $n){if($n==='.'||$n==='..')continue;$check=pwfh_check($n);pwfh_regular($d.'/'.$n,32);$out[$check]=true;}return $out;}
function pwfh_history_validate($j){if(($j['format']??null)!==PWFH_FORMAT||($j['tool']??null)!=='PressWarden'||!isset($j['run_id'],$j['suite'],$j['scope_fingerprint'],$j['active_findings'],$j['counts']))pwfh_fail('invalid history report');if(!is_array($j['active_findings'])||!is_array($j['counts']))pwfh_fail('invalid history report');return $j;}
function pwfh_history_read($runDir){return pwfh_history_validate(pwfh_read_json($runDir.'/history.json'));}
function pwfh_pointer_key($suite,$scopeFp){return hash('sha256',"PressWarden-history-v1\0$suite\0$scopeFp");}
function pwfh_pointer_read($index,$key){$p=$index.'/'.$key.'.json';if(!file_exists($p)&&!is_link($p))return null;$j=pwfh_read_json($p,4096);if(($j['format']??null)!==PWFH_FORMAT||($j['tool']??null)!=='PressWarden'||($j['key']??'')!==$key)pwfh_fail('invalid history pointer');$j['run_id']=pwfh_id($j['run_id']??'');if(!is_int($j['started_epoch']??null))pwfh_fail('invalid history pointer');return $j;}
function pwfh_history_active_map($j){$out=[];foreach($j['active_findings'] as $r){if(!is_array($r))pwfh_fail('invalid active history record');$id=pwfh_text($r['identity']??'',false,64);if(!preg_match('/^[a-f0-9]{64}$/D',$id)||isset($out[$id]))pwfh_fail('invalid active history identity');$out[$id]=$r;}if(count($out)>PWFH_MAX_FINDINGS)pwfh_fail('active history limit');return $out;}
function pwfh_display_record($r){$x=['identity'=>$r['identity'],'check'=>$r['check'],'section'=>$r['section'],'rule'=>$r['rule'],'severity'=>$r['severity'],'site'=>$r['site'],'path'=>$r['path'],'locator'=>$r['locator'],'locator_id'=>$r['locator_id'],'fingerprint'=>$r['fingerprint'],'fingerprint_basis'=>$r['fingerprint_basis'],'occurrences'=>$r['occurrences']];foreach(['first_seen_run','last_seen_run'] as $k)if(isset($r[$k]))$x[$k]=$r[$k];return $x;}
function pwfh_finalize($runs,$historyRoot,$id){
    $runs=pwfh_plain_dir($runs,false);$historyRoot=pwfh_plain_dir($historyRoot,true);$id=pwfh_id($id);$runDir=pwfh_plain_dir($runs.'/'.$id,false);$state=pwfh_state($runDir);if((string)$state['run_id']!==$id)pwfh_fail('run id mismatch');$status=(string)($state['status']??'');if(!in_array($status,['COMPLETED','INCOMPLETE','FAILED'],true))pwfh_fail('run is not finalized for history');$suite=pwfh_text($state['suite'],false,96);$scope=pwfh_scope($runDir);$scopeFp=pwfh_text($scope['fingerprint'],false,64);$started=(int)$state['started_epoch'];$version=pwfh_text($state['version'],false,64);
    [$current,$matchesBy]=pwfh_observations($runDir);$results=pwfh_results($state);$errors=pwfh_capture_error_checks($runDir);$captureIntegrity=true;$checkCoverage=[];
    foreach($results as $check=>$r){$st=$r['status'];if(!in_array($st,['clean','findings','skipped','missing','error'],true))pwfh_fail('invalid run result status');$expected=$r['findings'];$observed=$matchesBy[$check]??0;$integrity=!isset($errors[$check]);if($st==='clean'||$st==='findings'){if($expected===null||$expected!==$observed)$integrity=false;}if(!$integrity)$captureIntegrity=false;$checkCoverage[$check]=['status'=>$st,'expected_findings'=>$expected,'observed_findings'=>$observed,'capture_integrity'=>$integrity];}
    foreach($matchesBy as $check=>$n){if(!isset($results[$check])){$captureIntegrity=false;$checkCoverage[$check]=['status'=>'unknown','expected_findings'=>null,'observed_findings'=>$n,'capture_integrity'=>false];}}
    $index=pwfh_plain_dir($historyRoot.'/index',true);$key=pwfh_pointer_key($suite,$scopeFp);$lock=pwfh_lock($index.'/.'.$key.'.lock');
    try {
        $pointer=pwfh_pointer_read($index,$key);$previous=null;$previousRun='';$previousStarted=0;$overlap=false;$versionChanged=false;
        if($pointer!==null){
            $previousRun=$pointer['run_id'];$previousStarted=(int)$pointer['started_epoch'];
            $previousDir=pwfh_plain_dir($runs.'/'.$previousRun,false);$previous=pwfh_history_read($previousDir);
            if(($previous['suite']??'')!==$suite||($previous['scope_fingerprint']??'')!==$scopeFp)pwfh_fail('history pointer scope mismatch');
            $priorVersion=pwfh_text($previous['version']??'',false,64);$versionChanged=$priorVersion!==$version;
            $priorFinal=(int)($previous['finalized_epoch']??0);if($priorFinal>0&&$priorFinal>$started)$overlap=true;
        }
        $previousActive=$previous===null?[]:pwfh_history_active_map($previous);$events=[];$active=[];$counts=['NEW'=>0,'RECURRING'=>0,'CHANGED'=>0,'RESOLVED'=>0,'NOT_RECHECKED'=>0];
        foreach($current as $identity=>$r){
            if(isset($previousActive[$identity])){$old=$previousActive[$identity];$classification=((string)($old['fingerprint']??'')===(string)$r['fingerprint'])?'RECURRING':'CHANGED';$r['first_seen_run']=$old['first_seen_run']??($old['last_seen_run']??$previousRun);}
            else{$classification='NEW';$r['first_seen_run']=$id;}
            $r['last_seen_run']=$id;$active[$identity]=$r;$e=pwfh_display_record($r);$e['classification']=$classification;$events[]=$e;++$counts[$classification];
        }
        $discoveryComplete=(string)($state['discovery_status']??'')==='complete';
        foreach($previousActive as $identity=>$old){
            if(isset($current[$identity]))continue;$check=(string)($old['check']??'');$cov=$checkCoverage[$check]??null;
            $canResolve=$captureIntegrity&&$discoveryComplete&&!$overlap&&!$versionChanged&&is_array($cov)&&$cov['capture_integrity']===true&&($cov['status']==='clean'||$cov['status']==='findings');
            $classification=$canResolve?'RESOLVED':'NOT_RECHECKED';$e=pwfh_display_record($old);$e['classification']=$classification;$events[]=$e;++$counts[$classification];
            if(!$canResolve)$active[$identity]=$old;
        }
        $comparison=$previous===null?'FIRST_OBSERVATION':($overlap?'OVERLAPPING_RUNS':($versionChanged?'VERSION_CHANGED':'COMPARABLE'));
        $doc=['format'=>PWFH_FORMAT,'tool'=>'PressWarden','run_id'=>$id,'suite'=>$suite,'version'=>$version,'scope_fingerprint'=>$scopeFp,'generated_at'=>pwfh_now(),'finalized_epoch'=>time(),'compared_to'=>$previousRun===''?null:$previousRun,'comparison'=>$comparison,'capture_integrity'=>$captureIntegrity,'discovery_status'=>(string)($state['discovery_status']??'unknown'),'counts'=>$counts,'check_coverage'=>$checkCoverage,'active_findings'=>array_values($active),'events'=>$events];
        $historyPath=$runDir.'/history.json';pwfh_atomic_json($historyPath,$doc,true);
        $indexUpdated=false;
        if($captureIntegrity&&($pointer===null||$started>=$previousStarted)){
            $ptr=['format'=>PWFH_FORMAT,'tool'=>'PressWarden','key'=>$key,'suite'=>$suite,'scope_fingerprint'=>$scopeFp,'run_id'=>$id,'started_epoch'=>$started,'updated_at'=>pwfh_now()];pwfh_atomic_json($index.'/'.$key.'.json',$ptr,false);$indexUpdated=true;
        }
        echo "STATUS\t",($captureIntegrity?'COMPLETE':'INCOMPLETE'),"\n";
        echo "REPORT\t",$historyPath,"\n";
        echo "COMPARE\t",($previousRun===''?'FIRST':$previousRun),"\n";
        echo "INDEX\t",($indexUpdated?'UPDATED':'UNCHANGED'),"\n";
        foreach(['NEW','RECURRING','CHANGED','RESOLVED','NOT_RECHECKED'] as $k)echo $k,"\t",$counts[$k],"\n";
        return $captureIntegrity?0:2;
    } finally { pwfh_unlock($lock); }
}
function pwfh_copy_check($runs,$parentId,$childId,$check){
    $runs=pwfh_plain_dir($runs,false);$parentId=pwfh_id($parentId);$childId=pwfh_id($childId);$check=pwfh_check($check);$parent=pwfh_plain_dir($runs.'/'.$parentId,false);$child=pwfh_plain_dir($runs.'/'.$childId,false);pwfh_state($parent);pwfh_state($child);$parentObs=pwfh_plain_dir($parent.'/observations',false);$childObs=pwfh_plain_dir($child.'/observations',false);
    $err=$parent.'/capture-errors/'.$check;if(file_exists($err)||is_link($err)){pwfh_capture_error($child,$check);}
    $names=@scandir($parentObs);if(!is_array($names))pwfh_fail('cannot list parent observations');$copied=0;
    foreach($names as $n){if($n==='.'||$n==='..')continue;if(!preg_match('/^obs-[a-f0-9]{24}\.json$/D',$n))pwfh_fail('unexpected parent observation entry');$j=pwfh_read_json($parentObs.'/'.$n,1048576);if(($j['format']??null)!==PWFH_FORMAT||($j['tool']??null)!=='PressWarden')pwfh_fail('invalid parent observation');if(($j['check']??'')!==$check)continue;$dest=$childObs.'/obs-'.bin2hex(random_bytes(12)).'.json';pwfh_atomic_json($dest,$j,true);++$copied;if($copied>PWFH_MAX_OBS_FILES)pwfh_fail('carried observation limit');}
    return 0;
}
function pwfh_show_record($r,$classification){
    $check=(string)($r['check']??'unknown');$rule=(string)($r['rule']??'');$site=(string)($r['site']??'');$path=(string)($r['path']??'');$loc=(string)($r['locator_id']??'');$sev=(string)($r['severity']??'');
    $where='';if($site!==''&&$path!=='')$where=$site.' › '.$path;elseif($site!=='')$where=$site.($loc!==''?' › '.$loc:'');elseif($loc!=='')$where=$loc;else$where='evidence '.substr((string)($r['identity']??''),0,12);
    printf("  %-13s %-18s %s%s%s\n",$classification,$check,$rule!==''?'['.$rule.'] ':'',$where,$sev!==''?' • '.$sev:'');
}
function pwfh_show($runs,$id){
    $runs=pwfh_plain_dir($runs,false);if($id===''||$id==='latest'){$latest=$runs.'/latest';pwfh_regular($latest,4096);$id=trim((string)@file_get_contents($latest,false,null,0,4097));}$id=pwfh_id($id);$runDir=pwfh_plain_dir($runs.'/'.$id,false);$path=$runDir.'/history.json';
    if(!file_exists($path)&&!is_link($path)){$state=pwfh_state($runDir);$status=(string)($state['status']??'UNKNOWN');fwrite(STDOUT,"No finalized finding history for run $id. Run status: $status. Interrupted/running scans do not publish resolution history.\n");return 2;}
    $j=pwfh_history_read($runDir);$counts=$j['counts'];fwrite(STDOUT,"PRESSWARDEN FINDING HISTORY\n\n");printf("RUN           %s\n",$j['run_id']);printf("SUITE         %s\n",$j['suite']);printf("COMPARE       %s\n",$j['compared_to']??'first structured observation');printf("COMPARISON    %s\n",$j['comparison']??'unknown');printf("CAPTURE       %s\n",!empty($j['capture_integrity'])?'COMPLETE':'INCOMPLETE');printf("DISCOVERY     %s\n",strtoupper((string)($j['discovery_status']??'unknown')));printf("NEW           %d\n",(int)($counts['NEW']??0));printf("RECURRING     %d\n",(int)($counts['RECURRING']??0));printf("CHANGED       %d\n",(int)($counts['CHANGED']??0));printf("RESOLVED      %d\n",(int)($counts['RESOLVED']??0));printf("NOT RECHECKED %d\n",(int)($counts['NOT_RECHECKED']??0));
    $events=$j['events']??[];if(!is_array($events))pwfh_fail('invalid history events');$shown=0;foreach(['NEW','CHANGED','RESOLVED','NOT_RECHECKED','RECURRING'] as $class){$header=false;foreach($events as $r){if(!is_array($r)||($r['classification']??'')!==$class)continue;if(!$header){echo "\n$class\n";$header=true;}pwfh_show_record($r,$class);if(++$shown>=100){echo "\n… detail display capped at 100 identities; the private history.json contains the complete bounded record.\n";return !empty($j['capture_integrity'])?0:2;}}}
    return !empty($j['capture_integrity'])?0:2;
}

try{
    $cmd=$argv[1]??'';
    if($cmd==='init'){
        if($argc!==4)pwfh_fail('invalid history init arguments');$runDir=pwfh_plain_dir($argv[2],false);pwfh_state($runDir);pwfh_scope($runDir);$sites=pwfh_site_map_from_tsv($argv[3]);pwfh_create_dir($runDir.'/observations');pwfh_create_dir($runDir.'/capture-errors');pwfh_atomic_json($runDir.'/site-map.json',['format'=>PWFH_FORMAT,'tool'=>'PressWarden','sites'=>$sites],true);exit(0);
    }
    if($cmd==='capture'){
        if($argc!==7)pwfh_fail('invalid history capture arguments');pwfh_capture($argv[2],$argv[3],$argv[4],$argv[5],$argv[6]);exit(0);
    }
    if($cmd==='error'){
        if($argc!==4)pwfh_fail('invalid history error arguments');pwfh_capture_error($argv[2],$argv[3]);exit(0);
    }
    if($cmd==='carry'){
        if($argc!==6)pwfh_fail('invalid history carry arguments');pwfh_copy_check($argv[2],$argv[3],$argv[4],$argv[5]);exit(0);
    }
    if($cmd==='finalize'){
        if($argc!==5)pwfh_fail('invalid history finalize arguments');exit(pwfh_finalize($argv[2],$argv[3],$argv[4]));
    }
    if($cmd==='show'){
        if($argc!==4)pwfh_fail('invalid history show arguments');exit(pwfh_show($argv[2],$argv[3]));
    }
    pwfh_fail('unknown history command');
}catch(Throwable $e){fwrite(STDERR,"Finding history unavailable or incomplete.\n");exit(2);}
