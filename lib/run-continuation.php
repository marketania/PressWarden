<?php
// Safe suite-continuation planner/scope verifier. PHP 7.4 compatible; no WordPress bootstrap.
const PWC_MAX_BYTES = 524288;
const PWC_MAX_SITES = 4096;
const PWC_MAX_CHECKS = 256;

final class PressWardenContinueError extends RuntimeException {}
function pwc_fail($m) { throw new PressWardenContinueError($m); }
function pwc_text($v, $empty=false, $max=8192) {
    $v=(string)$v;
    if ((!$empty && $v==='') || strlen($v)>$max || preg_match('/[\x00-\x1F\x7F]/', $v)) pwc_fail('invalid continuation metadata');
    return $v;
}
function pwc_id($v) { $v=(string)$v; if(!preg_match('/^[A-Za-z0-9][A-Za-z0-9._-]{0,159}$/D',$v))pwc_fail('invalid run id'); return $v; }
function pwc_plain_dir($p) {
    $p=rtrim(pwc_text($p,false,8192),'/'); if($p==='')$p='/';
    if(is_link($p)||!is_dir($p))pwc_fail('unsafe continuation directory');
    $s=@lstat($p); if(!$s||(($s['mode']&0170000)!==0040000))pwc_fail('unsafe continuation directory'); return $p;
}
function pwc_regular($p,$max=PWC_MAX_BYTES) {
    if(is_link($p))pwc_fail('unsafe continuation file'); $s=@lstat($p);
    if(!$s||(($s['mode']&0170000)!==0100000)||$s['nlink']!==1||$s['size']<0||$s['size']>$max)pwc_fail('unsafe continuation file'); return $s;
}
function pwc_read_json($p) {
    pwc_regular($p); $raw=@file_get_contents($p,false,null,0,PWC_MAX_BYTES+1);
    if($raw===false||strlen($raw)>PWC_MAX_BYTES)pwc_fail('cannot read continuation state');
    $j=json_decode($raw,true,64); if(!is_array($j))pwc_fail('invalid continuation state'); return $j;
}
function pwc_write_all($h,$d){$o=0;$l=strlen($d);while($o<$l){$n=@fwrite($h,substr($d,$o));if($n===false||$n===0)pwc_fail('continuation write failed');$o+=$n;}if(!@fflush($h))pwc_fail('continuation flush failed');}
function pwc_publish_new($path,$data){
    $dir=pwc_plain_dir(dirname($path)); if(file_exists($path)||is_link($path))pwc_fail('continuation metadata already exists');
    $tmp=$dir.'/.continue.'.bin2hex(random_bytes(8)).'.tmp'; $old=umask(0077); try{$h=@fopen($tmp,'xb');}finally{umask($old);} if($h===false)pwc_fail('cannot stage continuation metadata');
    try{pwc_write_all($h,$data);}finally{if(!@fclose($h)){@unlink($tmp);pwc_fail('continuation close failed');}}
    if(!@link($tmp,$path)){@unlink($tmp);pwc_fail('cannot publish continuation metadata');}@unlink($tmp);
}
function pwc_scope_from_tsv($path){
    pwc_regular($path); $raw=@file_get_contents($path,false,null,0,PWC_MAX_BYTES+1); if($raw===false||strlen($raw)>PWC_MAX_BYTES)pwc_fail('cannot read scope snapshot');
    $root='';$depth='';$sites=[];$ex=[];
    foreach(preg_split('/\n/',$raw) as $line){if($line==='')continue;$p=explode("\t",$line,2);if(count($p)!==2)pwc_fail('malformed scope snapshot');[$k,$v]=$p;$v=pwc_text($v,false,8192);
        if($k==='ROOT'){if($root!=='')pwc_fail('duplicate scope root');$root=$v;}
        elseif($k==='DEPTH'){if($depth!==''||!preg_match('/^[0-9]{1,3}$/D',$v))pwc_fail('invalid scope depth');$depth=$v;}
        elseif($k==='SITE'){$sites[]=$v;}
        elseif($k==='EXCLUDE'){$ex[]=$v;}
        else pwc_fail('unknown scope record');
    }
    if($root===''||$depth===''||count($sites)<1||count($sites)>PWC_MAX_SITES||count($ex)>PWC_MAX_SITES)pwc_fail('incomplete scope snapshot');
    $sites=array_values(array_unique($sites));$ex=array_values(array_unique($ex));sort($sites,SORT_STRING);sort($ex,SORT_STRING);
    $base=['root'=>$root,'discovery_depth'=>(int)$depth,'scan_roots'=>$sites,'target_exclusions'=>$ex];
    $canon=json_encode($base,JSON_UNESCAPED_SLASHES);if($canon===false)pwc_fail('scope encoding failed');$base['fingerprint']=hash('sha256',$canon);return $base;
}
function pwc_scope_read($runDir){$j=pwc_read_json($runDir.'/scope.json');if(($j['format']??null)!==1||($j['tool']??null)!=='PressWarden'||!isset($j['fingerprint'],$j['scan_roots'],$j['root'],$j['discovery_depth'],$j['target_exclusions']))pwc_fail('run predates safe continuation scope metadata; rerun the suite before using continue');return $j;}
function pwc_resolve_run($runs,$id){
    $runs=pwc_plain_dir($runs);if($id===''||$id==='latest'){$latest=$runs.'/latest';pwc_regular($latest,4096);$id=trim((string)@file_get_contents($latest,false,null,0,4097));}
    $id=pwc_id($id);$dir=pwc_plain_dir($runs.'/'.$id);$state=pwc_read_json($dir.'/state.json');if(($state['tool']??null)!=='PressWarden')pwc_fail('invalid PressWarden run state');return [$id,$dir,$state,pwc_scope_read($dir)];
}
function pwc_result_map($state){
    $out=[];$results=$state['results']??[];if(!is_array($results))pwc_fail('invalid run results');
    foreach($results as $k=>$r){if(!is_array($r))pwc_fail('invalid run result');$name='';if(isset($r['check']))$name=pwc_text($r['check'],false,96);elseif(is_string($k))$name=pwc_text($k,false,96);else pwc_fail('run result missing check');if(isset($out[$name]))pwc_fail('duplicate run result');$out[$name]=$r;}
    return $out;
}
function pwc_checks($state){$c=$state['checks_selected']??null;if(!is_array($c)||count($c)<1||count($c)>PWC_MAX_CHECKS)pwc_fail('invalid stored check plan');$out=[];foreach($c as $v){$v=pwc_text($v,false,96);if(!preg_match('/^[A-Za-z0-9_-]+$/D',$v)||in_array($v,$out,true))pwc_fail('invalid stored check plan');$out[]=$v;}return $out;}
function pwc_is_alive($state){$pid=(int)($state['pid']??0);if($pid<1||!function_exists('posix_kill'))return null;return @posix_kill($pid,0);}
function pwc_plan_data($runs,$id,$version){
    [$id,$dir,$state,$scope]=pwc_resolve_run($runs,$id);$version=pwc_text($version,false,64);
    if((string)($state['version']??'')!==$version)pwc_fail('PressWarden version changed; rerun the suite instead of continuing mixed code');
    if((string)($state['discovery_status']??'')!=='complete')pwc_fail('original discovery was incomplete; rerun the suite instead of continuing partial scope');
    $status=(string)($state['status']??'');
    if($status==='RUNNING'){$alive=pwc_is_alive($state);if($alive===true)pwc_fail('recorded run still appears active');if($alive===null)pwc_fail('cannot prove the RUNNING process ended; use run-status and rerun safely');}
    elseif($status!=='INTERRUPTED'&&$status!=='FAILED')pwc_fail('only interrupted, failed, or provably abandoned runs can be continued');
    $suite=pwc_text($state['suite']??'',false,96);$supported=['fast','full','incident','db','intel','inspect-php','inspect-js','inspect-db','inspect-runtime'];if(!in_array($suite,$supported,true))pwc_fail('suite is not continuation-enabled');
    $checks=pwc_checks($state);$map=pwc_result_map($state);$carry=[];$missing=null;$seenMissing=false;
    foreach($checks as $i=>$check){if(isset($map[$check])){if($seenMissing)pwc_fail('run results are not a completed prefix');$r=$map[$check];$st=(string)($r['status']??'');if(!in_array($st,['clean','findings','skipped'],true))pwc_fail('completed prefix contains an incomplete check; rerun the suite');$n=$r['findings']??0;if($n!==null&&!is_numeric($n))pwc_fail('invalid carried finding count');$elapsed=$r['elapsed_seconds']??($r['elapsed']??0);if(!is_numeric($elapsed))pwc_fail('invalid carried elapsed time');$carry[]=['check'=>$check,'findings'=>$n===null?0:(int)$n,'status'=>$st,'elapsed'=>(int)$elapsed];}else{if(!$seenMissing){$missing=['check'=>$check,'index'=>$i+1];}$seenMissing=true;}}
    if($missing===null)pwc_fail('run has no unfinished check to continue');
    if($missing['check']==='wp-db-maintenance')pwc_fail('the interrupted check performs automatic database writes; rerun the DB/full suite explicitly instead of replaying it');
    return ['id'=>$id,'dir'=>$dir,'state'=>$state,'scope'=>$scope,'suite'=>$suite,'checks'=>$checks,'carry'=>$carry,'start'=>$missing['check'],'index'=>$missing['index']];
}
function pwc_emit_plan($p){
    $lines=[['RUN',$p['id']],['SUITE',$p['suite']],['ROOT',$p['scope']['root']],['DEPTH',(string)$p['scope']['discovery_depth']],['START',$p['start']],['INDEX',(string)$p['index']],['TOTAL',(string)count($p['checks'])],['CARRY',(string)count($p['carry'])]];
    foreach($p['scope']['target_exclusions'] as $v)$lines[]=['EXCLUDE',$v];foreach($lines as $r)echo $r[0],"\t",$r[1],"\n";
}
function pwc_write_carry($path,$carry){
    if(is_link($path))pwc_fail('unsafe carry file');$s=@lstat($path);if(!$s||(($s['mode']&0170000)!==0100000)||$s['nlink']!==1)pwc_fail('unsafe carry file');
    $h=@fopen($path,'wb');if($h===false)pwc_fail('cannot write carry file');try{foreach($carry as $r)pwc_write_all($h,$r['check']."\t".$r['findings']."\t".$r['status']."\t".$r['elapsed']."\n");}finally{@fclose($h);}
}

try{
    $cmd=$argv[1]??'';
    if($cmd==='capture'){
        if($argc!==4)pwc_fail('invalid capture arguments');$runDir=pwc_plain_dir($argv[2]);pwc_regular($runDir.'/state.json');$scope=pwc_scope_from_tsv($argv[3]);$data=['format'=>1,'tool'=>'PressWarden']+$scope;$json=json_encode($data,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES);if($json===false)pwc_fail('scope encoding failed');$json.="\n";pwc_publish_new($runDir.'/scope.json',$json);exit(0);
    }
    if($cmd==='plan'){
        if($argc!==5)pwc_fail('invalid plan arguments');$p=pwc_plan_data($argv[2],$argv[3],$argv[4]);pwc_emit_plan($p);exit(0);
    }
    if($cmd==='verify'){
        if($argc!==8)pwc_fail('invalid verify arguments');$p=pwc_plan_data($argv[2],$argv[3],$argv[4]);$suite=pwc_text($argv[5],false,96);if($suite!==$p['suite'])pwc_fail('suite changed since interrupted run');$currentChecks=preg_split('/[[:space:]]+/',trim(pwc_text($argv[6],false,16384)));if($currentChecks!==$p['checks'])pwc_fail('check plan changed since interrupted run');$scope=pwc_scope_from_tsv($argv[7]);if(!hash_equals((string)$p['scope']['fingerprint'],(string)$scope['fingerprint']))pwc_fail('site scope changed since interrupted run; rerun the suite for trustworthy coverage');$carryPath=$argv[8]??'';pwc_fail('invalid verify arguments');
    }
    pwc_fail('unknown continuation command');
}catch(Throwable $e){fwrite(STDERR,'INCOMPLETE: '.preg_replace('/[\r\n\t]+/',' ',(string)$e->getMessage())."\n");exit(2);}
