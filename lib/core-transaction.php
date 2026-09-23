<?php
/** Explicit, bounded WordPress core-file transaction; PHP 7.4; never bootstraps a site. */
require_once __DIR__.'/ops-safety.php';
function pw_core_rel($rel){
    if(!is_string($rel)||$rel===''||$rel[0]==='/'||strpos($rel,'\\')!==false||preg_match('/[\x00-\x1f\x7f]/',$rel))throw new RuntimeException('unsafe core relative path');
    foreach(explode('/',$rel) as $part)if($part===''||$part==='.'||$part==='..')throw new RuntimeException('unsafe core path component');
    if($rel==='wp-content'||strpos($rel,'wp-content/')===0||in_array($rel,['wp-config.php','.htaccess','.user.ini','php.ini'],true))throw new RuntimeException('protected non-core path');
    return $rel;
}
function pw_core_snapshot($path,$missing=false){
    pw_ops_path(dirname($path));clearstatcache(true,$path);
    if(!file_exists($path)&&!is_link($path)){if($missing)return null;throw new RuntimeException('required file disappeared');}
    $s=pw_ops_regular($path,33554432);
    if(function_exists('posix_geteuid')&&$s['uid']!==posix_geteuid())throw new RuntimeException('file ownership differs from operator');
    $hash=hash_file('sha256',$path);if(!is_string($hash))throw new RuntimeException('cannot hash file');
    return ['dev'=>$s['dev'],'ino'=>$s['ino'],'size'=>$s['size'],'mode'=>$s['mode']&0777,'uid'=>$s['uid'],'gid'=>$s['gid'],'sha256'=>$hash];
}
function pw_core_copy($from,$to){
    $in=@fopen($from,'rb');$out=@fopen($to,'xb');
    if(!$in||!$out){if(is_resource($in))fclose($in);if(is_resource($out))fclose($out);throw new RuntimeException('cannot allocate recovery/staging copy');}
    $n=stream_copy_to_stream($in,$out);fflush($out);fclose($in);fclose($out);
    if($n===false||!chmod($to,0600))throw new RuntimeException('copy or permissions failed');
}
function pw_core_save($file,array $journal){
    if(is_link($file))throw new RuntimeException('unsafe journal path');
    if(file_put_contents($file,json_encode($journal,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES),LOCK_EX)===false||!chmod($file,0600))throw new RuntimeException('journal write failed');
}
function pw_core_transaction($mode,$site,$manifestFile,$listFile,$package,$state){
    if(!in_array($mode,['restore','extras'],true))throw new RuntimeException('unknown core operation');
    pw_ops_scope($state,[$site]);pw_ops_regular($manifestFile);pw_ops_regular($listFile,1048576);
    $json=json_decode(file_get_contents($manifestFile),true);$checksums=$json['checksums']??null;
    if(!is_array($checksums)||!$checksums)throw new RuntimeException('invalid official checksum manifest');
    $lines=preg_split('/\r?\n/',file_get_contents($listFile),-1,PREG_SPLIT_NO_EMPTY);
    if(count($lines)>1000)throw new RuntimeException('core transaction file limit exceeded');
    $lockPath=pw_ops_lock_file($state,$site);$ls=lstat($lockPath);$lock=@fopen($lockPath,'r+b');$fs=$lock?fstat($lock):false;
    if(!$fs||$fs['dev']!==$ls['dev']||$fs['ino']!==$ls['ino']||is_link($lockPath)||!flock($lock,LOCK_EX|LOCK_NB))throw new RuntimeException('core writer lock busy/unsafe');
    $stages=[];
    try {
        $plan=[];
        foreach(array_unique($lines) as $rel){
            pw_core_rel($rel);$dst=$site.'/'.$rel;$before=pw_core_snapshot($dst,$mode==='restore');
            if(!is_dir(dirname($dst)))throw new RuntimeException('missing core directory; narrow repair will not invent a directory tree');
            if($mode==='extras'){
                if(!preg_match('#^wp-(admin|includes)/#',$rel)||isset($checksums[$rel]))throw new RuntimeException('extra is protected or belongs to official core');
                $plan[]=['relative'=>$rel,'before'=>$before];continue;
            }
            $expected=$checksums[$rel]??'';
            if(!is_string($expected)||!preg_match('/^[a-fA-F0-9]{32}$/D',$expected))throw new RuntimeException('core path has no valid official checksum');
            if($before&&hash_equals(strtolower($expected),md5_file($dst))){echo "UNCHANGED: $rel already matches official core\n";continue;}
            $src=$package.'/'.$rel;$snapshot=pw_core_snapshot($src);
            if(!hash_equals(strtolower($expected),md5_file($src)))throw new RuntimeException('cached official source failed checksum verification');
            $plan[]=['relative'=>$rel,'before'=>$before,'source'=>$snapshot,'expected_md5'=>strtolower($expected)];
        }
        if(!$plan){echo "UNCHANGED: no remaining core actions\n";return 0;}
        $backup=pw_ops_backup_dir($state,$site,'core-'.$mode);$journal=['site'=>$site,'operation'=>$mode,'status'=>'PREPARING','files'=>$plan];$meta=$backup.'/manifest.json';
        foreach($plan as $i=>$item){
            $dst=$site.'/'.$item['relative'];
            if($item['before']){
                $dest=$backup.'/'.sprintf('%04d.data',$i);pw_core_copy($dst,$dest);
                if(hash_file('sha256',$dest)!==$item['before']['sha256']||pw_core_snapshot($dst)!==$item['before'])throw new RuntimeException('source changed during evidence copy; no core action applied');
                $journal['files'][$i]['backup']=basename($dest);
            }
            if($mode==='restore'){
                $stage=dirname($dst).'/.presswarden-core-'.bin2hex(random_bytes(12));$stages[$i]=$stage;pw_core_copy($package.'/'.$item['relative'],$stage);
                if(hash_file('sha256',$stage)!==$item['source']['sha256']||md5_file($stage)!==$item['expected_md5'])throw new RuntimeException('staged official file verification failed');
                if(!chmod($stage,$item['before']['mode']??0644))throw new RuntimeException('staged mode preservation failed');
                if($item['before']&&filegroup($stage)!==$item['before']['gid']&&!chgrp($stage,$item['before']['gid']))throw new RuntimeException('staged group preservation failed');
            }
        }
        $journal['status']='BACKED_UP';pw_core_save($meta,$journal);$done=0;
        echo "Verified recovery copies and manifest: $backup\n";
        foreach($plan as $i=>$item){
            $dst=$site.'/'.$item['relative'];
            try {
                if(pw_core_snapshot($dst,$mode==='restore')!==$item['before'])throw new RuntimeException('live core file changed after backup; no overwrite');
                if($mode==='restore'){
                    if(!rename($stages[$i],$dst))throw new RuntimeException('atomic core publication failed');unset($stages[$i]);
                    if(md5_file($dst)!==$item['expected_md5'])throw new RuntimeException('published checksum mismatch; recovery retained, not blindly rolled back');
                    $journal['files'][$i]['result']='RESTORED_VERIFIED';echo 'RESTORED VERIFIED: '.$item['relative']."\n";
                }else{
                    if(!unlink($dst))throw new RuntimeException('extra removal failed');clearstatcache(true,$dst);
                    if(file_exists($dst)||is_link($dst))throw new RuntimeException('extra path reappeared; recovery retained');
                    $journal['files'][$i]['result']='REMOVED_VERIFIED';echo 'QUARANTINED+REMOVED VERIFIED: '.$item['relative']."\n";
                }
                $done++;pw_core_save($meta,$journal);
            }catch(Throwable $e){$journal['status']='PARTIAL_OR_UNVERIFIED';$journal['files'][$i]['result']='STOPPED';pw_core_save($meta,$journal);throw $e;}
        }
        $journal['status']='COMPLETED';pw_core_save($meta,$journal);echo "Verified core file actions: $done\n";return 0;
    }finally{foreach($stages as $stage){if(is_file($stage)&&!is_link($stage))@unlink($stage);}flock($lock,LOCK_UN);fclose($lock);}
}
if(isset($argv[0])&&realpath($argv[0])===__FILE__){
    try{if($argc!==7)throw new RuntimeException('invalid core transaction arguments');exit(pw_core_transaction($argv[1],$argv[2],$argv[3],$argv[4],$argv[5],$argv[6]));}
    catch(Throwable $e){fwrite(STDERR,'CORE INCOMPLETE: '.$e->getMessage()."\n");exit(2);}
}
