<?php
require __DIR__.'/../lib/core-transaction.php';
$t=sys_get_temp_dir().'/pw-core-'.bin2hex(random_bytes(8));mkdir($t,0700);$n=0;
function ok($v,$m){global$n;$n++;if(!$v)throw new RuntimeException($m);}
function rejected($f,$m){$caught=false;try{$f();}catch(Throwable$e){$caught=true;}ok($caught,$m);}
try{
 $site=$t.'/site';$pkg=$t.'/package';$state=$t.'/state';
 foreach([$site,$pkg,$state,$site.'/wp-includes',$pkg.'/wp-includes']as$d)mkdir($d,0700);
 file_put_contents($site.'/wp-config.php','<?php');file_put_contents($pkg.'/wp-includes/test.php','<?php // official inert fixture');
 file_put_contents($pkg.'/index.php','<?php // official missing fixture');file_put_contents($site.'/wp-includes/test.php','<?php // changed inert fixture');
 $checks=['wp-includes/test.php'=>md5_file($pkg.'/wp-includes/test.php'),'index.php'=>md5_file($pkg.'/index.php')];
 $manifest=$t.'/checks.json';$list=$t.'/list';file_put_contents($manifest,json_encode(['checksums'=>$checks]));file_put_contents($list,"wp-includes/test.php\nindex.php\n");
 ob_start();$rc=pw_core_transaction('restore',$site,$manifest,$list,$pkg,$state);$text=ob_get_clean();ok($rc===0,'restore completes');
 ok(md5_file($site.'/wp-includes/test.php')===$checks['wp-includes/test.php'],'mismatch restored');ok(md5_file($site.'/index.php')===$checks['index.php'],'missing restored');
 $journals=glob($state.'/backups/core-restore/*/manifest.json');ok(count($journals)===1,'manifest retained');$j=json_decode(file_get_contents($journals[0]),true);ok($j['status']==='COMPLETED','journal verified');
 ok(file_get_contents(dirname($journals[0]).'/0000.data')==='<?php // changed inert fixture','old evidence preserved');
 file_put_contents($site.'/wp-includes/extra.txt','old benign evidence');file_put_contents($list,"wp-includes/extra.txt\n");
 ob_start();$rc=pw_core_transaction('extras',$site,$manifest,$list,'',$state);ob_end_clean();ok($rc===0&&!file_exists($site.'/wp-includes/extra.txt'),'extra backed up and removed');
 foreach(['../outside','wp-includes/../../outside','wp-config.php','wp-content/demo.php','/absolute']as$bad){file_put_contents($list,$bad."\n");rejected(function()use($site,$manifest,$list,$pkg,$state){pw_core_transaction('restore',$site,$manifest,$list,$pkg,$state);},'path protected');}
 file_put_contents($list,"wp-includes/test.php\n");rejected(function()use($site,$manifest,$list,$state){pw_core_transaction('extras',$site,$manifest,$list,'',$state);},'official core cannot be extra');
 unlink($site.'/wp-includes/test.php');file_put_contents($t.'/outside','KEEP');symlink($t.'/outside',$site.'/wp-includes/test.php');
 rejected(function()use($site,$manifest,$list,$pkg,$state){pw_core_transaction('restore',$site,$manifest,$list,$pkg,$state);},'symlink target rejected');ok(file_get_contents($t.'/outside')==='KEEP','outside file intact');
 unlink($site.'/wp-includes/test.php');file_put_contents($site.'/wp-includes/test.php','unchanged');file_put_contents($pkg.'/wp-includes/test.php','bad package');
 rejected(function()use($site,$manifest,$list,$pkg,$state){pw_core_transaction('restore',$site,$manifest,$list,$pkg,$state);},'bad package rejected');ok(file_get_contents($site.'/wp-includes/test.php')==='unchanged','failed source does not overwrite');
 echo "Core transactions: $n assertions PASS\n";
}finally{$it=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($t,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::CHILD_FIRST);foreach($it as$f){if($f->isDir()&&!$f->isLink())rmdir($f->getPathname());else unlink($f->getPathname());}rmdir($t);}
