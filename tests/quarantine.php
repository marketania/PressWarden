<?php
require __DIR__.'/../lib/quarantine.php';
$base = sys_get_temp_dir().'/presswarden-quarantine-'.bin2hex(random_bytes(6));
mkdir($base, 0700); $tests = 0;
function check($v, $why) { global $tests; ++$tests; if (!$v) throw new RuntimeException('FAIL: '.$why); }
function refused($f, $why) { $caught = false; try { $f(); } catch (Throwable $e) { $caught = true; } check($caught, $why); }
function makeSite($p) {
    mkdir($p.'/wp-admin', 0700, true); mkdir($p.'/wp-content/plugins/demo', 0700, true); mkdir($p.'/wp-includes', 0700, true);
    file_put_contents($p.'/wp-settings.php', '<?php // inert'); file_put_contents($p.'/wp-load.php', '<?php // inert');
    file_put_contents($p.'/wp-includes/version.php', '<?php $wp_version="7.1";');
}
function fixture($name) {
    global $base;
    $root = "$base/$name"; mkdir($root); $site="$root/site"; makeSite($site);
    $p = ['root'=>$root,'quarantine'=>"$root/quarantine",'sites'=>[$site],'blocked'=>["$root/private"], 'mode'=>'generic', 'check'=>'test', 'section'=>'synthetic fixture', 'run_id'=>'test-123'];
    return [$site, $p];
}
function capture($f) { ob_start(); try { return $f(); } finally { ob_end_clean(); } }
function cases($p) { return glob($p['quarantine'].'/case-*') ?: []; }
function clean($path) {
    if (is_link($path) || !is_dir($path)) { @unlink($path); return; }
    foreach (scandir($path) as $n) if ($n!=='.'&&$n!=='..') clean($path.'/'.$n);
    @rmdir($path);
}
class CopyCorruptor extends PressWardenQuarantine {
    protected function copyObject($s,$d,$e) { parent::copyObject($s,$d,$e); file_put_contents($d,'corrupted'); }
}
class SourceMutator extends PressWardenQuarantine {
    protected function copyObject($s,$d,$e) { parent::copyObject($s,$d,$e); file_put_contents($s,'changed after copy'); }
}
class CopyFailure extends PressWardenQuarantine {
    protected function copyObject($s,$d,$e) { throw new RuntimeException('simulated copy failure'); }
}
class ManifestFailure extends PressWardenQuarantine {
    protected function writeNew($p,$d) { if (basename($p)==='manifest.json') throw new RuntimeException('simulated manifest failure'); parent::writeNew($p,$d); }
}
class JournalFailure extends PressWardenQuarantine {
    protected function event($c,$i,$e,$path='') { if ($e === 'remove-started') throw new RuntimeException('simulated journal failure'); parent::event($c,$i,$e,$path); }
}
class OutcomeFailure extends PressWardenQuarantine {
    protected function event($c,$i,$e,$path='') { if ($e === 'removed') throw new RuntimeException('simulated outcome failure'); parent::event($c,$i,$e,$path); }
}
class RemovalFailure extends PressWardenQuarantine {
    protected function removeEntry($p,$dir) { return false; }
}
class UnexpectedFile extends PressWardenQuarantine {
    protected function removeEntry($p,$dir) { if ($dir) file_put_contents($p.'/unexpected','new'); return parent::removeEntry($p,$dir); }
}
class AncestorMutator extends PressWardenQuarantine {
    protected function event($c,$i,$e,$path='') {
        parent::event($c,$i,$e,$path);
        if ($e === 'remove-started') {
            $parent = dirname($path); rename($parent, $parent.'-old'); mkdir($parent);
            rename($parent.'-old/'.basename($path), $path);
        }
    }
}
try {
    [$site,$policy] = fixture('regular'); $path="$site/wp-content/plugins/demo/test.php";
    $source="<?php /* inert test; never execute */ echo 'fixture';\n"; file_put_contents($path,$source); chmod($path,0755);
    $q = new PressWardenQuarantine(); $plan=$q->plan($policy,[$path]);
    check(is_file($path) && !file_exists($policy['quarantine']), 'planning makes no source/quarantine changes');
    $mask=umask(0022); $id=capture(function()use($q,$plan){return $q->apply($plan);}); check(umask()===0022,'caller umask preserved'); umask($mask);
    check(!file_exists($path),'approved file removed'); $case=$policy['quarantine'].'/'.$id;
    check(file_get_contents($case.'/objects/00001.bin')===$source,'copy byte-identical');
    check((fileperms($case)&0077)===0 && (fileperms($case.'/objects/00001.bin')&0177)===0,'evidence private and non-executable');
    $v=$q->verify($policy['quarantine'],$id); check($v['objects']===1 && $v['removal']==='recorded complete','verification separates copy and outcome');
    $m=$q->readJson($case.'/manifest.json'); check($m['run_id']==='test-123' && $m['items'][0]['original']===$path,'traceable original and run');
    check(!strpos(file_get_contents($case.'/manifest.json'),"echo 'fixture'"),'manifest omits source body');
    file_put_contents($case.'/objects/00001.bin','tampered'); refused(function()use($q,$policy,$id){$q->verify($policy['quarantine'],$id);},'tampered stored bytes refused');

    [$site,$p]=fixture('changed'); $f="$site/change.php";file_put_contents($f,'old');$plan=$q->plan($p,[$f]);file_put_contents($f,'new');
    refused(function()use($q,$plan){capture(function()use($q,$plan){$q->apply($plan);});},'change after approval snapshot refused');
    check(file_get_contents($f)==='new' && !cases($p),'changed original survives without capture');
    $plan=$q->plan($p,[$f]); rename($f,$f.'.old');file_put_contents($f,'new');
    refused(function()use($q,$plan){$q->apply($plan);},'same bytes new inode refused'); check(is_file($f),'replacement original retained');

    foreach (['CopyCorruptor','SourceMutator','CopyFailure','ManifestFailure','JournalFailure','RemovalFailure'] as $class) {
        [$site,$p]=fixture($class);$f="$site/sample.php";file_put_contents($f,'evidence');$obj=new $class();$plan=$obj->plan($p,[$f]);
        refused(function()use($obj,$plan){capture(function()use($obj,$plan){$obj->apply($plan);});},$class.' refuses removal');
        check(is_file($f),$class.' keeps original'); check(count(cases($p))===1,$class.' retains case');
    }
    [$site,$p]=fixture('post-unlink-write');$f="$site/a.php";file_put_contents($f,'a');$g="$site/b.php";file_put_contents($g,'b');$o=new OutcomeFailure();$plan=$o->plan($p,[$f,$g]);
    refused(function()use($o,$plan){capture(function()use($o,$plan){$o->apply($plan);});},'post-removal log failure explicit');
    check(!file_exists($f) && is_file($g),'post-removal failure stops before next target');
    $id=basename(cases($p)[0]);check($q->verify($p['quarantine'],$id)['removal']==='incomplete or unconfirmed','unconfirmed outcome not fabricated');

    [$site,$p]=fixture('links');$outside=$base.'/outside';file_put_contents($outside,'outside data');$link="$site/link.php";symlink($outside,$link);
    $plan=$q->plan($p,[$link]);$id=capture(function()use($q,$plan){return $q->apply($plan);});
    check(!is_link($link) && file_get_contents($outside)==='outside data','unlink only symlink, not referent');
    check(file_get_contents($p['quarantine'].'/'.$id.'/objects/00001.bin')===$outside,'link target stored inertly as text');
    check($q->verify($p['quarantine'],$id)['objects']===1,'link-text hash verified');
    $dangling="$site/dangling";symlink('/not/a/real/target',$dangling);$plan=$q->plan($p,[$dangling]);capture(function()use($q,$plan){$q->apply($plan);});check(!is_link($dangling),'dangling link supported');
    symlink($base,"$site/alias");refused(function()use($q,$p,$site){$q->plan($p,["$site/alias/outside"]);},'symlink ancestor refused');check(is_file($outside),'ancestor target preserved');
    link($outside,"$site/hard.php");refused(function()use($q,$p,$site){$q->plan($p,["$site/hard.php"]);},'hard-linked file refused');
    if(function_exists('posix_mkfifo')){posix_mkfifo("$site/pipe",0600);refused(function()use($q,$p,$site){$q->plan($p,["$site/pipe"]);},'FIFO refused without reading');}

    [$site,$p]=fixture('directory');mkdir("$site/.git/objects",0700,true);file_put_contents("$site/.git/objects/a",'object');symlink('/missing',"$site/.git/link");
    $plan=$q->plan($p,["$site/.git", "$site/.git/objects/a"]);check(count($plan['items'])===1,'ancestor selection collapses duplicates');
    $id=capture(function()use($q,$plan){return $q->apply($plan);});check(!is_dir("$site/.git"),'verified VCS directory removed leaf-first');check($q->verify($p['quarantine'],$id)['objects']===2,'directory copies and link text verified');
    mkdir("$site/.git");file_put_contents("$site/.git/a",'a');$o=new UnexpectedFile();$plan=$o->plan($p,["$site/.git"]);
    refused(function()use($o,$plan){capture(function()use($o,$plan){$o->apply($plan);});},'unexpected directory member stops empty-directory removal');check(file_get_contents("$site/.git/unexpected")==='new','new directory member never recursively deleted');
    refused(function()use($q,$p,$site){$q->plan($p,["$site/wp-content"]);},'arbitrary directory protected');
    makeSite("$site/.svn/nested");refused(function()use($q,$p,$site){$q->plan($p,["$site/.svn"]);},'nested WordPress site never removed');

    [$site,$p]=fixture('protected');
    foreach (['wp-config.php','.htaccess','.user.ini','php.ini','wp-login.php','wp-admin/x.php','wp-includes/a.php','wp-content/themes/a/functions.php'] as $r){
        if(!is_dir(dirname("$site/$r")))mkdir(dirname("$site/$r"),0700,true);file_put_contents("$site/$r",'protected');
        refused(function()use($q,$p,$site,$r){$q->plan($p,["$site/$r"]);},'protected '.$r);check(is_file("$site/$r"),'protected file survives');
    }
    $f="$site/a.php";file_put_contents($f,'a');$b=$p;$b['blocked'][]=$f;
    refused(function()use($q,$b,$f){$q->plan($b,[$f]);},'explicit exclusion protected');
    $b=$p;$b['quarantine']="$site/quarantine";$plan=$q->plan($b,[$f]);
    refused(function()use($q,$plan){$q->apply($plan);},'web-site quarantine destination refused');check(is_file($f),'web-site refusal preserves original');
    $b=$p;symlink($base.'/outside', $p['quarantine']);$plan=$q->plan($b,[$f]);refused(function()use($q,$plan){$q->apply($plan);},'symlink quarantine root refused');check(is_file($f),'unsafe destination leaves original');
    foreach ([$base.'/outside', "$site/../outside", "$site/./a.php", "$site/a.php\n"] as $bad) refused(function()use($q,$p,$bad){$q->plan($p,[$bad]);},'unsafe/out-of-scope path');
    refused(function()use($q,$p){$q->verify($p['quarantine'],'../outside');},'case traversal refused');
    refused(function()use($q,$p){$q->plan($p,[]);},'empty selection refused');
    refused(function()use($q,$p,$f){$q->plan($p,array_fill(0,1001,$f));},'target-count bound');

    [$site,$p]=fixture('ancestor-mutated');mkdir("$site/parent");$f="$site/parent/a.php";file_put_contents($f,'same file');
    $o=new AncestorMutator();$plan=$o->plan($p,[$f]);
    refused(function()use($o,$plan){capture(function()use($o,$plan){$o->apply($plan);});},'ancestor inode replacement before unlink refused');
    check(is_file($f),'unchanged leaf retained when parent changes');
    [$site,$p]=fixture('cleanup');$p['mode']='cleanup';mkdir("$site/__MACOSX");file_put_contents("$site/__MACOSX/x",'metadata');
    $plan=$q->plan($p,["$site/__MACOSX"]);capture(function()use($q,$plan){$q->apply($plan);});check(!is_dir("$site/__MACOSX"),'approved OS metadata directory supported');
    file_put_contents("$site/.gitignore",'metadata');mkdir("$site/.git");
    refused(function()use($q,$p,$site){$q->plan($p,["$site/.gitignore"]);},'live Git cleanup protection repeated at action time');
    file_put_contents("$site/wp-content/plugins/demo/.gitignore",'packaged');
    refused(function()use($q,$p,$site){$q->plan($p,["$site/wp-content/plugins/demo/.gitignore"]);},'packaged development metadata protected');
    refused(function()use($q){$q->plainParents('relative/path',true);},'relative inspection path rejected without looping');

    file_put_contents("$site/arbitrary.php",'code');
    refused(function()use($q,$p,$site){$q->plan($p,["$site/arbitrary.php"]);},'cleanup cannot accept arbitrary code');
    [$site,$p]=fixture('private-alias');$f="$site/secret.php";file_put_contents($f,'private');symlink($f,$p['root'].'/config-alias');$p['blocked'][]=$p['root'].'/config-alias';
    refused(function()use($q,$p,$f){$q->plan($p,[$f]);},'resolved private config alias protected');

    [$site,$p]=fixture('limit');$f="$site/large.sql";$h=fopen($f,'wb');ftruncate($h,PressWardenQuarantine::MAX_BYTES+1);fclose($h);
    refused(function()use($q,$p,$f){$q->plan($p,[$f]);},'sparse oversized file refused before full read');check(is_file($f),'oversized original retained');
    $dir="$site/.git";mkdir($dir);$cur=$dir;for($i=0;$i<66;$i++){$cur.='/d';mkdir($cur);}
    refused(function()use($q,$p,$dir){$q->plan($p,[$dir]);},'recursive depth bound');
    [$site,$p]=fixture('legacy');mkdir($p['quarantine']);mkdir($p['quarantine'].'/20260907-120000');file_put_contents($p['quarantine'].'/20260907-120000/legacy.php','old evidence');
    $f="$site/a.php";file_put_contents($f,'a');$plan=$q->plan($p,[$f]);$id=capture(function()use($q,$plan){return $q->apply($plan);});
    check(file_get_contents($p['quarantine'].'/20260907-120000/legacy.php')==='old evidence','legacy quarantine unmodified');
    symlink($outside,$p['quarantine'].'/'.$id.'/objects/00002.bin');refused(function()use($q,$p,$id){$q->verify($p['quarantine'],$id);},'unexpected/symlink object rejected');
    echo "Quarantine safety: $tests checks passed\n";
} finally { clean($base); }
