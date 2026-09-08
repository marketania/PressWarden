<?php
require __DIR__.'/../lib/db-threat-classify.php';
$count = 0;
function check_db($condition, $message) { global $count; ++$count; if (!$condition) { fwrite(STDERR, "FAIL: $message\n"); exit(1); } }
function throws_db($fn, $name) { try { $fn(); check_db(false, $name); } catch (RuntimeException $e) { check_db(true, $name); } }
$decoder = 'eval(atob("'.base64_encode('document.write("x");').'"));';
$script = '<script>'.$decoder.'</script>';
$cdn = '<script src="https://cdn.example.invalid/app.js"></script>';
$gated = 'if(document.cookie.indexOf("seen")<0){location.assign(atob("'.base64_encode('https://remote.invalid/a'). '"));}';
$cases = [
    [$script, 'option', 'widget_text', 'PW-DB-001'],
    ['<script>'.$gated.'</script>', 'post', '', 'PW-DB-001'],
    [$gated, 'option', 'custom_js', 'PW-DB-001'],
    [serialize(['value'=>$script]), 'option', 'widget_text', 'PW-DB-001'],
    [serialize(['one'=>['html'=>$script]]), 'option', 'widget_text', 'PW-DB-001'],
    [json_encode(['widgets'=>[['html'=>$script]]]), 'option', 'widget_text', 'PW-DB-001'],
    [serialize(['json'=>json_encode(['html'=>$script])]), 'option', 'widget_text', 'PW-DB-001'],
    [serialize(serialize(['html'=>$script])), 'option', 'widget_text', 'PW-DB-001'],
    [$cdn, 'option', 'header_scripts', 'PW-DB-003'],
    [$cdn, 'post', '', null],
    [$cdn, 'option', 'widget_text', null],
    [$cdn.'<script>const a=atob("aGVsbG8="); console.log(a);</script>', 'post', '', null],
    [serialize(['cdn'=>$cdn,'decoder'=>'const e=atob("aGVsbG8=");']), 'option', 'widget_text', null],
    ['<script>const e=atob("aHR0cHM6Ly9yZW1vdGUuaW52YWxpZC9h");</script><script>if(document.cookie){location.assign(e);}</script>', 'post','',null],
    ['<script>// '.$decoder."\n</script>", 'post', '', null],
    ['<script>const example='.json_encode($decoder).';</script>', 'post', '', null],
    ['<!--'.$script.'-->', 'option', 'widget_text', null],
    ['<textarea>'.$script.'</textarea>', 'post', '', null],
    ['<template>'.$script.'</template>', 'post', '', null],
    ['<template><template>text</template>'.$script.'</template>', 'post', '', null],
    ['<textarea title="x>y">'.$script.'</textarea>', 'post', '', null],
    ['<style>'.$script.'</style>', 'post', '', null],
    [htmlspecialchars($script, ENT_QUOTES), 'post', '', null],
    ['<script type="application/ld+json">'.json_encode(['example'=>$decoder]).'</script>', 'post', '', null],
    ['<script type="text/template">'.$decoder.'</script>', 'post', '', null],
    ['<script src="https://cdn.example.invalid/a.js">'.$decoder.'</script>', 'post', '', null],
    ['<iframe src="https://video.example.invalid/" width="640"></iframe><div style="display:none"></div>', 'post', '', null],
    ['<iframe src="https://tracking.example.invalid/" style="display:none"></iframe>', 'post', '', null],
    ['<iframe width="0" src="https://tracking.example.invalid/" onload="'.htmlspecialchars($decoder, ENT_QUOTES).'">', 'post', '', 'PW-DB-002'],
    ['<iframe width="0" src="/local" onload="'.htmlspecialchars($decoder, ENT_QUOTES).'">', 'post', '', null],
    ['<iframe src="https://remote.invalid/" width="640" title="width=0" onload="'.htmlspecialchars($decoder, ENT_QUOTES).'">', 'post', '', null],
    ['<?php eval(base64_decode($_POST["x"]));', 'post', '', 'PW-DB-005'],
    ['<?php system($_GET["x"]);', 'post', '', 'PW-DB-005'],
    ['<?php /* eval(base64_decode($_POST["x"])); */', 'post', '', null],
    ['<?php $x=\'eval(base64_decode($_POST["x"]));\';', 'post', '', null],
    ['<?php $x=base64_decode("aGVsbG8="); system("ls");', 'post', '', null],
    ['<?php function first(){ return $_POST["x"]; } function second(){ system("ls"); }', 'post', '', null],
    [str_repeat('A',180), 'option', str_repeat('a',32), null],
    ['https://first.invalid https://second.invalid', 'option', str_repeat('a',32), null],
    [base64_encode(str_repeat(' ',100).$gated), 'option', str_repeat('a',32), 'PW-DB-006'],
];
foreach ($cases as $i=>$case) { $result = presswarden_db_classify_content($case[0],$case[1],$case[2]); check_db(($result[1]??null)===$case[3], "classifier $i"); }
$reader = new PressWardenDbValues();
foreach ([null, true, false, 0, -7, 'é " ; { test', ['x'=>[false, null,'text'],8=>'eight']] as $i=>$value) check_db($reader->read(serialize($value))===$value,"scalar/array $i");
foreach (['O:6:"BadObj":0:{}','C:6:"BadObj":1:{x}','R:1;','r:1;', 's:50:"short";', 'a:2:{s:1:"x";i:1;s:1:"x";i:2;}', 'a:1:{s:1:"x";i:2;', 's:1:"x";JUNK', str_repeat('a:1:{i:0;',30).'N;'.str_repeat('}',30)] as $i=>$bad) throws_db(function()use($reader,$bad){$reader->read($bad);},"malformed $i");
$autoloaded = false;
spl_autoload_register(function()use(&$autoloaded){$autoloaded=true;});
throws_db(function()use($reader){$reader->read('O:6:"BadObj":0:{}');},'objects not loaded');
check_db(!$autoloaded,'autoload must not run');
foreach ([['administrator'=>true], ['administrator'=>false]] as $v) check_db(presswarden_db_admin_role(serialize($v)), 'role key semantics');
foreach ([['note'=>'administrator'],['not_administrator'=>true],['nested'=>['administrator'=>true]],[], 'administrator'] as $v) check_db(!presswarden_db_admin_role(serialize($v)), 'unrelated capability text');
check_db(presswarden_db_classify_admin('adminbackup','adminbackup@wordpress.org')[0]==='REVIEW','identity not proof');
check_db(presswarden_db_classify_admin('owner','owner@example.invalid')===null,'normal owner');
throws_db(function(){presswarden_db_units(str_repeat('x',1048577));},'value size bound');
check_db(strpos(presswarden_db_clean("x\n\033y"),"\033")===false,'terminal escaping');
check_db(count(presswarden_db_classify_all($script.'<?php eval($_GET["x"]);','post'))===2,'multiple rule preservation');
printf("Database content/structure/capability cases: %d passed\n", $count);
