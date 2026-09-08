<?php
require_once __DIR__.'/../lib/db-scan.php';
class PressWardenTestDb {
    public $options='wpx_3_options', $posts='wpx_3_posts', $users='wpx_users', $usermeta='wpx_usermeta', $prefix='wpx_3_', $last_error='';
    public $data=['option'=>[],'post'=>[],'admin'=>[]], $queries=[], $fail='', $suppressed=false;
    public function prepare($sql, ...$values) { foreach($values as $value) $sql=preg_replace('/%s/', "'".str_replace("'","''",$value)."'",$sql,1); return $sql; }
    public function suppress_errors($new) { $old=$this->suppressed;$this->suppressed=$new;return $old; }
    public function get_results($sql,$mode) {
        $this->queries[]=$sql;
        if (strpos($sql,'SELECT ')!==0 || $mode!=='ARRAY_A') throw new RuntimeException('not SELECT');
        $source = strpos($sql,'usermeta')!==false ? 'admin' : (strpos($sql,'_options')!==false ? 'option' : 'post');
        if ($this->fail===$source) { $this->last_error='PASSWORD_AND_SQL_MUST_NOT_LEAK';return null; }
        preg_match('/WHERE (?:um\.umeta_id|option_id|ID)>([0-9]+)/',$sql,$m);$after=(int)$m[1];
        preg_match('/LIMIT ([0-9]+)$/',$sql,$m);$limit=(int)$m[1];
        return array_slice(array_values(array_filter($this->data[$source],function($r)use($after){return $r['cursor_id']>$after;})),0,$limit);
    }
}
function pw_test_row($id,$body,$extra=[]) { return array_merge(['cursor_id'=>$id,'rid'=>$id,'bytes'=>strlen($body),'body'=>strlen($body)>1048576?null:$body,'name'=>'widget_text'],$extra); }
function pw_test_scan($db,$maxRows=5000,$maxBytes=33554432) { $records=[];$rc=(new PressWardenDbScan($db,function($r)use(&$records){$records[]=$r;},$maxRows,$maxBytes))->run();return [$rc,$records]; }
if (realpath($_SERVER['SCRIPT_FILENAME'])!==__FILE__) return;
$count=0;
function check_scan($c,$m){global $count;++$count;if(!$c){fwrite(STDERR,"FAIL: $m\n");exit(1);}}
$js='<script>eval(atob("'.base64_encode('document.write("x");').'"));</script>';
$db=new PressWardenTestDb();
for($i=1;$i<=1005;++$i)$db->data['option'][]=pw_test_row($i,$i===1005?$js:'<script src="https://cdn.invalid/app.js"></script>');
[$rc,$records]=pw_test_scan($db);check_scan($rc===0,'full scan');
check_scan(count($records)===2 && $records[0][4]==='1005','finding beyond old LIMIT 1000');
check_scan(!$db->suppressed,'restore error setting');
check_scan(count($db->queries)>60,'actual pagination');
foreach($db->queries as $q)check_scan(strpos($q,'ORDER BY ')!==false && strpos($q,'CASE WHEN OCTET_LENGTH')!==false,'bounded ordered SELECT');
[$rc,$records]=pw_test_scan($db,1000);check_scan($rc===2 && $records[0][1]==='row_limit','limit visible');
$db=new PressWardenTestDb();$db->data['post']=[pw_test_row(1,$js),pw_test_row(2,$js)];
check_scan(pw_test_scan($db,2)[0]===0,'exact limit not incomplete');
check_scan(pw_test_scan($db,1)[0]===2,'one beyond limit incomplete');
$db->fail='option';[$rc,$records]=pw_test_scan($db);check_scan($rc===2,'query failure');
check_scan(count(array_filter($records,function($r){return $r[0]==='FINDING';}))===2,'other tables still inspected');
check_scan(strpos(json_encode($records),'PASSWORD_AND_SQL')===false,'query details redacted');
$db=new PressWardenTestDb();$db->data['option']=[pw_test_row(1,str_repeat('x',1048577)),pw_test_row(2,$js)];
[$rc,$records]=pw_test_scan($db);check_scan($rc===2 && $records[0][1]==='value_size','oversize incomplete');
check_scan($records[1][0]==='FINDING','later finding retained after oversize');
$db->data['option']=[pw_test_row(1,str_repeat('x',1024)),pw_test_row(2,$js)];
[$rc,$records]=pw_test_scan($db,5000,1024);check_scan($rc===2 && $records[0][1]==='byte_limit','byte budget');
$db->data['option']=[pw_test_row(1,'a:1:{s:4:"html";O:6:"BadObj":0:{}}'),pw_test_row(2,$js)];
[$rc,$records]=pw_test_scan($db);check_scan($rc===2 && $records[0][1]==='value_analysis','unsupported objects incomplete');
$db=new PressWardenTestDb();
foreach([['note'=>'administrator'],['nested'=>['administrator'=>true]],['administrator'=>false],['administrator'=>true]] as $i=>$cap)$db->data['admin'][]=pw_test_row($i+1,serialize($cap),['login'=>'adminbackup','email'=>'adminbackup@wordpress.org']);
[$rc,$records]=pw_test_scan($db);check_scan($rc===0 && count($records)===3,'only top level role keys reviewed');
check_scan($records[0][1]==='REVIEW' && $records[0][4]==='3','false role value follows WordPress key semantics');
check_scan(strpos(json_encode($records),'adminbackup')===false,'PII not emitted');
$db->options='unsafe`table';[$rc,$records]=pw_test_scan($db);check_scan($rc===2,'unsafe identifier rejected');
try {new PressWardenDbScan($db,function(){},0);check_scan(false,'bad limit');}catch(RuntimeException $e){check_scan(true,'bad limit');}
$db=new PressWardenTestDb();$db->data['option']=[pw_test_row(1,$js)];
try {(new PressWardenDbScan($db,function(){throw new RuntimeException('output');}))->run();check_scan(false,'output failure');}catch(RuntimeException $e){check_scan(true,'output failure');}
printf("Database paging, budgets, query failures and evidence checks: %d passed\n",$count);
