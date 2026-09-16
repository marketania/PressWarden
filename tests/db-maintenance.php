<?php
// Execute the actual helper against controlled SQL responses, with process
// spawning disabled inside the helper's PHP process (shared-host simulation).
if (($argv[1] ?? '') === '--child') {
    define('ARRAY_A', 'ARRAY_A');
    function is_multisite() { return ($GLOBALS['argv'][2] ?? '') === 'db-blog' && ($GLOBALS['argv'][3] ?? '') !== 'single'; }
    function get_site($id) {
        if (($GLOBALS['argv'][3] ?? '') === 'missing') { return null; }
        return (object)array('blog_id'=>$id, 'deleted'=>(($GLOBALS['argv'][3] ?? '') === 'deleted'), 'archived'=>false, 'spam'=>false);
    }
    final class PWDBMFake {
        public $prefix = 'wp_'; public $last_error = ''; public $mode;
        public function __construct($mode) { $this->mode = $mode; }
        public function suppress_errors($on) {}
        public function get_col($sql) {
            if ($this->mode === 'listfail') { $this->last_error = 'PASSWORD=secret-sentinel'; return null; }
            if ($this->mode === 'empty') { return array(); }
            return array('wp_posts', 'foreign_posts', 'wp_options');
        }
        public function get_results($sql, $format) {
            if (strpos($sql, 'foreign_posts') !== false) { throw new RuntimeException('out-of-scope table touched'); }
            if ($this->mode === 'queryfail') { $this->last_error = 'PASSWORD=secret-sentinel'; return null; }
            if ($this->mode === 'nostatus') { return array(); }
            if ($this->mode === 'noteonly') { return array(array('Msg_type'=>'note','Msg_text'=>'recreate + analyze')); }
            if ($this->mode === 'bad') { return array(array('Msg_type'=>'error','Msg_text'=>'private-error-payload')); }
            if ($this->mode === 'unsupported') { return array(array('Msg_type'=>'note','Msg_text'=>"The storage engine doesn't support check")); }
            // Optimization recreation notes alone must not succeed, but with OK they may.
            return array(array('Msg_type'=>'note','Msg_text'=>'recreate + analyze'), array('Msg_type'=>'status','Msg_text'=>'OK'));
        }
        public function esc_like($s) { return addcslashes($s, '_%\\'); }
        public function prepare($sql, $pattern) {
            if ($pattern !== 'wp\\_%') { throw new RuntimeException('prefix wildcard not escaped'); }
            return $sql;
        }
        public function get_var($sql) {
            if ($this->mode === 'queryfail') { $this->last_error = 'PASSWORD=secret-sentinel'; return null; }
            if ($this->mode === 'badsize') { return '123junk'; }
            return '1000';
        }
    }
    $args = array($argv[4]);
    $wpdb = new PWDBMFake($argv[3]);
    putenv('PRESSWARDEN_DB_ACTION='.$argv[4]);
    require __DIR__.'/../lib/'.$argv[2].'.php';
    exit(0);
}
$cases = array(
    array('db-maintenance','ok','check',0),
    array('db-maintenance','ok','optimize',0),
    array('db-maintenance','unsupported','check',0),
    array('db-maintenance','listfail','check',31),
    array('db-maintenance','empty','check',31),
    array('db-maintenance','queryfail','check',31),
    array('db-maintenance','nostatus','check',31),
    array('db-maintenance','noteonly','check',31),
    array('db-maintenance','bad','check',10),
    array('db-maintenance','bad','repair',10),
    array('db-maintenance','nostatus','optimize',10),
    array('db-maintenance','noteonly','optimize',10),
    array('db-maintenance','bad','optimize',10),
    array('db-size','ok','',0),
    array('db-size','queryfail','',2),
    array('db-size','badsize','',2),
    array('db-blog','ok','2',0),
    array('db-blog','ok','0',2),
    array('db-blog','ok','002',2),
    array('db-blog','single','2',2),
    array('db-blog','missing','2',2),
    array('db-blog','deleted','2',2),
);
foreach ($cases as $case) {
    list($helper,$mode,$action,$expected)=$case;
    $cmd=array(PHP_BINARY,'-d','disable_functions=proc_open,proc_close,exec,shell_exec,system,passthru',__FILE__,'--child',$helper,$mode,$action);
    $proc=proc_open($cmd,array(0=>array('file','/dev/null','r'),1=>array('pipe','w'),2=>array('pipe','w')),$pipes);
    if (!is_resource($proc)) { throw new RuntimeException('could not start test'); }
    $out=stream_get_contents($pipes[1]); $err=stream_get_contents($pipes[2]); fclose($pipes[1]); fclose($pipes[2]);
    $rc=proc_close($proc);
    if ($rc!==$expected || strpos($out.$err,'secret-sentinel')!==false || strpos($out.$err,'private-error-payload')!==false) {
        throw new RuntimeException($helper.':'.$mode.':'.$action.' expected '.$expected.' got '.$rc.' '.$out.$err);
    }
    if ($helper==='db-maintenance' && $expected===0 && strpos($out,"PWDBM1\tDONE\t".$action."\t2")===false) {
        throw new RuntimeException('missing completion/table-scope proof');
    }
    if ($helper==='db-blog' && $expected===0 && trim($out)!=="PWDBBLOG1\t2") { throw new RuntimeException('wrong blog'); }
    if ($helper==='db-size' && $expected===0 && trim($out)!=="PWDBSIZE1\t1000") { throw new RuntimeException('wrong size'); }
}
echo "Native database helpers: ".count($cases)." restricted-host, SQL-result, privacy and prefix-scope cases PASS\n";
