<?php
/** CI-only SQL integration; temporary tables in an isolated MySQL service. */
require __DIR__.'/db-scan.php';
if (getenv('PW_TEST_REAL_DB') !== '1' || !extension_loaded('mysqli')) { fwrite(STDERR,"MySQL integration environment is required\n"); exit(2); }
mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
$link = new mysqli('127.0.0.1', 'root', getenv('PW_TEST_DB_PASSWORD'), 'presswarden_db_test', 3306);
$link->set_charset('utf8mb4');
class PressWardenMysqlTestDb extends PressWardenTestDb {
    private $link;
    public function __construct($link) { $this->link=$link; }
    public function prepare($sql, ...$values) { foreach($values as $value){$at=strpos($sql,'%s');$sql=substr_replace($sql,"'".$this->link->real_escape_string($value)."'",$at,2);}return $sql; }
    public function get_results($sql,$mode) {
        if (strpos($sql,'SELECT ')!==0 || $mode!=='ARRAY_A') throw new RuntimeException('not SELECT');
        $this->queries[]=$sql;
        try { return $this->link->query($sql)->fetch_all(MYSQLI_ASSOC); }
        catch(Throwable $e){$this->last_error=$e->getMessage();return null;}
    }
}
$db=new PressWardenMysqlTestDb($link);
$link->query('CREATE TEMPORARY TABLE wpx_3_options(option_id BIGINT PRIMARY KEY, option_name VARCHAR(255), option_value LONGTEXT)');
$link->query('CREATE TEMPORARY TABLE wpx_3_posts(ID BIGINT PRIMARY KEY, post_content LONGTEXT)');
$link->query('CREATE TEMPORARY TABLE wpx_users(ID BIGINT PRIMARY KEY, user_login VARCHAR(60), user_email VARCHAR(100))');
$link->query('CREATE TEMPORARY TABLE wpx_usermeta(umeta_id BIGINT PRIMARY KEY, user_id BIGINT, meta_key VARCHAR(255), meta_value LONGTEXT)');
$script='<script>eval(atob("'.base64_encode('document.write("x");').'"));</script>';
for($i=1;$i<=1010;++$i){
 $value=$i===1005?serialize(['unicode'=>'é安全','widget'=>$script]):'<script src="https://cdn.example.invalid/app.js"></script>';
 $link->query($db->prepare("INSERT INTO wpx_3_options VALUES ($i,'widget_text',%s)",$value));
}
$link->query("INSERT INTO wpx_users VALUES (1,'adminbackup','adminbackup@wordpress.org'),(2,'adminbackup','adminbackup@wordpress.org')");
$link->query($db->prepare("INSERT INTO wpx_usermeta VALUES (1,1,'wpx_3_capabilities',%s),(2,2,'wpx_3_capabilities',%s),(3,1,'other_capabilities',%s)",serialize(['note'=>'administrator']),serialize(['administrator'=>false]),serialize(['administrator'=>true])));
[$rc,$records]=pw_test_scan($db);
if($rc!==0 || count($records)!==3 || $records[0][4]!=='1005' || $records[1][4]!=='2') {fwrite(STDERR,json_encode($records)."\nSQL corpus failed\n");exit(1);}
if((int)$link->query('SELECT COUNT(*) FROM wpx_3_options')->fetch_row()[0]!== 1010)exit(1);
[$rc,$records]=pw_test_scan($db,1000); if($rc!==2 || $records[0][1]!=='row_limit')exit(1);
$link->query($db->prepare("INSERT INTO wpx_3_posts VALUES (1,%s)",str_repeat(' ',1048576).$script));
[$rc,$records]=pw_test_scan($db); if($rc!==2 || !in_array('value_size',array_column($records,1),true))exit(1);
$db->posts='nonexistent_posts';[$rc,$records]=pw_test_scan($db);if($rc!==2)exit(1);
echo "MySQL: keyset pagination, binary byte lengths, nonstandard/multisite prefixes, role keys, oversize and query failure: PASS\n";
