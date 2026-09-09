<?php
require __DIR__.'/../lib/baseline-csv.php';
$dir = sys_get_temp_dir().'/pw-baseline-csv-'.bin2hex(random_bytes(8)); mkdir($dir, 0700);
$n = 0;
function check_csv($body, $type, $expected) {
    global $dir, $n;
    file_put_contents($dir.'/input', $body);
    try { $result = presswarden_baseline_csv($dir.'/input', $type, 'example.com'); }
    catch (Throwable $e) { $result = null; }
    if ($expected !== $result) throw new RuntimeException('CSV assertion '.($n + 1));
    ++$n;
}
try {
    foreach (['P'=>"name,status,version\n",'T'=>"name,status,version\n",'A'=>"user_login\n",'C'=>"hook,recurrence\n"] as $t=>$h) check_csv($h, $t, '');
    check_csv("name,status,version\r\ndemo,active,1.0\r\n", 'P', "P\texample.com\tdemo\tactive|1.0\n");
    check_csv("name,status,version\ndemo,inactive,\n", 'P', "P\texample.com\tdemo\tinactive|\n");
    check_csv("name,status,version\n\"demo,quoted\",active,1\n", 'P', "P\texample.com\tdemo,quoted\tactive|1\n");
    check_csv("user_login\n\"quoted\"\"name\"\n", 'A', "A\texample.com\tquoted\"name\tadministrator\n");
    check_csv("hook,recurrence\nx,Z\nx,A\nx,Z\n", 'C', "C\texample.com\tx\t[\"A\",\"Z\"]\n");
    check_csv("hook,recurrence\nx,\"Every 5 minutes, custom\"\n", 'C', "C\texample.com\tx\t[\"Every 5 minutes, custom\"]\n");
    check_csv("name,status,version\ndemo,active,1\ndemo,active,1\n", 'P', "P\texample.com\tdemo\tactive|1\n");
    check_csv("name,status,version\ndemo,parent,1\n", 'T', "T\texample.com\tdemo\tparent|1\n");
    foreach (['active','active-network','inactive','must-use','dropin'] as $status) check_csv("name,status,version\ndemo,$status,1\n", 'P', "P\texample.com\tdemo\t$status|1\n");
    check_csv("hook,recurrence\nx,0\n", 'C', "C\texample.com\tx\t[\"0\"]\n");
    check_csv("hook,recurrence\nx,\"A, Z\"\n", 'C', "C\texample.com\tx\t[\"A, Z\"]\n");
    check_csv("hook,recurrence\nx,\n", 'C', "C\texample.com\tx\t[\"\"]\n");
    $inert = '$(touch '.$dir.'/must-not-run)';
    check_csv("user_login\n$inert\n", 'A', "A\texample.com\t$inert\tadministrator\n");
    foreach (["", "Warning: private diagnostic\nuser_login\n", "user_email\n", "user_login\n\n", "user_login\n\"unterminated\n", "user_login\nbad\"quote\n", "user_login\n\"bad\"suffix\n", "user_login\none,two\n", "user_login\n\"two\nlines\"\n", "user_login\nescape\033[31m\n", "user_login\nbad\0x\n", "user_login\nbad|x\n", "user_login\n".str_repeat('x',2049)."\n", "user_login\n".str_repeat('x',65537)."\n", str_repeat('x',8*1024*1024+1)] as $bad) check_csv($bad, 'A', null);
    check_csv("name,status,version\ndemo,active,1\ndemo,inactive,2\n", 'P', null);
    check_csv("name,status,version\ndemo,unknown,1\n", 'P', null);
    check_csv("name,status,version\ndemo,active,1,unexpected\n", 'P', null);
    check_csv("hook,recurrence\n,Daily\n", 'C', null);
    unlink($dir.'/input'); symlink($dir.'/target', $dir.'/input'); file_put_contents($dir.'/target', "user_login\n");
    try { presswarden_baseline_csv($dir.'/input','A','x'); throw new LogicException('Accepted symlink'); } catch (RuntimeException $e) { ++$n; }
    if (file_exists($dir.'/must-not-run')) throw new RuntimeException('Inventory was executed');
    ++$n;
    printf("Baseline CSV: %d assertions passed.\n",$n);
} finally {
    foreach (glob($dir.'/*') as $f) unlink($f); rmdir($dir);
}
