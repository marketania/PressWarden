<?php
require __DIR__.'/../lib/report-json.php';
$dir = sys_get_temp_dir().'/presswarden-json-test-'.bin2hex(random_bytes(8));
mkdir($dir, 0700);
$checks = 0;
function verify($condition, $label) { global $checks; ++$checks; if (!$condition) throw new RuntimeException($label); }
function rejects($fn) { try { $fn(); return false; } catch (Throwable $e) { return true; } }
try {
    $data = ['tool'=>'PressWarden','suite'=>'test','coverage_status'=>'complete','checks'=>[], 'private_marker'=>'not-to-be-printed'];
    $json = json_encode($data)."\n";
    $old = umask(0000);
    presswarden_report_json_write("$dir/test-run-summary.json", $json);
    verify(umask() === 0000, 'umask restored'); umask($old);
    verify(file_get_contents("$dir/test-run-summary.json") === $json, 'complete JSON');
    verify((fileperms("$dir/test-run-summary.json") & 0077) === 0, 'private permissions');
    verify(rejects(function()use($dir){presswarden_report_json_write("$dir/test-run-summary.json", 'replacement');}), 'unique history is immutable');
    verify(file_get_contents("$dir/test-run-summary.json") === $json, 'historical bytes preserved');
    symlink("$dir/test-run-summary.json", "$dir/symlink.json");
    verify(rejects(function()use($dir){presswarden_report_json_write("$dir/symlink.json", 'replacement');}), 'symlink refused');
    verify(is_link("$dir/symlink.json"), 'symlink preserved');
    verify(file_get_contents("$dir/test-run-summary.json") === $json, 'symlink target preserved');
    symlink("$dir/nonexistent.json", "$dir/dangling.json");
    verify(rejects(function()use($dir){presswarden_report_json_write("$dir/dangling.json", 'replacement');}), 'dangling link refused');
    verify(!file_exists("$dir/nonexistent.json"), 'dangling target not created');
    mkdir("$dir/directory.json");
    verify(rejects(function()use($dir){presswarden_report_json_write("$dir/directory.json", 'replacement');}), 'directory refused');
    presswarden_report_publish_latest("$dir/test-run-summary.json", "$dir/test-latest-summary.json");
    verify(file_get_contents("$dir/test-latest-summary.json") === $json, 'latest created');
    verify((fileperms("$dir/test-latest-summary.json") & 0077) === 0, 'latest private');
    $next = str_replace('complete','incomplete',$json);
    presswarden_report_json_write("$dir/test-next-summary.json", $next);
    presswarden_report_publish_latest("$dir/test-next-summary.json", "$dir/test-latest-summary.json");
    verify(file_get_contents("$dir/test-latest-summary.json") === $next, 'latest replaced completely');
    verify(file_get_contents("$dir/test-run-summary.json") === $json, 'older run untouched');
    file_put_contents("$dir/invalid.json", '{');
    verify(rejects(function()use($dir){presswarden_report_publish_latest("$dir/invalid.json", "$dir/test-latest-summary.json");}), 'invalid JSON refused');
    verify(file_get_contents("$dir/test-latest-summary.json") === $next, 'latest survives invalid input');
    verify(rejects(function()use($dir){presswarden_report_publish_latest("$dir/test-next-summary.json", "$dir/other-latest-summary.json");}), 'wrong suite refused');
    verify(rejects(function()use($dir){presswarden_report_publish_latest("$dir/symlink.json", "$dir/test-latest-summary.json");}), 'symlink source refused');
    unlink("$dir/test-latest-summary.json");
    symlink("$dir/test-run-summary.json", "$dir/test-latest-summary.json");
    verify(rejects(function()use($dir){presswarden_report_publish_latest("$dir/test-next-summary.json", "$dir/test-latest-summary.json");}), 'latest symlink refused');
    verify(is_link("$dir/test-latest-summary.json"), 'latest symlink not replaced');
    verify(file_get_contents("$dir/test-run-summary.json") === $json, 'latest symlink target untouched');
    verify(rejects(function()use($dir){presswarden_report_json_write("$dir/missing/new.json", '{}');}), 'missing directory rejected');
    verify(glob("$dir/.presswarden-json-*") === [], 'no staging files leaked');
    echo "Report JSON safety: $checks assertions passed\n";
} finally {
    foreach (scandir($dir) as $name) {
        if ($name === '.' || $name === '..') continue;
        $p = "$dir/$name";
        if (is_dir($p) && !is_link($p)) rmdir($p); else unlink($p);
    }
    rmdir($dir);
}
