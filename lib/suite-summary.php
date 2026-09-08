<?php
/** Generate a PressWarden suite report without treating failed checks as clean. */
require_once __DIR__.'/report-json.php';
if ($argc !== 10) { fwrite(STDERR, "Invalid suite summary arguments\n"); exit(2); }
[$res, $out, $suite, $version, $root, $sites, $domains, $rc, $log] = array_slice($argv, 1);
$lines = @file($res, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
if ($lines === false) { fwrite(STDERR, "Cannot read suite results\n"); exit(2); }
$checks = []; $total = 0; $completed = 0; $skipped = 0; $failed = 0;
foreach ($lines as $line) {
    $parts = explode('|', $line);
    if (count($parts) !== 4) { fwrite(STDERR, "Malformed suite result\n"); exit(2); }
    [$name, $number, $status, $elapsed] = $parts;
    $findings = is_numeric($number) ? (int)$number : null;
    if ($findings !== null) $total += $findings;
    if ($status === 'clean' || $status === 'findings') ++$completed;
    elseif ($status === 'skipped') ++$skipped;
    else ++$failed;
    $checks[] = ['check'=>$name, 'findings'=>$findings, 'status'=>$status, 'elapsed_seconds'=>(int)$elapsed];
}
$coverage = ((int)$rc > 1 || $failed > 0 || $completed === 0) ? 'incomplete' : ($skipped > 0 ? 'partial' : 'complete');
$data = ['tool'=>'PressWarden', 'version'=>$version, 'suite'=>$suite, 'generated_at'=>date(DATE_ATOM),
    'root'=>$root, 'wordpress_sites'=>(int)$sites, 'site_groups'=>(int)$domains,
    'exit_code'=>(int)$rc, 'total_findings'=>$total, 'coverage_status'=>$coverage,
    'checks_completed'=>$completed, 'checks_skipped'=>$skipped, 'checks_failed'=>$failed,
    'run_id'=>basename($log, '.log'), 'console_log'=>$log, 'checks'=>$checks];
$json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
try {
    if ($json === false) throw new RuntimeException('JSON encoding failed');
    presswarden_report_json_write($out, $json."\n");
} catch (Throwable $e) {
    fwrite(STDERR, "Cannot write suite JSON report\n"); exit(2);
}
