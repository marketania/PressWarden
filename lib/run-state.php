<?php
// PressWarden suite run-state journal. PHP 7.4 compatible; no WordPress bootstrap.
const PW_RUN_STATE_FORMAT = 1;
const PW_RUN_STATE_MAX_BYTES = 262144;
const PW_RUN_STATE_MAX_CHECKS = 256;

final class PressWardenRunStateError extends RuntimeException {}

function pwrs_fail($message) { throw new PressWardenRunStateError($message); }
function pwrs_now() { return gmdate('c'); }
function pwrs_text($value, $allowEmpty = false, $max = 4096) {
    $value = (string)$value;
    if ((!$allowEmpty && $value === '') || strlen($value) > $max || preg_match('/[\x00-\x1F\x7F]/', $value)) {
        pwrs_fail('invalid run-state text');
    }
    return $value;
}
function pwrs_run_id($value) {
    $value = (string)$value;
    if (!preg_match('/^[A-Za-z0-9][A-Za-z0-9._-]{0,159}$/D', $value)) pwrs_fail('invalid run id');
    return $value;
}
function pwrs_uint($value, $max = 1000000) {
    if (!preg_match('/^[0-9]+$/D', (string)$value)) pwrs_fail('invalid integer');
    $n = (int)$value;
    if ($n < 0 || $n > $max) pwrs_fail('integer out of range');
    return $n;
}
function pwrs_plain_dir($dir, $create = false) {
    $dir = rtrim(pwrs_text($dir, false, 8192), '/');
    if ($dir === '') $dir = '/';
    if (is_link($dir)) pwrs_fail('unsafe run-state directory');
    if (!file_exists($dir)) {
        if (!$create) pwrs_fail('run-state directory missing');
        $old = umask(0077);
        try { $ok = @mkdir($dir, 0700, true); } finally { umask($old); }
        if (!$ok && !is_dir($dir)) pwrs_fail('cannot create run-state directory');
    }
    $s = @lstat($dir);
    if (!$s || (($s['mode'] & 0170000) !== 0040000) || is_link($dir)) pwrs_fail('unsafe run-state directory');
    return $dir;
}
function pwrs_regular_file($path, $max = PW_RUN_STATE_MAX_BYTES) {
    if (is_link($path)) pwrs_fail('unsafe run-state file');
    $s = @lstat($path);
    if (!$s || (($s['mode'] & 0170000) !== 0100000) || $s['nlink'] !== 1 || $s['size'] < 0 || $s['size'] > $max) {
        pwrs_fail('unsafe run-state file');
    }
    return $s;
}
function pwrs_write_all($h, $data) {
    $off = 0; $len = strlen($data);
    while ($off < $len) {
        $n = @fwrite($h, substr($data, $off));
        if ($n === false || $n === 0) pwrs_fail('run-state write failed');
        $off += $n;
    }
    if (!@fflush($h)) pwrs_fail('run-state flush failed');
}
function pwrs_encode($state) {
    $data = json_encode($state, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    if ($data === false) pwrs_fail('run-state encoding failed');
    $data .= "\n";
    if (strlen($data) > PW_RUN_STATE_MAX_BYTES) pwrs_fail('run-state size limit');
    return $data;
}
function pwrs_atomic_write($path, $data, $createOnly = false) {
    $dir = pwrs_plain_dir(dirname($path), false);
    if (file_exists($path) || is_link($path)) {
        if ($createOnly) pwrs_fail('run-state already exists');
        pwrs_regular_file($path);
    }
    $tmp = $dir.'/.run-state.'.bin2hex(random_bytes(8)).'.tmp';
    $old = umask(0077);
    try { $h = @fopen($tmp, 'xb'); } finally { umask($old); }
    if ($h === false) pwrs_fail('cannot stage run-state');
    try {
        pwrs_write_all($h, $data);
    } finally {
        if (!@fclose($h)) { @unlink($tmp); pwrs_fail('run-state close failed'); }
    }
    if ($createOnly) {
        if (!@link($tmp, $path)) { @unlink($tmp); pwrs_fail('cannot publish new run-state'); }
        @unlink($tmp);
        return;
    }
    if (is_link($path)) { @unlink($tmp); pwrs_fail('unsafe run-state destination'); }
    if (!@rename($tmp, $path)) { @unlink($tmp); pwrs_fail('cannot publish run-state'); }
}
function pwrs_atomic_json($path, $state, $createOnly = false) { pwrs_atomic_write($path, pwrs_encode($state), $createOnly); }
function pwrs_atomic_text($path, $text) {
    if (file_exists($path) || is_link($path)) pwrs_regular_file($path, 4096);
    pwrs_atomic_write($path, $text, false);
}
function pwrs_read($path) {
    pwrs_regular_file($path);
    $raw = @file_get_contents($path, false, null, 0, PW_RUN_STATE_MAX_BYTES + 1);
    if ($raw === false || strlen($raw) > PW_RUN_STATE_MAX_BYTES) pwrs_fail('cannot read run-state');
    $state = json_decode($raw, true, 64);
    if (!is_array($state) || ($state['format'] ?? null) !== PW_RUN_STATE_FORMAT || ($state['tool'] ?? null) !== 'PressWarden') {
        pwrs_fail('invalid run-state');
    }
    return $state;
}
function pwrs_state_path($runs, $id) {
    $runs = pwrs_plain_dir($runs, false);
    $id = pwrs_run_id($id);
    $runDir = $runs.'/'.$id;
    pwrs_plain_dir($runDir, false);
    return $runDir.'/state.json';
}
function pwrs_parse_checks($raw) {
    $raw = trim(pwrs_text($raw, true, 16384));
    if ($raw === '') return array();
    $items = preg_split('/[[:space:]]+/', $raw);
    if (!is_array($items) || count($items) > PW_RUN_STATE_MAX_CHECKS) pwrs_fail('invalid check list');
    $out = array();
    foreach ($items as $item) {
        if (!preg_match('/^[A-Za-z0-9_-]{1,96}$/D', $item)) pwrs_fail('invalid check name');
        if (!in_array($item, $out, true)) $out[] = $item;
    }
    return $out;
}
function pwrs_update($path, $mutator) {
    $state = pwrs_read($path);
    $state = $mutator($state);
    $state['updated_at'] = pwrs_now();
    pwrs_atomic_json($path, $state, false);
}
function pwrs_validate_check($state, $check) {
    $check = pwrs_text($check, false, 96);
    if (!preg_match('/^[A-Za-z0-9_-]+$/D', $check)) pwrs_fail('invalid check name');
    if (!in_array($check, $state['checks_selected'] ?? array(), true)) pwrs_fail('check not in run plan');
    return $check;
}
function pwrs_show($runs, $id = '') {
    $runsRaw = rtrim(pwrs_text($runs, false, 8192), '/');
    if ($runsRaw === '') $runsRaw = '/';
    if (!file_exists($runsRaw) && !is_link($runsRaw)) {
        fwrite(STDOUT, "No recorded PressWarden suite runs.\n");
        return 0;
    }
    $runs = pwrs_plain_dir($runsRaw, false);
    if ($id === '' || $id === 'latest') {
        $latest = $runs.'/latest';
        if (!file_exists($latest) && !is_link($latest)) {
            fwrite(STDOUT, "No recorded PressWarden suite runs.\n");
            return 0;
        }
        pwrs_regular_file($latest, 4096);
        $id = trim((string)@file_get_contents($latest, false, null, 0, 4097));
    }
    $id = pwrs_run_id($id);
    $state = pwrs_read(pwrs_state_path($runs, $id));
    $results = is_array($state['results'] ?? null) ? $state['results'] : array();
    $clean = $findings = $skipped = $failed = 0;
    foreach ($results as $r) {
        switch ($r['status'] ?? '') {
            case 'clean': ++$clean; break;
            case 'findings': ++$findings; break;
            case 'skipped': ++$skipped; break;
            default: ++$failed; break;
        }
    }
    $status = (string)($state['status'] ?? 'UNKNOWN');
    fwrite(STDOUT, "PRESSWARDEN RUN STATUS\n\n");
    printf("RUN        %s\n", $state['run_id'] ?? $id);
    printf("SUITE      %s\n", $state['suite'] ?? 'unknown');
    printf("STATUS     %s\n", $status);
    printf("VERSION    %s\n", $state['version'] ?? 'unknown');
    printf("STARTED    %s\n", $state['started_at'] ?? 'unknown');
    if (!empty($state['finished_at'])) printf("FINISHED   %s\n", $state['finished_at']);
    printf("UPDATED    %s\n", $state['updated_at'] ?? 'unknown');
    printf("ROOT       %s\n", $state['root'] ?? 'unknown');
    printf("SITES      %s WordPress install(s) across %s site group(s)\n", $state['sites'] ?? '?', $state['domains'] ?? '?');
    printf("DISCOVERY  %s\n", strtoupper((string)($state['discovery_status'] ?? 'unknown')));
    $step = (int)($state['current_step'] ?? 0); $total = (int)($state['checks_total'] ?? 0);
    if (!empty($state['current_check'])) printf("CURRENT    [%d/%d] %s\n", $step, $total, $state['current_check']);
    printf("RESULTS    clean %d • findings %d • skipped %d • failed/incomplete %d\n", $clean, $findings, $skipped, $failed);
    if (!empty($state['interrupted_signal'])) printf("SIGNAL     %s\n", $state['interrupted_signal']);
    if (array_key_exists('exit_code', $state) && $state['exit_code'] !== null) printf("EXIT       %s\n", (string)$state['exit_code']);
    if (!empty($state['report_log'])) printf("REPORT     %s\n", $state['report_log']);
    if ($status === 'RUNNING') {
        $pid = (int)($state['pid'] ?? 0);
        if ($pid > 0 && function_exists('posix_kill')) {
            $alive = @posix_kill($pid, 0);
            printf("PROCESS    %s (recorded PID %d)\n", $alive ? 'appears active' : 'not running', $pid);
            if (!$alive) fwrite(STDOUT, "NOTE       No final marker was written; treat this run as interrupted/abandoned and rerun the affected check or suite.\n");
        } else {
            fwrite(STDOUT, "PROCESS    liveness unavailable; RUNNING means no final marker has been recorded yet.\n");
        }
    } elseif ($status === 'INTERRUPTED') {
        fwrite(STDOUT, "NOTE       This run did not complete. Partial reports may still contain useful validated evidence.\n");
    }
    return 0;
}

try {
    $cmd = $argv[1] ?? '';
    if ($cmd === 'init') {
        if ($argc !== 15) pwrs_fail('invalid init arguments');
        $runs = pwrs_plain_dir($argv[2], true); $id = pwrs_run_id($argv[3]);
        $suite = pwrs_text($argv[4], false, 96); $version = pwrs_text($argv[5], false, 64);
        $root = pwrs_text($argv[6], false, 8192); $sites = pwrs_uint($argv[7]); $domains = pwrs_uint($argv[8]);
        $total = pwrs_uint($argv[9], PW_RUN_STATE_MAX_CHECKS); $discovery = $argv[10];
        if ($discovery !== 'complete' && $discovery !== 'incomplete') pwrs_fail('invalid discovery status');
        $pid = pwrs_uint($argv[11], 2147483647); $checks = pwrs_parse_checks($argv[12]);
        $report = pwrs_text($argv[13], true, 8192); $startedEpoch = pwrs_uint($argv[14], 4102444800);
        if ($total !== count($checks)) pwrs_fail('check count mismatch');
        $runDir = $runs.'/'.$id;
        if (file_exists($runDir) || is_link($runDir)) pwrs_fail('run id already exists');
        $old = umask(0077); try { $ok = @mkdir($runDir, 0700); } finally { umask($old); }
        if (!$ok) pwrs_fail('cannot create run directory');
        $state = array(
            'format'=>PW_RUN_STATE_FORMAT, 'tool'=>'PressWarden', 'run_id'=>$id, 'suite'=>$suite, 'version'=>$version,
            'root'=>$root, 'sites'=>$sites, 'domains'=>$domains, 'discovery_status'=>$discovery, 'pid'=>$pid,
            'started_at'=>pwrs_now(), 'started_epoch'=>$startedEpoch, 'updated_at'=>pwrs_now(), 'finished_at'=>null,
            'status'=>'RUNNING', 'exit_code'=>null, 'interrupted_signal'=>null,
            'checks_total'=>$total, 'checks_selected'=>$checks, 'current_step'=>0, 'current_check'=>'', 'results'=>array(),
            'report_log'=>$report
        );
        pwrs_atomic_json($runDir.'/state.json', $state, true);
        pwrs_atomic_text($runs.'/latest', $id."\n");
        exit(0);
    }
    if ($cmd === 'step') {
        if ($argc !== 6) pwrs_fail('invalid step arguments');
        $path = $argv[2]; $index = pwrs_uint($argv[3], PW_RUN_STATE_MAX_CHECKS); $total = pwrs_uint($argv[4], PW_RUN_STATE_MAX_CHECKS); $check = $argv[5];
        pwrs_update($path, function($s) use ($index, $total, $check) {
            if (($s['status'] ?? '') !== 'RUNNING' || (int)($s['checks_total'] ?? -1) !== $total || $index < 1 || $index > $total) pwrs_fail('run-state step mismatch');
            $check = pwrs_validate_check($s, $check); $s['current_step']=$index; $s['current_check']=$check; return $s;
        });
        exit(0);
    }
    if ($cmd === 'result') {
        if ($argc !== 7) pwrs_fail('invalid result arguments');
        $path=$argv[2]; $check=$argv[3]; $status=$argv[4]; $findingsRaw=$argv[5]; $elapsed=pwrs_uint($argv[6], 31536000);
        if (!in_array($status, array('clean','findings','skipped','missing','error'), true)) pwrs_fail('invalid result status');
        $findings = $findingsRaw === '-' ? null : pwrs_uint($findingsRaw, 100000000);
        pwrs_update($path, function($s) use ($check,$status,$findings,$elapsed) {
            if (($s['status'] ?? '') !== 'RUNNING') pwrs_fail('run already finalized');
            $check = pwrs_validate_check($s, $check);
            foreach (($s['results'] ?? array()) as $r) if (($r['check'] ?? '') === $check) pwrs_fail('duplicate check result');
            $s['results'][]=array('check'=>$check,'status'=>$status,'findings'=>$findings,'elapsed_seconds'=>$elapsed);
            return $s;
        });
        exit(0);
    }
    if ($cmd === 'finish') {
        if ($argc !== 5) pwrs_fail('invalid finish arguments');
        $path=$argv[2]; $status=$argv[3]; $exit=pwrs_uint($argv[4],255);
        if (!in_array($status, array('COMPLETED','INCOMPLETE','FAILED'), true)) pwrs_fail('invalid final status');
        pwrs_update($path, function($s) use ($status,$exit) {
            if (($s['status'] ?? '') !== 'RUNNING') pwrs_fail('run already finalized');
            $s['status']=$status; $s['exit_code']=$exit; $s['finished_at']=pwrs_now(); $s['current_check']=''; return $s;
        });
        exit(0);
    }
    if ($cmd === 'interrupt') {
        if ($argc !== 6) pwrs_fail('invalid interrupt arguments');
        $path=$argv[2]; $signal=$argv[3]; $exit=pwrs_uint($argv[4],255); $check=pwrs_text($argv[5], true, 96);
        if (!in_array($signal, array('HUP','INT','TERM'), true)) pwrs_fail('invalid signal');
        pwrs_update($path, function($s) use ($signal,$exit,$check) {
            if (($s['status'] ?? '') !== 'RUNNING') return $s;
            if ($check !== '') $check = pwrs_validate_check($s, $check);
            $s['status']='INTERRUPTED'; $s['exit_code']=$exit; $s['interrupted_signal']=$signal; $s['finished_at']=pwrs_now();
            if ($check !== '') $s['current_check']=$check;
            return $s;
        });
        exit(0);
    }
    if ($cmd === 'show') {
        if ($argc < 3 || $argc > 4) pwrs_fail('invalid show arguments');
        exit(pwrs_show($argv[2], $argv[3] ?? ''));
    }
    pwrs_fail('invalid run-state command');
} catch (Throwable $e) {
    if ($e instanceof PressWardenRunStateError) fwrite(STDERR, "Run-state safeguard: ".$e->getMessage().".\n");
    else fwrite(STDERR, "Run-state safeguard: internal helper failure.\n");
    exit(2);
}
