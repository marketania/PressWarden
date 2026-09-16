<?php
// Native maintenance through the existing WordPress connection. PHP 7.4+.
// Fixed protocol/errors only: never emit SQL, credentials, or raw bootstrap text.
global $wpdb;
function pwdbm_emit($kind, $table = '', $message = '') {
    foreach (array($table, $message) as $value) {
        if (preg_match('/[\x00-\x1f\x7f]/', $value)) { exit(31); }
    }
    echo "PWDBM1\t", $kind, "\t", $table, "\t", $message, "\n";
}
function pwdbm_ident($table) { return '`' . str_replace('`', '``', $table) . '`'; }
function pwdbm_check($wpdb, $table) {
    $wpdb->last_error = '';
    $rows = $wpdb->get_results('CHECK TABLE ' . pwdbm_ident($table), ARRAY_A);
    if ($wpdb->last_error || !is_array($rows) || !$rows) {
        return array('unknown', 'CHECK TABLE query failed or returned no status');
    }
    $ok = false; $unsupported = false; $bad = false;
    foreach ($rows as $row) {
        $type = strtolower((string)($row['Msg_type'] ?? $row['msg_type'] ?? ''));
        $text = strtolower(trim((string)($row['Msg_text'] ?? $row['msg_text'] ?? '')));
        if (strpos($text, "doesn't support check") !== false
            || strpos($text, 'does not support check') !== false
            || strpos($text, 'not support check') !== false) { $unsupported = true; continue; }
        if ($type === 'error') { $bad = true; }
        if ($type === 'status' && in_array($text, array('ok', 'table is already up to date'), true)) { $ok = true; }
    }
    if ($bad) { return array('bad', 'CHECK TABLE reported a table error'); }
    if ($ok) { return array('ok', 'OK'); }
    if ($unsupported) { return array('unsupported', 'storage engine does not support CHECK TABLE'); }
    return array('unknown', 'CHECK TABLE did not establish table health');
}
function pwdbm_optimize_ok($rows) {
    if (!is_array($rows) || !$rows) { return false; }
    $ok = false;
    foreach ($rows as $row) {
        $type = strtolower((string)($row['Msg_type'] ?? $row['msg_type'] ?? ''));
        $text = strtolower(trim((string)($row['Msg_text'] ?? $row['msg_text'] ?? '')));
        if ($type === 'error') { return false; }
        if ($type === 'status' && in_array($text, array('ok', 'table is already up to date'), true)) { $ok = true; }
    }
    // InnoDB's recreate/analyze note followed by OK is a valid success.
    return $ok;
}
try {
    $action = getenv('PRESSWARDEN_DB_ACTION');
    if (!in_array($action, array('check', 'repair', 'optimize'), true) || !isset($wpdb) || !is_object($wpdb)) {
        pwdbm_emit('ERROR', '', 'invalid action or WordPress connection'); exit(31);
    }
    $wpdb->suppress_errors(true);
    $prefix = (function_exists('is_multisite') && is_multisite()) ? ($wpdb->base_prefix ?? '') : ($wpdb->prefix ?? '');
    if (!is_string($prefix) || $prefix === '' || preg_match('/[\x00-\x1f\x7f]/', $prefix)) {
        pwdbm_emit('ERROR', '', 'WordPress table prefix is unavailable'); exit(31);
    }
    $wpdb->last_error = '';
    $all = $wpdb->get_col('SHOW TABLES');
    if (!is_array($all) || $wpdb->last_error) { pwdbm_emit('ERROR', '', 'SHOW TABLES failed'); exit(31); }
    $tables = array();
    foreach ($all as $table) {
        if (!is_string($table) || preg_match('/[\x00-\x1f\x7f]/', $table)) { pwdbm_emit('ERROR', '', 'invalid table name'); exit(31); }
        if (strncmp($table, $prefix, strlen($prefix)) === 0) { $tables[] = $table; }
    }
    if (!$tables || count($tables) > 20000) { pwdbm_emit('ERROR', '', 'no matching WordPress tables or table limit exceeded'); exit(31); }
    $failed = 0; $unknown = 0;
    foreach ($tables as $table) {
        if ($action === 'optimize') {
            $wpdb->last_error = '';
            $rows = $wpdb->get_results('OPTIMIZE TABLE ' . pwdbm_ident($table), ARRAY_A);
            if ($wpdb->last_error || !pwdbm_optimize_ok($rows)) {
                $failed++; pwdbm_emit('OPTFAIL', $table, 'OPTIMIZE TABLE did not return explicit success');
            } else { pwdbm_emit('OPTIMIZED', $table, 'OK'); }
            continue;
        }
        list($state, $message) = pwdbm_check($wpdb, $table);
        if ($state === 'unknown') { $unknown++; pwdbm_emit('ERROR', $table, $message); continue; }
        if ($state === 'unsupported') { pwdbm_emit('SKIP', $table, $message); continue; }
        if ($state === 'ok') { continue; }
        if ($action === 'check') { $failed++; pwdbm_emit('BAD', $table, $message); continue; }
        $wpdb->last_error = '';
        $wpdb->get_results('REPAIR TABLE ' . pwdbm_ident($table), ARRAY_A);
        list($after, $message) = pwdbm_check($wpdb, $table);
        if ($after === 'ok') { pwdbm_emit('REPAIRED', $table, 'verified healthy'); }
        elseif ($after === 'unknown') { $unknown++; pwdbm_emit('ERROR', $table, $message); }
        else { $failed++; pwdbm_emit('UNRESOLVED', $table, 'table health not restored'); }
    }
    echo "PWDBM1\tDONE\t", $action, "\t", count($tables), "\n";
    exit($unknown ? 31 : ($failed ? 10 : 0));
} catch (Throwable $e) {
    pwdbm_emit('ERROR', '', 'native database helper failed'); exit(31);
}
