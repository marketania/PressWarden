<?php
/** Run only through WP-CLI eval-file; WordPress bootstrap is not a sandbox. */
require_once rtrim((string)getenv('PRESSWARDEN_DIR'), '/').'/lib/db-scan.php';
global $wpdb;
$emit = function ($fields) {
    $line = 'PWDB1'."\t".implode("\t", $fields)."\n";
    if (@fwrite(STDOUT, $line) !== strlen($line)) throw new RuntimeException('output');
};
try {
    $rows = getenv('PRESSWARDEN_DB_MAX_ROWS'); $bytes = getenv('PRESSWARDEN_DB_MAX_BYTES');
    $rows = $rows === false || $rows === '' ? '5000' : $rows;
    $bytes = $bytes === false || $bytes === '' ? '33554432' : $bytes;
    if (!preg_match('/^[0-9]{1,9}$/D', $rows) || !preg_match('/^[0-9]{1,9}$/D', $bytes)) throw new RuntimeException('configuration');
    $scanner = new PressWardenDbScan($wpdb, $emit, (int)$rows, (int)$bytes);
    $status = $scanner->run();
} catch (Throwable $e) {
    // Never print exception messages: wpdb/bootstrap errors may contain secrets.
    fwrite(STDERR, "Database inspection did not complete.\n"); $status = 2;
}
exit($status);
