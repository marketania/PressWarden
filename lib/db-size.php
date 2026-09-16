<?php
// Read-only allocated-size measurement for the current WordPress table prefix.
// Run with wp eval-file; no shell processes or external MySQL client. PHP 7.4+.
global $wpdb;
try {
    if (!isset($wpdb) || !is_object($wpdb) || !isset($wpdb->prefix)
        || !is_string($wpdb->prefix) || $wpdb->prefix === '') {
        exit(2);
    }
    $wpdb->suppress_errors(true);
    $wpdb->last_error = '';
    $sql = $wpdb->prepare(
        'SELECT COALESCE(SUM(data_length + index_length),0) FROM information_schema.tables '
        . 'WHERE table_schema = DATABASE() AND table_name LIKE %s',
        $wpdb->esc_like($wpdb->prefix) . '%'
    );
    $size = $wpdb->get_var($sql);
    if ($wpdb->last_error !== '' || !is_scalar($size)
        || !preg_match('/^(0|[1-9][0-9]{0,14})$/D', (string)$size)) {
        exit(2);
    }
    echo "PWDBSIZE1\t", $size, "\n";
} catch (Throwable $e) {
    // A failed measurement is unavailable, never zero and never a secret dump.
    exit(2);
}
