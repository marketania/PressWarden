<?php
// Read-only multisite target validation, run with WP-CLI eval-file. PHP 7.4+.
// LiteSpeed's own invalid-blog handler may return without aborting cleanup.
try {
    $id = isset($args[0]) ? (string)$args[0] : '';
    if (!preg_match('/^[1-9][0-9]{0,9}$/D', $id)
        || !function_exists('is_multisite') || !is_multisite()
        || !function_exists('get_site')) { exit(2); }
    $site = get_site((int)$id);
    if (!$site || (string)$site->blog_id !== $id || !empty($site->deleted)
        || !empty($site->archived) || !empty($site->spam)) { exit(2); }
    echo "PWDBBLOG1\t", $id, "\n";
} catch (Throwable $e) {
    // No raw WordPress errors, connection details, or object values in output.
    exit(2);
}
