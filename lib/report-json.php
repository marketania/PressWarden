<?php
/** Private, same-directory JSON publication. No payload execution or network. */
function presswarden_report_json_write($path, $json, $replace = false) {
    if (!is_string($json) || $json === '') throw new RuntimeException('Empty report');
    if ($replace && !preg_match('/^[A-Za-z0-9_-]+-latest-summary\.json$/D', basename($path))) {
        throw new RuntimeException('Only latest aliases can be replaced');
    }
    $parent = realpath(dirname($path));
    if ($parent === false || !is_dir($parent)) throw new RuntimeException('Report directory missing');
    $dest = $parent . DIRECTORY_SEPARATOR . basename($path);
    clearstatcache(true, $dest);
    if (is_link($dest) || (file_exists($dest) && (!$replace || !is_file($dest)))) {
        throw new RuntimeException('Unsafe or existing report destination');
    }
    // Exclusive creation avoids tempnam's fallback to a different filesystem.
    $temp = $parent . '/.presswarden-json-' . bin2hex(random_bytes(16));
    $oldMask = umask(0077);
    try { $handle = @fopen($temp, 'xb'); } finally { umask($oldMask); }
    if ($handle === false) throw new RuntimeException('Cannot stage report');
    try {
        $bytes = strlen($json); $offset = 0;
        while ($offset < $bytes) {
            $written = @fwrite($handle, substr($json, $offset));
            if ($written === false || $written === 0) throw new RuntimeException('Incomplete report write');
            $offset += $written;
        }
        if (!@fflush($handle)) throw new RuntimeException('Cannot flush report');
        if (!@fclose($handle)) throw new RuntimeException('Cannot close report');
        $handle = null;
        clearstatcache(true, $dest);
        if (is_link($dest) || (file_exists($dest) && (!$replace || !is_file($dest)))) {
            throw new RuntimeException('Report destination changed');
        }
        if ($replace) {
            // Only the documented *-latest-summary.json alias is replaceable.
            // Rename on the same filesystem exposes either old or complete new JSON.
            if (!@rename($temp, $dest)) throw new RuntimeException('Cannot publish latest report');
        } else {
            // link() is an atomic no-replace publication: history cannot be clobbered.
            if (!@link($temp, $dest)) throw new RuntimeException('Cannot publish unique report');
            @unlink($temp);
        }
    } finally {
        if (is_resource($handle)) @fclose($handle);
        if (is_file($temp)) @unlink($temp);
    }
}

function presswarden_report_publish_latest($source, $dest) {
    if (realpath(dirname($source)) !== realpath(dirname($dest))
        || is_link($source) || !is_file($source)
        || !preg_match('/^[A-Za-z0-9_-]+-latest-summary\.json$/D', basename($dest))) {
        throw new RuntimeException('Invalid report publication');
    }
    $json = @file_get_contents($source, false, null, 0, 8 * 1024 * 1024 + 1);
    if ($json === false || strlen($json) > 8 * 1024 * 1024) throw new RuntimeException('Cannot read report');
    $data = json_decode($json, true);
    if (!is_array($data) || ($data['tool'] ?? '') !== 'PressWarden'
        || !isset($data['suite'], $data['coverage_status'], $data['checks'])
        || !is_string($data['suite']) || basename($dest) !== $data['suite'].'-latest-summary.json') {
        throw new RuntimeException('Invalid report content');
    }
    presswarden_report_json_write($dest, $json, true);
}

if (isset($argv[0]) && realpath($argv[0]) === __FILE__) {
    try {
        if ($argc !== 4 || $argv[1] !== 'latest') throw new RuntimeException('Invalid arguments');
        presswarden_report_publish_latest($argv[2], $argv[3]);
    } catch (Throwable $e) {
        // Paths and report contents may be private; do not print exceptions.
        fwrite(STDERR, "INCOMPLETE: latest JSON could not be published; prior latest and unique report retained.\n");
        exit(2);
    }
}
