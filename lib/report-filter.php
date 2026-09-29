<?php
/** Byte-preserving exclusion projection. The original evidence is never rewritten. */
require_once __DIR__.'/report-display.php';
require_once __DIR__.'/ops-safety.php';

function pw_filter_findings($source, $destination, array $roots) {
    if (count($roots) > 10000) throw new RuntimeException('Too many excluded roots');
    $excluded = [];
    foreach ($roots as $root) {
        if (!is_string($root) || $root === '' || $root[0] !== '/' || strlen($root) > 4096
            || preg_match('/[\x00-\x1f\x7f]/', $root)) throw new RuntimeException('Invalid excluded root');
        $root = rtrim($root, '/');
        if ($root === '') throw new RuntimeException('Filesystem root cannot be excluded here');
        $excluded[] = $root;
    }
    clearstatcache(true, $source);
    $before = pw_display_snapshot(@lstat($source));
    $input = @fopen($source, 'rb');
    if ($input === false) throw new RuntimeException('Unreadable findings source');
    $output = null; $created = null; $complete = false;
    try {
        if (pw_display_snapshot(fstat($input)) !== $before) throw new RuntimeException('Source changed on open');
        pw_ops_dir(dirname($destination));
        $mask = umask(0077);
        try { $output = @fopen($destination, 'xb'); } finally { umask($mask); }
        if ($output === false) throw new RuntimeException('Projection destination already exists or is unsafe');
        $created = fstat($output);
        $read = 0; $written = 0; $start = true; $skip = false;
        while (!feof($input)) {
            $chunk = fgets($input, 8193);
            if ($chunk === false) {
                if (!feof($input)) throw new RuntimeException('Cannot read complete findings');
                break;
            }
            $read += strlen($chunk);
            if ($read > 128*1024*1024) throw new RuntimeException('Findings exceed bound');
            $ended = substr($chunk, -1) === "\n";
            if ($start) {
                // A non-final first chunk is longer than every allowed root.
                // Decide once per record, then stream long records without buffering them.
                $probe = $ended ? substr($chunk, 0, -1) : $chunk;
                $skip = false;
                foreach ($excluded as $root) {
                    if ($probe === $root || strpos($probe, $root.'/') === 0) { $skip = true; break; }
                }
            }
            if (!$skip) {
                $offset = 0; $length = strlen($chunk);
                while ($offset < $length) {
                    $n = @fwrite($output, substr($chunk, $offset));
                    if ($n === false || $n === 0) throw new RuntimeException('Cannot save projection');
                    $offset += $n; $written += $n;
                }
            }
            $start = $ended;
        }
        clearstatcache(true, $source);
        if ($read !== $before['size'] || pw_display_snapshot(fstat($input)) !== $before
            || pw_display_snapshot(@lstat($source)) !== $before) throw new RuntimeException('Source changed while reading');
        if (!@fflush($output) || fstat($output)['size'] !== $written) throw new RuntimeException('Incomplete projection');
        if (!@fclose($output)) throw new RuntimeException('Projection close failed');
        $output = null; $complete = true;
    } finally {
        fclose($input);
        if (is_resource($output)) fclose($output);
        if (!$complete && is_array($created)) {
            clearstatcache(true, $destination); $now = @lstat($destination);
            if (is_array($now) && $now['dev'] === $created['dev'] && $now['ino'] === $created['ino']) @unlink($destination);
        }
    }
}

if (isset($argv[0]) && realpath($argv[0]) === __FILE__) {
    try {
        if ($argc < 4) throw new RuntimeException('Missing projection arguments');
        pw_filter_findings($argv[1], $argv[2], array_slice($argv, 3));
    } catch (Throwable $e) {
        fwrite(STDERR, "INCOMPLETE: excluded findings could not be projected safely; original source retained.\n");
        exit(2);
    }
}
