<?php
/** Bounded, display-only rendering of tool-owned findings. Never execute input. */
function pw_display_text($text) {
    // Invalid byte strings must not pass raw C1 terminal controls. Preserve their
    // printable ASCII and represent other bytes rather than discarding evidence.
    if (preg_match('//u', $text) !== 1) {
        return preg_replace_callback('/[\x00-\x1f\x7f-\xff]/', function ($m) {
            return sprintf('\\x%02X', ord($m[0]));
        }, $text);
    }
    return preg_replace_callback('/[\x00-\x1f\x7f-\x9f\x{061c}\x{200e}\x{200f}\x{202a}-\x{202e}\x{2066}-\x{2069}]/u', function ($m) {
        if (strlen($m[0]) === 1) return sprintf('\\x%02X', ord($m[0]));
        return substr(json_encode($m[0]), 1, -1);
    }, $text);
}

function pw_display_snapshot($stat) {
    if (!is_array($stat) || ($stat['mode'] & 0170000) !== 0100000
        || $stat['nlink'] !== 1 || $stat['size'] > 128 * 1024 * 1024) {
        throw new RuntimeException('Unsafe, linked or oversized findings file');
    }
    $out = [];
    foreach (['dev','ino','mode','uid','gid','nlink','size','mtime','ctime'] as $key) $out[$key] = $stat[$key];
    return $out;
}

function pw_display_findings($path, $cap) {
    if (!preg_match('/^(?:0|[1-9][0-9]{0,4})$/D', $cap) || (int)$cap > 10000) {
        throw new RuntimeException('Invalid display cap');
    }
    clearstatcache(true, $path);
    $before = pw_display_snapshot(@lstat($path));
    $handle = @fopen($path, 'rb');
    if ($handle === false) throw new RuntimeException('Unreadable findings file');
    try {
        if (pw_display_snapshot(fstat($handle)) !== $before) throw new RuntimeException('Source changed on open');
        $rows = []; $count = 0; $bytes = 0; $prefix = ''; $length = 0;
        $record = function () use (&$rows, &$count, &$prefix, &$length, $cap) {
            if ($length > 0) {
                ++$count;
                if ($count <= (int)$cap) {
                    $text = pw_display_text($prefix);
                    if ($text === null) throw new RuntimeException('Rendering failed');
                    // Bound both source bytes and expanded escape representation.
                    if (strlen($text) > 4096) {
                        $text = substr($text, 0, 4096);
                        while ($text !== '' && preg_match('//u', $text) !== 1) $text = substr($text, 0, -1);
                        $text .= ' ... [display truncated]';
                    } elseif ($length > strlen($prefix)) {
                        $text .= ' ... [display truncated]';
                    }
                    $rows[] = $text;
                }
            }
            $prefix = ''; $length = 0;
        };
        while (!feof($handle)) {
            $chunk = fgets($handle, 8193);
            if ($chunk === false) {
                if (!feof($handle)) throw new RuntimeException('Read failed');
                break;
            }
            $bytes += strlen($chunk);
            if ($bytes > 128 * 1024 * 1024) throw new RuntimeException('Findings grew beyond limit');
            $ended = substr($chunk, -1) === "\n";
            if ($ended) $chunk = substr($chunk, 0, -1);
            $length += strlen($chunk);
            if (strlen($prefix) < 4096) $prefix .= substr($chunk, 0, 4096 - strlen($prefix));
            if ($ended) $record();
        }
        $record(); // Preserve a final record even without a newline.
        clearstatcache(true, $path);
        if ($bytes !== $before['size'] || pw_display_snapshot(fstat($handle)) !== $before
            || pw_display_snapshot(@lstat($path)) !== $before) {
            throw new RuntimeException('Findings changed while reading');
        }
        // First row is a trusted count; subsequent rows are terminal-safe text.
        // Nothing is emitted until the whole bounded read has been verified.
        echo $count, "\n";
        foreach ($rows as $row) echo $row, "\n";
    } finally {
        fclose($handle);
    }
}

if (isset($argv[0]) && realpath($argv[0]) === __FILE__) {
    try {
        if ($argc !== 3) throw new RuntimeException('Invalid arguments');
        pw_display_findings($argv[1], $argv[2]);
    } catch (Throwable $e) {
        // Paths/content are untrusted and may contain secrets or controls.
        fwrite(STDERR, "INCOMPLETE: findings source or display could not be verified.\n");
        exit(2);
    }
}
