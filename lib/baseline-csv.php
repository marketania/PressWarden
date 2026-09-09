<?php
/** Strict, inert WP-CLI inventory reader. No WordPress bootstrap or execution. */
function presswarden_baseline_csv($path, $type, $site) {
    $headers = ['P'=>['name','status','version'], 'T'=>['name','status','version'],
                'A'=>['user_login'], 'C'=>['hook','recurrence']];
    if (!isset($headers[$type]) || $site === '' || preg_match('/[\x00-\x1f\x7f]/', $site)) {
        throw new RuntimeException('Invalid inventory request');
    }
    if (is_link($path) || !is_file($path) || filesize($path) > 8 * 1024 * 1024) {
        throw new RuntimeException('Inventory unavailable or over budget');
    }
    $handle = @fopen($path, 'rb');
    if (!$handle) throw new RuntimeException('Inventory read failed');
    $first = true; $rows = []; $count = 0; $bytes = 0;
    try {
        while (($line = fgets($handle, 65538)) !== false) {
            $bytes += strlen($line);
            if ($bytes > 8 * 1024 * 1024 || strlen($line) > 65536 || ++$count > 50001) {
                throw new RuntimeException('Inventory limit');
            }
            $line = rtrim($line, "\r\n");
            // A field containing a newline/control character cannot be represented
            // in the existing TSV baseline. Reject it instead of inventing a value.
            if (preg_match('/[\x00-\x1f\x7f]/', $line)
                || !preg_match('/\A(?:"(?:[^"]|"")*"|[^",]*)(?:,(?:"(?:[^"]|"")*"|[^",]*))*\z/D', $line)) {
                throw new RuntimeException('Malformed CSV');
            }
            $fields = str_getcsv($line, ',', '"', '');
            if ($first) {
                $first = false;
                if ($fields !== $headers[$type]) throw new RuntimeException('Unexpected header');
                continue;
            }
            if (count($fields) !== count($headers[$type])) throw new RuntimeException('Unexpected fields');
            foreach ($fields as $field) {
                if (!is_string($field) || strlen($field) > 2048 || strpos($field, '|') !== false) {
                    throw new RuntimeException('Unsupported field');
                }
            }
            $key = $fields[0];
            if ($key === '') throw new RuntimeException('Empty identity');
            if ($type === 'P' && !in_array($fields[1], ['active','active-network','inactive','must-use','dropin'], true)) {
                throw new RuntimeException('Invalid plugin state');
            }
            if ($type === 'T' && !in_array($fields[1], ['active','inactive','parent'], true)) {
                throw new RuntimeException('Invalid theme state');
            }
            $value = $type === 'A' ? 'administrator' : ($type === 'C' ? $fields[1] : $fields[1].'|'.$fields[2]);
            if ($type === 'C') {
                // Repeated hooks may legitimately have multiple schedules. Compare
                // the sorted recurrence set, not whichever duplicate was read last.
                $rows[$key][$value] = true;
            } else {
                if (isset($rows[$key]) && $rows[$key] !== $value) throw new RuntimeException('Conflicting identity');
                $rows[$key] = $value;
            }
        }
        if (!feof($handle) || $first) throw new RuntimeException('Incomplete inventory');
    } finally { fclose($handle); }
    ksort($rows, SORT_STRING);
    $result = '';
    foreach ($rows as $key => $value) {
        if ($type === 'C') {
            $value = array_map('strval', array_keys($value)); sort($value, SORT_STRING);
            $value = json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            if ($value === false) throw new RuntimeException('Invalid recurrence encoding');
        }
        $record = $type."\t".$site."\t".$key."\t".$value."\n";
        if (strlen($record) > 65536 || strlen($result) + strlen($record) > 8 * 1024 * 1024) {
            throw new RuntimeException('Normalized inventory limit');
        }
        $result .= $record;
    }
    return $result;
}
if (isset($argv[0]) && realpath($argv[0]) === __FILE__) {
    try {
        if ($argc !== 4) throw new RuntimeException('Invalid arguments');
        $out = presswarden_baseline_csv($argv[1], $argv[2], $argv[3]);
        if ($out !== '' && fwrite(STDOUT, $out) !== strlen($out)) throw new RuntimeException('Write failed');
    } catch (Throwable $e) {
        // Never echo malformed WordPress output, exception text or inventory data.
        fwrite(STDERR, "INCOMPLETE: baseline inventory could not be validated.\n");
        exit(2);
    }
}
