<?php
/* Bounded-memory reader for a top-level JSON object whose values are objects. */
function presswarden_json_object_records($file) {
    $h = @fopen($file, 'rb');
    if (!$h) throw new RuntimeException('cannot open JSON file');
    $state = 0; $root = false; $done = false; $keyRaw = ''; $key = '';
    $keyEsc = false; $value = ''; $inString = false; $esc = false; $curly = 0; $square = 0;
    try {
        while (!feof($h)) {
            $chunk = fread($h, 65536);
            if ($chunk === false) throw new RuntimeException('JSON read failed');
            for ($i = 0, $n = strlen($chunk); $i < $n; $i++) {
                $c = $chunk[$i];
                if ($state === 0) {
                    if ($c === ' ' || $c === "\n" || $c === "\r" || $c === "\t" || $c === ',') continue;
                    if (!$root && $c === '{') { $root = true; continue; }
                    if ($root && $c === '}') { $done = true; break 2; }
                    if ($c !== '"') throw new RuntimeException('invalid object key');
                    $keyRaw = ''; $keyEsc = false; $state = 1; continue;
                }
                if ($state === 1) {
                    if ($keyEsc) { $keyRaw .= $c; $keyEsc = false; }
                    elseif ($c === '\\') { $keyRaw .= $c; $keyEsc = true; }
                    elseif ($c === '"') {
                        $key = json_decode('"'.$keyRaw.'"', true);
                        if (!is_string($key)) throw new RuntimeException('invalid key encoding');
                        $state = 2;
                    } else $keyRaw .= $c;
                    continue;
                }
                if ($state === 2) {
                    if ($c === ' ' || $c === "\n" || $c === "\r" || $c === "\t") continue;
                    if ($c !== ':') throw new RuntimeException('missing colon');
                    $state = 3; continue;
                }
                if ($state === 3) {
                    if ($c === ' ' || $c === "\n" || $c === "\r" || $c === "\t") continue;
                    if ($c !== '{') throw new RuntimeException('expected record object');
                    $value = '{'; $curly = 1; $square = 0; $inString = false; $esc = false; $state = 4; continue;
                }
                if ($state === 4) {
                    $value .= $c;
                    if ($inString) {
                        if ($esc) $esc = false;
                        elseif ($c === '\\') $esc = true;
                        elseif ($c === '"') $inString = false;
                        continue;
                    }
                    if ($c === '"') $inString = true;
                    elseif ($c === '{') $curly++;
                    elseif ($c === '}') $curly--;
                    elseif ($c === '[') $square++;
                    elseif ($c === ']') $square--;
                    if ($curly < 0 || $square < 0) throw new RuntimeException('invalid nesting');
                    if ($curly === 0 && $square === 0) {
                        $record = json_decode($value, true);
                        if (!is_array($record) || json_last_error() !== JSON_ERROR_NONE) throw new RuntimeException('invalid record JSON');
                        yield array($key, $record);
                        $value = ''; $state = 5;
                    }
                    continue;
                }
                if ($state === 5) {
                    if ($c === ' ' || $c === "\n" || $c === "\r" || $c === "\t") continue;
                    if ($c === ',') { $state = 0; continue; }
                    if ($c === '}') { $done = true; break 2; }
                    throw new RuntimeException('invalid record delimiter');
                }
            }
        }
    } finally { fclose($h); }
    if (!$root || !$done) throw new RuntimeException('truncated JSON object');
}

function presswarden_validate_wordfence_json($file) {
    $count = 0; $software = false;
    foreach (presswarden_json_object_records($file) as $pair) {
        $count++;
        if (isset($pair[1]['software']) && is_array($pair[1]['software'])) $software = true;
    }
    if ($count < 1 || !$software) throw new RuntimeException('no software records');
    return $count;
}

if (PHP_SAPI === 'cli' && isset($argv[1]) && realpath($argv[0]) === __FILE__) {
    try {
        if ($argv[1] === 'validate-wordfence') { echo presswarden_validate_wordfence_json($argv[2]), "\n"; exit(0); }
        exit(2);
    } catch (Throwable $e) { fwrite(STDERR, $e->getMessage()."\n"); exit(1); }
}
