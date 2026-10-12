<?php
/** Bounded, static core verification. Never bootstraps WordPress or follows links. */
function pw_core_relpath($name): bool {
    return is_string($name) && $name !== '' && strlen($name) <= 4096
        && !preg_match('/[\\x00-\\x1f\\x7f\\\\\\\\]/', $name)
        && $name[0] !== '/' && !preg_match('~(?:^|/)(?:\\.|\\.\\.|)(?:/|$)~', $name);
}

function pw_core_checksums(string $manifest): array {
    if (is_link($manifest) || !is_file($manifest)) throw new RuntimeException('Unsafe checksum manifest');
    $raw = @file_get_contents($manifest, false, null, 0, 4194305);
    if (!is_string($raw) || strlen($raw) > 4194304) throw new RuntimeException('Unreadable or oversized checksum manifest');
    $data = json_decode($raw, true);
    $checksums = is_array($data) ? ($data['checksums'] ?? null) : null;
    if (!is_array($checksums) || !$checksums || count($checksums) > 20000) throw new RuntimeException('Invalid checksum manifest');
    foreach ($checksums as $name => $checksum) {
        if (!pw_core_relpath($name) || !is_string($checksum) || !preg_match('/^[0-9a-f]{32}$/iD', $checksum)) {
            throw new RuntimeException('Invalid checksum manifest path or digest');
        }
    }
    return $checksums;
}

/** lstat each component before opening a file; absent and unsafe are distinct. */
function pw_core_path(string $root, string $relative): string {
    $path = $root; $parts = explode('/', $relative); $last = count($parts) - 1;
    foreach ($parts as $i => $part) {
        $path .= '/' . $part; clearstatcache(true, $path); $st = @lstat($path);
        if ($st === false) return 'missing';
        $type = $st['mode'] & 0170000;
        if ($type === 0120000) return 'unsafe';
        if ($i < $last && ($type !== 0040000 || !is_readable($path))) return 'unsafe';
        if ($i === $last && ($type !== 0100000 || $st['nlink'] !== 1 || !is_readable($path))) return 'unsafe';
    }
    return 'file';
}

function pw_core_verify(string $root, array $checksums): array {
    $r = ['status'=>'error', 'mismatch'=>[], 'missing'=>[], 'extra'=>[], 'errors'=>[]];
    $root = rtrim($root, '/');
    if ($root === '' || is_link($root) || realpath($root) !== $root || !is_dir($root)) {
        $r['errors'][] = 'INCOMPLETE: unsafe or unavailable WordPress root'; return $r;
    }
    $bytes = 0;
    foreach ($checksums as $name => $checksum) {
        if (!pw_core_relpath($name) || !is_string($checksum) || !preg_match('/^[0-9a-f]{32}$/iD', $checksum)) {
            $r['errors'][] = 'INCOMPLETE: invalid checksum manifest'; return $r;
        }
        if (strpos($name, 'wp-content/') === 0) continue;
        $kind = pw_core_path($root, $name);
        if ($kind === 'missing') { $r['missing'][] = $name; continue; }
        if ($kind !== 'file') { $r['errors'][] = 'INCOMPLETE: linked, special or unreadable core path: '.$name; continue; }
        $path = $root.'/'.$name; $before = @lstat($path);
        if (!$before || $before['size'] > 67108864 || $bytes + $before['size'] > 536870912) {
            $r['errors'][] = 'INCOMPLETE: core hashing size limit reached'; break;
        }
        $h = @fopen($path, 'rb');
        if (!$h) { $r['errors'][] = 'INCOMPLETE: cannot open core file: '.$name; continue; }
        try {
            $opened = fstat($h);
            if (!$opened || $before['dev'] !== $opened['dev'] || $before['ino'] !== $opened['ino']
                || ($opened['mode'] & 0170000) !== 0100000 || $opened['nlink'] !== 1) {
                throw new RuntimeException('Core file changed before hashing');
            }
            $ctx = hash_init('md5'); $read = hash_update_stream($ctx, $h, $before['size'] + 1);
            clearstatcache(true, $path); $after = @lstat($path); $end = fstat($h);
            foreach (['dev','ino','size','mtime','ctime','mode','nlink'] as $key) {
                if (!$after || !$end || $before[$key] !== $after[$key] || $opened[$key] !== $end[$key]) {
                    throw new RuntimeException('Core file changed while hashing');
                }
            }
            if ($read !== $before['size'] || !feof($h) || pw_core_path($root, $name) !== 'file') {
                throw new RuntimeException('Core file read was incomplete');
            }
            $bytes += $read;
            if (!hash_equals(strtolower($checksum), hash_final($ctx))) $r['mismatch'][] = $name;
        } catch (Throwable $e) {
            $r['errors'][] = 'INCOMPLETE: core file could not be verified: '.$name;
        } finally { fclose($h); }
    }
    $count = 0; $stack = [['wp-admin',0],['wp-includes',0]];
    while ($stack) {
        [$relative,$depth] = array_pop($stack); $dir = $root.'/'.$relative;
        clearstatcache(true, $dir); $st = @lstat($dir);
        if (!$st || ($st['mode'] & 0170000) !== 0040000 || !is_readable($dir)) {
            $r['errors'][] = 'INCOMPLETE: core directory unavailable, linked or unreadable: '.$relative; continue;
        }
        if ($depth > 32) { $r['errors'][] = 'INCOMPLETE: core directory depth limit reached'; continue; }
        try {
            $iterator = new DirectoryIterator($dir);
            foreach ($iterator as $entry) {
                if ($entry->isDot()) continue;
                if (++$count > 50000) { $r['errors'][] = 'INCOMPLETE: core inventory limit reached'; break 2; }
                $name = $relative.'/'.$entry->getFilename();
                if (!pw_core_relpath($name)) { $r['errors'][] = 'INCOMPLETE: unsafe filename in core tree (name withheld)'; continue; }
                $p = $root.'/'.$name; clearstatcache(true, $p); $item = @lstat($p);
                if (!$item) { $r['errors'][] = 'INCOMPLETE: core entry disappeared: '.$name; continue; }
                $type = $item['mode'] & 0170000;
                if ($type === 0040000) { $stack[] = [$name,$depth+1]; continue; }
                if ($type !== 0100000 || $item['nlink'] !== 1) {
                    $r['errors'][] = 'INCOMPLETE: linked or special entry in core tree: '.$name; continue;
                }
                if (!isset($checksums[$name])) $r['extra'][] = $name;
            }
        } catch (Throwable $e) { $r['errors'][] = 'INCOMPLETE: cannot enumerate core directory: '.$relative; }
    }
    $r['status'] = $r['errors'] ? 'error' : (($r['mismatch'] || $r['missing']) ? 'alert' : ($r['extra'] ? 'review' : 'clean'));
    return $r;
}

function pw_core_save(string $directory, string $id, array $result): void {
    if (!preg_match('/^[1-9][0-9]*$/D', $id)) throw new RuntimeException('Invalid result id');
    $details = $result['errors'];
    foreach (['mismatch'=>'MISMATCH  ', 'missing'=>'MISSING   ', 'extra'=>'EXTRA     '] as $type=>$prefix) {
        foreach ($result[$type] as $name) $details[] = $prefix.$name.($type === 'extra' ? ' (not in official core manifest)' : '');
    }
    $shown = array_slice($details, 0, 25);
    if (count($details) > 25) $shown[] = '... '.(count($details)-25).' more core issue(s) hidden';
    $files = ['status'=>[$result['status']], 'mismatch'=>$result['mismatch'], 'missing'=>$result['missing'],
        'extra'=>$result['extra'], 'bad'=>array_merge($result['mismatch'],$result['missing']), 'details'=>$shown];
    foreach ($files as $suffix=>$lines) {
        $content = $lines ? implode("\n", $lines)."\n" : '';
        $h = @fopen($directory.'/'.$id.'.'.$suffix, 'xb');
        if (!$h) throw new RuntimeException('Cannot create private verifier result');
        try { if (fwrite($h, $content) !== strlen($content)) throw new RuntimeException('Incomplete verifier result'); }
        finally { fclose($h); }
    }
}

if (isset($argv[0]) && realpath($argv[0]) === __FILE__) {
    try {
        if ($argc === 3 && $argv[1] === 'manifest') {
            exit(count(pw_core_checksums($argv[2])) > 100 ? 0 : 2);
        }
        if ($argc !== 3 || is_link($argv[1]) || !is_file($argv[1]) || !is_dir($argv[2]) || is_link($argv[2])) {
            throw new RuntimeException('Invalid verification input');
        }
        $h = fopen($argv[1], 'rb'); $rows = 0; $cache = []; umask(0077);
        while (($line = fgets($h, 16386)) !== false) {
            if (++$rows > 5000 || strlen($line) > 16384) throw new RuntimeException('Oversized core inventory');
            $parts = explode("\t", rtrim($line,"\r\n"));
            if (count($parts) !== 6) throw new RuntimeException('Invalid core inventory row');
            [$id,$root,$label,$version,$locale,$manifest] = $parts;
            try {
                if ($version === '' || $version === 'unknown') throw new RuntimeException('Cannot parse WordPress version');
                if (!isset($cache[$manifest])) {
                    // Bound cache memory across a fleet with many version/locale pairs.
                    if (count($cache) >= 8) $cache = [];
                    $cache[$manifest] = pw_core_checksums($manifest);
                }
                $result = pw_core_verify($root, $cache[$manifest]);
            } catch (Throwable $e) {
                $result = ['status'=>'error','mismatch'=>[],'missing'=>[],'extra'=>[],
                    'errors'=>['INCOMPLETE: checksum manifest or WordPress version could not be verified']];
            }
            pw_core_save($argv[2],$id,$result);
        }
        if (!feof($h)) throw new RuntimeException('Cannot finish core inventory');
        fclose($h);
    } catch (Throwable $e) {
        fwrite(STDERR, "INCOMPLETE: static core verification failed; no site files changed.\n"); exit(2);
    }
}
