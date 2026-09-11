<?php
/** Internal prepare/apply protocol and public read-only case inspection. */
require_once __DIR__.'/quarantine.php';
// Filesystem warnings can contain private paths. Only controlled errors leave this helper.
set_error_handler(function () { return true; });
$q = new PressWardenQuarantine();
try {
    $mode = $argv[1] ?? '';
    if ($mode === '--prepare' && $argc === 4) {
        if (is_link($argv[2]) || !is_file($argv[2])) throw new RuntimeException('invalid context');
        $raw = file_get_contents($argv[2], false, null, 0, 1048577);
        if ($raw === false || strlen($raw) > 1048576 || substr($raw, -1) !== "\0") throw new RuntimeException('invalid context');
        $parts = explode("\0", substr($raw, 0, -1));
        if (count($parts) % 2) throw new RuntimeException('invalid context');
        $p = ['sites'=>[], 'blocked'=>[]]; $targets = [];
        for ($i = 0; $i < count($parts); $i += 2) {
            $key = $parts[$i]; $value = $parts[$i + 1];
            if ($key === 'site') $p['sites'][] = $value;
            elseif ($key === 'blocked') { if ($value !== '') $p['blocked'][] = $value; }
            elseif ($key === 'target') $targets[] = $value;
            elseif (in_array($key, ['root','quarantine','mode','check','section','run_id','version'], true) && !isset($p[$key])) $p[$key] = $value;
            else throw new RuntimeException('invalid context');
        }
        $q->writeJson($argv[3], $q->plan($p, $targets));
    } elseif ($mode === '--apply' && $argc === 3) {
        $q->apply($q->readJson($argv[2]));
    } elseif ($mode === 'verify' && $argc === 4) {
        $r = $q->verify($argv[2], $argv[3]);
        printf("VERIFIED COPY  %s\n  SHA-256: %d stored object(s) match the manifest.\n  Removal: %s.\n", $argv[3], $r['objects'], $r['removal']);
        printf("  Hash agreement is not proof of safety, authenticity, or successful site cleanup.\n");
    } elseif ($mode === 'list' && $argc === 3) {
        $root = $argv[2]; $count = 0; $legacy = 0;
        if (!file_exists($root) && !is_link($root)) { echo "No quarantine cases found.\n"; exit(0); }
        $q->plainParents($root, true);
        if (is_link($root) || !is_dir($root)) throw new RuntimeException('unsafe quarantine root');
        // Inspect only directory entries, not quarantined contents or live sites.
        $h = opendir($root); if ($h === false) throw new RuntimeException('unreadable quarantine root');
        $ids = [];
        try {
            while (false !== ($name = readdir($h))) {
                if ($name === '.' || $name === '..') continue;
                if (++$count > 10000) throw new RuntimeException('case listing limit');
                if (is_link($root.'/'.$name)) continue;
                if (preg_match('/^case-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{16}$/D', $name) && is_dir($root.'/'.$name)) $ids[] = $name;
                elseif (is_dir($root.'/'.$name)) ++$legacy;
            }
        } finally { closedir($h); }
        rsort($ids, SORT_STRING);
        echo "PressWarden quarantine cases (newest names first; not yet verified)\n";
        foreach (array_slice($ids, 0, 100) as $id) printf("  %s\n", $id);
        printf("Cases: %d; legacy/unrecognized directories: %d (left untouched).\n", count($ids), $legacy);
        if (count($ids) > 100) echo "Showing 100 case IDs. Use the quarantine directory for older cases.\n";
        echo "Verify a case with: ./presswarden quarantine verify CASE_ID\n";
    } else throw new RuntimeException('invalid arguments');
} catch (Throwable $e) {
    // Do not echo arbitrary exception messages, file contents or filesystem diagnostics.
    if ($e instanceof PressWardenQuarantineError) {
        $reason = $e->getMessage();
        fwrite(STDERR, "Quarantine safeguard: ".$reason.".\n");
        if (strpos($reason, 'approved selection revalidation failed:') === 0
            || $reason === 'approved selection changed since snapshot') {
            fwrite(STDERR, "INCOMPLETE: selected content changed or became unavailable after the approval snapshot. No removal started; rerun the current check to refresh the action list.\n");
            exit(2);
        }
    }
    fwrite(STDERR, "INCOMPLETE: quarantine operation refused or failed. Existing evidence was retained; inspect permissions, paths, limits and docs/QUARANTINE.md.\n");
    exit(2);
}
