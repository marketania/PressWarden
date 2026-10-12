<?php
// Inert, bounded provider-output parsing. Never bootstrap WordPress here.
try {
    $mode = $argv[1] ?? '';
    if (!in_array($mode, ['inventory','availability','checksums'], true)) throw new RuntimeException();
    $raw = @file_get_contents($argv[2] ?? '', false, null, 0, 8388609);
    if (!is_string($raw) || strlen($raw) > 8388608) throw new RuntimeException();
    // WP-CLI's verifier emits no JSON at all when there are no deviations.
    if ($mode === 'checksums' && trim($raw) === '') exit(0);
    $rows = json_decode($raw, false, 64);
    if (!is_array($rows) || count($rows) > 10000) throw new RuntimeException();
    $allowed = array_fill_keys(array_slice($argv, 3), true);
    $clean = static function (string $v): string {
        return preg_replace('/[\p{Cc}\p{Cf}|]/u', '?', $v);
    };
    $safe_name = static function ($v): bool {
        return is_string($v) && strlen($v) <= 200 && (bool)preg_match('/\A[A-Za-z0-9][A-Za-z0-9._-]*\z/', $v) && $v !== '..';
    };
    $lines = []; $seen = [];
    foreach ($rows as $row) {
        if (!is_object($row)) throw new RuntimeException();
        if ($mode === 'checksums') {
            if (!$safe_name($row->plugin_name ?? null) || !isset($allowed[$row->plugin_name]) ||
                !is_string($row->file ?? null) || $row->file === '' || strlen($row->file) > 4096 ||
                !is_string($row->message ?? null) || $row->message === '' || strlen($row->message) > 2000) throw new RuntimeException();
            if ($row->file[0] === '/' || strpos($row->file, '\\') !== false) throw new RuntimeException();
            foreach (explode('/', $row->file) as $part) {
                if ($part === '' || $part === '.' || $part === '..') throw new RuntimeException();
            }
            $lines[] = implode('|', [$row->plugin_name, $clean($row->file), $clean($row->message)]);
        } else {
            if (!$safe_name($row->name ?? null) || !is_string($row->status ?? null) ||
                !in_array($row->status, ['active','active-network','inactive','must-use','dropin','paused'], true) ||
                isset($seen[$row->name])) throw new RuntimeException();
            $seen[$row->name] = true;
            if (!in_array($row->status, ['active','active-network'], true)) continue;
            if ($mode === 'availability') {
                if (!is_string($row->wporg_status ?? null)) throw new RuntimeException();
                $lines[] = $row->name . '|' . $clean(strtolower($row->wporg_status));
            } else {
                if (!is_string($row->version ?? null) || !is_string($row->title ?? null)) throw new RuntimeException();
                $lines[] = implode('|', [$row->name, $row->status, $clean($row->version), $clean($row->title)]);
            }
        }
    }
    // Publish only after the complete structure validates, never a partial plan.
    if ($lines) echo implode("\n", $lines), "\n";
} catch (Throwable $e) {
    fwrite(STDERR, "Invalid, unsafe or oversized plugin verification data; coverage incomplete.\n");
    exit(2);
}
