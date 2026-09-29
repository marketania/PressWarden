<?php
/** Bounded, inert WPScan JSON interpretation. Never include/evaluate site code. */
function pw_wpscan_text($value, $limit = 320) {
    if (!is_string($value)) return '';
    $secret = getenv('WPSCAN_API_TOKEN');
    if (is_string($secret) && $secret !== '') $value = str_replace($secret, '[redacted]', $value);
    $value = preg_replace('/[\p{Cc}\p{Cf}]/u', '?', $value);
    if (!is_string($value) || !preg_match('/\A.{0,' . $limit . '}/us', $value, $match)) return '[invalid text]';
    return $match[0];
}
function pw_wpscan_url($value) {
    if (!is_string($value) || strlen($value) > 4096 || preg_match('/[\x00-\x20\x7f\\\\]/', $value)) return false;
    if (!filter_var($value, FILTER_VALIDATE_URL)) return false;
    $parts = parse_url($value);
    if (!$parts || !isset($parts['scheme'], $parts['host']) || !in_array(strtolower($parts['scheme']), ['http','https'], true)) return false;
    foreach (['user','pass','query','fragment'] as $key) if (array_key_exists($key, $parts)) return false;
    $port = isset($parts['port']) ? ':' . $parts['port'] : '';
    $path = $parts['path'] ?? '/';
    return strtolower($parts['scheme']) . '://' . strtolower($parts['host']) . $port . rtrim($path, '/') . '/';
}
function pw_wpscan_read($path, $max) {
    if (!is_file($path) || is_link($path)) throw new RuntimeException('Unsafe or missing provider output');
    $f = @fopen($path, 'rb');
    if (!$f) throw new RuntimeException('Unreadable provider output');
    $raw = stream_get_contents($f, $max + 1); fclose($f);
    if ($raw === false || strlen($raw) > $max) throw new RuntimeException('Provider output exceeds its size limit');
    return $raw;
}
function pw_wpscan_report($path, $expected, $exit, $diagnostics) {
    $raw = pw_wpscan_read($path, 8 * 1024 * 1024);
    $report = json_decode($raw, false, 64);
    if (json_last_error() !== JSON_ERROR_NONE || !($report instanceof stdClass)) throw new RuntimeException('Invalid WPScan JSON result');
    $issues = [];
    if (!in_array($exit, [0, 5], true)) $issues[] = 'WPScan did not complete successfully (exit ' . $exit . ')';
    if ($diagnostics) $issues[] = 'WPScan emitted diagnostics; raw output withheld';
    if (pw_wpscan_url($report->target_url ?? null) !== pw_wpscan_url($expected)) {
        // Findings for a different target must not be attributed to this installation.
        throw new RuntimeException('WPScan target URL does not match the validated site URL');
    }
    if (isset($report->scan_aborted)) $issues[] = 'WPScan reports an aborted scan';
    if (!isset($report->stop_time) || !is_int($report->stop_time) || $report->stop_time <= 0) $issues[] = 'WPScan completion marker is missing';
    if (!empty($report->response_status_codes_warning) || !empty($report->response_status_codes_warnings)) $issues[] = 'Remote HTTP coverage warnings were reported';
    if (!empty($report->notices)) $issues[] = 'WPScan reported notices requiring review';
    $api = $report->vuln_api ?? null;
    if (!($api instanceof stdClass) || isset($api->error) || isset($api->http_error) || isset($api->parse_error)) {
        $issues[] = 'Vulnerability API coverage is unavailable or failed';
    } elseif (!isset($api->requests_done_during_scan, $api->requests_remaining)
              || !is_int($api->requests_done_during_scan) || $api->requests_done_during_scan < 1
              || !is_int($api->requests_remaining) || $api->requests_remaining <= 0) {
        $issues[] = 'Vulnerability API coverage is unverified or quota exhausted';
    }
    $components = [];
    $version = $report->version ?? null;
    if ($version instanceof stdClass && is_string($version->number ?? null) && $version->number !== '') {
        $components[] = ['WordPress', $version];
    } else $issues[] = 'Remote WordPress version coverage is unknown';
    if (!property_exists($report, 'main_theme')) $issues[] = 'Main theme coverage field is missing';
    elseif ($report->main_theme !== null) $components[] = ['main theme', $report->main_theme];
    foreach (['plugins','themes'] as $kind) {
        if (!isset($report->$kind) || !($report->$kind instanceof stdClass)) {
            $issues[] = 'Invalid or missing ' . $kind . ' inventory'; continue;
        }
        $items = get_object_vars($report->$kind);
        if (count($items) > 5000) throw new RuntimeException('WPScan inventory exceeds its record limit');
        foreach ($items as $slug => $item) {
            if (!preg_match('/^[A-Za-z0-9][A-Za-z0-9_.-]{0,199}$/D', $slug)) {
                $issues[] = 'Invalid provider component identifier'; continue;
            }
            $components[] = [$kind . '/' . $slug, $item];
        }
    }
    $findings = []; $seen = []; $count = 0;
    foreach ($components as $entry) {
        list($name, $component) = $entry;
        if (!($component instanceof stdClass) || !isset($component->vulnerabilities) || !is_array($component->vulnerabilities)) {
            $issues[] = 'Invalid vulnerability records for a reported component'; continue;
        }
        if ($name !== 'WordPress' && (!isset($component->version) || !($component->version instanceof stdClass)
            || !is_string($component->version->number ?? null) || $component->version->number === '')) {
            $issues[] = 'A reported component version is unknown';
        }
        foreach ($component->vulnerabilities as $vulnerability) {
            if (++$count > 10000) throw new RuntimeException('WPScan vulnerability record limit exceeded');
            if (!($vulnerability instanceof stdClass) || !is_string($vulnerability->title ?? null) || $vulnerability->title === '') {
                $issues[] = 'Malformed vulnerability record'; continue;
            }
            $title = pw_wpscan_text($vulnerability->title);
            $id = pw_wpscan_text($vulnerability->uuid ?? '', 80);
            $fixed = pw_wpscan_text($vulnerability->fixed_in ?? '', 80);
            $text = $name . ': ' . $title . ($id !== '' ? ' [ID ' . $id . ']' : '') . ($fixed !== '' ? ' (provider fixed-in: ' . $fixed . ')' : '');
            if (!isset($seen[$text])) { $findings[] = $text; $seen[$text] = true; }
        }
    }
    if ($exit === 5 && !$findings) $issues[] = 'WPScan signaled vulnerabilities but no valid vulnerability records were returned';
    foreach (array_slice($findings, 0, 100) as $text) echo "FINDING\t", $text, "\n";
    if (count($findings) > 100) $issues[] = 'Finding display limit reached; coverage is incomplete';
    foreach (array_unique($issues) as $message) echo "INCOMPLETE\t", $message, "\n";
    if (!$issues && !$findings) echo "OK\tNo vulnerability records reported by remote passive enumeration; not a full installed-component inventory\n";
    return $issues ? 2 : ($findings ? 1 : 0);
}
if (realpath($_SERVER['SCRIPT_FILENAME'] ?? '') === __FILE__) {
    try {
        if (($argv[1] ?? '') === 'url' && count($argv) === 3) {
            $raw = pw_wpscan_read($argv[2], 4096);
            // Permit one normal CLI line ending, not extra output or embedded control bytes.
            $raw = preg_replace('/\r?\n\z/', '', $raw);
            $url = pw_wpscan_url($raw);
            if ($url === false) throw new RuntimeException('Site home must be a single HTTP(S) URL without credentials, query or fragment');
            echo $url, "\n"; exit(0);
        }
        if (($argv[1] ?? '') !== 'report' || count($argv) !== 6 || !ctype_digit($argv[4]) || !in_array($argv[5], ['0','1'], true)) throw new RuntimeException('Invalid provider parser request');
        if (pw_wpscan_url($argv[3]) === false) throw new RuntimeException('Invalid expected target');
        exit(pw_wpscan_report($argv[2], $argv[3], (int)$argv[4], $argv[5] === '1'));
    } catch (Throwable $e) {
        // All exception messages are static or constructed from validated integers.
        echo "INCOMPLETE\t", pw_wpscan_text($e->getMessage()), "\n";
        exit(2);
    }
}
