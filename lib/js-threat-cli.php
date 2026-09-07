<?php
/** PressWarden read-only JS validator. Input: NUL-delimited absolute paths. */
require __DIR__.'/js-flow.php';
$scanner = new PressWardenJsFlow(); $errors = 0;
$cache = []; $candidates = 0; $analyses = 0; $reused = 0;
function pw_js_display_path($path) {
    return preg_replace_callback('~[\x00-\x1f\x7f]~', function ($m) { return sprintf('\\x%02X', ord($m[0])); }, $path);
}
while (($path = stream_get_line(STDIN, 1048576, "\0")) !== false) {
    if ($path === '') continue;
    try {
        if (!is_file($path) || !is_readable($path)) throw new RuntimeException('file is no longer readable');
        $source = @file_get_contents($path, false, null, 0, 6 * 1024 * 1024 + 1);
        if ($source === false || strlen($source) > 6 * 1024 * 1024) throw new RuntimeException('read failed or file grew beyond the 6 MiB analysis limit');
        if (!preg_match('~\b(?:atob|fromCharCode|decodeURIComponent|unescape)\s*\(~', $source)) continue;
        ++$candidates;
        $html = (bool)preg_match('~\.html?$~i', $path);
        // Content-keyed, process-local LRU. Never trust a path, package name,
        // modification time, or a previous run's hash. No source bodies cached.
        $key = ($html ? 'html:' : 'js:').hash('sha256', $source);
        if (array_key_exists($key, $cache)) {
            ++$reused; $found = $cache[$key]; unset($cache[$key]);
        } else {
            ++$analyses; $units = [$source];
            if ($html) {
                $units = [];
                if (preg_match_all('~<script\b([^>]*)>([\s\S]*?)</script\s*>~i', $source, $matches, PREG_SET_ORDER)) {
                    foreach ($matches as $m) {
                        if (preg_match('~\btype\s*=\s*[\'"](?:application/(?:ld\+)?json|text/template)[\'"]~i', $m[1])) continue;
                        $units[] = $m[2];
                    }
                }
            }
            $found = [];
            foreach ($units as $unit) foreach ($scanner->scan($unit) as $finding) {
                if (($found[$finding['rule']]['kind'] ?? '') !== 'ALERT') $found[$finding['rule']] = $finding;
            }
            // The decoded handler must belong to the same hidden remote tag.
            // An unrelated decoder elsewhere in the file is not corroboration.
            if (preg_match_all('~<iframe\b[^>]*>~i', $source, $frames)) foreach ($frames[0] as $tag) {
                if (preg_match('~\bsrc\s*=\s*[\'"](?:https?:)?//~i', $tag)
                    && preg_match('~display\s*:\s*none|visibility\s*:\s*hidden|(?:width|height)\s*=\s*[\'"]?0(?:[\'"\s>])~i', $tag)
                    && preg_match('~\bon(?:load|error)\s*=[^>]*\beval\s*\(\s*atob\s*\(~i', $tag)) {
                    $found['PW-JS-003'] = ['kind'=>'REVIEW', 'rule'=>'PW-JS-003', 'line'=>0, 'evidence'=>'same iframe: hidden external src and decoded event-handler execution'];
                }
            }
        }
        $cache[$key] = $found;
        if (count($cache) > 512) array_shift($cache);
        foreach ($found as $f) {
            $position = $html ? 'inline-script line ' : 'line ';
            $evidence = $position.$f['line'].'; '.$f['evidence'];
            printf("%s\t%s\t%s [%s; %s]\n", $f['kind'], $f['rule'], pw_js_display_path($path), $f['rule'], $evidence);
        }
    } catch (Throwable $e) {
        ++$errors;
        // Escape filenames, omit source bodies, decoded payloads, and URL secrets.
        fwrite(STDERR, 'INCOMPLETE: '.pw_js_display_path($path).': '.$e->getMessage()."\n");
    }
}
fprintf(STDERR, "JS ANALYSIS: %d decoder-bearing files; %d unique analyses; %d identical-file results reused\n", $candidates, $analyses, $reused);
exit($errors > 0 ? 2 : 0);
