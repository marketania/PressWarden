<?php
/** Read-only PHP intelligence validator. Input: NUL-delimited local paths. */
require __DIR__.'/php-flow.php';
require __DIR__.'/progress.php';
$progress = new PressWardenProgress('PHP'); $processed = 0;
$scanner = new PressWardenPhpFlow(); $errors = $candidates = $analyses = $reused = 0; $cache = [];
function pw_php_display_path($path) {
    return preg_replace_callback('~[\x00-\x1f\x7f]~', function ($m) { return sprintf('\\x%02X',ord($m[0])); },$path);
}
while (($path = stream_get_line(STDIN, 1048576, "\0")) !== false) {
    if ($path === '') continue;
    try {
        if (strpos($path,'://') !== false || !is_file($path) || !is_readable($path)) throw new RuntimeException('unreadable file');
        $source = @file_get_contents($path, false, null, 0, 5*1024*1024+1);
        if ($source === false || strlen($source) > 5*1024*1024) throw new RuntimeException('read/size limit');
        if (!preg_match('~\$_(?:GET|POST|REQUEST|COOKIE)|\bbase64_decode\s*\(~i',$source)) continue;
        ++$candidates; $key = hash('sha256',$source);
        if (array_key_exists($key,$cache)) { ++$reused; $found = $cache[$key]; unset($cache[$key]); }
        else { ++$analyses; $found = $scanner->scan($source); }
        $cache[$key] = $found;
        if (count($cache) > 256) array_shift($cache);
        foreach ($found as $f) {
            $row = sprintf("%s\t%s\t%s [%s; line %d; %s]\n",$f['kind'],$f['rule'],pw_php_display_path($path),$f['rule'],$f['line'],$f['evidence']);
            if (@fwrite(STDOUT,$row) !== strlen($row)) throw new RuntimeException('evidence write failure');
        }
    } catch (Throwable $e) {
        ++$errors;
        // Parser/runtime exception messages can quote secrets from source. Do
        // not log them; distinguish an incomplete analysis without source text.
        fwrite(STDERR,'INCOMPLETE: '.pw_php_display_path($path).': PHP read or analysis failed; no clean verdict'."\n");
    } finally {
        ++$processed; $progress->advance($processed);
    }
}
$progress->finish($processed, $errors);
fprintf(STDERR,"PHP ANALYSIS: %d candidate files; %d unique analyses; %d identical-file results reused\n",$candidates,$analyses,$reused);
exit($errors ? 2 : 0);
