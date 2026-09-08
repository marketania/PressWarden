<?php
/** Validate the DB helper protocol. Never forward raw WP/bootstrap output. */
if ($argc !== 4) exit(2);
[$file, $site, $status] = array_slice($argv, 1);
$input = @fopen($file, 'rb'); if (!$input) exit(2);
$site = preg_replace_callback('~[\x00-\x1f\x7f]~', function ($m) { return sprintf('\\x%02X', ord($m[0])); }, $site);
$done = false; $invalid = false; $errors = 0; $findings = 0; $read = 0; $seen = [];
$write = function ($line) { if (@fwrite(STDOUT, $line."\n") !== strlen($line)+1) exit(2); };
while (($line = fgets($input, 4096)) !== false) {
    $read += strlen($line); if ($read > 8388608) { $invalid = true; break; }
    if (strpos($line, "PWDB1\t") !== 0) continue;
    $fields = explode("\t", rtrim($line, "\r\n"));
    if ($done) { $invalid = true; continue; }
    if (count($fields) === 6 && $fields[1] === 'FINDING'
        && in_array($fields[2], ['ALERT','REVIEW'], true)
        && preg_match('/^PW-DB-00[1-6]$/D', $fields[3])
        && in_array($fields[4], ['option','post','admin'], true)
        && preg_match('/^[1-9][0-9]{0,17}$/D', $fields[5])) {
        $key = implode(':', array_slice($fields, 3));
        if (isset($seen[$key])) { $invalid = true; continue; }
        $seen[$key] = true; ++$findings;
        $write($fields[2]."\t".$fields[3]."\t".$site.' ['.$fields[3].'; '.$fields[4].' row '.$fields[5].']');
    } elseif (count($fields) === 5 && $fields[1] === 'ERROR'
        && in_array($fields[2], ['inspection','row_limit','byte_limit','value_size','value_analysis'], true)
        && in_array($fields[3], ['option','post','admin'], true)
        && preg_match('/^[0-9]{1,18}$/D', $fields[4])) {
        ++$errors;
        // Only controlled codes and numeric IDs reach the report.
        $write('ERROR'."\t".$fields[2]."\t".$site.' ['.$fields[3].' row '.$fields[4].']');
    } elseif (count($fields) === 6 && $fields[1] === 'DONE') {
        foreach (array_slice($fields, 2) as $number) if (!preg_match('/^[0-9]{1,10}$/D', $number)) $invalid = true;
        $done = true;
        if ((int)$fields[2] !== $errors || (int)$fields[3] !== $findings) $invalid = true;
    } else $invalid = true;
}
if (!feof($input)) $invalid = true;
fclose($input);
$incomplete = $invalid || !$done || $errors > 0 || $status !== '0';
if ($incomplete && $errors === 0) $write("ERROR\tinspection\t".$site);
$write('STATUS'."\t".($incomplete ? 'INCOMPLETE' : 'COMPLETE')."\t".$site);
exit($incomplete ? 2 : 0);
