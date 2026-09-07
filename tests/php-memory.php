<?php
require __DIR__.'/../lib/php-flow.php';
$s = new PressWardenPhpFlow();
$source = '<?php /*'.str_repeat('documentation ',330000).'*/ $f=$_GET["f"]; $f();';
$r = $s->scan($source);
if (count($r)!==1 || $r[0]['rule']!=='PW-PHP-004') exit(1);
printf("PHP large-comment fixture: %d bytes; peak %d bytes; detection retained\n",strlen($source),memory_get_peak_usage(true));
// Dense input exceeds the explicit token budget. It must not become CLEAN.
try { $s->scan('<?php '.str_repeat(';',400010)); exit(1); }
catch (RuntimeException $e) { echo "PHP token budget reports incomplete\n"; }
