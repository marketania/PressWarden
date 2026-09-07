<?php
require __DIR__.'/../lib/js-flow.php';
// More than 5 MiB of unrelated modules, followed by a real review-worthy chain.
$source = str_repeat('(function(){const e=atob("aGVsbG8=");return e;})();', 110000);
$source .= 'if(document.cookie){const u=atob("aHR0cHM6Ly9wYXlsb2FkLmludmFsaWQveA==");location.href=u;}';
$scanner = new PressWardenJsFlow();
$found = $scanner->scan($source);
if (!in_array('PW-JS-004', array_column($found, 'rule'), true)) exit(1);
printf("Streaming JS: %d bytes; peak %d bytes; late injection detected\n", strlen($source), memory_get_peak_usage(true));
