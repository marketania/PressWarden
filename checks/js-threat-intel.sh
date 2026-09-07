#!/usr/bin/env bash
# js-threat-intel — high-signal browser-side malware and injected-loader detection.
NAME=js-threat-intel; DESC="JavaScript malware / injected-loader / redirect intelligence"
SCAN_DOES="Prefilters JavaScript/HTML assets and validates compound browser-side behaviors such as decoded execution, obfuscated remote script injection, hidden external iframes, and decoded redirect targets."
SCAN_WHY="Balada, SocGholish, Sign1, VexTrio-like redirectors and unrelated compromises often live in JavaScript or stored HTML rather than obvious PHP webshells."
. "$(cd "$(dirname "$0")/.." && pwd)/lib/_lib.sh"

_make_validator() {
  local f="$1"
  cat > "$f" <<'PRESSWARDEN_JS_VALIDATOR'
<?php
function pw_js_decode_literal($decoder, $arg) {
    $decoder=strtolower($decoder);
    if ($decoder==='atob' || $decoder==='window.atob') {
        $v=base64_decode($arg,true);
        return $v===false ? null : $v;
    }
    if ($decoder==='decodeuricomponent' || $decoder==='window.decodeuricomponent') {
        return rawurldecode($arg);
    }
    if ($decoder==='unescape' || $decoder==='window.unescape') {
        $arg=preg_replace_callback('~%u([0-9a-f]{4})~i',function($m){
            $cp=hexdec($m[1]);
            if ($cp<0x80) return chr($cp);
            if ($cp<0x800) return chr(0xC0|($cp>>6)).chr(0x80|($cp&0x3F));
            return chr(0xE0|($cp>>12)).chr(0x80|(($cp>>6)&0x3F)).chr(0x80|($cp&0x3F));
        },$arg);
        return rawurldecode($arg);
    }
    if ($decoder==='string.fromcharcode') {
        $out='';
        foreach (preg_split('~\s*,\s*~',trim($arg)) as $n) {
            if ($n==='') return null;
            if (preg_match('~^0x[0-9a-f]+$~i',$n)) $v=hexdec(substr($n,2));
            elseif (preg_match('~^\d+$~',$n)) $v=(int)$n;
            else return null;
            if ($v<0 || $v>65535) return null;
            $out.=chr($v & 0xff);
        }
        return $out;
    }
    return null;
}

function pw_js_script_target($value) {
    if (!is_string($value)) return false;
    $value=ltrim($value);
    return (bool)preg_match('~^(?:(?:https?:)?//|javascript:|data:(?:text|application)/(?:javascript|ecmascript))~i',$value);
}

function pw_js_redirect_target($value) {
    if (!is_string($value)) return false;
    $value=ltrim($value);
    return (bool)preg_match('~^(?:(?:https?:)?//|javascript:|data:(?:text/html|(?:text|application)/(?:javascript|ecmascript)))~i',$value);
}

function pw_js_high_risk_target($value) {
    if (!is_string($value)) return false;
    $v=ltrim($value);
    if (preg_match('~^(?:javascript:|data:(?:text/html|(?:text|application)/(?:javascript|ecmascript)))~i',$v)) return true;
    $url=strpos($v,'//')===0 ? 'https:'.$v : $v;
    $host=@parse_url($url,PHP_URL_HOST);
    return is_string($host) && filter_var($host,FILTER_VALIDATE_IP)!==false;
}

function pw_js_evasion_gate($s) {
    // High-confidence injection/redirect rules require visitor/environment
    // gating near the sink. Avoid generic pathname/query routing signals that
    // are common in normal application bundles.
    $subject='(?:document\.cookie|navigator\.(?:userAgent|platform)|document\.referrer|location\.(?:hostname|host)|(?:localStorage|sessionStorage)\.(?:getItem|key)|screen\.(?:width|height))';
    if (preg_match('~\bif\s*\(.{0,900}?'.$subject.'.{0,900}?\)\s*\{?~is',$s)) return true;
    if (preg_match('~'.$subject.'.{0,500}?(?:\.includes\s*\(|\.indexOf\s*\(|\.match\s*\(|\.test\s*\(|===|!==|==|!=)~is',$s)) return true;
    return false;
}

function pw_js_collect_literal_decoders($s) {
    $vars=[]; $patterns=[
        '~(?:^|[;,{(])\s*(?:(?:var|let|const)\s+)?([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*((?:window\.)?atob|(?:window\.)?decodeURIComponent|(?:window\.)?unescape)\s*\(\s*([\'\"])([^\'\"]{1,8192})\3\s*\)~im',
        '~(?:^|[;,{(])\s*(?:(?:var|let|const)\s+)?([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(String\.fromCharCode)\s*\(\s*([0-9a-fx,\s]{3,8192})\s*\)~im'
    ];
    if (preg_match_all($patterns[0],$s,$m,PREG_SET_ORDER)) {
        foreach($m as $x){$v=pw_js_decode_literal($x[2],$x[4]);if(pw_js_script_target($v))$vars[$x[1]]=$v;}
    }
    if (preg_match_all($patterns[1],$s,$m,PREG_SET_ORDER)) {
        foreach($m as $x){$v=pw_js_decode_literal($x[2],$x[3]);if(pw_js_script_target($v))$vars[$x[1]]=$v;}
    }
    return $vars;
}

function pw_js_direct_decoded_src($s,$scriptVar) {
    $sv=preg_quote($scriptVar,'~'); $m=[];
    $prefix='(?:'.$sv.'\.src\s*=\s*|'.$sv.'\.setAttribute\s*\(\s*[\'\"]src[\'\"]\s*,\s*)';
    if (preg_match('~'.$prefix.'((?:window\.)?atob|(?:window\.)?decodeURIComponent|(?:window\.)?unescape)\s*\(\s*([\'\"])([^\'\"]{1,8192})\2\s*\)~i',$s,$m)) {
        $v=pw_js_decode_literal($m[1],$m[3]);
        return pw_js_script_target($v) ? $v : null;
    }
    if (preg_match('~'.$prefix.'(String\.fromCharCode)\s*\(\s*([0-9a-fx,\s]{3,8192})\s*\)~i',$s,$m)) {
        $v=pw_js_decode_literal($m[1],$m[2]);
        return pw_js_script_target($v) ? $v : null;
    }
    return null;
}

function pw_js_tied_obfuscated_loader($s) {
    // Analyze a tight neighborhood around each actual script element. This
    // prevents framework/minified bundles from combining unrelated decoder,
    // visitor-state and chunk-loader modules merely because they share a file.
    if (!preg_match_all('~(?:^|[;,{(])\s*(?:(?:var|let|const)\s+)?([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:window\.)?document\.createElement\s*\(\s*[\'\"]script[\'\"]\s*\)~im',$s,$scripts,PREG_SET_ORDER|PREG_OFFSET_CAPTURE)) return false;
    foreach($scripts as $sm){
        $scriptVar=$sm[1][0]; $offset=$sm[0][1];
        $start=max(0,$offset-700); $window=substr($s,$start,3600);
        $sv=preg_quote($scriptVar,'~');
        $inserted=(bool)preg_match('~\b(?:appendChild|insertBefore|append|prepend)\s*\(\s*'.$sv.'\b~i',$window);
        if(!$inserted) continue;

        $target=pw_js_direct_decoded_src($window,$scriptVar);
        if($target!==null && (pw_js_high_risk_target($target) || pw_js_evasion_gate($window))) return true;

        $dangerVars=pw_js_collect_literal_decoders($window);
        foreach($dangerVars as $name=>$decodedTarget){
            $v=preg_quote($name,'~');
            $reaches=(bool)preg_match('~(?:'.$sv.'\.src\s*=\s*'.$v.'\b|'.$sv.'\.setAttribute\s*\(\s*[\'\"]src[\'\"]\s*,\s*'.$v.'\b)~i',$window);
            if($reaches && (pw_js_high_risk_target($decodedTarget) || pw_js_evasion_gate($window))) return true;
        }
    }
    return false;
}

function pw_js_tied_decoded_redirect($s) {
    // Direct decoder -> location sink with a literal target. Each match is
    // evaluated only inside a small neighborhood so unrelated bundle modules
    // cannot satisfy the rule together.
    $patterns=[
        '~(?:window\.)?location(?:\.href)?\s*=\s*((?:window\.)?atob|(?:window\.)?decodeURIComponent|(?:window\.)?unescape)\s*\(\s*([\'\"])([^\'\"]{1,8192})\2\s*\)~i',
        '~(?:window\.)?location\.(?:assign|replace)\s*\(\s*((?:window\.)?atob|(?:window\.)?decodeURIComponent|(?:window\.)?unescape)\s*\(\s*([\'\"])([^\'\"]{1,8192})\2\s*\)\s*\)~i',
        '~(?:window\.)?location(?:\.href)?\s*=\s*(String\.fromCharCode)\s*\(\s*([0-9a-fx,\s]{3,8192})\s*\)~i',
        '~(?:window\.)?location\.(?:assign|replace)\s*\(\s*(String\.fromCharCode)\s*\(\s*([0-9a-fx,\s]{3,8192})\s*\)\s*\)~i'
    ];
    foreach($patterns as $i=>$re){
        if(!preg_match_all($re,$s,$matches,PREG_SET_ORDER|PREG_OFFSET_CAPTURE)) continue;
        foreach($matches as $m){
            $decoder=$m[1][0];
            $arg=($i<2) ? $m[3][0] : $m[2][0];
            $target=pw_js_decode_literal($decoder,$arg);
            if(!pw_js_redirect_target($target)) continue;
            $offset=$m[0][1]; $start=max(0,$offset-700); $window=substr($s,$start,3200);
            if(pw_js_high_risk_target($target) || pw_js_evasion_gate($window)) return true;
        }
    }

    // Literal decoder assignment -> same variable reaches location sink nearby.
    $assignments=[
        '~(?:^|[;,{(])\s*(?:(?:var|let|const)\s+)?([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*((?:window\.)?atob|(?:window\.)?decodeURIComponent|(?:window\.)?unescape)\s*\(\s*([\'\"])([^\'\"]{1,8192})\3\s*\)~im',
        '~(?:^|[;,{(])\s*(?:(?:var|let|const)\s+)?([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(String\.fromCharCode)\s*\(\s*([0-9a-fx,\s]{3,8192})\s*\)~im'
    ];
    foreach($assignments as $i=>$re){
        if(!preg_match_all($re,$s,$matches,PREG_SET_ORDER|PREG_OFFSET_CAPTURE)) continue;
        foreach($matches as $m){
            $name=$m[1][0]; $decoder=$m[2][0];
            $arg=($i===0) ? $m[4][0] : $m[3][0];
            $target=pw_js_decode_literal($decoder,$arg);
            if(!pw_js_redirect_target($target)) continue;
            $offset=$m[0][1]; $start=max(0,$offset-700); $window=substr($s,$start,3200);
            $v=preg_quote($name,'~');
            $reaches=(bool)preg_match('~(?:window\.)?location(?:\.href)?\s*=\s*'.$v.'\b|(?:window\.)?location\.(?:assign|replace)\s*\(\s*'.$v.'\b~i',$window);
            if($reaches && (pw_js_high_risk_target($target) || pw_js_evasion_gate($window))) return true;
        }
    }
    return false;
}

while (($line=fgets(STDIN))!==false) {
    $file=rtrim($line,"\r\n"); if($file===''||!is_file($file))continue;
    $s=@file_get_contents($file); if($s===false)continue;
    $low=strtolower($s);
    $decoder='(?:atob|String\.fromCharCode|decodeURIComponent|unescape)';
    $decode=(bool)preg_match('~\b'.$decoder.'\s*\(~i',$s);
    $directExec=(bool)preg_match('~\b(?:eval|Function)\s*\(\s*'.$decoder.'\s*\(~i',$s);
    $domInsert=(bool)preg_match('~\b(?:appendChild|insertBefore|document\.write)\s*\(~i',$s);
    $remote=(bool)preg_match('~https?:\\?/\\?/|[\'\"](?:src|href)[\'\"]\s*[,=:]~i',$s);
    $decodedSrc=pw_js_tied_obfuscated_loader($s);
    $decodedRedirect=pw_js_tied_decoded_redirect($s);
    $hiddenIframe=(bool)preg_match('~<iframe\b[^>]*(?:display\s*:\s*none|visibility\s*:\s*hidden|width\s*=\s*[\'\"]?0|height\s*=\s*[\'\"]?0)[^>]*>~i',$s);
    $iframeRemote=(bool)preg_match('~<iframe\b[^>]+https?://~i',$s);

    if ($directExec && ($domInsert || $remote || strlen($s)>4000)) {
        echo "ALERT\tPW-JS-001\t",$file,"\n"; continue;
    }
    if ($decodedSrc) {
        echo "ALERT\tPW-JS-002\t",$file,"\n"; continue;
    }
    if ($decodedRedirect) {
        echo "ALERT\tPW-JS-004\t",$file,"\n"; continue;
    }
    if ($hiddenIframe && $iframeRemote && ($decode || strpos($low,'eval(')!==false)) {
        echo "REVIEW\tPW-JS-003\t",$file,"\n"; continue;
    }
}
PRESSWARDEN_JS_VALIDATOR
}

main() {
  banner
  local CAND V A1 A2 A4 R3 s
  CAND=$(tmpf); V=$(tmpf); A1=$(tmpf); A2=$(tmpf); A4=$(tmpf); R3=$(tmpf)
  : > "$CAND"; : > "$A1"; : > "$A2"; : > "$A4"; : > "$R3"

  for s in "${TREE_ROOTS[@]}"; do
    find "$s" -xdev \
      \( -type d \( -name vendor -o -name node_modules -o -name cache -o -name caches -o -name wflogs -o -name .git -o -name .private \) -prune \) -o \
      \( -type f \( -name '*.js' -o -name '*.html' -o -name '*.htm' \) -size -6M -print0 \) 2>/dev/null \
      | xargs -0 -r grep -IlEi 'atob\s*\(|String\.fromCharCode\s*\(|decodeURIComponent\s*\(|unescape\s*\(|createElement\s*\(|appendChild\s*\(|insertBefore\s*\(|<iframe|eval\s*\(|location(\.href|\.assign|\.replace)?[[:space:]]*[=(]' 2>/dev/null >> "$CAND"
  done
  sort -u "$CAND" -o "$CAND"

  if [ -s "$CAND" ] && command -v php >/dev/null 2>&1; then
    _make_validator "$V"
    php "$V" < "$CAND" 2>/dev/null | while IFS=$'\t' read -r kind rule file; do
      [ -n "$file" ] || continue
      case "$kind:$rule" in
        ALERT:PW-JS-001) printf '%s\n' "$file" >> "$A1" ;;
        ALERT:PW-JS-002) printf '%s\n' "$file" >> "$A2" ;;
        ALERT:PW-JS-004) printf '%s\n' "$file" >> "$A4" ;;
        REVIEW:PW-JS-003) printf '%s\n' "$file" >> "$R3" ;;
      esac
    done
    sort -u "$A1" -o "$A1"; sort -u "$A2" -o "$A2"; sort -u "$A4" -o "$A4"; sort -u "$R3" -o "$R3"
  fi

  sec "PW-JS-001 • decoded JavaScript execution" "eval/Function fed by atob/fromCharCode/decode routines + corroborating browser behavior"
  report "$A1" issue "no decoded JavaScript execution chains found"

  sec "PW-JS-002 • obfuscated remote script injection" "same script object + statically decoded target + DOM insertion + local visitor/environment evasion gate"
  report "$A2" issue "no high-confidence obfuscated remote script-injection chains found"
  note "A statically encoded CDN/chunk URL is not malware by itself. PW-JS-002 also requires nearby visitor/environment gating, except intrinsically high-risk javascript/data targets or IP-host targets."
  note "Elementor/Wordfence/core-style bundles are not allowlisted by name; the rule is behaviorally stricter so legitimate packages and generated LiteSpeed copies do not become alerts simply for loading scripts."

  sec "PW-JS-004 • obfuscated browser redirect" "local literal decode → same redirect sink + external/executable target + visitor/environment evasion gate"
  report "$A4" issue "no high-confidence obfuscated browser redirect chains found"
  note "PW-JS-004 no longer correlates decoder variables and location sinks across an entire minified bundle. Static encoded application redirects are not malware by themselves."
  note "Normal first-party redirects and dynamic application routing remain clean; high-confidence alerts require a proven decoded external/executable target plus nearby evasion/gating, except intrinsically high-risk javascript/data or IP-host targets."

  sec "PW-JS-003 • hidden external iframe with obfuscation" "hidden iframe + remote URL + decode/eval evidence"
  report "$R3" review "no hidden external iframe with corroborating obfuscation found"

  rm -f "$CAND" "$V"
  finish
}
run_logged js-threat-intel
