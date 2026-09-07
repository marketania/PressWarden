#!/usr/bin/env bash
# js-threat-intel — high-signal browser-side malware and injected-loader detection.
NAME=js-threat-intel; DESC="JavaScript malware / injected-loader / redirect intelligence"
SCAN_DOES="Prefilters JavaScript/HTML assets and validates compound browser-side behaviors such as decoded execution, obfuscated remote script loading, hidden external iframes, and decoded redirect targets."
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

function pw_js_collect_literal_decoders($s) {
    $vars=[]; $patterns=[
        '~(?:^|[;,{(])\s*(?:(?:var|let|const)\s+)?([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*((?:window\.)?atob|(?:window\.)?decodeURIComponent|(?:window\.)?unescape)\s*\(\s*([\'\"])([^\'\"]{1,8192})\3\s*\)~im',
        '~(?:^|[;,{(])\s*(?:(?:var|let|const)\s+)?([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(String\.fromCharCode)\s*\(\s*([0-9a-fx,\s]{3,8192})\s*\)~im'
    ];
    if (preg_match_all($patterns[0],$s,$m,PREG_SET_ORDER)) {
        foreach($m as $x){$v=pw_js_decode_literal($x[2],$x[4]);if(pw_js_script_target($v))$vars[$x[1]]=true;}
    }
    if (preg_match_all($patterns[1],$s,$m,PREG_SET_ORDER)) {
        foreach($m as $x){$v=pw_js_decode_literal($x[2],$x[3]);if(pw_js_script_target($v))$vars[$x[1]]=true;}
    }
    return $vars;
}

function pw_js_direct_decoded_src($s,$scriptVar) {
    $sv=preg_quote($scriptVar,'~'); $m=[];
    $prefix='(?:'.$sv.'\.src\s*=\s*|'.$sv.'\.setAttribute\s*\(\s*[\'\"]src[\'\"]\s*,\s*)';
    if (preg_match('~'.$prefix.'((?:window\.)?atob|(?:window\.)?decodeURIComponent|(?:window\.)?unescape)\s*\(\s*([\'\"])([^\'\"]{1,8192})\2\s*\)~i',$s,$m)) {
        return pw_js_script_target(pw_js_decode_literal($m[1],$m[3]));
    }
    if (preg_match('~'.$prefix.'(String\.fromCharCode)\s*\(\s*([0-9a-fx,\s]{3,8192})\s*\)~i',$s,$m)) {
        return pw_js_script_target(pw_js_decode_literal($m[1],$m[2]));
    }
    return false;
}

function pw_js_tied_obfuscated_loader($s) {
    // Analyze a bounded neighborhood around each actual script element. This
    // prevents minified bundles from correlating an unrelated atob() in one
    // module with a normal chunk-loader variable of the same short name in a
    // different module.
    if (!preg_match_all('~(?:^|[;,{(])\s*(?:(?:var|let|const)\s+)?([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:window\.)?document\.createElement\s*\(\s*[\'\"]script[\'\"]\s*\)~im',$s,$scripts,PREG_SET_ORDER|PREG_OFFSET_CAPTURE)) return false;
    foreach($scripts as $sm){
        $scriptVar=$sm[1][0]; $offset=$sm[0][1];
        $start=max(0,$offset-1000); $window=substr($s,$start,6000);
        $sv=preg_quote($scriptVar,'~');
        $inserted=(bool)preg_match('~\b(?:appendChild|insertBefore|append|prepend)\s*\(\s*'.$sv.'\b~i',$window);
        if(!$inserted) continue;
        if(pw_js_direct_decoded_src($window,$scriptVar)) return true;
        $dangerVars=pw_js_collect_literal_decoders($window);
        foreach(array_keys($dangerVars) as $name){
            $v=preg_quote($name,'~');
            if(preg_match('~(?:'.$sv.'\.src\s*=\s*'.$v.'\b|'.$sv.'\.setAttribute\s*\(\s*[\'\"]src[\'\"]\s*,\s*'.$v.'\b)~i',$window)) return true;
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
    $hiddenIframe=(bool)preg_match('~<iframe\b[^>]*(?:display\s*:\s*none|visibility\s*:\s*hidden|width\s*=\s*[\'\"]?0|height\s*=\s*[\'\"]?0)[^>]*>~i',$s);
    $iframeRemote=(bool)preg_match('~<iframe\b[^>]+https?://~i',$s);

    $redirectDirect=(bool)preg_match('~(?:window\.)?location(?:\.href)?\s*=\s*'.$decoder.'\s*\(|(?:window\.)?location\.(?:assign|replace)\s*\(\s*'.$decoder.'\s*\(~i',$s);
    $redirectVar=false;
    $decodedVars=[];
    if(!$redirectDirect && preg_match_all('~(?:var|let|const)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*'.$decoder.'\s*\(~i',$s,$matches)){
        $decodedVars=array_values(array_unique($matches[1]));
        foreach($decodedVars as $name){
            $v=preg_quote($name,'~');
            if(preg_match('~(?:window\.)?location(?:\.href)?\s*=\s*'.$v.'\b|(?:window\.)?location\.(?:assign|replace)\s*\(\s*'.$v.'\b~i',$s)){
                $redirectVar=true; break;
            }
        }
    }

    if ($directExec && ($domInsert || $remote || strlen($s)>4000)) {
        echo "ALERT\tPW-JS-001\t",$file,"\n"; continue;
    }
    if ($decodedSrc) {
        echo "ALERT\tPW-JS-002\t",$file,"\n"; continue;
    }
    if (($redirectDirect || $redirectVar) && $decode) {
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

  sec "PW-JS-002 • obfuscated remote script-loader injection" "same script object + statically decoded external/executable target + DOM insertion"
  report "$A2" issue "no high-confidence obfuscated remote script-loader chains found"
  note "PW-JS-002 does not correlate unrelated decoder and script-loader code across a minified bundle. Dynamic application values such as atob(config) are not findings unless the decoded script target can be proven statically."

  sec "PW-JS-004 • decoded browser redirect target" "decoded/character-reconstructed value reaches location assignment/replace/assign • redirect-malware behavior"
  report "$A4" issue "no decoded browser redirect chains found"
  note "Normal first-party redirects such as location.href='/account' are not findings because the redirect target must be reconstructed through a decoder."

  sec "PW-JS-003 • hidden external iframe with obfuscation" "hidden iframe + remote URL + decode/eval evidence"
  report "$R3" review "no hidden external iframe with corroborating obfuscation found"

  rm -f "$CAND" "$V"
  finish
}
run_logged js-threat-intel
