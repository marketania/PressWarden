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
while (($line=fgets(STDIN))!==false) {
    $file=rtrim($line,"\r\n"); if($file===''||!is_file($file))continue;
    $s=@file_get_contents($file); if($s===false)continue;
    $low=strtolower($s);
    $decoder='(?:atob|String\.fromCharCode|decodeURIComponent|unescape)';
    $decode=(bool)preg_match('~\b'.$decoder.'\s*\(~i',$s);
    $directExec=(bool)preg_match('~\b(?:eval|Function)\s*\(\s*'.$decoder.'\s*\(~i',$s);
    $scriptElement=(bool)preg_match('~createElement\s*\(\s*[\'\"]script[\'\"]\s*\)~i',$s);
    $domInsert=(bool)preg_match('~\b(?:appendChild|insertBefore|document\.write)\s*\(~i',$s);
    $remote=(bool)preg_match('~https?:\\?/\\?/|[\'\"](?:src|href)[\'\"]\s*[,=:]~i',$s);

    // Track every decoder-assigned variable. Malware often places a harmless
    // decoded value first so detectors that inspect only the first assignment
    // miss the later value that actually reaches a browser sink.
    $decodedVars=[];
    if(preg_match_all('~(?:var|let|const)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*'.$decoder.'\s*\(~i',$s,$matches)){
        $decodedVars=array_values(array_unique($matches[1]));
    }

    $decodedSrc=(bool)preg_match('~(?:\.src\s*=|setAttribute\s*\(\s*[\'\"]src[\'\"]\s*,\s*)\s*'.$decoder.'\s*\(~i',$s);
    if(!$decodedSrc){
        foreach($decodedVars as $name){
            $v=preg_quote($name,'~');
            if(preg_match('~(?:\.src\s*=\s*'.$v.'\b|setAttribute\s*\(\s*[\'\"]src[\'\"]\s*,\s*'.$v.'\b)~i',$s)){
                $decodedSrc=true; break;
            }
        }
    }
    $hiddenIframe=(bool)preg_match('~<iframe\b[^>]*(?:display\s*:\s*none|visibility\s*:\s*hidden|width\s*=\s*[\'\"]?0|height\s*=\s*[\'\"]?0)[^>]*>~i',$s);
    $iframeRemote=(bool)preg_match('~<iframe\b[^>]+https?://~i',$s);

    $redirectDirect=(bool)preg_match('~(?:window\.)?location(?:\.href)?\s*=\s*'.$decoder.'\s*\(|(?:window\.)?location\.(?:assign|replace)\s*\(\s*'.$decoder.'\s*\(~i',$s);
    $redirectVar=false;
    if(!$redirectDirect){
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
    if ($scriptElement && $decodedSrc && $domInsert) {
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

  sec "PW-JS-002 • obfuscated remote script-loader injection" "decoded value reaches script src + dynamic script creation + DOM insertion • Balada-like behavior"
  report "$A2" issue "no obfuscated dynamic script-loader chains found"
  note "String.fromCharCode or createElement(script) alone are not findings; PW-JS-002 requires a decoded value to reach the script source."

  sec "PW-JS-004 • decoded browser redirect target" "decoded/character-reconstructed value reaches location assignment/replace/assign • redirect-malware behavior"
  report "$A4" issue "no decoded browser redirect chains found"
  note "Normal first-party redirects such as location.href='/account' are not findings because the redirect target must be reconstructed through a decoder."

  sec "PW-JS-003 • hidden external iframe with obfuscation" "hidden iframe + remote URL + decode/eval evidence"
  report "$R3" review "no hidden external iframe with corroborating obfuscation found"

  rm -f "$CAND" "$V"
  finish
}
run_logged js-threat-intel
