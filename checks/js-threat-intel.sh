#!/usr/bin/env bash
# js-threat-intel — high-signal browser-side malware and injected-loader detection.
NAME=js-threat-intel; DESC="JavaScript malware / injected-loader intelligence"
SCAN_DOES="Prefilters JavaScript/HTML assets and validates compound browser-side behaviors such as decoded execution, obfuscated remote script loading, and hidden external iframe injection."
SCAN_WHY="Balada, SocGholish, Sign1 and unrelated compromises often live in JavaScript or stored HTML rather than obvious PHP webshells."
. "$(cd "$(dirname "$0")/.." && pwd)/lib/_lib.sh"

_make_validator() {
  local f="$1"
  cat > "$f" <<'PRESSWARDEN_JS_VALIDATOR'
<?php
while (($line=fgets(STDIN))!==false) {
    $file=rtrim($line,"\r\n"); if($file===''||!is_file($file))continue;
    $s=@file_get_contents($file); if($s===false)continue;
    $low=strtolower($s);
    $decode=(bool)preg_match('~\b(?:atob|string\.fromcharcode|decodeuricomponent|unescape)\s*\(~i',$s);
    $directExec=(bool)preg_match('~\b(?:eval|function)\s*\(\s*(?:atob|string\.fromcharcode|decodeuricomponent|unescape)\s*\(~i',$s);
    $scriptCreate=(bool)preg_match('~(?:createelement\s*\(\s*[\'\"]script[\'\"]|\.src\s*=|setattribute\s*\(\s*[\'\"]src[\'\"])~i',$s);
    $domInsert=(bool)preg_match('~\b(?:appendchild|insertbefore|document\.write)\s*\(~i',$s);
    $remote=(bool)preg_match('~https?:\\?/\\?/|[\'\"](?:src|href)[\'\"]\s*[,=:]~i',$s);
    $hiddenIframe=(bool)preg_match('~<iframe\b[^>]*(?:display\s*:\s*none|visibility\s*:\s*hidden|width\s*=\s*[\'\"]?0|height\s*=\s*[\'\"]?0)[^>]*>~i',$s);
    $iframeRemote=(bool)preg_match('~<iframe\b[^>]+https?://~i',$s);
    if ($directExec && ($domInsert || $remote || strlen($s)>4000)) {
        echo "ALERT\tPW-JS-001\t",$file,"\n"; continue;
    }
    if ($decode && $scriptCreate && $domInsert) {
        echo "ALERT\tPW-JS-002\t",$file,"\n"; continue;
    }
    if ($hiddenIframe && $iframeRemote && ($decode || strpos($low,'eval(')!==false)) {
        echo "REVIEW\tPW-JS-003\t",$file,"\n"; continue;
    }
}
PRESSWARDEN_JS_VALIDATOR
}

main() {
  banner
  local CAND V A1 A2 R3 s
  CAND=$(tmpf); V=$(tmpf); A1=$(tmpf); A2=$(tmpf); R3=$(tmpf)
  : > "$CAND"; : > "$A1"; : > "$A2"; : > "$R3"

  for s in "${TREE_ROOTS[@]}"; do
    find "$s" -xdev \
      \( -type d \( -name vendor -o -name node_modules -o -name cache -o -name caches -o -name wflogs -o -name .git -o -name .private \) -prune \) -o \
      \( -type f \( -name '*.js' -o -name '*.html' -o -name '*.htm' \) -size -6M -print0 \) 2>/dev/null \
      | xargs -0 -r grep -IlEi 'atob\s*\(|String\.fromCharCode\s*\(|createElement\s*\(|appendChild\s*\(|insertBefore\s*\(|<iframe|eval\s*\(' 2>/dev/null >> "$CAND"
  done
  sort -u "$CAND" -o "$CAND"

  if [ -s "$CAND" ] && command -v php >/dev/null 2>&1; then
    _make_validator "$V"
    php "$V" < "$CAND" 2>/dev/null | while IFS=$'\t' read -r kind rule file; do
      [ -n "$file" ] || continue
      case "$kind:$rule" in
        ALERT:PW-JS-001) printf '%s\n' "$file" >> "$A1" ;;
        ALERT:PW-JS-002) printf '%s\n' "$file" >> "$A2" ;;
        REVIEW:PW-JS-003) printf '%s\n' "$file" >> "$R3" ;;
      esac
    done
    sort -u "$A1" -o "$A1"; sort -u "$A2" -o "$A2"; sort -u "$R3" -o "$R3"
  fi

  sec "PW-JS-001 • decoded JavaScript execution" "eval/Function fed by atob/fromCharCode/decode routines + corroborating browser behavior"
  report "$A1" issue "no decoded JavaScript execution chains found"

  sec "PW-JS-002 • obfuscated remote script-loader injection" "decoder + dynamic script/src construction + DOM insertion • Balada-like behavior"
  report "$A2" issue "no obfuscated dynamic script-loader chains found"
  note "String.fromCharCode or createElement(script) alone are not findings; PW-JS-002 requires the compound loader behavior."

  sec "PW-JS-003 • hidden external iframe with obfuscation" "hidden iframe + remote URL + decode/eval evidence"
  report "$R3" review "no hidden external iframe with corroborating obfuscation found"

  rm -f "$CAND" "$V"
  finish
}
run_logged js-threat-intel
