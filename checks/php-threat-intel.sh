#!/usr/bin/env bash
# php-threat-intel — focused high-confidence PHP threat behaviors not covered by generic sinks.
NAME=php-threat-intel; DESC="dynamic PHP execution + credential/admin-targeted payload intelligence"
SCAN_DOES="Validates request-controlled dynamic execution, credential-capture/exfiltration, and admin-targeted remote browser payload behavior."
SCAN_WHY="Backdoors and malicious plugins may avoid classic eval/base64 signatures by invoking attacker-selected functions, stealing credentials, or targeting logged-in administrators with remote browser payloads."
. "$(cd "$(dirname "$0")/.." && pwd)/lib/_lib.sh"

_make_validator() {
  local f="$1"
  cat > "$f" <<'PRESSWARDEN_PHP_INTEL'
<?php
function pw_php_admin_context($s) {
  return (bool)preg_match('~\bis_admin\s*\(\s*\)~i',$s)
      && (bool)preg_match('~\bcurrent_user_can\s*\(\s*[\'\"]manage_options[\'\"]~i',$s)
      && (bool)preg_match('~\$_SERVER\s*\[\s*[\'\"]HTTP_USER_AGENT[\'\"]\s*\]~i',$s)
      && (bool)preg_match('~(?:Windows|Win32|Win64)~i',$s);
}

function pw_php_browser_sink_uses($s,$var) {
  $v=preg_quote($var,'~');
  return (bool)preg_match('~\b(?:echo|print)\b[^;]{0,1200}\$'.$v.'\b~is',$s)
      || (bool)preg_match('~\bwp_add_inline_script\s*\([^;]{0,1600}\$'.$v.'\b~is',$s)
      || (bool)preg_match('~\bwp_enqueue_script\s*\([^;]{0,1600}\$'.$v.'\b~is',$s);
}

function pw_php_admin_payload_chain($raw) {
  // PW-PHP-006 is deliberately data-flow based. Large security/framework files
  // can legitimately contain admin checks, UA handling, Windows compatibility,
  // remote HTTP, base64 decoding and output in unrelated methods. Those facts
  // must never be combined at whole-file scope.
  if (preg_match_all('~\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:wp_remote_get|wp_remote_post|file_get_contents|curl_exec)\s*\(~i',$raw,$remoteMatches,PREG_SET_ORDER|PREG_OFFSET_CAPTURE)) {
    foreach($remoteMatches as $rm) {
      $remoteVar=$rm[1][0]; $offset=$rm[0][1];
      $start=max(0,$offset-1800); $window=substr($raw,$start,7000);
      if(!pw_php_admin_context($window)) continue;
      $rv=preg_quote($remoteVar,'~');

      // Direct flow: remote response variable reaches base64_decode().
      if(preg_match_all('~\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*base64_decode\s*\([^;]{0,1600}\$'.$rv.'\b[^;]{0,600}\)\s*;?~is',$window,$decoded,PREG_SET_ORDER)) {
        foreach($decoded as $dm){if(pw_php_browser_sink_uses($window,$dm[1])) return true;}
      }

      // Common WordPress flow: wp_remote_retrieve_body($response), then decode.
      if(preg_match_all('~\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*wp_remote_retrieve_body\s*\(\s*\$'.$rv.'\s*\)\s*;?~i',$window,$bodies,PREG_SET_ORDER)) {
        foreach($bodies as $bm){
          $bodyVar=preg_quote($bm[1],'~');
          if(preg_match_all('~\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*base64_decode\s*\(\s*\$'.$bodyVar.'\b[^;]{0,500}\)\s*;?~is',$window,$decoded,PREG_SET_ORDER)) {
            foreach($decoded as $dm){if(pw_php_browser_sink_uses($window,$dm[1])) return true;}
          }
        }
      }
    }
  }

  // Direct one-expression flow for file_get_contents()/curl_exec() payloads.
  if(preg_match_all('~\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*base64_decode\s*\(\s*(?:file_get_contents|curl_exec)\s*\([^;]{0,1600}\)\s*\)\s*;?~is',$raw,$direct,PREG_SET_ORDER|PREG_OFFSET_CAPTURE)) {
    foreach($direct as $dm){
      $offset=$dm[0][1]; $start=max(0,$offset-1800); $window=substr($raw,$start,6000);
      if(pw_php_admin_context($window) && pw_php_browser_sink_uses($window,$dm[1][0])) return true;
    }
  }
  return false;
}

while(($line=fgets(STDIN))!==false){
  $file=rtrim($line,"\r\n");if($file===''||!is_file($file))continue;$s=@file_get_contents($file);if($s===false)continue;
  $tokens=@token_get_all($s);if(!is_array($tokens))continue;$code='';
  foreach($tokens as $t){if(!is_array($t)){$code.=$t;continue;}if($t[0]===T_COMMENT||$t[0]===T_DOC_COMMENT||$t[0]===T_CONSTANT_ENCAPSED_STRING||$t[0]===T_ENCAPSED_AND_WHITESPACE)$code.=' ';else$code.=$t[1];}
  $dyn=(bool)preg_match('~\$(\w+)\s*=\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]+\].{0,1200}?\$\\1\s*\(~s',$code)
      || (bool)preg_match('~\bcall_user_func(?:_array)?\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\b~s',$code);
  if($dyn){echo "ALERT\tPW-PHP-004\t",$file,"\n";continue;}
  $raw=$s;
  $login=(bool)preg_match('~\$_POST\s*\[\s*[\'\"](?:log|user_login|username)[\'\"]\s*\]~i',$raw);
  $pass=(bool)preg_match('~\$_POST\s*\[\s*[\'\"](?:pwd|user_pass|password)[\'\"]\s*\]~i',$raw);
  $outbound=(bool)preg_match('~\b(?:wp_remote_get|wp_remote_post|curl_exec|curl_setopt|file_get_contents)\s*\(~i',$raw);
  $weakTls=(bool)preg_match('~CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0)|[\'\"]sslverify[\'\"]\s*=>\s*false~i',$raw);
  if($login&&$pass&&$outbound&&$weakTls){echo "ALERT\tPW-PHP-005\t",$file,"\n";continue;}

  if(pw_php_admin_payload_chain($raw)) echo "ALERT\tPW-PHP-006\t",$file,"\n";
}
PRESSWARDEN_PHP_INTEL
}

main() {
  banner
  local CAND V A4 A5 A6 s
  CAND=$(tmpf); V=$(tmpf); A4=$(tmpf); A5=$(tmpf); A6=$(tmpf); : > "$CAND"; : > "$A4"; : > "$A5"; : > "$A6"
  for s in "${TREE_ROOTS[@]}"; do
    find "$s" -xdev \
      \( -type d \( -name vendor -o -name node_modules -o -name cache -o -name caches -o -name uploads -o -name wflogs -o -name .git -o -name .private \) -prune \) -o \
      \( -type f \( -name '*.php' -o -name '*.phtml' \) -size -5M -print0 \) 2>/dev/null \
      | xargs -0 -r grep -IlE '\$_(GET|POST|REQUEST|COOKIE)|user_login|user_pass|CURLOPT_SSL_VERIFYPEER|sslverify|is_admin[[:space:]]*\(|current_user_can[[:space:]]*\(|HTTP_USER_AGENT|base64_decode[[:space:]]*\(' 2>/dev/null >> "$CAND"
  done
  sort -u "$CAND" -o "$CAND"
  if [ -s "$CAND" ] && command -v php >/dev/null 2>&1; then
    _make_validator "$V"
    php "$V" < "$CAND" 2>/dev/null | while IFS=$'\t' read -r kind rule file; do
      [ -n "$file" ] || continue
      case "$rule" in
        PW-PHP-004) printf '%s\n' "$file" >> "$A4" ;;
        PW-PHP-005) printf '%s\n' "$file" >> "$A5" ;;
        PW-PHP-006) printf '%s\n' "$file" >> "$A6" ;;
      esac
    done
    sort -u "$A4" -o "$A4"; sort -u "$A5" -o "$A5"; sort -u "$A6" -o "$A6"
  fi

  sec "PW-PHP-004 • request-controlled dynamic function execution" "attacker-controlled function name + invocation/call_user_func"
  report "$A4" issue "no request-controlled dynamic function execution found"

  sec "PW-PHP-005 • credential capture with weakened-TLS exfiltration" "login + password POST capture + outbound request + certificate verification disabled"
  report "$A5" issue "no high-confidence credential-exfiltration chain found"

  sec "PW-PHP-006 • admin-targeted remote browser payload" "same local admin/Windows gate + remote response → base64 decode → browser/output sink"
  report "$A6" issue "no high-confidence admin-targeted remote browser payload chain found"
  note "PW-PHP-006 is behavior-based coverage informed by 2026 fake-browser-update malware research; it now requires data flow from a remote response through base64_decode() into a concrete browser/output sink inside the same local context."
  note "Large utility files are not findings merely because admin checks, HTTP, User-Agent handling, Windows compatibility, decoding, and output exist in unrelated functions."

  rm -f "$CAND" "$V"
  finish
}
run_logged php-threat-intel
