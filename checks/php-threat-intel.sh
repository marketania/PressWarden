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

  $isAdmin=(bool)preg_match('~\bis_admin\s*\(\s*\)~i',$raw);
  $manage=(bool)preg_match('~\bcurrent_user_can\s*\(\s*[\'\"]manage_options[\'\"]~i',$raw);
  $ua=(bool)preg_match('~\$_SERVER\s*\[\s*[\'\"]HTTP_USER_AGENT[\'\"]\s*\]~i',$raw);
  $windows=(bool)preg_match('~(?:Windows|Win32|Win64)~i',$raw);
  $decode=(bool)preg_match('~\bbase64_decode\s*\(~i',$raw);
  $remote=(bool)preg_match('~\b(?:wp_remote_get|wp_remote_post|curl_exec|file_get_contents)\s*\(~i',$raw);
  // A hook registration such as add_action() is orchestration, not evidence
  // that a decoded remote payload reaches the browser. Require an actual
  // script/output sink to keep this high-confidence rule conservative.
  $browserSink=(bool)preg_match('~\b(?:wp_add_inline_script|wp_enqueue_script)\s*\(|\b(?:echo|print)\b~i',$raw);
  if($isAdmin&&$manage&&$ua&&$windows&&$decode&&$remote&&$browserSink)echo "ALERT\tPW-PHP-006\t",$file,"\n";
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

  sec "PW-PHP-006 • admin-targeted remote browser payload" "wp-admin + manage_options + Windows UA gating + remote fetch + base64 decode + concrete browser/output sink"
  report "$A6" issue "no high-confidence admin-targeted remote browser payload chain found"
  note "PW-PHP-006 is behavior-based coverage informed by 2026 fake-browser-update malware research; it does not depend on a campaign domain or plugin name."
  note "Login handling, outbound HTTP, base64_decode(), is_admin(), User-Agent checks, or add_action() alone are not findings; the rule requires a concrete browser/output sink."

  rm -f "$CAND" "$V"
  finish
}
run_logged php-threat-intel
