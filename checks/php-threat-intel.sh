#!/usr/bin/env bash
# php-threat-intel — focused high-confidence PHP threat behaviors not covered by generic sinks.
NAME=php-threat-intel; DESC="dynamic PHP execution + credential-exfil intelligence"
SCAN_DOES="Validates request-controlled dynamic function execution and credential-capture patterns combined with outbound transmission/verification weakening."
SCAN_WHY="Backdoors and credential stealers may avoid eval/base64 signatures by invoking attacker-selected functions or hiding exfiltration inside plausible WordPress plugin code."
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
  $outbound=(bool)preg_match('~\b(?:wp_remote_post|curl_exec|curl_setopt|file_get_contents)\s*\(~i',$raw);
  $weakTls=(bool)preg_match('~CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0)|[\'\"]sslverify[\'\"]\s*=>\s*false~i',$raw);
  if($login&&$pass&&$outbound&&$weakTls)echo "ALERT\tPW-PHP-005\t",$file,"\n";
}
PRESSWARDEN_PHP_INTEL
}

main() {
  banner
  local CAND V A4 A5 s
  CAND=$(tmpf); V=$(tmpf); A4=$(tmpf); A5=$(tmpf); : > "$CAND"; : > "$A4"; : > "$A5"
  for s in "${TREE_ROOTS[@]}"; do
    find "$s" -xdev \
      \( -type d \( -name vendor -o -name node_modules -o -name cache -o -name caches -o -name uploads -o -name wflogs -o -name .git -o -name .private \) -prune \) -o \
      \( -type f \( -name '*.php' -o -name '*.phtml' \) -size -5M -print0 \) 2>/dev/null \
      | xargs -0 -r grep -IlE '\$_(GET|POST|REQUEST|COOKIE)|user_login|user_pass|CURLOPT_SSL_VERIFYPEER|sslverify' 2>/dev/null >> "$CAND"
  done
  sort -u "$CAND" -o "$CAND"
  if [ -s "$CAND" ] && command -v php >/dev/null 2>&1; then
    _make_validator "$V"
    php "$V" < "$CAND" 2>/dev/null | while IFS=$'\t' read -r kind rule file; do
      [ -n "$file" ] || continue
      case "$rule" in PW-PHP-004) printf '%s\n' "$file" >> "$A4" ;; PW-PHP-005) printf '%s\n' "$file" >> "$A5" ;; esac
    done
    sort -u "$A4" -o "$A4"; sort -u "$A5" -o "$A5"
  fi

  sec "PW-PHP-004 • request-controlled dynamic function execution" "attacker-controlled function name + invocation/call_user_func"
  report "$A4" issue "no request-controlled dynamic function execution found"

  sec "PW-PHP-005 • credential capture with weakened-TLS exfiltration" "login + password POST capture + outbound request + certificate verification disabled"
  report "$A5" issue "no high-confidence credential-exfiltration chain found"
  note "Login handling or outbound HTTP alone is not a finding; PW-PHP-005 requires captured credential fields plus outbound transmission plus explicit TLS verification weakening."

  rm -f "$CAND" "$V"
  finish
}
run_logged php-threat-intel
