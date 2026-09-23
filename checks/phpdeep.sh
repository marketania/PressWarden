#!/usr/bin/env bash
# phpdeep — content-level PHP malware signatures. Full runs only.
NAME=phpdeep; DESC="deep PHP malware signatures"
SCAN_DOES="Reads PHP code for known malware markers, obfuscation, request-driven execution, webshell behavior, and packed payloads."
SCAN_WHY="Malware can hide inside legitimate plugin or theme files, so file location and checksums alone cannot catch every injection."
. "$(cd "$(dirname "$0")/.." && pwd)/lib/_lib.sh"

EX_ALL=(--include=*.php --include=*.php5 --include=*.php7 --include=*.phtml
        --exclude-dir=node_modules --exclude-dir=.git)
EX_GENERIC=(--include=*.php --include=*.php5 --include=*.php7 --include=*.phtml
            --exclude-dir=vendor --exclude-dir=node_modules --exclude-dir=languages
            --exclude-dir=cache --exclude-dir=.git --exclude-dir=wflogs --exclude-dir=upgrade
            --exclude-dir=.private)

main() {
  banner
  note "very-high-confidence signatures scan dependency/cache trees too; broader heuristic signatures skip noisy dependency trees"
  note "create_function() alone remains REVIEW-level and only in sensitive entry files"
  local L

  sec "Known malware campaign markers" "all PHP trees"
  L=$(tmpf)
  grep -rIl "${EX_ALL[@]}" -E \
    'CloakRedirectMU|plugin-start\.com|VCT168|vct-168|demitiger168|idx-opt-plugin|_AGENT_FILE|MIN_AGENT_SIZE' \
    "${TREE_ROOTS[@]/%//}" 2>/dev/null | sort -u > "$L"
  report "$L"

  sec "Request-driven code execution" "all PHP trees • very high confidence"
  L=$(tmpf)
  grep -rIl "${EX_ALL[@]}" -E \
    '(eval|assert)[[:space:]]*\([[:space:]]*(base64_decode|gzinflate|gzuncompress)?[[:space:]]*\(?[[:space:]]*\$_(GET|POST|REQUEST|COOKIE)|(system|exec|shell_exec|passthru|popen|proc_open)[[:space:]]*\([[:space:]]*\$_(GET|POST|REQUEST|COOKIE|SERVER)' \
    "${TREE_ROOTS[@]/%//}" 2>/dev/null | sort -u > "$L"
  report "$L"

  sec "High-confidence obfuscation" "generic code; dependency/cache trees skipped"
  L=$(tmpf)
  grep -rIl "${EX_GENERIC[@]}" -E \
    'eval[[:space:]]*\([[:space:]]*(base64_decode|gzinflate|gzuncompress|str_rot13)[[:space:]]*\(|assert[[:space:]]*\([[:space:]]*\$_(GET|POST|REQUEST|COOKIE)|\$\{"\\x47\\x4c|base64_decode[[:space:]]*\([^)]+\)[[:space:]]*;?[[:space:]]*eval[[:space:]]*\(' \
    "${TREE_ROOTS[@]/%//}" 2>/dev/null | sort -u > "$L"
  report "$L"

  sec "Legacy dynamic execution" "sensitive entry files only"
  L=$(tmpf)
  {
    find "${SCAN_ROOTS[@]}" -maxdepth 1 -type f -name '*.php' -print0 2>/dev/null
    find "${SCAN_ROOTS[@]/%//wp-content/mu-plugins}" -type f -name '*.php' -print0 2>/dev/null
    find "${SCAN_ROOTS[@]/%//wp-content/themes}" -type f \
      \( -name 'functions.php' -o -name 'init.php' -o -name 'bootstrap.php' -o -name 'loader.php' \) -print0 2>/dev/null
    find "${SCAN_ROOTS[@]/%//wp-content/plugins}" -mindepth 2 -maxdepth 2 -type f -name '*.php' -print0 2>/dev/null
  } | xargs -0 -r grep -IlE 'preg_replace[[:space:]]*\([^,]*/e|create_function[[:space:]]*\(' 2>/dev/null | sort -u > "$L"
  report "$L" review

  sec "Remote payload written to filesystem"
  L=$(tmpf)
  grep -rIl "${EX_GENERIC[@]}" -E \
    'file_put_contents[[:space:]]*\([^,)]*,[[:space:]]*(file_get_contents|curl_exec)|fwrite[[:space:]]*\([^,]+,[[:space:]]*(file_get_contents|curl_exec)' \
    "${TREE_ROOTS[@]/%//}" 2>/dev/null | sort -u > "$L"
  report "$L" review

  sec "Request-controlled filesystem / include primitives" "compound evidence only • comments/strings ignored"
  L=$(tmpf)
  P=$(tmpf)
  : > "$L"; : > "$P"

  grep -rIl "${EX_GENERIC[@]}" -E \
    '(move_uploaded_file|copy|file_put_contents|fwrite|unlink|rename|chmod|include|include_once|require|require_once)[[:space:]]*\(|\$_(GET|POST|REQUEST|COOKIE|FILES)' \
    "${TREE_ROOTS[@]/%//}" 2>/dev/null | sort -u > "$P"

  if [ -s "$P" ] && command -v php >/dev/null 2>&1; then
    V=$(tmpf)
    cat > "$V" <<'PRESSWARDEN_PHP_WEBSHELL_VALIDATOR'
<?php
$patterns = [
    '~\b(?:include|include_once|require|require_once)\s*\(?\s*\$_(?:GET|POST|REQUEST|COOKIE)\b~i',
    '~\b(?:unlink|rmdir)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\b~i',
    '~\brename\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\b~i',
    '~\bchmod\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\b~i',
    '~\bfile_put_contents\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\b~i',
    '~\bfile_put_contents\s*\([^,]+,\s*(?:(?:base64_decode|gzinflate|gzdecode|gzuncompress)\s*\(\s*)?\$_(?:GET|POST|REQUEST|COOKIE)\b~i',
    '~\bmove_uploaded_file\s*\([^,]*\$_FILES\b[^,]*,\s*\$_(?:GET|POST|REQUEST|COOKIE)\b~i',
    '~\bcopy\s*\([^,]*\$_FILES\b[^,]*,\s*\$_(?:GET|POST|REQUEST|COOKIE)\b~i',
];
while (($line = fgets(STDIN)) !== false) {
    $f = rtrim($line, "\r\n");
    if ($f === '' || !is_file($f)) continue;
    $src = @file_get_contents($f); if ($src === false) continue;
    $tokens = @token_get_all($src); if (!is_array($tokens)) continue;
    $code = '';
    foreach ($tokens as $t) {
        if (!is_array($t)) { $code .= $t; continue; }
        $id = $t[0];
        if ($id === T_COMMENT || $id === T_DOC_COMMENT || $id === T_CONSTANT_ENCAPSED_STRING || $id === T_ENCAPSED_AND_WHITESPACE) $code .= ' ';
        else $code .= $t[1];
    }
    foreach ($patterns as $pattern) if (preg_match($pattern, $code)) { echo $f, PHP_EOL; break; }
}
PRESSWARDEN_PHP_WEBSHELL_VALIDATOR
    php "$V" < "$P" 2>/dev/null | sort -u > "$L"
    rm -f "$V"
  elif [ -s "$P" ]; then
    while IFS= read -r f; do
      [ -f "$f" ] || continue
      awk '
        /^[[:space:]]*(\/\/|#|\*)/ { next }
        /(include|include_once|require|require_once)[[:space:]]*\(?[[:space:]]*\$_(GET|POST|REQUEST|COOKIE)/ { found=1 }
        /(unlink|rmdir|chmod)[[:space:]]*\([[:space:]]*\$_(GET|POST|REQUEST|COOKIE)/ { found=1 }
        /rename[[:space:]]*\([[:space:]]*\$_(GET|POST|REQUEST|COOKIE)/ { found=1 }
        /file_put_contents[[:space:]]*\([[:space:]]*\$_(GET|POST|REQUEST|COOKIE)/ { found=1 }
        END { exit(found ? 0 : 1) }
      ' "$f" 2>/dev/null && printf "%s\n" "$f"
    done < "$P" | sort -u > "$L"
  fi

  rm -f "$P"
  report "$L" review "no direct request-controlled filesystem/include primitives found"
  note 'Standalone base64_decode($_GET/$_POST/$_COOKIE) is not a webshell finding; legitimate plugins use encoded request tokens.'
  note 'Static chmod(...,0777) calls are not findings here; filesystem-security checks the ACTUAL resulting permissions instead.'
  note 'Normal move_uploaded_file()/copy() upload handling is not a finding unless the destination is directly request-controlled.'

  sec "Packed/encoded payloads in sensitive execution files" "long line + encoding/obfuscation evidence"
  L=$(tmpf); P=$(tmpf); : > "$L"; : > "$P"
  {
    find "${SCAN_ROOTS[@]}" -maxdepth 1 -type f \
      \( -name 'wp-config.php' -o -name '*.php' -o -name '*.php[57]' -o -name '*.phtml' \) -print 2>/dev/null
    find "${SCAN_ROOTS[@]/%//wp-content}" -maxdepth 1 -type f \
      \( -name '*.php' -o -name '*.php[57]' -o -name '*.phtml' \) -print 2>/dev/null
    find "${SCAN_ROOTS[@]/%//wp-content/mu-plugins}" -type f \
      \( -name '*.php' -o -name '*.php[57]' -o -name '*.phtml' \) -print 2>/dev/null
    find "${SCAN_ROOTS[@]/%//wp-content/themes}" -mindepth 2 -maxdepth 2 -type f \
      \( -name '*.php' -o -name '*.php[57]' -o -name '*.phtml' \) -print 2>/dev/null
    find "${SCAN_ROOTS[@]/%//wp-content/themes}" -type f \
      \( -name 'functions.php' -o -name 'init.php' -o -name 'bootstrap.php' -o -name 'loader.php' \) -print 2>/dev/null
    find "${SCAN_ROOTS[@]/%//wp-content/plugins}" -mindepth 2 -maxdepth 2 -type f \
      \( -name '*.php' -o -name '*.php[57]' -o -name '*.phtml' \) -print 2>/dev/null
    find "${SCAN_ROOTS[@]/%//wp-content/plugins}" -type f \
      \( -name 'functions.php' -o -name 'init.php' -o -name 'bootstrap.php' -o -name 'loader.php' \) -print 2>/dev/null
  } | sort -u > "$P"

  while IFS= read -r f; do
    [ -f "$f" ] || continue
    awk '
      function encoded_run(line, i, c, n, best) {
        n=0; best=0
        for (i=1; i<=length(line); i++) {
          c=substr(line,i,1)
          if (c ~ /[A-Za-z0-9+\/=]/) { n++; if (n>best) best=n }
          else n=0
        }
        return best
      }
      {
        line=$0
        if (line ~ /(base64_decode|gzinflate|gzdecode|gzuncompress|str_rot13|hex2bin|openssl_decrypt)[[:space:]]*\(/) has_decode=1
        if (line ~ /(eval|assert|create_function)[[:space:]]*\(/) has_exec=1
        if (length(line) < 1500) next
        if (encoded_run(line) >= 900) has_blob=1
        t=line; n=gsub(/\\x[0-9A-Fa-f][0-9A-Fa-f]/, "", t); if (n >= 80) direct=1
        t=line; n=gsub(/chr[[:space:]]*\([[:space:]]*[0-9][0-9]?[0-9]?[[:space:]]*\)/, "", t); if (n >= 40) direct=1
        if (line ~ /(base64_decode|gzinflate|gzdecode|gzuncompress|str_rot13|hex2bin|openssl_decrypt)[[:space:]]*\(/ &&
            line ~ /(eval|assert|create_function)[[:space:]]*\(/) direct=1
      }
      END { exit((direct || (has_blob && has_decode && has_exec)) ? 0 : 1) }
    ' "$f" 2>/dev/null && printf '%s\n' "$f" >> "$L"
  done < "$P"
  rm -f "$P"
  sort -u "$L" -o "$L"
  report "$L" review
  note "Length alone is not a FULL finding either; long legitimate class maps/JSON/templates are ignored unless packed/encoded characteristics are also present."

  finish
}
run_logged phpdeep
