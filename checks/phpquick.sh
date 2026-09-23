#!/usr/bin/env bash
# phpquick — FAST high-confidence wp-content malware content scan
NAME=phpquick; DESC="FAST wp-content malware content scan"
SCAN_DOES="Performs one high-confidence PHP content pass across wp-content while pruning noisy/heavy dependency, cache, language, and upload trees; then inspects only sensitive plugin/theme/MU/drop-in entry files for broader malware indicators and packed payloads."
SCAN_WHY="Many compromises modify legitimate functions.php or plugin bootstrap files. This gives FAST meaningful content-level malware coverage without repeatedly reading every PHP dependency the way the FULL phpdeep scan does."
. "$(cd "$(dirname "$0")/.." && pwd)/lib/_lib.sh"

_candidate_expr='(eval|assert|system|exec|shell_exec|passthru|popen|proc_open|include|include_once|require|require_once)[[:space:]]*\(?[[:space:]]*\$_(GET|POST|REQUEST|COOKIE|SERVER)|CloakRedirectMU|plugin-start\.com|VCT168|vct-168|demitiger168|idx-opt-plugin|_AGENT_FILE|MIN_AGENT_SIZE'
_entry_expr='(eval|assert)[[:space:]]*\([[:space:]]*((base64_decode|gzinflate|gzdecode|gzuncompress|str_rot13)[[:space:]]*\([[:space:]]*)?\$_(GET|POST|REQUEST|COOKIE)|(system|exec|shell_exec|passthru|popen|proc_open)[[:space:]]*\([[:space:]]*\$_(GET|POST|REQUEST|COOKIE|SERVER)|(include|include_once|require|require_once)[[:space:]]*\(?[[:space:]]*\$_(GET|POST|REQUEST|COOKIE)|file_put_contents[[:space:]]*\([^,)]*,[[:space:]]*(file_get_contents|curl_exec)|fwrite[[:space:]]*\([^,]+,[[:space:]]*(file_get_contents|curl_exec)|preg_replace[[:space:]]*\([^,]*/e|CloakRedirectMU|plugin-start\.com|VCT168|vct-168|demitiger168|idx-opt-plugin'

_validate_high_conf_candidates() {
  if command -v php >/dev/null 2>&1; then
    local validator
    validator=$(tmpf)
    cat > "$validator" <<'PRESSWARDEN_PHP_VALIDATOR'
<?php
$marker = '~CloakRedirectMU|plugin-start\.com|VCT168|vct-168|demitiger168|idx-opt-plugin|_AGENT_FILE|MIN_AGENT_SIZE~i';
$behavior = '~(?:
  \b(?:eval|assert)\s*\(\s*(?:(?:base64_decode|gzinflate|gzdecode|gzuncompress|str_rot13)\s*\(\s*)?\$_(?:GET|POST|REQUEST|COOKIE)\b
  |\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\b
  |\b(?:include|include_once|require|require_once)\s*\(?\s*\$_(?:GET|POST|REQUEST|COOKIE)\b
)~ix';
while (($line = fgets(STDIN)) !== false) {
    $f = rtrim($line, "\r\n");
    if ($f === '' || !is_file($f)) continue;
    $src = @file_get_contents($f); if ($src === false) continue;
    if (preg_match($marker, $src)) { echo $f, PHP_EOL; continue; }
    $tokens = @token_get_all($src); if (!is_array($tokens)) continue;
    $code = '';
    foreach ($tokens as $t) {
        if (!is_array($t)) { $code .= $t; continue; }
        $id = $t[0];
        if ($id === T_COMMENT || $id === T_DOC_COMMENT || $id === T_CONSTANT_ENCAPSED_STRING || $id === T_ENCAPSED_AND_WHITESPACE) $code .= ' ';
        else $code .= $t[1];
    }
    if (preg_match($behavior, $code)) echo $f, PHP_EOL;
}
PRESSWARDEN_PHP_VALIDATOR
    php "$validator" 2>/dev/null
    rm -f "$validator"
  else
    while IFS= read -r f; do
      [ -f "$f" ] || continue
      awk '
        /^[[:space:]]*(\/\/|#|\*)/ { next }
        /CloakRedirectMU|plugin-start\.com|VCT168|vct-168|demitiger168|idx-opt-plugin|_AGENT_FILE|MIN_AGENT_SIZE/ { found=1 }
        /(eval|assert)[[:space:]]*\([[:space:]]*((base64_decode|gzinflate|gzdecode|gzuncompress|str_rot13)[[:space:]]*\([[:space:]]*)?\$_(GET|POST|REQUEST|COOKIE)/ { found=1 }
        /(system|exec|shell_exec|passthru|popen|proc_open)[[:space:]]*\([[:space:]]*\$_(GET|POST|REQUEST|COOKIE|SERVER)/ { found=1 }
        /^[[:space:]]*(include|include_once|require|require_once)[[:space:]]*\(?[[:space:]]*\$_(GET|POST|REQUEST|COOKIE)/ { found=1 }
        END { exit(found ? 0 : 1) }
      ' "$f" 2>/dev/null && printf "%s\n" "$f"
    done
  fi
}
main() {
  banner
  local L E H raw s d

  sec "High-confidence malicious PHP behavior in wp-content" "token-validated execution sinks + known markers • comments ignored"
  L=$(tmpf); raw=$(tmpf); : > "$L"; : > "$raw"
  for s in "${SCAN_ROOTS[@]}"; do
    d="$s/wp-content"; [ -d "$d" ] || continue
    find "$d" -xdev \
      \( -type d \( -name vendor -o -name node_modules -o -name cache -o -name languages \
                    -o -name uploads -o -name wflogs -o -name upgrade -o -name .git -o -name .private \) -prune \) -o \
      \( -type f \( -name '*.php' -o -name '*.php5' -o -name '*.php7' -o -name '*.phtml' \) -print0 \) \
      2>/dev/null \
      | xargs -0 -r grep -IlE -- "$_candidate_expr" 2>/dev/null >> "$raw"
  done
  sort -u "$raw" -o "$raw"
  if [ -s "$raw" ]; then _validate_high_conf_candidates < "$raw" | sort -u > "$L"; fi
  rm -f "$raw"
  H=$(tmpf); cp "$L" "$H"
  report "$L" issue "no high-confidence malicious PHP behavior found in the FAST wp-content pass"
  note 'Comments/docblocks and quoted strings are stripped before generic execution rules are evaluated; English text such as "require $_GET" cannot become an alert.'
  note 'Standalone base64_decode(request/cookie) is intentionally NOT an alert; FAST requires execution/remote-code behavior or a known campaign marker.'
  note "FAST prunes vendor/node_modules/cache/languages/uploads/wflogs/upgrade; FULL phpdeep scans more broadly and uses additional heuristics."

  E=$(tmpf); : > "$E"
  for s in "${SCAN_ROOTS[@]}"; do
    find "$s/wp-content" -maxdepth 1 -type f \( -name '*.php' -o -name '*.php5' -o -name '*.php7' -o -name '*.phtml' \) -print 2>/dev/null >> "$E"
    find "$s/wp-content/mu-plugins" -type f \( -name '*.php' -o -name '*.php5' -o -name '*.php7' -o -name '*.phtml' \) -print 2>/dev/null >> "$E"
    find "$s/wp-content/themes" -mindepth 2 -maxdepth 2 -type f \( -name '*.php' -o -name '*.php5' -o -name '*.php7' -o -name '*.phtml' \) -print 2>/dev/null >> "$E"
    find "$s/wp-content/themes" -type f \( -name 'functions.php' -o -name 'init.php' -o -name 'bootstrap.php' -o -name 'loader.php' -o -name 'header.php' -o -name 'footer.php' -o -name 'index.php' -o -name '404.php' \) -not -path '*/vendor/*' -not -path '*/node_modules/*' -not -path '*/cache/*' -print 2>/dev/null >> "$E"
    find "$s/wp-content/plugins" -mindepth 2 -maxdepth 2 -type f \( -name '*.php' -o -name '*.php5' -o -name '*.php7' -o -name '*.phtml' \) -print 2>/dev/null >> "$E"
    find "$s/wp-content/plugins" -type f \( -name 'functions.php' -o -name 'init.php' -o -name 'bootstrap.php' -o -name 'loader.php' \) -not -path '*/vendor/*' -not -path '*/node_modules/*' -not -path '*/cache/*' -print 2>/dev/null >> "$E"
  done
  sort -u "$E" -o "$E"

  sec "Sensitive WordPress entry-file malware indicators" "MU/drop-ins • theme entry files • plugin bootstrap/root PHP"
  L=$(tmpf); raw=$(tmpf); : > "$L"; : > "$raw"
  if [ -s "$E" ]; then
    tr '\n' '\0' < "$E" | xargs -0 -r grep -IlE -- "$_entry_expr" 2>/dev/null | sort -u > "$raw"
    if [ -s "$H" ]; then grep -Fvx -f "$H" "$raw" > "$L" 2>/dev/null || true; else cp "$raw" "$L"; fi
  fi
  rm -f "$raw"
  report "$L" review "no additional broader malware indicators in sensitive wp-content entry files"

  sec "Packed/encoded payloads in sensitive wp-content entry files" "long line + encoding/obfuscation evidence • targeted FAST scope"
  L=$(tmpf); raw=$(tmpf); : > "$L"; : > "$raw"
  if [ -s "$E" ]; then
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
          if (line ~ /(base64_decode|gzinflate|gzdecode|gzuncompress|str_rot13|hex2bin|openssl_decrypt)[[:space:]]*\(/ && line ~ /(eval|assert|create_function)[[:space:]]*\(/) direct=1
        }
        END { exit((direct || (has_blob && has_decode && has_exec)) ? 0 : 1) }
      ' "$f" 2>/dev/null && printf '%s\n' "$f" >> "$raw"
    done < "$E"
    sort -u "$raw" -o "$raw"
    if [ -s "$H" ]; then grep -Fvx -f "$H" "$raw" > "$L" 2>/dev/null || true; else cp "$raw" "$L"; fi
  fi
  rm -f "$raw"
  report "$L" review "no packed/encoded payloads with corroborating obfuscation evidence in sensitive wp-content entry files"
  note "A >1500-character line by itself is no longer a finding; FAST requires encoded/obfuscated payload characteristics too."
  note "The former static asset-directory PHP rule was removed: WordPress/plugin build systems legitimately generate many *.asset.php and similar PHP metadata files."

  rm -f "$E" "$H"
  finish
}
run_logged phpquick
