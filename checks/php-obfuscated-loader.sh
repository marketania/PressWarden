#!/usr/bin/env bash
# php-obfuscated-loader — high-signal detector for packed/obfuscated remote loaders.
NAME=php-obfuscated-loader; DESC="obfuscated remote asset/network loader detection"
SCAN_DOES="Finds PHP that reconstructs hidden strings/endpoints from packed numeric data with XOR/chr/ord logic and then feeds the result into browser or network-loading sinks."
SCAN_WHY="Malicious plugins can look like normal dashboard/branding code while hiding an external JavaScript or payload URL behind custom byte-array decoding that ordinary eval/base64 signatures miss."
. "$(cd "$(dirname "$0")/.." && pwd)/lib/_lib.sh"

_validate_obfuscated_loaders() {
  local validator="$1"
  cat > "$validator" <<'PRESSWARDEN_OBFUSCATED_LOADER_PHP'
<?php
while (($line = fgets(STDIN)) !== false) {
    $f = rtrim($line, "\r\n");
    if ($f === '' || !is_file($f)) continue;
    $src = @file_get_contents($f);
    if ($src === false) continue;

    $tokens = @token_get_all($src);
    if (!is_array($tokens)) continue;
    $code = '';
    foreach ($tokens as $t) {
        if (!is_array($t)) { $code .= $t; continue; }
        if ($t[0] === T_COMMENT || $t[0] === T_DOC_COMMENT) $code .= ' ';
        else $code .= $t[1];
    }

    $hasXorDecoder = preg_match('~\bchr\s*\([^;{}]{0,500}\^\s*ord\s*\(~is', $code)
        || (strpos($code, '^') !== false && preg_match('~\bchr\s*\(~i', $code) && preg_match('~\bord\s*\(~i', $code));

    $hasPackedKey = preg_match('~array_map\s*\(\s*[\'\"]chr[\'\"]\s*,~i', $code);
    $packedArrays = preg_match_all('~\[(?:\s*\d{1,3}\s*,){7,}\s*\d{1,3}\s*\]~s', $code, $dummy);
    $hasPackedData = $hasPackedKey || $packedArrays >= 1;

    $browserSink = preg_match('~\bwp_enqueue_(?:script|style)\s*\(~i', $code);
    $networkSink = preg_match('~\b(?:wp_remote_get|wp_remote_post|curl_exec|file_get_contents)\s*\(~i', $code);

    if ($hasXorDecoder && $hasPackedData && $browserSink) {
        echo "ALERT\t", $f, PHP_EOL;
    } elseif ($hasXorDecoder && $hasPackedData && $networkSink) {
        echo "REVIEW\t", $f, PHP_EOL;
    }
}
PRESSWARDEN_OBFUSCATED_LOADER_PHP
}

main() {
  banner
  local CAND V A R s d
  CAND=$(tmpf); V=$(tmpf); A=$(tmpf); R=$(tmpf)
  : > "$CAND"; : > "$A"; : > "$R"

  for s in "${SCAN_ROOTS[@]}"; do
    for d in "$s/wp-content/plugins" "$s/wp-content/themes" "$s/wp-content/mu-plugins"; do
      [ -d "$d" ] || continue
      find "$d" -xdev \
        \( -type d \( -name vendor -o -name node_modules -o -name cache -o -name languages -o -name wflogs -o -name .git -o -name .private \) -prune \) -o \
        \( -type f \( -name '*.php' -o -name '*.php5' -o -name '*.php7' -o -name '*.phtml' \) -print0 \) 2>/dev/null \
        | xargs -0 -r grep -IlE '(wp_enqueue_(script|style)|wp_remote_(get|post)|curl_exec|file_get_contents)[[:space:]]*\(' 2>/dev/null >> "$CAND"
    done
  done
  sort -u "$CAND" -o "$CAND"

  if [ -s "$CAND" ] && command -v php >/dev/null 2>&1; then
    _validate_obfuscated_loaders "$V"
    php "$V" < "$CAND" 2>/dev/null | while IFS=$'\t' read -r kind file; do
      [ -n "$file" ] || continue
      case "$kind" in ALERT) printf '%s\n' "$file" >> "$A" ;; REVIEW) printf '%s\n' "$file" >> "$R" ;; esac
    done
    sort -u "$A" -o "$A"; sort -u "$R" -o "$R"
  fi

  sec "Obfuscated remote browser asset loaders" "packed byte data + XOR decoder + wp_enqueue_script/style • high confidence"
  report "$A" issue "no PHP files hide browser asset URLs behind packed XOR decoding"
  note "This catches loaders that reconstruct a hidden external JavaScript/style URL at runtime instead of storing the URL plainly."
  note "XOR, chr(), ord(), numeric arrays, or wp_enqueue_script() alone are not findings; the detector requires the compound behavior."

  sec "Obfuscated remote network endpoints" "packed byte data + XOR decoder + remote-fetch sink • review"
  report "$R" review "no packed/XOR-decoded remote network loaders found"

  rm -f "$CAND" "$V"
  finish
}
run_logged php-obfuscated-loader
