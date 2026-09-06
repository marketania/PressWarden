#!/usr/bin/env bash
# htcheck — root + nested .htaccess integrity
NAME=htcheck; DESC=".htaccess integrity + nested directive abuse"
SCAN_DOES="Inspects root and nested .htaccess files for redirect cloaking, PHP-handler abuse, and malicious directives."
SCAN_WHY="Attackers often use .htaccess for stealth redirects or persistence without modifying normal WordPress PHP files."
. "$(cd "$(dirname "$0")/.." && pwd)/lib/_lib.sh"

main() {
  banner
  local L O f n s nested

  sec "Known campaign markers"
  L=$(tmpf)
  grep -lE 'plugin-start\.com|CloakRedirectMU|VCT168|vct-168|demitiger168|idx-opt-plugin' \
    "${SCAN_ROOTS[@]/%//.htaccess}" 2>/dev/null > "$L"
  report "$L"

  L=$(tmpf)
  for s in "${SCAN_ROOTS[@]}"; do [ -f "$s/.htaccess" ] && printf '%s\n' "$s/.htaccess"; done > "$L"
  n=$(grep -c . "$L" 2>/dev/null); n=${n:-0}
  sec "Bot-conditional external redirects" "$n root .htaccess file(s) examined"
  O=$(tmpf)
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    awk -v F="$f" '
      /^[[:space:]]*#/                                      { next }
      /RewriteCond[[:space:]]+%\{HTTP_USER_AGENT\}/         { flag=1 }
      /RewriteCond[[:space:]]+%\{HTTP:CF-IPCountry\}/       { flag=1 }
      /RewriteCond[[:space:]]+%\{HTTP_REFERER\}.*(google|bing|yandex)/ { flag=1 }
      /RewriteRule/ && /https?:\/\// && flag                { print F": "$0; flag=0 }
      /<\/IfModule>/                                        { flag=0 }
    ' "$f" >> "$O"
  done < "$L"
  rm -f "$L"; report "$O"

  sec "Root auto_prepend_file outside Wordfence"
  L=$(tmpf)
  grep -Hn 'auto_prepend_file' "${SCAN_ROOTS[@]/%//.htaccess}" 2>/dev/null \
    | grep -v 'wordfence-waf.php' > "$L"
  report "$L"

  sec "Root obfuscation and PHP handler overrides"
  L=$(tmpf)
  grep -HnE 'base64_decode|eval\(|gzinflate|AddType[^#]*x-httpd-php[^#]*\.(jpg|jpeg|png|gif|txt|ico|css)|SetHandler[^#]*php[^#]*\.(jpg|jpeg|png|gif|txt|ico|css)' \
    "${SCAN_ROOTS[@]/%//.htaccess}" 2>/dev/null > "$L"
  report "$L"

  sec "Nested .htaccess dangerous directives" "content-based; discovered WordPress-root .htaccess files are handled as roots, not nested files"
  nested=$(tmpf); L=$(tmpf); O=$(tmpf)
  : > "$nested"; : > "$O"
  for s in "${TREE_ROOTS[@]}"; do
    find "$s" -mindepth 2 -type f -name '.htaccess' \
      -not -path '*/.private/*' -print 2>/dev/null >> "$nested"
  done

  # A nested WordPress installation is still a first-class WordPress root.
  # Its root .htaccess is already examined by the root checks above, so exclude
  # it here to avoid false positives such as a legitimate Wordfence WAF
  # auto_prepend_file inside /public_html/special/.htaccess.
  if [ -s "$nested" ]; then
    while IFS= read -r f; do
      [ -n "$f" ] || continue
      local is_wp_root_ht=0 r
      for r in "${SCAN_ROOTS[@]}"; do
        if [ "$f" = "$r/.htaccess" ]; then
          is_wp_root_ht=1
          break
        fi
      done
      [ "$is_wp_root_ht" -eq 1 ] && continue
      printf '%s\n' "$f" >> "$O"
    done < "$nested"
  fi

  if [ -s "$O" ]; then
    while IFS= read -r f; do
      grep -HnEi \
        'auto_(prepend|append)_file|AddType[^#]*x-httpd-php[^#]*\.(jpg|jpeg|png|gif|txt|ico|css)|SetHandler[^#]*php|php_(value|flag)[[:space:]]+auto_(prepend|append)_file' \
        "$f" 2>/dev/null >> "$L" || true
    done < "$O"
  fi
  rm -f "$nested" "$O"
  report "$L" issue "no dangerous directives in non-root nested .htaccess files"

  sec "Directory listing enabled"
  L=$(tmpf)
  grep -Hn 'Options[[:space:]].*+Indexes' "${SCAN_ROOTS[@]/%//.htaccess}" 2>/dev/null > "$L"
  report "$L" review

  finish
}
run_logged htcheck
