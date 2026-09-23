#!/usr/bin/env bash
# wp-root — unexpected files sitting in the document root
NAME=wp-root; DESC="document root inventory"
SCAN_DOES="Compares each document root with the normal WordPress root layout while allowing verified Hostinger and Wordfence exceptions. Healthy sites are collapsed into one summary; only exceptions are listed individually."
SCAN_WHY="Unexpected root files are common locations for backdoors, droppers, redirect scripts, and abandoned sensitive artifacts."
. "$(cd "$(dirname "$0")/.." && pwd)/lib/_lib.sh"

KNOWN='^(index\.php|wp-load\.php|wp-blog-header\.php|wp-settings\.php|wp-config\.php|wp-config-sample\.php|wp-cron\.php|wp-links-opml\.php|wp-login\.php|wp-mail\.php|wp-activate\.php|wp-signup\.php|wp-trackback\.php|wp-comments-post\.php|xmlrpc\.php|readme\.html|license\.txt|robots\.txt|\.htaccess|\.user\.ini|favicon\.ico|ads\.txt|sitemap.*\.xml|wp-admin|wp-includes|wp-content|cgi-bin|\.well-known)$'

root_entry_is_expected() {
  local s="$1" e="$2" f
  f="$s/$e"
  case "$e" in
    .private) [ -d "$f" ] && return 0 ;;
    wordfence-waf.php)
      [ -f "$f" ] || return 1
      [ -d "$s/wp-content/plugins/wordfence" ] || return 1
      grep -qE 'Wordfence|WFWAF|wordfenceClass|wfWAF' "$f" 2>/dev/null && return 0
      ;;
  esac
  return 1
}

main() {
  require_wp; banner; discover_sites
  sec "Non-standard entries in the web root" "${#WP_SITES[@]} sites • exceptions only"
  local s d L e entries clean_n=0 total_n
  total_n=${#WP_SITES[@]}
  for s in "${WP_SITES[@]}"; do
    d=$(site_domain "$s"); L=$(tmpf); entries=$(tmpf)
    find "$s" -maxdepth 1 -mindepth 1 -printf '%f\n' 2>/dev/null | sort > "$entries"
    : > "$L"
    while IFS= read -r e; do
      [ -n "$e" ] || continue
      printf '%s\n' "$e" | grep -qE "$KNOWN" && continue
      root_entry_is_expected "$s" "$e" && continue
      printf '%s\n' "$e" >> "$L"
    done < "$entries"
    rm -f "$entries"
    if [ -s "$L" ]; then
      flag "$d" "$(grep -c . "$L") extra entr(ies)" "$(cat "$L")"
    else
      clean_n=$((clean_n+1))
    fi
    rm -f "$L"
  done
  [ "$clean_n" -gt 0 ] && printf '    %s%s✓ CLEAN%s  %s%s/%s sites%s have no non-standard root entries\n' "$B" "$G" "$X" "$B" "$clean_n" "$total_n" "$X"
  note "expected root exceptions are suppressed only when verified: Hostinger .private directory; Wordfence WAF bootstrap"
  finish
}
run_logged wp-root
