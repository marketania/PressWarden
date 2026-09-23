#!/usr/bin/env bash
# wp-plugin-integrity — official checksums for WordPress.org-hosted plugins.
NAME=wp-plugin-integrity; DESC="official WordPress.org plugin checksum verification (full)"
SCAN_DOES="Verifies active WordPress.org plugin files against official repository checksums in one WP-CLI verification process per site."
SCAN_WHY="Checksum mismatches prove the installed file differs from the official package. Extra files are classified separately so generated/metadata files do not look like confirmed malware."
. "$(cd "$(dirname "$0")/.." && pwd)/lib/_lib.sh"

_wporg_cached_status() { local slug="$1" f="$PRESSWARDEN_CACHE_DIR/wporg-plugin-status/${slug}.status" st=""; if [ -s "$f" ]; then st=$(head -n 1 "$f" 2>/dev/null || true); [ -n "$st" ] && { printf '%s' "$st"; return 0; }; fi; return 1; }
_fill_wporg_fallback() {
  local site="$1" jsonf="$2" outf="$3"
  if ! wpq "$site" plugin list --fields=name,status,wporg_status --format=json --skip-update-check >"$jsonf" 2>/dev/null; then return 1; fi
  php -r '$rows=json_decode((string)@file_get_contents($argv[1]),true);if(!is_array($rows))exit(2);foreach($rows as $r){$st=(string)($r["status"]??"");if($st!=="active"&&$st!=="active-network")continue;$n=str_replace(["|","\r","\n"],["-"," "," "],(string)($r["name"]??""));$w=strtolower((string)($r["wporg_status"]??""));if($n!=="")echo $n,"|",$w,"\n";}' "$jsonf" > "$outf"
}
_checksum_json_records() { local f="$1"; [ -s "$f" ] || return 0; php -r '$rows=json_decode((string)@file_get_contents($argv[1]),true);if(!is_array($rows))exit(2);foreach($rows as $r){$c=static function($v){return str_replace(["|","\r","\n"],["-"," "," "],(string)$v);};echo $c($r["plugin_name"]??""),"|",$c($r["file"]??""),"|",$c($r["message"]??""),"\n";}' "$f"; }
_is_metadata_extra() { local f="${1##*/}"; case "$f" in .DS_Store|Thumbs.db|desktop.ini) return 0 ;; esac; return 1; }
_is_active_code_file() { local f="${1,,}"; case "$f" in *.php|*.php[0-9]|*.phtml|*.phar|*.inc|*.js|*.mjs|*.cjs|*.html|*.htm|*.svg|*.htaccess|*.user.ini) return 0 ;; esac; return 1; }

main() {
  require_wp; banner; discover_sites
  local s d invjson fallback_json fallback_rec activef out err recf alertf reviewf metaf name status ver title wpst checked rc plugin file msg need_fallback site_alerts site_reviews site_meta site_errors
  local -a eligible
  sec "WordPress.org plugin checksums" "official checksums • one verifier process/site • classified exceptions • full suite"
  note "Checksum mismatch means the installed file differs from the official package; it is not automatically proof of malware."
  note "Added .DS_Store/Thumbs.db/desktop.ini files are harmless cleanup metadata; other added files are REVIEW unless stronger evidence exists."
  note "Uses the wp-plugins lifecycle cache when available; direct runs fall back to one JSON metadata inventory call per site."

  for s in "${WP_SITES[@]}"; do
    d=$(site_domain "$s"); invjson=$(tmpf); activef=$(tmpf); fallback_json=$(tmpf); fallback_rec=$(tmpf); out=$(tmpf); err=$(tmpf); recf=$(tmpf); alertf=$(tmpf); reviewf=$(tmpf); metaf=$(tmpf)
    eligible=(); checked=0; site_alerts=0; site_reviews=0; site_meta=0; site_errors=0
    if ! wpq "$s" plugin list --fields=name,status,version,title --format=json --skip-update-check >"$invjson" 2>"$err"; then issue "$d" "plugin inventory failed" "$(tr '\r\n' ' ' < "$err" | cut -c1-300)"; rm -f "$invjson" "$activef" "$fallback_json" "$fallback_rec" "$out" "$err" "$recf" "$alertf" "$reviewf" "$metaf"; continue; fi
    if ! php -r '$rows=json_decode((string)@file_get_contents($argv[1]),true);if(!is_array($rows))exit(2);foreach($rows as $r){$st=(string)($r["status"]??"");if($st!=="active"&&$st!=="active-network")continue;$c=static function($v){return str_replace(["|","\r","\n"],["-"," "," "],(string)$v);};echo $c($r["name"]??""),"|",$c($st),"|",$c($r["version"]??""),"|",$c($r["title"]??""),"\n";}' "$invjson" > "$activef"; then issue "$d" "plugin inventory JSON could not be parsed"; rm -f "$invjson" "$activef" "$fallback_json" "$fallback_rec" "$out" "$err" "$recf" "$alertf" "$reviewf" "$metaf"; continue; fi
    need_fallback=0; while IFS='|' read -r name status ver title; do [ -n "$name" ] || continue; _wporg_cached_status "$name" >/dev/null 2>&1 || { need_fallback=1; break; }; done < "$activef"; [ "$need_fallback" -eq 1 ] && _fill_wporg_fallback "$s" "$fallback_json" "$fallback_rec" || true
    while IFS='|' read -r name status ver title; do [ -n "$name" ] || continue; wpst=$(_wporg_cached_status "$name" 2>/dev/null || true); [ -z "$wpst" ] && [ -s "$fallback_rec" ] && wpst=$(awk -F'|' -v n="$name" '$1==n {print $2; exit}' "$fallback_rec"); [ "$wpst" = active ] && eligible+=("$name"); done < "$activef"
    checked=${#eligible[@]}; if [ "$checked" -eq 0 ]; then printf '    %sℹ N/A%s      %s%s%s  %s›%s  no active WordPress.org plugins eligible for checksum verification\n' "$C" "$X" "$B$M" "$d" "$X" "$D" "$X"; rm -f "$invjson" "$activef" "$fallback_json" "$fallback_rec" "$out" "$err" "$recf" "$alertf" "$reviewf" "$metaf"; continue; fi
    wpq "$s" plugin verify-checksums "${eligible[@]}" --format=json >"$out" 2>"$err"; rc=$?
    if ! _checksum_json_records "$out" > "$recf" 2>/dev/null; then printf '    %s%s⚠ VERIFY ERROR%s %s%s%s  %s›%s  checksum output was not valid JSON\n' "$B" "$Y" "$X" "$B$M" "$d" "$X" "$D" "$X"; [ -s "$err" ] && printf '        %s%s%s\n' "$D" "$(tr '\r\n' ' ' < "$err" | cut -c1-350)" "$X"; REVIEWS=$((REVIEWS+1)); TOTAL=$((TOTAL+1)); rm -f "$invjson" "$activef" "$fallback_json" "$fallback_rec" "$out" "$err" "$recf" "$alertf" "$reviewf" "$metaf"; continue; fi
    while IFS='|' read -r plugin file msg; do [ -n "$plugin$msg$file" ] || continue; case "$msg" in "Checksum does not match") if _is_active_code_file "$file"; then printf '%s|%s|%s\n' "$plugin" "$file" "$msg" >> "$alertf"; else printf '%s|%s|%s\n' "$plugin" "$file" "$msg" >> "$reviewf"; fi ;; "File was added") if _is_metadata_extra "$file"; then printf '%s|%s|%s\n' "$plugin" "$file" "$msg" >> "$metaf"; else printf '%s|%s|%s\n' "$plugin" "$file" "$msg" >> "$reviewf"; fi ;; *) printf '%s|%s|%s\n' "$plugin" "$file" "$msg" >> "$reviewf" ;; esac; done < "$recf"
    site_alerts=$(grep -c . "$alertf" 2>/dev/null); site_alerts=${site_alerts:-0}; site_reviews=$(grep -c . "$reviewf" 2>/dev/null); site_reviews=${site_reviews:-0}; site_meta=$(grep -c . "$metaf" 2>/dev/null); site_meta=${site_meta:-0}
    if [ "$site_alerts" -gt 0 ]; then printf '    %s%s✖ ALERT%s   %s%s%s  %s›%s  %s official executable/code checksum mismatch(es)\n' "$B" "$R" "$X" "$B$M" "$d" "$X" "$D" "$X" "$site_alerts"; while IFS='|' read -r plugin file msg; do printf '        %s%s%s  %s—%s  %s  %s(%s)%s\n' "$B" "$plugin" "$X" "$D" "$X" "$file" "$D" "$msg" "$X"; done < "$alertf"; ALERTS=$((ALERTS+site_alerts)); TOTAL=$((TOTAL+site_alerts)); fi
    if [ "$site_reviews" -gt 0 ]; then printf '    %s%s⚠ REVIEW%s  %s%s%s  %s›%s  %s plugin package deviation(s) need review\n' "$B" "$Y" "$X" "$B$M" "$d" "$X" "$D" "$X" "$site_reviews"; while IFS='|' read -r plugin file msg; do printf '        %s%s%s  %s—%s  %s  %s(%s)%s\n' "$B" "$plugin" "$X" "$D" "$X" "$file" "$D" "$msg" "$X"; done < "$reviewf"; REVIEWS=$((REVIEWS+site_reviews)); TOTAL=$((TOTAL+site_reviews)); fi
    if [ "$site_meta" -gt 0 ]; then printf '    %sℹ CLEANUP%s  %s%s%s  %s›%s  %s harmless OS metadata file(s) are not in official packages\n' "$C" "$X" "$B$M" "$d" "$X" "$D" "$X" "$site_meta"; while IFS='|' read -r plugin file msg; do printf '        %s%s%s  %s—%s  %s  %s(safe to delete)%s\n' "$B" "$plugin" "$X" "$D" "$X" "$file" "$D" "$X"; done < "$metaf"; fi
    if [ "$rc" -ne 0 ] && [ "$site_alerts" -eq 0 ] && [ "$site_reviews" -eq 0 ] && [ "$site_meta" -eq 0 ]; then printf '    %s%s⚠ VERIFY ERROR%s %s%s%s  %s›%s  WordPress.org checksum verification could not complete\n' "$B" "$Y" "$X" "$B$M" "$d" "$X" "$D" "$X"; [ -s "$err" ] && printf '        %s%s%s\n' "$D" "$(tr '\r\n' ' ' < "$err" | cut -c1-400)" "$X"; REVIEWS=$((REVIEWS+1)); TOTAL=$((TOTAL+1)); site_errors=1; fi
    if [ "$site_alerts" -eq 0 ] && [ "$site_reviews" -eq 0 ] && [ "$site_errors" -eq 0 ]; then if [ "$site_meta" -gt 0 ]; then printf '    %s%s✓ VERIFIED%s %s%s%s  %s›%s  %s plugin(s) verified; metadata cleanup only\n' "$B" "$G" "$X" "$B$M" "$d" "$X" "$D" "$X" "$checked"; else printf '    %s%s✓ OK%s      %s%s%s  %s›%s  %s plugin(s) verified\n' "$B" "$G" "$X" "$B$M" "$d" "$X" "$D" "$X" "$checked"; fi; fi
    rm -f "$invjson" "$activef" "$fallback_json" "$fallback_rec" "$out" "$err" "$recf" "$alertf" "$reviewf" "$metaf"
  done
  finish
}
run_logged wp-plugin-integrity
