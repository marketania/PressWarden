#!/usr/bin/env bash
# wp-plugins — cached WordPress.org lifecycle, inactive plugins, MU plugins, and drop-ins
NAME=wp-plugins; DESC="plugin inventory + cached repository lifecycle + MU/drop-in coverage"
SCAN_DOES="Inventories plugins locally once per site, then resolves WordPress.org directory lifecycle once per unique normal-plugin slug and reuses a persistent cache. Must-use plugins and drop-ins never enter repository lifecycle lookups."
SCAN_WHY="Portfolio-wide slug caching avoids repeating the same WordPress.org API query across dozens of sites while preserving lifecycle visibility and local active/inactive inventory."
. "$(cd "$(dirname "$0")/.." && pwd)/lib/_lib.sh"

_repo_bucket_grouped() {
  local f="$1" label="$2" col="$3" mark="$4" explanation="$5" sev="${6:-info}" installs groups keys p ver title sites site_count plural
  installs=$(grep -c . "$f" 2>/dev/null); installs=${installs:-0}; [ "$installs" -gt 0 ] || return 0
  keys=$(tmpf); awk -F'|' 'NF>=5 {print $2"|"$5}' "$f" | sort -u > "$keys"; groups=$(grep -c . "$keys" 2>/dev/null); groups=${groups:-0}
  printf '\n    %s%s%s %-12s%s %s%s unique plugin/version group(s)%s  %s•%s  %s installation(s)%s\n' "$B" "$col" "$mark" "$label" "$X" "$B" "$groups" "$X" "$D" "$X" "$installs" "$X"
  printf '      %s%s%s\n' "$D" "$explanation" "$X"
  while IFS='|' read -r p ver; do
    [ -n "$p" ] || continue; title=$(awk -F'|' -v p="$p" -v v="$ver" '$2==p && $5==v {print $3; exit}' "$f"); [ -n "$title" ] || title="$p"
    sites=$(awk -F'|' -v p="$p" -v v="$ver" '$2==p && $5==v && !seen[$1]++ {if(n++) printf ", "; printf "%s",$1} END{print ""}' "$f")
    site_count=$(awk -F'|' -v p="$p" -v v="$ver" '$2==p && $5==v && !seen[$1]++{n++}END{print n+0}' "$f"); [ "$site_count" -eq 1 ] && plural="" || plural="s"
    printf '      %s%s%s %-12s%s %s%s%s' "$B" "$col" "$mark" "$label" "$X" "$B" "$title" "$X"; [ -n "$ver" ] && printf '  %sv%s%s' "$D" "$ver" "$X"; printf '  %s(%s site%s)%s\n' "$D" "$site_count" "$plural" "$X"; _meta_field 12 "WEBSITES" "$sites"
  done < "$keys"; rm -f "$keys"
  case "$sev" in alert) ALERTS=$((ALERTS+groups)); TOTAL=$((TOTAL+groups)) ;; review) REVIEWS=$((REVIEWS+groups)); TOTAL=$((TOTAL+groups)) ;; esac
}
_mu_known() { local name="${1,,}"; case "$name" in 0-worker|0-worker.php|hostinger|hostinger-*|hostinger_*) return 0 ;; esac; return 1; }
_plugin_json_to_records() { local jsonf="$1"; php -r '$raw=@file_get_contents($argv[1]);$rows=json_decode((string)$raw,true);if(!is_array($rows))exit(2);foreach($rows as $r){$name=(string)($r["name"]??"");$status=(string)($r["status"]??"");$ver=(string)($r["version"]??"");$title=(string)($r["title"]??$name);$c=static function($v){return str_replace(["|","\r","\n"],["-"," "," "],(string)$v);};echo $c($name),"|",$c($status),"|",$c($ver),"|",$c($title),"\n";}' "$jsonf"; }

_WPORG_CACHE_DIR=""; _WPORG_CACHE_TTL=86400; _WPORG_NOW=0; _WPORG_STATUS=""; _WPORG_ERROR=""; _WPORG_REUSED=0; _WPORG_FETCHED=0; _WPORG_ERRORS=0
_wporg_cache_fresh() { local f="$1" mt age; [ "${PRESSWARDEN_WPORG_PLUGIN_REFRESH:-0}" != "1" ] || return 1; [ -s "$f" ] || return 1; mt=$(stat -c %Y "$f" 2>/dev/null || printf '0'); case "$mt" in ''|*[!0-9]*) return 1 ;; esac; age=$((_WPORG_NOW-mt)); [ "$age" -ge 0 ] && [ "$age" -lt "$_WPORG_CACHE_TTL" ]; }
_wporg_fetch_status() {
  local slug="$1" cachef body errf http rc parsed url tmpcache; _WPORG_STATUS=""; _WPORG_ERROR=""; cachef="$_WPORG_CACHE_DIR/${slug}.status"
  if _wporg_cache_fresh "$cachef"; then _WPORG_STATUS=$(head -n 1 "$cachef" 2>/dev/null || true); if [ -n "$_WPORG_STATUS" ]; then _WPORG_REUSED=$((_WPORG_REUSED+1)); return 0; fi; fi
  body=$(tmpf); errf=$(tmpf); http=""; rc=1
  url="https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request%5Blocale%5D=en_US&request%5Bslug%5D=${slug}&request%5Bfields%5D%5Bsections%5D=0&request%5Bfields%5D%5Bdescription%5D=0&request%5Bfields%5D%5Bshort_description%5D=0&request%5Bfields%5D%5Bversions%5D=0&request%5Bfields%5D%5Breviews%5D=0&request%5Bfields%5D%5Bbanners%5D=0&request%5Bfields%5D%5Bicons%5D=0&request%5Bfields%5D%5Bcontributors%5D=0&request%5Bfields%5D%5Btags%5D=0"
  if command -v curl >/dev/null 2>&1; then http=$(curl --silent --show-error --location --connect-timeout 8 --max-time 20 -o "$body" -w '%{http_code}' "$url" 2>"$errf"); rc=$?; elif command -v wget >/dev/null 2>&1; then wget -q -T 20 -O "$body" "$url" 2>"$errf"; rc=$?; [ -s "$body" ] && rc=0; http="unknown"; else printf 'no curl/wget available' > "$errf"; rc=127; fi
  if [ "$rc" -ne 0 ] || [ ! -s "$body" ]; then _WPORG_ERROR=$(tr '\r\n' ' ' < "$errf" | cut -c1-180); [ -n "$_WPORG_ERROR" ] || _WPORG_ERROR="WordPress.org metadata request failed"; _WPORG_ERRORS=$((_WPORG_ERRORS+1)); rm -f "$body" "$errf"; return 1; fi
  parsed=$(php -r '$j=json_decode((string)@file_get_contents($argv[1]),true);if(!is_array($j))exit(2);if(isset($j["error"])&&is_string($j["error"])&&$j["error"]!=="")echo strtolower($j["error"]);else echo "active";' "$body" 2>/dev/null); rc=$?; rm -f "$body" "$errf"
  if [ "$rc" -ne 0 ] || [ -z "$parsed" ]; then _WPORG_ERROR="invalid WordPress.org plugin metadata response (HTTP ${http:-unknown})"; _WPORG_ERRORS=$((_WPORG_ERRORS+1)); return 1; fi
  case "$parsed" in not_found) _WPORG_STATUS="external" ;; active|closed|disabled|new|pending|approved|rejected) _WPORG_STATUS="$parsed" ;; *) _WPORG_STATUS="$parsed" ;; esac
  tmpcache=$(tmpf); printf '%s\n' "$_WPORG_STATUS" > "$tmpcache"; mv -f "$tmpcache" "$cachef" 2>/dev/null || { cp "$tmpcache" "$cachef" 2>/dev/null || true; rm -f "$tmpcache"; }; chmod 600 "$cachef" 2>/dev/null || true; _WPORG_FETCHED=$((_WPORG_FETCHED+1)); return 0
}

main() {
  require_wp; banner; discover_sites
  local s d name title localst ver wpst f jsonf recf errtxt A CL DI EX NW PN AP RJ UN ER MU DROP INA LOCAL META SLUGS METAERR files
  A=$(tmpf); CL=$(tmpf); DI=$(tmpf); EX=$(tmpf); NW=$(tmpf); PN=$(tmpf); AP=$(tmpf); RJ=$(tmpf); UN=$(tmpf); ER=$(tmpf); MU=$(tmpf); DROP=$(tmpf); INA=$(tmpf); LOCAL=$(tmpf); META=$(tmpf); SLUGS=$(tmpf); METAERR=$(tmpf); files="$A $CL $DI $EX $NW $PN $AP $RJ $UN $ER $MU $DROP $INA $LOCAL $META $SLUGS $METAERR"
  _WPORG_CACHE_DIR="$PRESSWARDEN_CACHE_DIR/wporg-plugin-status"; mkdir -p "$_WPORG_CACHE_DIR"; chmod 700 "$PRESSWARDEN_CACHE_DIR" "$_WPORG_CACHE_DIR" 2>/dev/null || true; _WPORG_CACHE_TTL="${PRESSWARDEN_WPORG_PLUGIN_CACHE_TTL:-86400}"; case "$_WPORG_CACHE_TTL" in ''|*[!0-9]*) _WPORG_CACHE_TTL=86400 ;; esac; _WPORG_NOW=$(date +%s)
  sec "WordPress.org plugin directory status" "normal plugins only • unique-slug API cache • grouped by plugin + version"
  note "Repository lifecycle metadata is not malware proof. CLOSED/DISABLED/etc. are yellow review states; commercial plugins can share slugs with old WordPress.org listings."
  note "wporg_last_updated is intentionally not queried because it is not displayed and can require an extra WordPress.org Trac request per plugin."

  for s in "${WP_SITES[@]}"; do
    d=$(site_domain "$s"); jsonf=$(tmpf); recf=$(tmpf); errtxt=""
    if ! wpq "$s" plugin list --fields=name,status,version,title --format=json --skip-update-check >"$jsonf" 2>"$recf"; then errtxt=$(tr '\r\n' ' ' < "$recf" | cut -c1-180); printf '%s|local plugin inventory failed|%s\n' "$d" "$errtxt" >> "$ER"; rm -f "$jsonf" "$recf"; continue; fi
    if ! _plugin_json_to_records "$jsonf" > "$recf" 2>/dev/null; then printf '%s|local plugin inventory returned invalid JSON|unable to parse wp plugin list output\n' "$d" >> "$ER"; rm -f "$jsonf" "$recf"; continue; fi; rm -f "$jsonf"
    while IFS='|' read -r name localst ver title; do [ -n "$name" ] || continue; [ -n "$title" ] || title="$name"; case "$localst" in must-use) printf '%s|%s|%s\n' "$d" "$name" "$ver" >> "$MU"; continue ;; dropin) printf '%s|%s|%s\n' "$d" "$name" "$ver" >> "$DROP"; continue ;; inactive) printf '%s|%s|%s\n' "$d" "$name" "$ver" >> "$INA" ;; esac; printf '%s|%s|%s|%s|%s\n' "$d" "$name" "$title" "$localst" "$ver" >> "$LOCAL"; done < "$recf"; rm -f "$recf"
  done
  awk -F'|' 'NF>=5 && $2!="" {print $2}' "$LOCAL" | sort -u > "$SLUGS"; while IFS= read -r name; do [ -n "$name" ] || continue; if _wporg_fetch_status "$name"; then printf '%s|%s\n' "$name" "$_WPORG_STATUS" >> "$META"; else printf '%s|%s\n' "$name" "$_WPORG_ERROR" >> "$METAERR"; fi; done < "$SLUGS"
  local unique_slugs; unique_slugs=$(grep -c . "$SLUGS" 2>/dev/null); unique_slugs=${unique_slugs:-0}; printf '\n    %sℹ CACHE%s  %s unique normal-plugin slug(s)  %s•%s  %s reused%s  %s•%s  %s fetched%s' "$C" "$X" "$unique_slugs" "$D" "$X" "$_WPORG_REUSED" "$X" "$D" "$X" "$_WPORG_FETCHED" "$X"; [ "$_WPORG_ERRORS" -gt 0 ] && printf '  %s•%s  %s%s API error(s)%s' "$D" "$X" "$Y" "$_WPORG_ERRORS" "$X"; printf '\n'; printf '      %sTTL %ss • force refresh: PRESSWARDEN_WPORG_PLUGIN_REFRESH=1%s\n' "$D" "$_WPORG_CACHE_TTL" "$X"
  while IFS='|' read -r d name title localst ver; do [ -n "$name" ] || continue; wpst=$(awk -F'|' -v p="$name" '$1==p {print $2; exit}' "$META"); if [ -z "$wpst" ]; then errtxt=$(awk -F'|' -v p="$name" '$1==p {sub($1 FS,""); print; exit}' "$METAERR"); [ -n "$errtxt" ] || errtxt="WordPress.org status unavailable"; printf '%s|%s|%s\n' "$d" "$name" "$errtxt" >> "$ER"; continue; fi; case "$wpst" in active) printf '%s|%s|%s|%s|%s|%s\n' "$d" "$name" "$title" "$localst" "$ver" "$wpst" >> "$A" ;; closed) printf '%s|%s|%s|%s|%s|%s\n' "$d" "$name" "$title" "$localst" "$ver" "$wpst" >> "$CL" ;; disabled) printf '%s|%s|%s|%s|%s|%s\n' "$d" "$name" "$title" "$localst" "$ver" "$wpst" >> "$DI" ;; new) printf '%s|%s|%s|%s|%s|%s\n' "$d" "$name" "$title" "$localst" "$ver" "$wpst" >> "$NW" ;; pending) printf '%s|%s|%s|%s|%s|%s\n' "$d" "$name" "$title" "$localst" "$ver" "$wpst" >> "$PN" ;; approved) printf '%s|%s|%s|%s|%s|%s\n' "$d" "$name" "$title" "$localst" "$ver" "$wpst" >> "$AP" ;; rejected) printf '%s|%s|%s|%s|%s|%s\n' "$d" "$name" "$title" "$localst" "$ver" "$wpst" >> "$RJ" ;; external) printf '%s|%s|%s|%s|%s|%s\n' "$d" "$name" "$title" "$localst" "$ver" "$wpst" >> "$EX" ;; *) printf '%s|%s|%s|%s|%s|%s\n' "$d" "$name" "$title" "$localst" "$ver" "$wpst" >> "$UN" ;; esac; done < "$LOCAL"
  local na; na=$(grep -c . "$A" 2>/dev/null); na=${na:-0}; printf '\n    %s%s✓ ACTIVE%s      %s%s plugin installation(s)%s  %s— normal WordPress.org listing%s\n' "$B" "$G" "$X" "$B" "$na" "$X" "$D" "$X"
  _repo_bucket_grouped "$CL" CLOSED "$Y" "⚠" "WordPress.org slug is closed/not downloadable; verify provenance and whether the installed plugin should be replaced." review
  _repo_bucket_grouped "$DI" DISABLED "$Y" "⚠" "WordPress.org slug is in a rare disabled state; verify provenance and maintenance path." review
  _repo_bucket_grouped "$RJ" REJECTED "$Y" "⚠" "Rejected directory state is unusual for an installed package; verify provenance." review
  _repo_bucket_grouped "$NW" NEW "$Y" "⚠" "Pending initial WordPress.org review; unusual for an already-installed package." review
  _repo_bucket_grouped "$PN" PENDING "$Y" "⚠" "WordPress.org review is pending; verify provenance." review
  _repo_bucket_grouped "$AP" APPROVED "$C" "◆" "Approved but not reported as an active public listing." review
  _repo_bucket_grouped "$EX" EXTERNAL "$WHT" "ℹ" "No WordPress.org match; commonly premium, custom, bundled, or local." info
  _repo_bucket_grouped "$UN" OTHER "$Y" "?" "Unrecognized WordPress.org lifecycle value; review raw metadata." review
  if [ -s "$ER" ]; then printf '\n    %s%s✖ QUERY ERROR%s\n' "$B" "$R" "$X"; while IFS='|' read -r d name errtxt; do printf '      %s%s%s  %s›%s  %s%s%s  %s—%s %s\n' "$B$M" "$d" "$X" "$D" "$X" "$B" "$name" "$X" "$D" "$X" "$errtxt"; ALERTS=$((ALERTS+1)); TOTAL=$((TOTAL+1)); done < "$ER"; fi

  sec "Inactive plugins still on disk" "reuses the local inventory; no second WP-CLI pass"
  local inactive_sites=0 site_inactive; for s in "${WP_SITES[@]}"; do d=$(site_domain "$s"); site_inactive=$(awk -F'|' -v d="$d" '$1==d {if(n++)printf " "; printf "%s",$2} END{if(n)print ""}' "$INA"); if [ -n "$site_inactive" ]; then inactive_sites=$((inactive_sites+1)); flag "$d" "inactive: $site_inactive"; fi; done; [ "$inactive_sites" -gt 0 ] || printf '    %s✓ CLEAN%s  no inactive plugins found\n' "$G" "$X"; note "inactive plugin data is reused from the same local inventory"; note "remove inactive plugins you do not need; their files can still be reachable directly"

  sec "Must-use plugin inventory" "NO MU + unknown MU shown per-site • known ManageWP/Hostinger MU collapsed by plugin"
  local mu_count site_mu known_label known_mu known_keys known_sites known_count plural; known_mu=$(tmpf)
  for s in "${WP_SITES[@]}"; do d=$(site_domain "$s"); site_mu=$(tmpf); awk -F'|' -v d="$d" '$1==d {print $2"|"$3}' "$MU" > "$site_mu"; mu_count=$(grep -c . "$site_mu" 2>/dev/null); mu_count=${mu_count:-0}; if [ "$mu_count" -eq 0 ]; then printf '    %sℹ NO MU%s      %s%s%s  %s›%s  no must-use plugins reported\n' "$D" "$X" "$B$M" "$d" "$X" "$D" "$X"; rm -f "$site_mu"; continue; fi; while IFS='|' read -r name ver; do [ -n "$name" ] || continue; if _mu_known "$name"; then printf '%s|%s|%s\n' "$name" "$ver" "$d" >> "$known_mu"; else printf '    %s%s⚠ REVIEW MU%s %s%s%s  %s›%s  %s%s%s' "$B" "$Y" "$X" "$B$M" "$d" "$X" "$D" "$X" "$B" "$name" "$X"; [ -n "$ver" ] && printf '  %sv%s%s' "$D" "$ver" "$X"; printf '  %s(unrecognized MU plugin)%s\n' "$D" "$X"; REVIEWS=$((REVIEWS+1)); TOTAL=$((TOTAL+1)); fi; done < "$site_mu"; rm -f "$site_mu"; done
  if [ -s "$known_mu" ]; then known_keys=$(tmpf); awk -F'|' '{print $1"|"$2}' "$known_mu" | sort -u > "$known_keys"; printf '\n    %s%s✓ KNOWN MU%s  expected ManageWP/Hostinger MU plugins detected\n' "$B" "$G" "$X"; while IFS='|' read -r name ver; do [ -n "$name" ] || continue; case "${name,,}" in 0-worker|0-worker.php) known_label="ManageWP" ;; *) known_label="Hostinger" ;; esac; known_sites=$(awk -F'|' -v n="$name" -v v="$ver" '$1==n && $2==v && !seen[$3]++ {if(c++)printf ", "; printf "%s",$3} END{print ""}' "$known_mu"); known_count=$(awk -F'|' -v n="$name" -v v="$ver" '$1==n && $2==v && !seen[$3]++ {c++} END{print c+0}' "$known_mu"); [ "$known_count" -eq 1 ] && plural="" || plural="s"; printf '      %s✓%s %s%s%s' "$G" "$X" "$B" "$name" "$X"; [ -n "$ver" ] && printf '  %sv%s%s' "$D" "$ver" "$X"; printf '  %s(%s • %s site%s)%s\n' "$D" "$known_label" "$known_count" "$plural" "$X"; _meta_field 12 WEBSITES "$known_sites"; done < "$known_keys"; rm -f "$known_keys"; fi; rm -f "$known_mu"
  note "known MU plugins are summarized once by plugin/version; only NO MU and unrecognized MU plugins remain per-site"

  sec "Drop-ins + object-cache coverage" "only missing object-cache sites and non-object-cache drop-ins are shown"
  local cache_on=0 cache_off=0 other_drop; for s in "${WP_SITES[@]}"; do d=$(site_domain "$s"); if [ -f "$s/wp-content/object-cache.php" ]; then cache_on=$((cache_on+1)); else cache_off=$((cache_off+1)); printf '    %s%s⚠ CACHE OFF%s   %s%s%s  %s›%s  object-cache.php missing — candidate to enable\n' "$B" "$Y" "$X" "$B$M" "$d" "$X" "$D" "$X"; fi; other_drop=$(find "$s/wp-content" -maxdepth 1 -type f \( -name 'advanced-cache.php' -o -name 'db.php' -o -name 'maintenance.php' -o -name 'sunrise.php' \) -printf '%f ' 2>/dev/null); [ -n "$other_drop" ] && printf '      %sℹ OTHER DROP-IN%s  %s%s%s  %s›%s  %s\n' "$C" "$X" "$B$M" "$d" "$X" "$D" "$X" "$other_drop"; done
  [ "$cache_off" -eq 0 ] && printf '    %s%s✓ CACHE COVERAGE%s  all %s site(s) have object-cache.php\n' "$B" "$G" "$X" "${#WP_SITES[@]}"; printf '\n    %s%sOBJECT CACHE SUMMARY%s  %s%s present%s  •  %s%s missing%s  •  %s%s total%s\n' "$B" "$C" "$X" "$G" "$cache_on" "$X" "$Y" "$cache_off" "$X" "$B" "${#WP_SITES[@]}" "$X"; note "object-cache.php presence is intentionally hidden per-site when enabled; only missing sites are listed"; note "presence of object-cache.php does not by itself prove the backing Redis/Memcached service is healthy"
  for f in $files; do rm -f "$f"; done; finish
}
run_logged wp-plugins
