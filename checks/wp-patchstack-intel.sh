#!/usr/bin/env bash
# wp-patchstack-intel — optional cached Patchstack product/version vulnerability intelligence.
NAME=wp-patchstack-intel; DESC="optional Patchstack product/version intelligence"
SCAN_DOES="Deduplicates installed WordPress component/version pairs, performs locally cached Patchstack product lookups, and prioritizes observed exploitation/CISA KEV matches."
SCAN_WHY="A fleet may repeat the same plugin/version dozens of times; deduplicated cached lookups provide useful vulnerability intelligence without wasting API quota."
. "$(cd "$(dirname "$0")/.." && pwd)/lib/_lib.sh"
. "$PRESSWARDEN_DIR/lib/intel.sh"

_urlencode() { php -r 'echo rawurlencode($argv[1]);' "$1" 2>/dev/null; }
_cache_fresh() { local f="$1" ttl="$2" now mt; [ -s "$f" ] || return 1; now=$(date +%s); mt=$(stat -c %Y "$f" 2>/dev/null || printf 0); case "$mt" in ''|*[!0-9]*) return 1 ;; esac; [ $((now-mt)) -lt "$ttl" ]; }
_fetch_patchstack() {
  local type="$1" slug="$2" ver="$3" out="$4" key="$5" url es ev http rc
  es=$(_urlencode "$slug"); ev=$(_urlencode "$ver"); url="https://patchstack.com/database/api/v2/product/$type/$es/$ev"
  if command -v curl >/dev/null 2>&1; then
    http=$(curl -sS -L --connect-timeout 10 --max-time 45 -H "PSKey: $key" -A 'PressWarden/1.1 Threat Intelligence' -o "$out" -w '%{http_code}' "$url" 2>/dev/null); rc=$?
    [ "$rc" -eq 0 ] || return 2; printf '%s' "$http"; return 0
  fi
  if command -v wget >/dev/null 2>&1; then
    wget -q -T 45 --header="PSKey: $key" -O "$out" "$url" 2>/dev/null || return 2; printf '200'; return 0
  fi
  return 127
}

_inventory_records() {
  local s="$1" site="$2" kind="$3" f
  f=$(tmpf)
  if [ "$kind" = plugin ]; then
    wpq "$s" plugin list --fields=name,status,version --format=json --skip-update-check > "$f" 2>/dev/null || { rm -f "$f"; return; }
  else
    wpq "$s" theme list --fields=name,status,version --format=json --skip-update-check > "$f" 2>/dev/null || { rm -f "$f"; return; }
  fi
  php -r '$j=json_decode((string)@file_get_contents($argv[1]),true);$site=$argv[2];$type=$argv[3];foreach((array)$j as $r){$n=str_replace("|","-",(string)($r["name"]??""));$v=str_replace("|","-",(string)($r["version"]??""));$st=str_replace("|","-",(string)($r["status"]??""));if($n!==""&&$v!=="")echo $type,"|",$n,"|",$v,"|",$site,"|",$st,"\n";}' "$f" "$site" "$kind" 2>/dev/null || true
  rm -f "$f"
}

main() {
  require_wp; banner; discover_sites
  local key="${PRESSWARDEN_PATCHSTACK_KEY:-}" dir cache ttl max inv uniq s d core type slug ver sites statuses id cachef tmp http rc lookups=0 unknown=0 vulns=0 kevf pf kind title cve exploited score priority fixed url iskev
  sec "Patchstack vulnerability intelligence" "optional • deduplicated component/version lookup • cached • exploit-aware"
  if [ -z "$key" ]; then note "SKIPPED: no PRESSWARDEN_PATCHSTACK_KEY configured."; finish; return 0; fi
  command -v php >/dev/null 2>&1 || { flag "Patchstack" "PHP CLI is required to parse intelligence results"; finish; return 1; }
  dir=$(pw_intel_state_dir); cache="$dir/patchstack"; kevf="$dir/cisa-kev.json"; mkdir -p "$cache" || { flag "Patchstack" "cannot create cache directory $cache"; finish; return 1; }
  ttl="${PRESSWARDEN_PATCHSTACK_CACHE_TTL:-21600}"; max="${PRESSWARDEN_PATCHSTACK_MAX_LOOKUPS:-250}"
  case "$ttl" in ''|*[!0-9]*) ttl=21600 ;; esac; case "$max" in ''|*[!0-9]*) max=250 ;; esac

  inv=$(tmpf); uniq=$(tmpf); : > "$inv"
  for s in "${WP_SITES[@]}"; do
    d=$(site_domain "$s"); core=$(wpq "$s" core version 2>/dev/null || true); [ -n "$core" ] && printf 'wordpress|wordpress|%s|%s|active\n' "$core" "$d" >> "$inv"
    _inventory_records "$s" "$d" plugin >> "$inv"; _inventory_records "$s" "$d" theme >> "$inv"
  done
  awk -F'|' 'NF>=5{print $1"|"$2"|"$3}' "$inv" | sort -u > "$uniq"

  while IFS='|' read -r type slug ver; do
    [ -n "$slug" ] || continue
    if [ "$lookups" -ge "$max" ]; then note "Lookup cap reached ($max unique component/version pairs); raise PRESSWARDEN_PATCHSTACK_MAX_LOOKUPS to inspect more."; break; fi
    lookups=$((lookups+1)); id=$(printf '%s' "$type|$slug|$ver" | cksum | awk '{print $1"-"$2}'); cachef="$cache/$id.json"
    if ! _cache_fresh "$cachef" "$ttl" || [ "${PRESSWARDEN_INTEL_REFRESH:-0}" = 1 ]; then
      tmp="$cache/.lookup.$$.tmp"; http=$(_fetch_patchstack "$type" "$slug" "$ver" "$tmp" "$key"); rc=$?
      if [ "$rc" -ne 0 ]; then rm -f "$tmp"; flag "Patchstack" "lookup failed for $type $slug v$ver"; continue; fi
      case "$http" in
        200) php -r '$j=json_decode((string)@file_get_contents($argv[1]),true);exit(is_array($j)?0:1);' "$tmp" >/dev/null 2>&1 || { rm -f "$tmp"; flag "Patchstack" "invalid JSON for $type $slug v$ver"; continue; }; mv -f "$tmp" "$cachef" ;;
        404) printf '{"vulnerabilities":[],"presswarden_unknown_product":true}\n' > "$cachef"; rm -f "$tmp" ;;
        401|403) rm -f "$tmp"; flag "Patchstack" "API key is missing permission or invalid (HTTP $http)"; break ;;
        429) rm -f "$tmp"; flag "Patchstack" "rate limit reached (HTTP 429); cached results remain available"; break ;;
        *) rm -f "$tmp"; flag "Patchstack" "HTTP $http for $type $slug v$ver"; continue ;;
      esac
      chmod 600 "$cachef" 2>/dev/null || true
    fi

    if php -r '$j=json_decode((string)@file_get_contents($argv[1]),true);exit(!empty($j["presswarden_unknown_product"])?0:1);' "$cachef" >/dev/null 2>&1; then unknown=$((unknown+1)); continue; fi
    sites=$(awk -F'|' -v t="$type" -v s="$slug" -v v="$ver" '$1==t&&$2==s&&$3==v&&!seen[$4]++{if(n++)printf ", ";printf "%s",$4}END{print ""}' "$inv")
    statuses=$(awk -F'|' -v t="$type" -v s="$slug" -v v="$ver" '$1==t&&$2==s&&$3==v{print $5}' "$inv" | sort -u | paste -sd, -)
    pf=$(tmpf)
    php -r '
      $j=json_decode((string)@file_get_contents($argv[1]),true);$kev=[];if(is_file($argv[2])){$k=json_decode((string)@file_get_contents($argv[2]),true);foreach((array)($k["vulnerabilities"]??[]) as $r){$c=strtoupper((string)($r["cveID"]??""));if($c)$kev[$c]=1;}}
      foreach((array)($j["vulnerabilities"]??[]) as $r){$title=preg_replace("/[\\r\\n\\t|]+/"," ",(string)($r["title"]??"Patchstack vulnerability"));$c=$r["cve"]??"";if(is_array($c))$c=implode(",",$c);$c=strtoupper(trim((string)$c));if($c!==""&&strpos($c,"CVE-")!==0&&preg_match("/^\\d{4}-\\d+$/",$c))$c="CVE-".$c;$expl=!empty($r["is_exploited"]);$score=$r["cvss_score"]??($r["cvss"]["score"]??"");$prio=$r["patch_priority"]??"";$fixed=$r["matched_range"]["fixed_in"]??($r["fixed_in"]??($r["version_info"]["fixed"]??""));$url=$r["direct_url"]??($r["url"]??"");$iskev=$c!==""&&isset($kev[$c]);$kind=($expl||$iskev||(is_numeric($score)&&$score>=7)||(is_numeric($prio)&&$prio>=3))?"ALERT":"REVIEW";echo $kind,"|",$title,"|",$c,"|",($expl?1:0),"|",$score,"|",$prio,"|",$fixed,"|",$url,"|",($iskev?1:0),"\n";}
    ' "$cachef" "$kevf" > "$pf" 2>/dev/null || true
    while IFS='|' read -r kind title cve exploited score priority fixed url iskev; do
      [ -n "$kind" ] || continue; vulns=$((vulns+1))
      printf '\n      %s%s%s PATCHSTACK%s  %s%s%s v%s  %s(local: %s)%s\n' "$B" "$([ "$kind" = ALERT ] && printf "$R" || printf "$Y")" "$([ "$kind" = ALERT ] && printf '✖' || printf '⚠')" "$X" "$B" "$slug" "$X" "$ver" "$D" "${statuses:-unknown}" "$X"
      printf '        %s\n' "$title"; [ -n "$cve" ] && printf '        CVE: %s%s%s' "$B" "$cve" "$X"; [ "$iskev" = 1 ] && printf '  %s• CISA KEV%s' "$R" "$X"; [ "$exploited" = 1 ] && printf '  %s• Patchstack observed exploitation%s' "$R" "$X"; printf '\n'
      [ -n "$score" ] && printf '        CVSS: %s\n' "$score"; [ -n "$fixed" ] && printf '        Fixed: %s\n' "$fixed"; _meta_field 12 WEBSITES "$sites"
      if [ "$kind" = ALERT ]; then ALERTS=$((ALERTS+1)); TOTAL=$((TOTAL+1)); else REVIEWS=$((REVIEWS+1)); TOTAL=$((TOTAL+1)); fi
    done < "$pf"
    rm -f "$pf"
  done < "$uniq"

  [ "$TOTAL" -eq 0 ] && printf '    %s✓ CLEAN%s  no actionable Patchstack vulnerability matches in checked components\n' "$G" "$X"
  note "Patchstack checked $lookups unique component/version pair(s); $unknown were not recognized by the product endpoint. Cache TTL: ${ttl}s."
  note "PressWarden does not redistribute Patchstack vulnerability data; API access, rate limits and plan permissions are controlled by Patchstack."
  rm -f "$inv" "$uniq"
  finish
}
run_logged wp-patchstack-intel
