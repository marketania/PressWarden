#!/usr/bin/env bash
# wp-wordfence-intel — Wordfence V3 Scanner detection + Production/CISA enrichment.
NAME=wp-wordfence-intel; DESC="Wordfence Scanner detection + Production/CISA enrichment"
SCAN_DOES="Streams the locally cached Wordfence V3 Scanner Feed against installed WordPress core/plugins/themes, then streams Production only for matching UUID enrichment and elevates matching CVEs present in CISA KEV."
SCAN_WHY="The Scanner Feed is purpose-built for detection. Bounded-memory streaming keeps large complete feeds usable on constrained shared hosting while Production/CISA enrichment improves prioritization."
. "$(cd "$(dirname "$0")/.." && pwd)/lib/_lib.sh"
. "$PRESSWARDEN_DIR/lib/intel.sh"

_inventory_plugins() {
  local s="$1" site="$2" f
  f=$(tmpf)
  if wpq "$s" plugin list --fields=name,status,version --format=json --skip-update-check > "$f" 2>/dev/null; then
    php -r '$j=json_decode((string)@file_get_contents($argv[1]),true);$site=$argv[2];foreach((array)$j as $r){$n=str_replace("|","-",(string)($r["name"]??""));$v=str_replace("|","-",(string)($r["version"]??""));$st=str_replace("|","-",(string)($r["status"]??""));if($n!=="")echo $site,"|plugin|",$n,"|",$v,"|",$st,"\n";}' "$f" "$site" 2>/dev/null || true
  fi
  rm -f "$f"
}

_inventory_themes() {
  local s="$1" site="$2" f
  f=$(tmpf)
  if wpq "$s" theme list --fields=name,status,version --format=json --skip-update-check > "$f" 2>/dev/null; then
    php -r '$j=json_decode((string)@file_get_contents($argv[1]),true);$site=$argv[2];foreach((array)$j as $r){$n=str_replace("|","-",(string)($r["name"]??""));$v=str_replace("|","-",(string)($r["version"]??""));$st=str_replace("|","-",(string)($r["status"]??""));if($n!=="")echo $site,"|theme|",$n,"|",$v,"|",$st,"\n";}' "$f" "$site" 2>/dev/null || true
  fi
  rm -f "$f"
}

main() {
  require_wp; banner; discover_sites
  local dir scanner production detection kev inv out err s d core rc line kind site type slug ver st id cve score iskev patched ref enriched def_notice def_url mitre_notice mitre_url findings=0 mode
  local -A attribution_seen=()
  dir=$(pw_intel_state_dir); scanner="$dir/wordfence-scanner.json"; production="$dir/wordfence-production.json"; kev="$dir/cisa-kev.json"; detection="$scanner"; mode='Scanner Feed'
  mkdir -p "$dir" 2>/dev/null || true

  sec "Installed-version vulnerability intelligence" "Wordfence V3 Scanner detection • Production enrichment • CISA KEV • bounded-memory streaming"
  if [ ! -s "$scanner" ] && [ -n "${PRESSWARDEN_WORDFENCE_TOKEN:-}" ] && [ "${PRESSWARDEN_INTEL_AUTO_UPDATE:-1}" != "0" ]; then
    note "Wordfence Scanner cache missing; attempting one intelligence update before matching."
    pw_intel_update >/dev/null 2>&1 || true
  fi
  if [ ! -s "$scanner" ] && [ -s "$production" ]; then detection="$production"; mode='Production fallback'; fi
  if [ ! -s "$detection" ]; then
    note "SKIPPED: no cached Wordfence feed. Configure PRESSWARDEN_WORDFENCE_TOKEN and run ./presswarden intel update."
    finish; return 0
  fi
  [ -r "$PRESSWARDEN_DIR/lib/json-object-stream.php" ] && [ -r "$PRESSWARDEN_DIR/lib/wordfence-match.php" ] || {
    flag "intelligence" "streaming Wordfence helper is missing from the PressWarden installation"; finish; return 1;
  }

  inv=$(tmpf); : > "$inv"
  for s in "${WP_SITES[@]}"; do
    d=$(site_domain "$s"); core=$(wpq "$s" core version 2>/dev/null || true); [ -n "$core" ] && printf '%s|core|wordpress|%s|active\n' "$d" "$core" >> "$inv"
    _inventory_plugins "$s" "$d" >> "$inv"
    _inventory_themes "$s" "$d" >> "$inv"
  done

  out=$(tmpf); err=$(tmpf)
  php "$PRESSWARDEN_DIR/lib/wordfence-match.php" "$detection" "$production" "$inv" "$kev" > "$out" 2> "$err"; rc=$?
  if [ "$rc" -ne 0 ]; then
    flag "intelligence" "Wordfence feed could not be streamed/matched (rc=$rc)" "$(tail -n 2 "$err" 2>/dev/null)"
    rm -f "$inv" "$out" "$err"; finish; return 1
  fi
  if [ -s "$err" ]; then note "Production enrichment warning: $(tail -n 1 "$err")"; fi

  while IFS='|' read -r kind site type slug ver st id cve score iskev patched ref enriched def_notice def_url mitre_notice mitre_url; do
    [ -n "$kind" ] || continue; findings=$((findings+1))
    line="$type $slug v$ver (local: ${st:-unknown}) — Wordfence Intelligence match $id"
    [ -n "$cve" ] && line="$line • $cve"
    [ "$iskev" = "1" ] && line="$line • CISA KEV / known exploited"
    [ -n "$score" ] && line="$line • CVSS $score"
    [ -n "$patched" ] && line="$line • patched: $patched"
    [ "$enriched" = "0" ] && line="$line • Scanner-only record"
    case "$kind" in ALERT) issue "$site" "$line" ;; REVIEW) flag "$site" "$line" ;; INFO) printf '    %sℹ INFO%s  %s%s%s  › %s\n' "$C" "$X" "$B$M" "$site" "$X" "$line" ;; esac
    [ -n "$ref" ] && printf '      %sSOURCE%s  %s\n' "$D" "$X" "$ref"
    if [ -z "${attribution_seen[$id]:-}" ]; then
      [ -n "$def_notice" ] && printf '      %sATTRIBUTION%s  %s%s%s\n' "$D" "$X" "$def_notice" "$([ -n "$def_url" ] && printf ' • ' || true)" "$def_url"
      [ -n "$mitre_notice" ] && printf '      %sATTRIBUTION%s  %s%s%s\n' "$D" "$X" "$mitre_notice" "$([ -n "$mitre_url" ] && printf ' • ' || true)" "$mitre_url"
      attribution_seen[$id]=1
    fi
  done < "$out"

  [ "$findings" -eq 0 ] && printf '    %s✓ CLEAN%s  no installed versions matched the cached Wordfence detection feed\n' "$G" "$X"
  note "Detection source: $mode. Feed records are streamed one at a time; Production is retained only for matched UUID enrichment."
  [ -s "$kev" ] && note "CISA KEV correlation active: matching CVEs are elevated as known-exploited." || note "CISA KEV cache not present; run ./presswarden intel update to add known-exploited prioritization."
  note "Wordfence feed data stays in the local intel cache and is not redistributed by PressWarden; source and available copyright attribution are shown for matched records."
  note "Feed use remains subject to the current Wordfence Intelligence and CVE attribution terms documented in intel/SOURCES.md."
  rm -f "$inv" "$out" "$err"
  finish
}
run_logged wp-wordfence-intel
