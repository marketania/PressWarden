#!/usr/bin/env bash
# wp-wordfence-intel — Wordfence V3 Scanner detection + Production/CISA enrichment.
NAME=wp-wordfence-intel; DESC="Wordfence Scanner detection + Production/CISA enrichment"
SCAN_DOES="Matches installed WordPress core/plugins/themes against the locally cached Wordfence V3 Scanner Feed, then enriches matching UUIDs from the Production Feed and elevates matching CVEs present in CISA KEV."
SCAN_WHY="The Scanner Feed is purpose-built for detection; separating detection from enrichment preserves coverage while letting CVE/CVSS/known-exploitation data improve prioritization when available."
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

_make_matcher() {
  local f="$1"
  cat > "$f" <<'PRESSWARDEN_WF_MATCHER'
<?php
[$scannerFile,$productionFile,$invFile,$kevFile]=array_slice($argv,1);
$scanner=json_decode((string)@file_get_contents($scannerFile),true); if(!is_array($scanner))exit(30);
$production=[];
if(is_file($productionFile)){
    $p=json_decode((string)@file_get_contents($productionFile),true);
    if(is_array($p))foreach($p as $key=>$rec){if(!is_array($rec))continue;$id=(string)($rec['id']??$key);if($id!=='')$production[$id]=$rec;}
}
$kev=[];
if(is_file($kevFile)){
    $k=json_decode((string)@file_get_contents($kevFile),true);
    foreach((array)($k['vulnerabilities']??[]) as $r){$c=strtoupper((string)($r['cveID']??''));if($c!=='')$kev[$c]=true;}
}
$inv=[];
foreach(@file($invFile,FILE_IGNORE_NEW_LINES|FILE_SKIP_EMPTY_LINES)?:[] as $line){
    $p=explode('|',$line);if(count($p)<5)continue;[$site,$type,$slug,$version,$status]=$p;
    $inv[strtolower($type).'|'.strtolower($slug)][]=[$site,$type,$slug,$version,$status];
}
function pw_bound($v,$b,$inclusive,$lower){if($b==='*'||$b==='')return true;$c=version_compare($v,$b);return $lower?($inclusive?$c>=0:$c>0):($inclusive?$c<=0:$c<0);}
function pw_affected($v,$ranges){foreach((array)$ranges as $r){$from=(string)($r['from_version']??'*');$to=(string)($r['to_version']??'*');$fi=(bool)($r['from_inclusive']??true);$ti=(bool)($r['to_inclusive']??true);if(pw_bound($v,$from,$fi,true)&&pw_bound($v,$to,$ti,false))return true;}return false;}
function pw_clean($s){return trim(preg_replace('/[\r\n\t|]+/',' ',(string)$s));}
foreach($scanner as $key=>$scanRec){
    if(!is_array($scanRec))continue;
    $id=pw_clean($scanRec['id']??$key); if($id==='')continue;
    $prod=$production[$id]??[];
    $info=(bool)($scanRec['informational']??false);
    $cve=strtoupper(pw_clean($prod['cve']??''));
    $rating=strtolower((string)($prod['cvss']['rating']??''));
    $score=pw_clean($prod['cvss']['score']??'');
    $refs=(array)($scanRec['references']??[]); if(!$refs&&is_array($prod))$refs=(array)($prod['references']??[]);
    $ref=pw_clean($refs[0]??'');
    $isKev=$cve!==''&&isset($kev[$cve]);
    $enriched=is_array($prod)&&!empty($prod)?'1':'0';
    $copy=(array)(($prod['copyrights']??null) ?: ($scanRec['copyrights']??[]));
    $defiant=(array)($copy['defiant']??[]); $mitre=(array)($copy['mitre']??[]);
    $defNotice=pw_clean($defiant['notice']??''); $defUrl=pw_clean($defiant['license_url']??'');
    $mitreNotice=pw_clean($mitre['notice']??''); $mitreUrl=pw_clean($mitre['license_url']??'');
    foreach((array)($scanRec['software']??[]) as $sw){
        $type=strtolower((string)($sw['type']??''));$slug=strtolower((string)($sw['slug']??''));if($type==='core')$slug='wordpress';
        $invKey=$type.'|'.$slug;if(empty($inv[$invKey]))continue;
        foreach($inv[$invKey] as $item){
            [$site,$itype,$islug,$version,$status]=$item;
            if($version===''||!pw_affected($version,$sw['affected_versions']??[]))continue;
            $kind='REVIEW'; if($info)$kind='INFO'; elseif($isKev||$rating==='critical'||$rating==='high')$kind='ALERT';
            $patched=implode(',',array_map('strval',(array)($sw['patched_versions']??[])));
            echo $kind,"|",pw_clean($site),"|",pw_clean($itype),"|",pw_clean($islug),"|",pw_clean($version),"|",pw_clean($status),"|",$id,"|",$cve,"|",$score,"|",($isKev?'1':'0'),"|",pw_clean($patched),"|",$ref,"|",$enriched,"|",$defNotice,"|",$defUrl,"|",$mitreNotice,"|",$mitreUrl,"\n";
        }
    }
}
PRESSWARDEN_WF_MATCHER
}

main() {
  require_wp; banner; discover_sites
  local dir scanner production detection kev inv matcher out s d core rc line kind site type slug ver st id cve score iskev patched ref enriched def_notice def_url mitre_notice mitre_url findings=0 mode
  local -A attribution_seen=()
  dir=$(pw_intel_state_dir); scanner="$dir/wordfence-scanner.json"; production="$dir/wordfence-production.json"; kev="$dir/cisa-kev.json"; detection="$scanner"; mode='Scanner Feed'
  mkdir -p "$dir" 2>/dev/null || true

  sec "Installed-version vulnerability intelligence" "Wordfence V3 Scanner detection • Production enrichment • CISA KEV"
  if [ ! -s "$scanner" ] && [ -n "${PRESSWARDEN_WORDFENCE_TOKEN:-}" ] && [ "${PRESSWARDEN_INTEL_AUTO_UPDATE:-1}" != "0" ]; then
    note "Wordfence Scanner cache missing; attempting one intelligence update before matching."
    pw_intel_update >/dev/null 2>&1 || true
  fi
  if [ ! -s "$scanner" ] && [ -s "$production" ]; then detection="$production"; mode='Production fallback'; fi
  if [ ! -s "$detection" ]; then
    note "SKIPPED: no cached Wordfence feed. Configure PRESSWARDEN_WORDFENCE_TOKEN and run ./presswarden intel update."
    finish; return 0
  fi

  inv=$(tmpf); : > "$inv"
  for s in "${WP_SITES[@]}"; do
    d=$(site_domain "$s"); core=$(wpq "$s" core version 2>/dev/null || true); [ -n "$core" ] && printf '%s|core|wordpress|%s|active\n' "$d" "$core" >> "$inv"
    _inventory_plugins "$s" "$d" >> "$inv"
    _inventory_themes "$s" "$d" >> "$inv"
  done

  matcher=$(tmpf); out=$(tmpf); _make_matcher "$matcher"
  php "$matcher" "$detection" "$production" "$inv" "$kev" > "$out" 2>/dev/null; rc=$?
  if [ "$rc" -ne 0 ]; then
    flag "intelligence" "Wordfence feed could not be parsed/matched (rc=$rc)"
    rm -f "$inv" "$matcher" "$out"; finish; return 1
  fi

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
      [ -n "$def_notice" ] && printf '      %sATTRIBUTION%s  %s%s%s' "$D" "$X" "$def_notice" "$([ -n "$def_url" ] && printf ' • ' || true)" "$def_url"
      [ -n "$def_notice" ] && printf '\n'
      [ -n "$mitre_notice" ] && printf '      %sATTRIBUTION%s  %s%s%s' "$D" "$X" "$mitre_notice" "$([ -n "$mitre_url" ] && printf ' • ' || true)" "$mitre_url"
      [ -n "$mitre_notice" ] && printf '\n'
      attribution_seen[$id]=1
    fi
  done < "$out"

  [ "$findings" -eq 0 ] && printf '    %s✓ CLEAN%s  no installed versions matched the cached Wordfence detection feed\n' "$G" "$X"
  note "Detection source: $mode. Production data enriches matching UUIDs with CVE/CVSS when available."
  [ -s "$kev" ] && note "CISA KEV correlation active: matching CVEs are elevated as known-exploited." || note "CISA KEV cache not present; run ./presswarden intel update to add known-exploited prioritization."
  note "Wordfence feed data stays in the local intel cache and is not redistributed by PressWarden; source and available copyright attribution are shown for matched records."
  note "Feed use remains subject to the current Wordfence Intelligence and CVE attribution terms documented in intel/SOURCES.md."
  rm -f "$inv" "$matcher" "$out"
  finish
}
run_logged wp-wordfence-intel
