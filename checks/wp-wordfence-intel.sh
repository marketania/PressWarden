#!/usr/bin/env bash
# wp-wordfence-intel — optional Wordfence Intelligence V3 vulnerability matching + CISA KEV correlation.
NAME=wp-wordfence-intel; DESC="Wordfence Intelligence + CISA KEV correlation"
SCAN_DOES="Matches locally installed WordPress core/plugins/themes against a locally cached Wordfence Intelligence V3 Production Feed and elevates matching CVEs present in CISA KEV."
SCAN_WHY="Known-vulnerable installed versions are actionable even without local compromise evidence, and known exploitation should take priority over score alone."
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
[$feedFile,$invFile,$kevFile]=array_slice($argv,1);
$feed=json_decode((string)@file_get_contents($feedFile),true); if(!is_array($feed))exit(30);
$kev=[]; if(is_file($kevFile)){ $k=json_decode((string)@file_get_contents($kevFile),true); foreach((array)($k['vulnerabilities']??[]) as $r){$c=strtoupper((string)($r['cveID']??''));if($c!=='')$kev[$c]=true;} }
$inv=[];
foreach(@file($invFile,FILE_IGNORE_NEW_LINES|FILE_SKIP_EMPTY_LINES)?:[] as $line){$p=explode('|',$line);if(count($p)<5)continue;[$site,$type,$slug,$version,$status]=$p;$key=strtolower($type).'|'.strtolower($slug);$inv[$key][]=[$site,$type,$slug,$version,$status];}
function pw_bound($v,$b,$inclusive,$lower){if($b==='*'||$b==='')return true;$c=version_compare($v,$b);return $lower?($inclusive?$c>=0:$c>0):($inclusive?$c<=0:$c<0);}
function pw_affected($v,$ranges){foreach((array)$ranges as $r){$from=(string)($r['from_version']??'*');$to=(string)($r['to_version']??'*');$fi=(bool)($r['from_inclusive']??true);$ti=(bool)($r['to_inclusive']??true);if(pw_bound($v,$from,$fi,true)&&pw_bound($v,$to,$ti,false))return true;}return false;}
function pw_clean($s){$s=preg_replace('/[\r\n\t|]+/',' ',(string)$s);return trim($s);}
foreach($feed as $rec){
  if(!is_array($rec))continue;$title=pw_clean($rec['title']??'Wordfence vulnerability');$cve=strtoupper(pw_clean($rec['cve']??''));$info=(bool)($rec['informational']??false);$rating=strtolower((string)($rec['cvss']['rating']??''));$score=(string)($rec['cvss']['score']??'');$refs=(array)($rec['references']??[]);$ref=pw_clean($refs[0]??'');
  foreach((array)($rec['software']??[]) as $sw){$type=strtolower((string)($sw['type']??''));$slug=strtolower((string)($sw['slug']??''));if($type==='core')$slug='wordpress';$key=$type.'|'.$slug;if(empty($inv[$key]))continue;
    foreach($inv[$key] as $item){[$site,$itype,$islug,$version,$status]=$item;if($version===''||!pw_affected($version,$sw['affected_versions']??[]))continue;$isKev=$cve!==''&&isset($kev[$cve]);
      $kind='REVIEW';if($info)$kind='INFO';elseif($isKev||$rating==='critical'||$rating==='high')$kind='ALERT';
      $patched=implode(',',array_map('strval',(array)($sw['patched_versions']??[])));$rem=pw_clean($sw['remediation']??'');
      echo $kind,"|",pw_clean($site),"|",pw_clean($itype),"|",pw_clean($islug),"|",pw_clean($version),"|",pw_clean($status),"|",$title,"|",$cve,"|",pw_clean($score),"|",($isKev?'1':'0'),"|",pw_clean($patched),"|",$rem,"|",$ref,"\n";
    }
  }
}
PRESSWARDEN_WF_MATCHER
}

main() {
  require_wp; banner; discover_sites
  local dir feed kev inv matcher out s d core rc line kind site type slug ver st title cve score iskev patched rem ref findings=0
  dir=$(pw_intel_state_dir); feed="$dir/wordfence-production.json"; kev="$dir/cisa-kev.json"
  mkdir -p "$dir" 2>/dev/null || true

  sec "Installed-version vulnerability intelligence" "Wordfence Intelligence V3 Production Feed • CISA KEV correlation"
  if [ ! -s "$feed" ] && [ -n "${PRESSWARDEN_WORDFENCE_TOKEN:-}" ] && [ "${PRESSWARDEN_INTEL_AUTO_UPDATE:-1}" != "0" ]; then
    note "Wordfence cache missing; attempting one intelligence update before matching."
    pw_intel_update >/dev/null 2>&1 || true
  fi
  if [ ! -s "$feed" ]; then
    note "SKIPPED: no cached Wordfence Intelligence feed. Configure PRESSWARDEN_WORDFENCE_TOKEN and run ./presswarden intel update."
    finish; return 0
  fi

  inv=$(tmpf); : > "$inv"
  for s in "${WP_SITES[@]}"; do
    d=$(site_domain "$s"); core=$(wpq "$s" core version 2>/dev/null || true); [ -n "$core" ] && printf '%s|core|wordpress|%s|active\n' "$d" "$core" >> "$inv"
    _inventory_plugins "$s" "$d" >> "$inv"
    _inventory_themes "$s" "$d" >> "$inv"
  done

  matcher=$(tmpf); out=$(tmpf); _make_matcher "$matcher"
  php "$matcher" "$feed" "$inv" "$kev" > "$out" 2>/dev/null; rc=$?
  if [ "$rc" -ne 0 ]; then
    flag "intelligence" "Wordfence feed could not be parsed/matched (rc=$rc)"
    rm -f "$inv" "$matcher" "$out"; finish; return 1
  fi

  while IFS='|' read -r kind site type slug ver st title cve score iskev patched rem ref; do
    [ -n "$kind" ] || continue; findings=$((findings+1))
    line="$type $slug v$ver (local: ${st:-unknown}) — $title"
    [ -n "$cve" ] && line="$line [$cve]"
    [ "$iskev" = "1" ] && line="$line • CISA KEV / known exploited"
    [ -n "$score" ] && line="$line • CVSS $score"
    [ -n "$patched" ] && line="$line • patched: $patched"
    case "$kind" in
      ALERT) issue "$site" "$line" ;;
      REVIEW) flag "$site" "$line" ;;
      INFO) printf '    %sℹ INFO%s  %s%s%s  › %s\n' "$C" "$X" "$B$M" "$site" "$X" "$line" ;;
    esac
  done < "$out"
  [ "$findings" -eq 0 ] && printf '    %s✓ CLEAN%s  no installed versions matched the cached Wordfence vulnerability feed\n' "$G" "$X"
  [ -s "$kev" ] && note "CISA KEV correlation active: matching CVEs are elevated as known-exploited." || note "CISA KEV cache not present; run ./presswarden intel update to add known-exploited prioritization."
  note "Vulnerability data is locally cached from Wordfence Intelligence; PressWarden does not redistribute the feed. Review Wordfence Intelligence terms/copyright metadata for downstream display requirements."
  rm -f "$inv" "$matcher" "$out"
  finish
}
run_logged wp-wordfence-intel
