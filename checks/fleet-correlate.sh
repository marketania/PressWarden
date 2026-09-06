#!/usr/bin/env bash
# fleet-correlate — correlate baseline deltas across multiple WordPress installs.
NAME=fleet-correlate; DESC="cross-site correlation of new or changed security-relevant artifacts"
SCAN_DOES="Uses the accepted baseline as a noise filter, then looks for the same newly-added or changed file hash, administrator identity, or cron event appearing across multiple WordPress installations."
SCAN_WHY="Shared malicious artifacts often reveal account-wide spread, while ordinary duplicate core/plugin files are common and must not be treated as suspicious merely because they exist on many sites."
PRESSWARDEN_DIR="${PRESSWARDEN_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
# shellcheck source=lib/baseline.sh
. "$PRESSWARDEN_DIR/lib/baseline.sh"

main() {
  local scope current capture diff candidates findings
  banner
  sec "Fleet outbreak correlation" "baseline-filtered • review-only"

  scope=$(_pw_baseline_scope_dir)
  current="$scope/current"
  if [ ! -s "$current/manifest.tsv" ] || [ ! -s "$current/meta.tsv" ]; then
    note "No baseline exists for this scan root; fleet change correlation skipped."
    note "Create a baseline after validating a known-good state: ./presswarden baseline create [path]"
    finish
    return
  fi
  if [ "$(_pw_meta_value "$current/meta.tsv" root)" != "$ROOT" ]; then
    note "Saved baseline belongs to a different scan root; fleet change correlation skipped."
    finish
    return
  fi

  capture="$scope/.correlate.$$"
  diff=$(tmpf); candidates=$(tmpf); findings=$(tmpf)
  rm -rf "$capture"; mkdir -p "$capture" || die "cannot create fleet-correlation capture"
  : > "$candidates"; : > "$findings"

  _pw_baseline_capture "$capture"
  _pw_baseline_build_diff "$current/manifest.tsv" "$capture/manifest.tsv" "$diff"

  # Candidate set is deliberately restricted to current ADD/CHANGE deltas.
  # Existing duplicate WordPress/plugin files therefore never become findings
  # solely because multiple sites contain the same legitimate package file.
  awk -F '\t' 'BEGIN{OFS="\t"}
    ($1=="ADD" || $1=="CHANGE") && $2=="F" { split($5,a,":"); if (a[1] != "") print "F",a[1] }
    ($1=="ADD" || $1=="CHANGE") && $2=="A" { if ($4 != "") print "A",$4 }
    ($1=="ADD" || $1=="CHANGE") && $2=="C" { if ($4 != "") print "C",$4 "|" $5 }
  ' "$diff" | sort -u > "$candidates"

  if [ -s "$candidates" ]; then
    awk -F '\t' 'BEGIN{OFS="\t"}
      NR==FNR { cand[$1 SUBSEP $2]=1; next }
      $1=="F" { split($4,a,":"); ind=a[1] }
      $1=="A" { ind=$3 }
      $1=="C" { ind=$3 "|" $4 }
      $1!="F" && $1!="A" && $1!="C" { next }
      {
        k=$1 SUBSEP ind
        if (!(k in cand)) next
        sk=k SUBSEP $2
        if (!(sk in seen)) { seen[sk]=1; sites[k]++; if (site_list[k]=="") site_list[k]=$2; else site_list[k]=site_list[k] ", " $2 }
        if ($1=="F" && detail[k]=="") detail[k]=$2 ":" $3
      }
      END {
        for (k in sites) {
          if (sites[k] < 2) continue
          split(k,p,SUBSEP); kind=p[1]; ind=p[2]
          if (kind=="F") {
            short=substr(ind,1,16)
            printf "FLEET FILE  %d sites  ›  sha256=%s…  • %s", sites[k], short, site_list[k]
            if (detail[k] != "") printf "  • sample=%s", detail[k]
            printf "\n"
          } else if (kind=="A") {
            printf "FLEET ADMIN  %d sites  ›  username=%s  • %s\n", sites[k], ind, site_list[k]
          } else if (kind=="C") {
            split(ind,c,"\\|")
            printf "FLEET CRON  %d sites  ›  hook=%s", sites[k], c[1]
            if (c[2] != "") printf "  recurrence=%s", c[2]
            printf "  • %s\n", site_list[k]
          }
        }
      }
    ' "$candidates" "$capture/manifest.tsv" | sort > "$findings"
  fi

  rm -rf "$capture"; rm -f "$diff" "$candidates"
  report "$findings" review "no repeated new/changed artifacts across multiple sites" noaction
  note "Fleet correlation is a spread signal, not automatic malware attribution; confirm with malware, integrity, persistence, or account evidence."
  finish
}

run_logged fleet-correlate
