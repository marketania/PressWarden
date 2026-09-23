#!/usr/bin/env bash
# baseline-changes — compare current security-relevant state to a saved baseline.
NAME=baseline-changes; DESC="security-relevant changes since the accepted baseline"
SCAN_DOES="Compares executable/configuration file hashes and available WordPress plugin, theme, administrator, and cron state against the saved baseline."
SCAN_WHY="Unexpected changes can reveal persistence or reinfection, but change alone is not proof of compromise, so every baseline delta is review-only."
PRESSWARDEN_DIR="${PRESSWARDEN_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
# shellcheck source=lib/baseline.sh
. "$PRESSWARDEN_DIR/lib/baseline.sh"

main() (
  local scope current capture diff findings action type site key newv oldv label row
  banner
  sec "Changes since baseline" "review-only • no automatic remediation"

  scope=$(_pw_baseline_scope_dir)
  current="$scope/current"
  if [ ! -e "$current" ] && [ ! -L "$current" ] && [ ! -e "$scope/.baseline.lock" ]; then
    note "No baseline exists for this scan root; incident scanning will continue without change history."
    note "Create one after validating a known-good state: ./presswarden baseline create [path]"
    finish
    return
  fi

  _pw_baseline_prepare_comparison || return 2
  capture="$PW_BASELINE_CAPTURE"; diff="$PW_BASELINE_DIFF"
  findings="$PW_BASELINE_WORK/findings"; : > "$findings" || return 2
  while IFS= read -r row; do
    IFS=$'\034' read -r action type site key newv oldv <<< "${row//$'\t'/$'\034'}"
    [ -n "$action" ] || continue
    case "$type:$action" in
      F:ADD) label='NEW FILE' ;;
      F:CHANGE) label='CHANGED FILE' ;;
      F:REMOVE) label='REMOVED FILE' ;;
      P:ADD) label='PLUGIN ADDED' ;;
      P:CHANGE) label='PLUGIN CHANGED' ;;
      P:REMOVE) label='PLUGIN REMOVED' ;;
      T:ADD) label='THEME ADDED' ;;
      T:CHANGE) label='THEME CHANGED' ;;
      T:REMOVE) label='THEME REMOVED' ;;
      A:ADD) label='ADMIN ADDED' ;;
      A:CHANGE) label='ADMIN CHANGED' ;;
      A:REMOVE) label='ADMIN REMOVED' ;;
      C:ADD) label='CRON ADDED' ;;
      C:CHANGE) label='CRON CHANGED' ;;
      C:REMOVE) label='CRON REMOVED' ;;
      *) label="$action $type" ;;
    esac
    case "$type" in
      P|T|C)
        if [ "$action" = CHANGE ]; then
          printf '%s  %s  ›  %s  (%s -> %s)\n' "$label" "$site" "$key" "$oldv" "$newv" >> "$findings" || return 2
        else
          printf '%s  %s  ›  %s\n' "$label" "$site" "$key" >> "$findings" || return 2
        fi
        ;;
      *) printf '%s  %s  ›  %s\n' "$label" "$site" "$key" >> "$findings" || return 2 ;;
    esac
  done < "$diff" || return 2

  rm -rf "$capture"; rm -f "$diff"
  report "$findings" review "no changes since the accepted baseline" noaction
  note "Baseline changes are context signals only; correlate them with integrity, malware, account, and persistence findings before remediation."
  finish
)

run_logged baseline-changes
