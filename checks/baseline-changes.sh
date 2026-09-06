#!/usr/bin/env bash
# baseline-changes — compare current security-relevant state to a saved baseline.
NAME=baseline-changes; DESC="security-relevant changes since the accepted baseline"
SCAN_DOES="Compares executable/configuration file hashes and available WordPress plugin, theme, administrator, and cron state against the saved baseline."
SCAN_WHY="Unexpected changes can reveal persistence or reinfection, but change alone is not proof of compromise, so every baseline delta is review-only."
PRESSWARDEN_DIR="${PRESSWARDEN_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
# shellcheck source=lib/baseline.sh
. "$PRESSWARDEN_DIR/lib/baseline.sh"

main() {
  local scope current capture diff findings action type site key newv oldv label
  banner
  sec "Changes since baseline" "review-only • no automatic remediation"

  scope=$(_pw_baseline_scope_dir)
  current="$scope/current"
  if [ ! -s "$current/manifest.tsv" ] || [ ! -s "$current/meta.tsv" ]; then
    note "No baseline exists for this scan root; incident scanning will continue without change history."
    note "Create one after validating a known-good state: ./presswarden baseline create [path]"
    finish
    return
  fi

  if [ "$(_pw_meta_value "$current/meta.tsv" root)" != "$ROOT" ]; then
    note "Saved baseline belongs to a different scan root; change comparison skipped."
    finish
    return
  fi

  capture="$scope/.incident-compare.$$"
  diff=$(tmpf)
  findings=$(tmpf)
  rm -rf "$capture"; mkdir -p "$capture" || die "cannot create baseline comparison capture"
  : > "$findings"

  _pw_baseline_capture "$capture"
  _pw_baseline_build_diff "$current/manifest.tsv" "$capture/manifest.tsv" "$diff"

  while IFS=$'\t' read -r action type site key newv oldv; do
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
          printf '%s  %s  ›  %s  (%s -> %s)\n' "$label" "$site" "$key" "$oldv" "$newv" >> "$findings"
        else
          printf '%s  %s  ›  %s\n' "$label" "$site" "$key" >> "$findings"
        fi
        ;;
      *) printf '%s  %s  ›  %s\n' "$label" "$site" "$key" >> "$findings" ;;
    esac
  done < "$diff"

  rm -rf "$capture"; rm -f "$diff"
  report "$findings" review "no changes since the accepted baseline" noaction
  note "Baseline changes are context signals only; correlate them with integrity, malware, account, and persistence findings before remediation."
  finish
}

run_logged baseline-changes
