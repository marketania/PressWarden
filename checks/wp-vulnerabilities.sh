#!/usr/bin/env bash
# wp-vulnerabilities — optional remote WPScan vulnerability intelligence.
# Configure WPSCAN_API_TOKEN in ~/.config/presswarden/config (chmod 600) or the environment.
NAME=wp-vulnerabilities; DESC="optional WPScan vulnerability intelligence"
SCAN_DOES="Optionally evaluates structured WPScan results from remote passive plugin/theme enumeration. This is not a complete installed-component inventory."
SCAN_WHY="A known vulnerability is distinct from evidence of compromise; failed or unavailable intelligence must not be reported as clean."
. "$(cd "$(dirname "$0")/.." && pwd)/lib/_lib.sh"

_wpscan_incomplete() {
  PW_CHECK_INCOMPLETE=1
  note "INCOMPLETE: $1"
}

main() {
  local s d url dir rc parser_rc kind message diagnostics seconds dep
  local api_token="${WPSCAN_API_TOKEN:-}"
  sec "Known vulnerability intelligence" "optional • external WPScan API/CLI"
  if [ -z "$api_token" ]; then
    note 'SKIPPED: no WPScan API token is configured; no vulnerability coverage was obtained.'
    return 0
  fi
  seconds="${PRESSWARDEN_WPSCAN_TIMEOUT:-180}"
  case "$seconds" in ''|*[!0-9]*) _wpscan_incomplete 'Invalid WPScan timeout; use 1–3600 seconds.'; finish; return 2 ;; esac
  if [ "${#seconds}" -gt 4 ] || [ "$seconds" -lt 1 ] || [ "$seconds" -gt 3600 ]; then
    _wpscan_incomplete 'Invalid WPScan timeout; use 1–3600 seconds.'; finish; return 2
  fi
  for dep in wp wpscan php timeout; do
    if ! command -v "$dep" >/dev/null 2>&1; then
      _wpscan_incomplete "Configured WPScan check needs $dep; install the dependency or deliberately disable this optional integration."
      finish; return 2
    fi
  done
  discover_sites; banner
  note 'Resolving each home URL loads trusted WordPress/MU-plugin code. For suspected compromise use static investigation or an isolated copy first.'
  note 'Only scan authorized remote URLs. No guessed URL fallback. API queries can consume quota; raw provider diagnostics are withheld.'
  for s in "${WP_SITES[@]}"; do
    d=$(site_label_from_root "$s")
    dir=$(mktemp -d "${TMPDIR:-/tmp}/presswarden-wpscan.XXXXXX") || { _wpscan_incomplete 'Cannot reserve private temporary storage.'; break; }
    chmod 700 "$dir" || { _wpscan_incomplete 'Cannot protect temporary storage.'; rmdir -- "$dir"; break; }
    # WP-CLI bootstrap is executable/trusted, not sandboxed by skip flags. Keep
    # stdout and stderr separate: wpq merges them and is unsuitable for URLs.
    (umask 077; ulimit -f 8192; timeout --kill-after=5s "${seconds}s" wp option get home --path="$s" --skip-plugins --skip-themes --skip-packages --no-color) > "$dir/url" 2> "$dir/wp.err"
    rc=$?
    if [ "$rc" -ne 0 ] || [ -s "$dir/wp.err" ] || ! url=$(php -d memory_limit=64M "$PRESSWARDEN_DIR/lib/wpscan-result.php" url "$dir/url" 2>/dev/null); then
      _wpscan_incomplete "$d: unable to validate WordPress home; nothing was sent to WPScan. Inspect the trusted installation configuration."
      rm -f -- "$dir/url" "$dir/wp.err"; rmdir -- "$dir"; continue
    fi
    # A fresh private cwd prevents loading .wpscan options from a served site.
    # HOME/XDG scanner configuration remains trusted administrator input.
    (cd "$dir" && umask 077 && ulimit -f 8192 && WPSCAN_API_TOKEN="$api_token" timeout --kill-after=5s "${seconds}s" wpscan --url "$url" --enumerate vp,vt --plugins-detection passive --no-banner --format json) > "$dir/result" 2> "$dir/scan.err"
    rc=$?; diagnostics=0; [ ! -s "$dir/scan.err" ] || diagnostics=1
    WPSCAN_API_TOKEN="$api_token" php -d memory_limit=96M "$PRESSWARDEN_DIR/lib/wpscan-result.php" report "$dir/result" "$url" "$rc" "$diagnostics" > "$dir/parsed" 2> "$dir/parse.err"
    parser_rc=$?
    if [ "$parser_rc" -gt 2 ] || [ -s "$dir/parse.err" ] || [ ! -s "$dir/parsed" ]; then
      _wpscan_incomplete "$d: result interpretation failed; no clean coverage claim is possible."
    else
      while IFS=$'\t' read -r kind message; do
        case "$kind" in
          FINDING) flag "$d" 'WPScan vulnerability record (provider evidence; review applicability)' "$message" ;;
          INCOMPLETE) _wpscan_incomplete "$d: $message" ;;
          OK) ok "$d" "$message" ;;
          *) _wpscan_incomplete "$d: unexpected parser output." ;;
        esac
      done < "$dir/parsed"
      [ "$parser_rc" -ne 2 ] || PW_CHECK_INCOMPLETE=1
    fi
    rm -f -- "$dir/url" "$dir/wp.err" "$dir/result" "$dir/scan.err" "$dir/parsed" "$dir/parse.err"
    rmdir -- "$dir" || _wpscan_incomplete 'Temporary-directory cleanup failed; inspect private temp storage.'
  done
  finish
}
run_logged wp-vulnerabilities
