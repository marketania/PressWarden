#!/usr/bin/env bash
# wp-vulnerabilities — optional remote WPScan vulnerability intelligence.
# Configure WPSCAN_API_TOKEN in ~/.config/presswarden/config (chmod 600) or the environment.
NAME=wp-vulnerabilities; DESC="optional WPScan vulnerability intelligence"
SCAN_DOES="Optionally queries WPScan vulnerability intelligence for known issues affecting installed WordPress components."
SCAN_WHY="An installed version can be known vulnerable even before a local malware scan finds evidence that the vulnerability was exploited."
. "$(cd "$(dirname "$0")/.." && pwd)/lib/_lib.sh"


main() {
  require_wp; banner; discover_sites
  local s d url out rc api_token token_source
  api_token="${WPSCAN_API_TOKEN:-}"
  token_source="central config/environment"

  sec "Known vulnerability intelligence" "optional • external WPScan API/CLI"
  if ! command -v wpscan >/dev/null 2>&1; then
    note "SKIPPED: wpscan command is not installed."
    note "This remains standalone because external vulnerability intelligence requires an additional service/tool."
    finish; return 0
  fi
  if [ -z "$api_token" ]; then
    note "SKIPPED: no WPScan API token is available."
    finish; return 0
  fi
  note "WPScan API credential: $token_source (token value hidden)."
  note "WPScan vulnerability data is API-backed and can consume multiple API requests per site."

  for s in "${WP_SITES[@]}"; do
    d=$(site_domain "$s"); url=$(wpq "$s" option get home 2>/dev/null || echo "https://$d")
    out=$(tmpf)
    WPSCAN_API_TOKEN="$api_token" wpscan --url "$url" --enumerate vp,vt --plugins-detection passive --no-banner --format cli-no-colour > "$out" 2>&1; rc=$?
    if grep -qiE 'vulnerabilit(y|ies)' "$out" && ! grep -qiE 'No Known Vulnerabilities Detected' "$out"; then
      flag "$d" "WPScan reported vulnerability-related output" "$(grep -Ei 'vulnerab|CVE-|Fixed in' "$out" | head -25)"
    elif [ "$rc" -ne 0 ]; then
      flag "$d" "WPScan returned rc=$rc" "$(tail -n 8 "$out")"
    else ok "$d" "no vulnerable plugin/theme finding reported"; fi
    rm -f "$out"
  done
  finish
}
run_logged wp-vulnerabilities
