#!/usr/bin/env bash
NAME=doctor; DESC="installation/config/dependency/discovery/intelligence preflight"
SCAN_DOES="Validates PressWarden, dependencies, config permissions, threat-intelligence readiness, optional integrations, WordPress discovery, shell syntax, and restricted-hosting compatibility."
SCAN_WHY="Separates scanner/environment problems from real website findings before a security audit starts."
. "$(cd "$(dirname "$0")/.." && pwd)/lib/_lib.sh"
. "$PRESSWARDEN_DIR/lib/intel.sh"
main() {
  banner
  sec "Runtime dependencies" "required commands + feature readiness"
  local c missing=0 sha_tool=''
  for c in bash php find grep sed awk sort stat cksum; do
    if command -v "$c" >/dev/null 2>&1; then ok "$c" "$(command -v "$c")"; else issue "$c" "required command not found"; missing=$((missing+1)); fi
  done
  for c in wp curl wget jq yara; do
    if command -v "$c" >/dev/null 2>&1; then ok "$c" "$(command -v "$c")"; else printf '    %sℹ OPTIONAL%s  %-8s not found\n' "$C" "$X" "$c"; fi
  done

  if command -v sha256sum >/dev/null 2>&1; then sha_tool='sha256sum'
  elif command -v shasum >/dev/null 2>&1; then sha_tool='shasum -a 256'
  elif command -v openssl >/dev/null 2>&1; then sha_tool='openssl sha256'
  fi
  if [ -n "$sha_tool" ]; then
    ok "SHA-256" "$sha_tool available for baseline/change hashing"
  else
    flag "SHA-256" "sha256sum, shasum, or openssl not found • baseline/change commands unavailable"
  fi

  if command -v tar >/dev/null 2>&1 && { command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1; }; then
    ok "SELF-UPDATE" "tar + download client available"
  elif ! command -v tar >/dev/null 2>&1; then
    flag "SELF-UPDATE" "tar not found • scans still work, but ./presswarden update is unavailable"
  else
    flag "SELF-UPDATE" "curl/wget not found • scans still work, but ./presswarden update is unavailable"
  fi

  sec "Configuration" "private config + state paths"
  if [ -r "$PRESSWARDEN_CONFIG_FILE" ]; then
    local mode
    mode=$(stat -c %a "$PRESSWARDEN_CONFIG_FILE" 2>/dev/null || stat -f %Lp "$PRESSWARDEN_CONFIG_FILE" 2>/dev/null || printf 'unknown')
    case "$mode" in 600|400) ok "CONFIG" "$PRESSWARDEN_CONFIG_FILE • mode $mode" ;; *) flag "CONFIG MODE" "$PRESSWARDEN_CONFIG_FILE • mode $mode (chmod 600 if it stores API keys)" ;; esac
  else
    printf '    %sℹ CONFIG%s  using built-in defaults; optional config: %s\n' "$C" "$X" "$PRESSWARDEN_CONFIG_FILE"
  fi
  printf '    %sℹ ROOT%s    %s\n' "$C" "$X" "$ROOT"
  printf '    %sℹ STATE%s   %s\n' "$C" "$X" "$PRESSWARDEN_STATE_DIR"
  printf '    %sℹ CACHE%s   %s\n' "$C" "$X" "$PRESSWARDEN_CACHE_DIR"

  sec "WordPress discovery" "validated installs, including nested WordPress"
  if [ "${#SCAN_ROOTS[@]}" -gt 0 ]; then
    ok "DISCOVERY" "${#SCAN_ROOTS[@]} WordPress install(s) • ${#DISCOVERED_DOMAINS[@]} site group(s)"
    if [ "${#SCAN_ROOTS[@]}" -le 10 ]; then
      local sr labels='' sl
      for sr in "${SCAN_ROOTS[@]}"; do sl=$(site_label_from_root "$sr"); [ -n "$labels" ] && labels="$labels, $sl" || labels="$sl"; done
      printf '    %sℹ SITES%s   %s\n' "$C" "$X" "$labels"
    fi
    [ "${#NESTED_SITES[@]}" -gt 0 ] && printf '    %sℹ NESTED%s  %s\n' "$C" "$X" "$(nested_sites_summary)"
  else
    flag "DISCOVERY" "no WordPress installs found below $ROOT"
  fi

  sec "Threat intelligence" "native knowledge base + local external-feed cache"
  local idir native_count campaign_count kev_count wf_scan_count wf_prod_count
  idir=$(pw_intel_state_dir)
  native_count=$(grep -cvE '^[[:space:]]*(#|$)' "$PRESSWARDEN_DIR/intel/native-rules.tsv" 2>/dev/null || true); native_count=${native_count:-0}
  campaign_count=$(grep -cvE '^[[:space:]]*(#|$)' "$PRESSWARDEN_DIR/intel/campaigns.tsv" 2>/dev/null || true); campaign_count=${campaign_count:-0}
  kev_count=$(_pw_intel_count_json "$idir/cisa-kev.json" cisa)
  wf_scan_count=$(_pw_intel_count_json "$idir/wordfence-scanner.json" wordfence)
  wf_prod_count=$(_pw_intel_count_json "$idir/wordfence-production.json" wordfence)
  [ "$native_count" -gt 0 ] && ok "NATIVE RULES" "$native_count rule ID(s) available" || flag "NATIVE RULES" "native rule catalog missing or empty"
  printf '    %sℹ CAMPAIGNS%s   %s documented campaign family reference(s)\n' "$C" "$X" "$campaign_count"
  if [ "$kev_count" -gt 0 ]; then ok "CISA KEV" "$kev_count record(s) cached • $(_pw_intel_age "$idir/cisa-kev.json")"; else printf '    %sℹ CISA KEV%s    not cached yet • run ./presswarden intel update\n' "$C" "$X"; fi
  if [ -n "${PRESSWARDEN_WORDFENCE_TOKEN:-}" ] || [ "$wf_scan_count" -gt 0 ] || [ "$wf_prod_count" -gt 0 ]; then
    if [ "$wf_scan_count" -gt 0 ]; then ok "WF SCANNER" "$wf_scan_count detection record(s) cached • $(_pw_intel_age "$idir/wordfence-scanner.json")"; else printf '    %sℹ WF SCANNER%s  not cached yet • run ./presswarden intel update\n' "$C" "$X"; fi
    if [ "$wf_prod_count" -gt 0 ]; then ok "WF PROD" "$wf_prod_count enrichment record(s) cached • $(_pw_intel_age "$idir/wordfence-production.json")"; else printf '    %sℹ WF PROD%s     not cached yet • detection can still use Scanner feed\n' "$C" "$X"; fi
  else
    printf '    %sℹ WORDFENCE%s   not configured (optional)\n' "$C" "$X"
  fi
  [ -n "${PRESSWARDEN_PATCHSTACK_KEY:-}" ] && ok "PATCHSTACK" "API key configured • lookups are deduplicated/cached" || printf '    %sℹ PATCHSTACK%s  not configured (optional)\n' "$C" "$X"
  if [ -n "${PRESSWARDEN_YARA_RULES:-}" ]; then
    if command -v yara >/dev/null 2>&1 && [ -r "$PRESSWARDEN_YARA_RULES" ] && [ -f "$PRESSWARDEN_YARA_RULES" ]; then
      ok "YARA" "external rules configured • $PRESSWARDEN_YARA_RULES"
    elif ! command -v yara >/dev/null 2>&1; then
      flag "YARA" "PRESSWARDEN_YARA_RULES is configured but yara is not installed"
    else
      flag "YARA" "configured external rules file is not readable: $PRESSWARDEN_YARA_RULES"
    fi
  else
    printf '    %sℹ YARA%s        not configured (optional external rules only)\n' "$C" "$X"
  fi
  printf '    %sℹ INTEL DIR%s   %s\n' "$C" "$X" "$idir"

  sec "Optional integrations" "tokens are never printed"
  [ -n "${WPSCAN_API_TOKEN:-}" ] && ok "WPScan" "configured" || printf '    %sℹ WPSCAN%s      not configured\n' "$C" "$X"
  [ -n "${HOSTINGER_API_TOKEN:-}" ] && ok "Hostinger" "configured for optional PHP-details enrichment" || printf '    %sℹ HOSTINGER%s   not configured (not required)\n' "$C" "$X"

  sec "Shell integrity" "all distributed shell scripts + no process substitution"
  local bad=0 f total=0
  local listf; listf=$(tmpf)
  find "$PRESSWARDEN_DIR" -type f \( -name '*.sh' -o -name 'presswarden' \) 2>/dev/null | sort > "$listf"
  while IFS= read -r f; do
    total=$((total+1)); bash -n "$f" >/dev/null 2>&1 || { flag "SYNTAX" "$f"; bad=$((bad+1)); }
  done < "$listf"
  rm -f "$listf"
  if grep -R -nE '<[[:space:]]*<\(|>[[:space:]]*>\(' "$PRESSWARDEN_DIR/checks" "$PRESSWARDEN_DIR/lib" "$PRESSWARDEN_DIR/suites" >/dev/null 2>&1; then
    flag "PORTABILITY" "process substitution found in runtime scanner code"; bad=$((bad+1))
  else
    ok "PORTABILITY" "runtime scanner code contains no process substitution (/dev/fd dependency)"
  fi
  [ "$bad" -eq 0 ] && ok "SYNTAX" "$total shell entrypoint(s) parsed successfully"

  finish
  [ "$missing" -eq 0 ] && [ "$bad" -eq 0 ]
}
main
