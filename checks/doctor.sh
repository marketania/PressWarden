#!/usr/bin/env bash
NAME=doctor; DESC="installation/config/dependency/discovery preflight"
SCAN_DOES="Validates PressWarden, dependencies, config permissions, optional integrations, WordPress discovery, shell syntax, and restricted-hosting compatibility."
SCAN_WHY="Separates scanner/environment problems from real website findings before a security audit starts."
. "$(cd "$(dirname "$0")/.." && pwd)/lib/_lib.sh"
main() {
  banner
  sec "Runtime dependencies" "required and optional command availability"
  local c missing=0
  for c in bash php find grep sed awk sort stat cksum; do
    if command -v "$c" >/dev/null 2>&1; then ok "$c" "$(command -v "$c")"; else issue "$c" "required command not found"; missing=$((missing+1)); fi
  done
  for c in wp curl wget jq; do
    if command -v "$c" >/dev/null 2>&1; then ok "$c" "$(command -v "$c")"; else printf '    %sℹ OPTIONAL%s  %-8s not found\n' "$C" "$X" "$c"; fi
  done

  sec "Configuration" "private config + state paths"
  if [ -r "$PRESSWARDEN_CONFIG_FILE" ]; then
    local mode; mode=$(stat -c %a "$PRESSWARDEN_CONFIG_FILE" 2>/dev/null || printf 'unknown')
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
  # doctor can use process substitution locally, but distributed scanner checks intentionally avoid it on shared hosts.
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
