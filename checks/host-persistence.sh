#!/usr/bin/env bash
# host-persistence — account-level cron, shell startup and SSH persistence inventory
NAME=host-persistence; DESC="hosting-account persistence checks (cron, shell startup, SSH keys)"
SCAN_DOES="Inspects account cron jobs, shell startup files, and SSH-key inventory for persistence outside WordPress itself."
SCAN_WHY="An account-level backdoor can reinfect otherwise clean websites after WordPress files and databases have been repaired."
. "$(cd "$(dirname "$0")/.." && pwd)/lib/_lib.sh"

main() {
  banner
  local L CFILE f cronout keys

  sec "High-confidence suspicious cron persistence"
  CFILE=$(tmpf); L=$(tmpf); : > "$CFILE"
  crontab -l 2>/dev/null | grep -vE '^[[:space:]]*(#|$)' > "$CFILE" || true
  grep -Ei \
    '(curl|wget)[^#]*(\||&&|;)[^#]*(sh|bash|php|python|perl)|base64[^#]*(--decode|-d)[^#]*(sh|bash|php)|/tmp/[^ ]*\.(sh|php|pl|py)([ ;]|$)|php[^#]*wp-content/(uploads|cache)/' \
    "$CFILE" 2>/dev/null > "$L" || true
  report "$L" issue "no high-confidence suspicious cron persistence"

  sec "Network-fetching cron jobs" "review only; many can be legitimate"
  L=$(tmpf)
  grep -Ei '(curl|wget)[[:space:]].*https?://' "$CFILE" 2>/dev/null > "$L" || true
  report "$L" review "no network-fetching cron jobs"
  local cn; cn=$(grep -c . "$CFILE" 2>/dev/null); cn=${cn:-0}; note "account crontab contains $cn active job(s)"
  rm -f "$CFILE"

  sec "Shell startup persistence"
  L=$(tmpf)
  for f in "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.profile" "$HOME/.zshrc"; do
    [ -f "$f" ] || continue
    grep -HnEi '(curl|wget).*(\||&&|;).*(sh|bash|php|python|perl)|base64.*(--decode|-d)|source[[:space:]]+/tmp/|\.[[:space:]]+/tmp/' "$f" 2>/dev/null >> "$L" || true
  done
  report "$L" issue "no suspicious shell-startup persistence patterns"

  sec "SSH authorized key inventory" "fingerprints only; no key material displayed"
  if [ -s "$HOME/.ssh/authorized_keys" ]; then
    if command -v ssh-keygen >/dev/null 2>&1; then
      ssh-keygen -lf "$HOME/.ssh/authorized_keys" 2>/dev/null | sed 's/^/    ℹ SSH KEY   /'
    else
      keys=$(grep -cvE '^[[:space:]]*(#|$)' "$HOME/.ssh/authorized_keys" 2>/dev/null || echo 0)
      note "$keys authorized SSH key line(s); ssh-keygen unavailable for fingerprints"
    fi
  else
    printf '    %s✓ CLEAN%s  no authorized_keys file with keys found\n' "$G" "$X"
  fi
  note "SSH keys are inventory only; compare fingerprints with keys you recognize."

  finish
}
run_logged host-persistence
