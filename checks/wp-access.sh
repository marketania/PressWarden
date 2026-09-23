#!/usr/bin/env bash
# wp-access — administrator and application-password inventory
NAME=wp-access; DESC="WordPress privileged access inventory"
SCAN_DOES="Lists administrator accounts with username/email and inventories administrator application passwords without enumerating ordinary site users."
SCAN_WHY="Admin/API access is a common persistence path after compromise; highlighting sites with multiple administrators makes unexpected privileged access easier to spot."
. "$(cd "$(dirname "$0")/.." && pwd)/lib/_lib.sh"

main() {
  require_wp; banner; discover_sites
  local s d out adminsf cache n uid login email appn apps any_apps=0 multi=0
  cache=$(tmpf); : > "$cache"

  sec "Administrator inventory" "green=one admin • yellow=multiple admins • username + email shown"
  for s in "${WP_SITES[@]}"; do
    d=$(site_domain "$s"); adminsf=$(tmpf); : > "$adminsf"
    out=$(wpq "$s" user list --role=administrator --fields=ID,user_login,user_email --format=csv 2>/dev/null || true)
    if ! printf '%s\n' "$out" | head -1 | grep -q '^ID,user_login,user_email'; then
      issue "$d" "administrator query failed"
      rm -f "$adminsf"
      continue
    fi
    printf '%s\n' "$out" | tail -n +2 > "$adminsf"
    n=$(grep -c . "$adminsf" 2>/dev/null); n=${n:-0}
    if [ "$n" -eq 0 ]; then
      issue "$d" "no administrator account returned"
      rm -f "$adminsf"
      continue
    fi

    if [ "$n" -eq 1 ]; then
      printf '    %s%s✓ ADMIN%s      %s%s%s  %s›%s  1 administrator\n' "$B" "$G" "$X" "$B$M" "$d" "$X" "$D" "$X"
    else
      multi=$((multi+1))
      printf '    %s%s⚠ MULTI-ADMIN%s %s%s%s  %s›%s  %s administrators — review access\n' "$B" "$Y" "$X" "$B$M" "$d" "$X" "$D" "$X" "$n"
    fi

    while IFS=, read -r uid login email; do
      [ -n "$uid" ] || continue
      printf '        %s•%s %-24s  <%s>\n' "$D" "$X" "$login" "$email"
      printf '%s\t%s\t%s\t%s\t%s\n' "$s" "$d" "$uid" "$login" "$email" >> "$cache"
    done < "$adminsf"
    rm -f "$adminsf"
  done
  [ "$multi" -gt 0 ] && note "$multi site(s) have more than one administrator; yellow is visibility/inventory and does not count as a security finding"

  sec "Administrator application passwords" "inventory only • password hashes/secrets are never displayed"
  while IFS=$'\t' read -r s d uid login email; do
    [ -n "$uid" ] || continue
    appn=$(wpq "$s" user application-password list "$uid" --format=count 2>/dev/null || true)
    case "$appn" in ''|*[!0-9]*) continue ;; esac
    [ "$appn" -gt 0 ] || continue
    any_apps=1
    printf '    %sℹ APP PASSWORD%s %s%s%s  %s›%s  %s <%s> • %s credential(s)\n' "$C" "$X" "$B$M" "$d" "$X" "$D" "$X" "$login" "$email" "$appn"
    apps=$(wpq "$s" user application-password list "$uid" --fields=name,created,last_used,last_ip --format=csv 2>/dev/null || true)
    printf '%s\n' "$apps" | sed 's/^/        /'
  done < "$cache"
  [ "$any_apps" -eq 1 ] || printf '    %s✓ CLEAN%s  no administrator application passwords reported\n' "$G" "$X"
  note "Application passwords can be legitimate integrations; review names, last-use times, and source IPs after a compromise."
  note "Non-admin capability enumeration is intentionally skipped for performance on sites with large user tables."

  rm -f "$cache"
  finish
}
run_logged wp-access
