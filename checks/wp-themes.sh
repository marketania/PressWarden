#!/usr/bin/env bash
# wp-themes — inactive theme hardening inventory
NAME=wp-themes; DESC="inactive theme inventory"
SCAN_DOES="Lists only inactive themes, using the human-readable theme title and installed version. Sites with no inactive themes stay quiet."
SCAN_WHY="Unused themes increase attack surface even when inactive; this keeps the report focused on cleanup candidates instead of repeating every healthy active theme."
. "$(cd "$(dirname "$0")/.." && pwd)/lib/_lib.sh"

main() {
  require_wp; banner; discover_sites
  local s d out status ver title n site_count=0 theme_count=0 inactivef

  sec "Inactive themes" "only sites with inactive themes are shown"

  for s in "${WP_SITES[@]}"; do
    d=$(site_domain "$s")
    out=$(wpq "$s" theme list --status=inactive --fields=status,version,title --format=csv --skip-update-check 2>/dev/null || true)
    if ! printf '%s\n' "$out" | head -1 | grep -q '^status,version,title'; then
      flag "$d" "theme inventory query failed"
      continue
    fi

    inactivef=$(tmpf); : > "$inactivef"
    while IFS=, read -r status ver title; do
      status=${status#\"}; status=${status%\"}
      ver=${ver#\"}; ver=${ver%\"}
      title=${title#\"}; title=${title%\"}
      [ "$status" = "inactive" ] || continue
      printf '%s|%s\n' "$title" "$ver" >> "$inactivef"
    done <<< "$(printf '%s\n' "$out" | tail -n +2)"

    n=$(grep -c . "$inactivef" 2>/dev/null); n=${n:-0}
    if [ "$n" -gt 0 ]; then
      site_count=$((site_count+1)); theme_count=$((theme_count+n))
      printf '    %s%s⚠ INACTIVE%s  %s%s%s  %s›%s  %s theme(s)\n' \
        "$B" "$Y" "$X" "$B$M" "$d" "$X" "$D" "$X" "$n"
      while IFS='|' read -r title ver; do
        [ -n "$title" ] || continue
        printf '        %s•%s %s%s%s' "$D" "$X" "$B" "$title" "$X"
        [ -n "$ver" ] && printf '  %sv%s%s' "$D" "$ver" "$X"
        printf '\n'
      done < "$inactivef"
    fi
    rm -f "$inactivef"
  done

  if [ "$site_count" -eq 0 ]; then
    printf '    %s✓ CLEAN%s  no inactive themes found\n' "$G" "$X"
  else
    printf '\n    %sℹ SUMMARY%s  %s inactive theme(s) across %s site(s)\n' "$C" "$X" "$theme_count" "$site_count"
  fi
  note "Inactive themes are cleanup/hardening candidates only; they do not count as compromise findings."
  finish
}
run_logged wp-themes
