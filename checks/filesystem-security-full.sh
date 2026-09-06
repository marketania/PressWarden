#!/usr/bin/env bash
# filesystem-security-full — exhaustive recursive permission/symlink audit; FULL suite only
NAME=filesystem-security-full; DESC="FULL recursive filesystem permissions + symlink containment"
SCAN_DOES="Recursively checks every WordPress file and directory for world-writable permissions and unsafe symlink targets."
SCAN_WHY="The exhaustive pass finds deeply nested permission weaknesses that the targeted FAST scan intentionally skips."
. "$(cd "$(dirname "$0")/.." && pwd)/lib/_lib.sh"

main() {
  banner
  local L s f mode modes target owner

  sec "World-writable files and directories" "FULL recursive scan • mode other-write bit set"
  L=$(tmpf)
  for s in "${TREE_ROOTS[@]}"; do
    find "$s" -xdev \( -type f -o -type d \) -perm -0002 \
      -not -path '*/.private/*' -print 2>/dev/null >> "$L"
  done
  sort -u "$L" -o "$L"
  report "$L" issue "no world-writable files/directories anywhere in WordPress trees"

  sec "wp-config.php permission posture" "inventory; group/other WRITE is an alert"
  L=$(tmpf); modes=$(tmpf); : > "$L"; : > "$modes"
  for s in "${SCAN_ROOTS[@]}"; do
    f="$s/wp-config.php"; [ -f "$f" ] || continue
    mode=$(stat -c '%a' "$f" 2>/dev/null || echo unknown)
    printf '%s|%s\n' "$mode" "$(site_domain "$s")" >> "$modes"
    case "$mode" in
      *[2367][0-7]|*[0-7][2367]) printf '%s mode=%s (group/other writable)\n' "$f" "$mode" >> "$L" ;;
    esac
  done
  report "$L" issue "no wp-config.php file is group/other writable"
  printf '    %sℹ MODES%s  ' "$C" "$X"
  cut -d'|' -f1 "$modes" | sort | uniq -c | awk '{printf "%s=%s site(s)  ",$2,$1} END{print ""}'
  note "Mode inventory is informational; shared-host ownership models vary, so read-only differences are not auto-flagged."
  rm -f "$modes"

  sec "Symlinks escaping a WordPress site root" "FULL recursive scan"
  L=$(tmpf)
  for s in "${TREE_ROOTS[@]}"; do
    CAND=$(tmpf)
    find "$s" -xdev -type l -not -path '*/.private/*' -print 2>/dev/null > "$CAND"
    while IFS= read -r f; do
      [ -n "$f" ] || continue
      target=$(readlink -f "$f" 2>/dev/null || true); [ -n "$target" ] || continue
      owner=$(_site_root_for_path "$f" 2>/dev/null || true); [ -n "$owner" ] || owner="$s"
      case "$target" in "$owner"|"$owner"/*) : ;; *) printf '%s -> %s\n' "$f" "$target" ;; esac
    done < "$CAND" >> "$L"
    rm -f "$CAND"
  done
  sort -u "$L" -o "$L"
  report "$L" review "no symlink escapes detected anywhere in WordPress trees"

  finish
}
run_logged filesystem-security-full
