#!/usr/bin/env bash
# filesystem-security-full — exhaustive recursive permission/symlink audit; FULL suite only
NAME=filesystem-security-full; DESC="FULL recursive filesystem permissions + symlink containment"
SCAN_DOES="Recursively checks every WordPress file and directory for world-writable permissions and unsafe symlink targets."
SCAN_WHY="The exhaustive pass finds deeply nested permission weaknesses that the targeted FAST scan intentionally skips."
. "$(cd "$(dirname "$0")/.." && pwd)/lib/_lib.sh"

main() {
  banner
  local L s f mode modes target owner CAND tmp failures label failed_n
  local tree_total tree_done percent world_failed=0 symlink_failed=0

  sec "World-writable files and directories" "FULL recursive scan • mode other-write bit set"
  L=$(tmpf); failures=$(tmpf); : > "$L"; : > "$failures"
  tree_total=${#TREE_ROOTS[@]}; tree_done=0
  pw_progress_init
  pw_progress_draw "World-writable: 0% | 0/$tree_total trees processed" 1
  for s in "${TREE_ROOTS[@]}"; do
    label=$(site_label_from_root "$s")
    percent=0; [ "$tree_total" -gt 0 ] && percent=$((tree_done*100/tree_total))
    pw_progress_draw "World-writable: $percent% | $tree_done/$tree_total trees processed | scanning $label" 1
    tmp=$(tmpf); : > "$tmp"
    if ! find "$s" -xdev \( -type f -o -type d \) -perm -0002 \
      -not -path '*/.private/*' -print > "$tmp" 2>/dev/null; then
      world_failed=1
      printf '%s\n' "$label" >> "$failures"
    fi
    cat "$tmp" >> "$L" || world_failed=1
    rm -f "$tmp"
    tree_done=$((tree_done+1)); percent=0
    [ "$tree_total" -gt 0 ] && percent=$((tree_done*100/tree_total))
  done
  if [ "$world_failed" -ne 0 ]; then
    pw_progress_draw "World-writable: INCOMPLETE | $tree_done/$tree_total trees attempted" 1
  else
    pw_progress_draw "World-writable: 100% | $tree_done/$tree_total trees processed" 1
  fi
  pw_progress_end
  sort -u "$L" -o "$L"
  if [ "$world_failed" -ne 0 ]; then
    PW_CHECK_INCOMPLETE=1
    if [ -s "$L" ]; then
      report "$L" issue "" noaction
    else
      rm -f "$L"
      printf '    %s⚠ INCOMPLETE%s  no world-writable items found in successfully traversed portions\n' "$Y" "$X"
    fi
    failed_n=$(sort -u "$failures" | grep -c . 2>/dev/null || true); failed_n=${failed_n:-0}
    printf '    Recursive permission traversal failed for %s WordPress tree(s); validated findings are retained.\n' "$failed_n"
  else
    report "$L" issue "no world-writable files/directories anywhere in WordPress trees" noaction
  fi
  rm -f "$failures"
  note "Permission findings are configuration posture only; PressWarden never offers generic delete/quarantine for them."

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
  report "$L" issue "no wp-config.php file is group/other writable" noaction
  printf '    %sℹ MODES%s  ' "$C" "$X"
  cut -d'|' -f1 "$modes" | sort | uniq -c | awk '{printf "%s=%s site(s)  ",$2,$1} END{print ""}'
  note "Mode inventory is informational; shared-host ownership models vary, so read-only differences are not auto-flagged."
  rm -f "$modes"

  sec "Symlinks escaping a WordPress site root" "FULL recursive scan"
  L=$(tmpf); failures=$(tmpf); : > "$L"; : > "$failures"
  tree_total=${#TREE_ROOTS[@]}; tree_done=0
  pw_progress_init
  pw_progress_draw "Symlinks: 0% | 0/$tree_total trees processed" 1
  for s in "${TREE_ROOTS[@]}"; do
    label=$(site_label_from_root "$s")
    percent=0; [ "$tree_total" -gt 0 ] && percent=$((tree_done*100/tree_total))
    pw_progress_draw "Symlinks: $percent% | $tree_done/$tree_total trees processed | scanning $label" 1
    CAND=$(tmpf); : > "$CAND"
    if ! find "$s" -xdev -type l -not -path '*/.private/*' -print > "$CAND" 2>/dev/null; then
      symlink_failed=1
      printf '%s\n' "$label" >> "$failures"
    fi
    while IFS= read -r f; do
      [ -n "$f" ] || continue
      target=$(readlink -f "$f" 2>/dev/null || true); [ -n "$target" ] || continue
      owner=$(_site_root_for_path "$f" 2>/dev/null || true); [ -n "$owner" ] || owner="$s"
      case "$target" in "$owner"|"$owner"/*) : ;; *) printf '%s -> %s\n' "$f" "$target" ;; esac
    done < "$CAND" >> "$L"
    rm -f "$CAND"
    tree_done=$((tree_done+1)); percent=0
    [ "$tree_total" -gt 0 ] && percent=$((tree_done*100/tree_total))
  done
  if [ "$symlink_failed" -ne 0 ]; then
    pw_progress_draw "Symlinks: INCOMPLETE | $tree_done/$tree_total trees attempted" 1
  else
    pw_progress_draw "Symlinks: 100% | $tree_done/$tree_total trees processed" 1
  fi
  pw_progress_end
  sort -u "$L" -o "$L"
  if [ "$symlink_failed" -ne 0 ]; then
    PW_CHECK_INCOMPLETE=1
    if [ -s "$L" ]; then
      report "$L" review "" noaction
    else
      rm -f "$L"
      printf '    %s⚠ INCOMPLETE%s  no escaping symlinks found in successfully traversed portions\n' "$Y" "$X"
    fi
    failed_n=$(sort -u "$failures" | grep -c . 2>/dev/null || true); failed_n=${failed_n:-0}
    printf '    Recursive symlink traversal failed for %s WordPress tree(s); validated findings are retained.\n' "$failed_n"
  else
    report "$L" review "no symlink escapes detected anywhere in WordPress trees" noaction
  fi
  rm -f "$failures"

  finish
}
run_logged filesystem-security-full
