#!/usr/bin/env bash
# filesystem-security — FAST targeted permission/symlink posture for high-risk locations
NAME=filesystem-security; DESC="targeted filesystem permissions + symlink containment"
SCAN_DOES="Checks permissions and symlink containment only in high-risk WordPress paths for a fast daily security assessment."
SCAN_WHY="World-writable critical files or escaping symlinks can let another process or compromised site modify WordPress code."
. "$(cd "$(dirname "$0")/.." && pwd)/lib/_lib.sh"

main() {
  banner
  local L s f mode modes target owner d

  sec "World-writable high-risk paths" "FAST targeted scan • exhaustive recursion is FULL-only"
  L=$(tmpf); : > "$L"
  for s in "${SCAN_ROOTS[@]}"; do
    # Document-root objects and critical WordPress roots/files.
    find "$s" -xdev -mindepth 0 -maxdepth 1 \( -type f -o -type d \) -perm -0002 \
      -not -name '.private' -print 2>/dev/null >> "$L"

    for f in \
      "$s/wp-config.php" "$s/.htaccess" "$s/wp-load.php" "$s/wp-settings.php" \
      "$s/wp-login.php" "$s/wp-admin" "$s/wp-includes" "$s/wp-content" \
      "$s/wp-content/plugins" "$s/wp-content/themes" "$s/wp-content/uploads" \
      "$s/wp-content/mu-plugins"; do
      [ -e "$f" ] || continue
      find "$f" -xdev -mindepth 0 -maxdepth 0 \( -type f -o -type d \) -perm -0002 -print 2>/dev/null >> "$L"
    done

    # Plugin/theme roots and their immediate files are execution-sensitive but cheap to inspect.
    for d in "$s/wp-content/plugins" "$s/wp-content/themes" "$s/wp-content/mu-plugins"; do
      [ -d "$d" ] || continue
      find "$d" -xdev -mindepth 1 -maxdepth 2 \( -type f -o -type d \) -perm -0002 -print 2>/dev/null >> "$L"
    done

    # For uploads, directory writability matters more than every individual media file in FAST mode.
    d="$s/wp-content/uploads"
    [ -d "$d" ] && find "$d" -xdev -mindepth 1 -maxdepth 2 -type d -perm -0002 -print 2>/dev/null >> "$L"
  done
  sort -u "$L" -o "$L"
  report "$L" issue "no world-writable high-risk paths"
  note "FAST checks root/critical files, plugin/theme/MU roots (depth 2), and upload directories (depth 2)."
  note "./presswarden full uses filesystem-security-full for exhaustive recursive permission coverage."

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

  sec "Escaping symlinks in high-risk paths" "FAST targeted scan • exhaustive scan is FULL-only"
  L=$(tmpf); : > "$L"
  for s in "${SCAN_ROOTS[@]}"; do
    # Root plus shallow wp-content areas only in FAST mode.
    find "$s" -xdev -maxdepth 2 -type l -not -path '*/.private/*' -print 2>/dev/null >> "$L.candidates"
    for d in "$s/wp-content/plugins" "$s/wp-content/themes" "$s/wp-content/mu-plugins" "$s/wp-content/uploads"; do
      [ -d "$d" ] || continue
      find "$d" -xdev -maxdepth 2 -type l -not -path '*/.private/*' -print 2>/dev/null >> "$L.candidates"
    done
    if [ -f "$L.candidates" ]; then
      while IFS= read -r f; do
        [ -n "$f" ] || continue
        target=$(readlink -f "$f" 2>/dev/null || true); [ -n "$target" ] || continue
        case "$target" in "$s"|"$s"/*) : ;; *) printf '%s -> %s\n' "$f" "$target" >> "$L" ;; esac
      done < "$L.candidates"
      : > "$L.candidates"
    fi
  done
  rm -f "$L.candidates"
  sort -u "$L" -o "$L"
  report "$L" review "no escaping symlinks in targeted high-risk paths"

  finish
}
run_logged filesystem-security
