#!/usr/bin/env bash
# wp-uploads — fast uploads audit: executable files + hidden-file anomalies.
NAME=wp-uploads; DESC="uploads executable/file-placement audit (fast)"
SCAN_DOES="Looks for executable scripts and suspicious hidden files inside WordPress media upload directories."
SCAN_WHY="Uploads should normally contain media, so executable code there is a high-signal location for webshells and malicious payloads."
. "$(cd "$(dirname "$0")/.." && pwd)/lib/_lib.sh"
main() {
  banner
  local L

  sec "Executable/script file types in uploads"
  L=$(tmpf)
  find "${SCAN_ROOTS[@]/%//wp-content/uploads}" -type f \
    \( -iname '*.php*' -o -iname '*.phtml' -o -iname '*.phar' \
       -o -iname '*.cgi' -o -iname '*.pl' -o -iname '*.py' -o -iname '*.sh' \) \
    2>/dev/null > "$L"
  report "$L" issue "no executable/script file types found in uploads"

  sec "Hidden files in uploads"
  L=$(tmpf)
  find "${SCAN_ROOTS[@]/%//wp-content/uploads}" -type f -name '.*' \
    ! -name '.htaccess' ! -name '.user.ini' 2>/dev/null > "$L"
  report "$L" review

  note "Upload .htaccess files are content-checked by htcheck; upload .user.ini files are content-checked by confcheck instead of being flagged merely for existing."
  note "Deep image-content inspection is available in ./presswarden full; PressWarden asks before running that slow scan."
  finish
}
run_logged wp-uploads
