#!/usr/bin/env bash
NAME=php-runtime; DESC='inert PHP auto-load and request-time configuration persistence indicators'
SCAN_DOES='Inspects local PHP and .htaccess auto-load directives as text. It does not execute configuration, contact a hosting API, or modify web settings.'
SCAN_WHY='Malicious auto_prepend_file/auto_append_file and enabled remote includes can persist across WordPress repairs. CLI PHP settings do not establish the web runtime state.'
. "$(cd "$(dirname "$0")/.." && pwd)/lib/_lib.sh"
main() {
  banner
  sec 'PHP persistence configuration' 'text evidence; no WordPress bootstrap'
  local paths findings errors rc
  paths=$(tmpf); findings=$(tmpf); errors=$(tmpf)
  for root in "${TREE_ROOTS[@]}"; do
    if ! find "$root" -type f \( -name '.user.ini' -o -name 'php.ini' -o -name '.htaccess' \) -not -path '*/.private/*' -print0 >> "$paths" 2>> "$errors"; then
      PW_CHECK_INCOMPLETE=1; printf 'INCOMPLETE: configuration discovery failed.\n' >&2
    fi
  done
  rc=0
  php "$PRESSWARDEN_DIR/lib/runtime-evidence.php" < "$paths" > "$findings" 2>> "$errors" || rc=$?
  if [ "$rc" -ne 0 ]; then PW_CHECK_INCOMPLETE=1; printf 'INCOMPLETE: unreadable, linked, or oversized PHP configuration evidence.\n' >&2; fi
  report "$findings" review 'no auto-load/remote-include directives matched in inspected configuration' noaction
  note 'An auto-load directive may be legitimate, including a WAF. Verify the referenced file and provenance; a match alone is not proof of malware.'
  note 'Web-effective PHP configuration remains unknown. For current/recommended configuration and provider details use PressHarden.'
  rm -f "$paths" "$errors"
  finish
}
run_logged php-runtime
