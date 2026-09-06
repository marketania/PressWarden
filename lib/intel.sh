#!/usr/bin/env bash
# Threat-intelligence cache/status helpers. Intended to be sourced by the CLI.

pw_intel_state_dir() {
  if [ -n "${PRESSWARDEN_INTEL_DIR:-}" ]; then
    printf '%s' "$PRESSWARDEN_INTEL_DIR"
  elif [ "${PRESSWARDEN_PORTABLE:-0}" = 1 ]; then
    printf '%s' "$PRESSWARDEN_DIR/var/intel"
  else
    printf '%s' "${PRESSWARDEN_STATE_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/presswarden}/intel"
  fi
}

_pw_intel_fetch() {
  local url="$1" out="$2" auth="${3:-}"
  if command -v curl >/dev/null 2>&1; then
    if [ -n "$auth" ]; then
      curl -fsSL --connect-timeout 10 --max-time 120 -A 'PressWarden/1.1 Threat Intelligence' -H "$auth" "$url" -o "$out"
    else
      curl -fsSL --connect-timeout 10 --max-time 120 -A 'PressWarden/1.1 Threat Intelligence' "$url" -o "$out"
    fi
    return $?
  fi
  if command -v wget >/dev/null 2>&1; then
    if [ -n "$auth" ]; then
      wget -q -T 120 --header="$auth" -O "$out" "$url"
    else
      wget -q -T 120 -O "$out" "$url"
    fi
    return $?
  fi
  printf 'PressWarden intel: curl or wget is required for updates.\n' >&2
  return 127
}

_pw_intel_json_valid() {
  local file="$1" kind="$2"
  command -v php >/dev/null 2>&1 || return 1
  case "$kind" in
    cisa)
      php -r '$j=json_decode((string)@file_get_contents($argv[1]),true);exit(is_array($j)&&isset($j["vulnerabilities"])&&is_array($j["vulnerabilities"])?0:1);' "$file" >/dev/null 2>&1
      ;;
    wordfence)
      php -r '$j=json_decode((string)@file_get_contents($argv[1]),true);if(!is_array($j)||count($j)<1)exit(1);foreach($j as $id=>$r){if(!is_array($r)||!isset($r["software"])||!is_array($r["software"]))continue;exit(0);}exit(1);' "$file" >/dev/null 2>&1
      ;;
    *) return 1 ;;
  esac
}

_pw_intel_count_json() {
  local file="$1" kind="$2"
  [ -s "$file" ] || { printf '0'; return; }
  case "$kind" in
    cisa) php -r '$j=json_decode((string)@file_get_contents($argv[1]),true);echo is_array($j["vulnerabilities"]??null)?count($j["vulnerabilities"]):0;' "$file" 2>/dev/null || printf '0' ;;
    wordfence) php -r '$j=json_decode((string)@file_get_contents($argv[1]),true);echo is_array($j)?count($j):0;' "$file" 2>/dev/null || printf '0' ;;
    *) printf '0' ;;
  esac
}

_pw_intel_age() {
  local file="$1" now mt age
  [ -e "$file" ] || { printf 'never'; return; }
  now=$(date +%s); mt=$(stat -c %Y "$file" 2>/dev/null || printf '0')
  case "$mt" in ''|*[!0-9]*) printf 'unknown'; return ;; esac
  age=$((now-mt))
  if [ "$age" -lt 120 ]; then printf '%ss ago' "$age"
  elif [ "$age" -lt 7200 ]; then printf '%sm ago' "$((age/60))"
  elif [ "$age" -lt 172800 ]; then printf '%sh ago' "$((age/3600))"
  else printf '%sd ago' "$((age/86400))"; fi
}

_pw_intel_update_wordfence_feed() {
  local label="$1" endpoint="$2" dest="$3" token="$4" tmp
  tmp="${dest}.tmp.$$"
  printf '  %-25s ' "$label"
  if _pw_intel_fetch "$endpoint" "$tmp" "Authorization: Bearer $token" && _pw_intel_json_valid "$tmp" wordfence; then
    mv -f "$tmp" "$dest"; chmod 600 "$dest" 2>/dev/null || true
    printf '✓ %s records\n' "$(_pw_intel_count_json "$dest" wordfence)"
    return 0
  fi
  rm -f "$tmp"
  printf '⚠ update failed; existing cache preserved\n'
  return 1
}

pw_intel_status() {
  local dir native campaigns cisa wfscan wfprod nc ncamp nkev nscan nprod
  dir=$(pw_intel_state_dir); native="$PRESSWARDEN_DIR/intel/native-rules.tsv"; campaigns="$PRESSWARDEN_DIR/intel/campaigns.tsv"
  cisa="$dir/cisa-kev.json"; wfscan="$dir/wordfence-scanner.json"; wfprod="$dir/wordfence-production.json"
  nc=$(grep -cvE '^[[:space:]]*(#|$)' "$native" 2>/dev/null || true); nc=${nc:-0}
  ncamp=$(grep -cvE '^[[:space:]]*(#|$)' "$campaigns" 2>/dev/null || true); ncamp=${ncamp:-0}
  nkev=$(_pw_intel_count_json "$cisa" cisa); nscan=$(_pw_intel_count_json "$wfscan" wordfence); nprod=$(_pw_intel_count_json "$wfprod" wordfence)
  printf 'PressWarden Threat Intelligence v%s\n\n' "${VERSION:-$(cat "$PRESSWARDEN_DIR/VERSION" 2>/dev/null)}"
  printf '  Native behavior rules   %s\n' "$nc"
  printf '  Campaign families       %s\n' "$ncamp"
  printf '  CISA KEV records        %s  (%s)\n' "$nkev" "$(_pw_intel_age "$cisa")"
  if [ -n "${PRESSWARDEN_WORDFENCE_TOKEN:-}" ] || [ -s "$wfscan" ] || [ -s "$wfprod" ]; then
    printf '  Wordfence Scanner       %s  (%s)\n' "$nscan" "$(_pw_intel_age "$wfscan")"
    printf '  Wordfence Production    %s  (%s)\n' "$nprod" "$(_pw_intel_age "$wfprod")"
  else
    printf '  Wordfence Intelligence  not configured\n'
  fi
  if [ -n "${PRESSWARDEN_PATCHSTACK_KEY:-}" ]; then printf '  Patchstack API          configured\n'; else printf '  Patchstack API          not configured\n'; fi
  if [ -n "${WPSCAN_API_TOKEN:-}" ]; then printf '  WPScan API              configured\n'; else printf '  WPScan API              not configured\n'; fi
  printf '\n  Intel directory         %s\n' "$dir"
  printf '\nUse: ./presswarden intel update\n'
}

pw_intel_update() {
  local dir tmp dest token failed=0 cisa_source=''
  dir=$(pw_intel_state_dir); mkdir -p "$dir" || return 2; chmod 700 "$dir" 2>/dev/null || true
  printf 'Updating PressWarden threat intelligence...\n\n'

  if [ "${PRESSWARDEN_INTEL_CISA:-1}" != "0" ]; then
    dest="$dir/cisa-kev.json"; tmp="$dir/.cisa-kev.$$.tmp"
    printf '  CISA KEV                  '
    if _pw_intel_fetch 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json' "$tmp" && _pw_intel_json_valid "$tmp" cisa; then
      cisa_source='cisa.gov'
    else
      rm -f "$tmp"; tmp="$dir/.cisa-kev.$$.tmp"
      if _pw_intel_fetch 'https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json' "$tmp" && _pw_intel_json_valid "$tmp" cisa; then cisa_source='CISA GitHub mirror'; fi
    fi
    if [ -n "$cisa_source" ]; then
      mv -f "$tmp" "$dest"; chmod 600 "$dest" 2>/dev/null || true
      printf '✓ %s records • %s\n' "$(_pw_intel_count_json "$dest" cisa)" "$cisa_source"
    else
      rm -f "$tmp"; printf '⚠ update failed from canonical feed and official GitHub mirror; existing cache preserved\n'; failed=$((failed+1))
    fi
  fi

  token="${PRESSWARDEN_WORDFENCE_TOKEN:-}"
  if [ -n "$token" ]; then
    _pw_intel_update_wordfence_feed 'Wordfence Scanner' 'https://www.wordfence.com/api/intelligence/v3/vulnerabilities/scanner' "$dir/wordfence-scanner.json" "$token" || failed=$((failed+1))
    _pw_intel_update_wordfence_feed 'Wordfence Production' 'https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production' "$dir/wordfence-production.json" "$token" || failed=$((failed+1))
  else
    printf '  Wordfence Intelligence    ↷ skipped (no PRESSWARDEN_WORDFENCE_TOKEN)\n'
  fi

  if [ -n "${PRESSWARDEN_PATCHSTACK_KEY:-}" ]; then
    printf '  Patchstack                 ✓ key configured; product lookups cache during FULL/intel scans\n'
  else
    printf '  Patchstack                 ↷ skipped (no PRESSWARDEN_PATCHSTACK_KEY)\n'
  fi

  printf '\n'; pw_intel_status
  [ "$failed" -eq 0 ]
}
