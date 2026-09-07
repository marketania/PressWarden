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

_pw_intel_user_agent() {
  local v="${VERSION:-}"
  [ -n "$v" ] || v=$(tr -d '[:space:]' < "$PRESSWARDEN_DIR/VERSION" 2>/dev/null || true)
  [ -n "$v" ] || v='unknown'
  printf 'PressWarden/%s Threat Intelligence' "$v"
}

_pw_intel_curl_escape() {
  local v="$1"
  v=${v//\\/\\\\}
  v=${v//\"/\\\"}
  printf '%s' "$v"
}

_pw_intel_fetch_php_auth() {
  local url="$1" out="$2" auth="$3" ua
  command -v php >/dev/null 2>&1 || return 127
  ua=$(_pw_intel_user_agent)
  printf '%s' "$auth" | php -r '
    $auth=trim(stream_get_contents(STDIN)); $url=$argv[1]; $out=$argv[2]; $ua=$argv[3];
    $ctx=stream_context_create(["http"=>[
      "method"=>"GET", "timeout"=>120, "ignore_errors"=>true,
      "header"=>$auth."\r\nUser-Agent: ".$ua."\r\n"
    ]]);
    $data=@file_get_contents($url,false,$ctx); if($data===false) exit(2);
    $status=0; foreach((array)($http_response_header??[]) as $h){if(preg_match("~^HTTP/\\S+\\s+(\\d{3})~i",$h,$m))$status=(int)$m[1];}
    if($status<200||$status>=300) exit(3);
    exit(@file_put_contents($out,$data)===false?4:0);
  ' "$url" "$out" "$ua"
}

_pw_intel_fetch() {
  local url="$1" out="$2" auth="${3:-}" escaped ua
  ua=$(_pw_intel_user_agent)
  if command -v curl >/dev/null 2>&1; then
    if [ -n "$auth" ]; then
      escaped=$(_pw_intel_curl_escape "$auth")
      printf 'header = "%s"\n' "$escaped" | \
        curl -fsSL --config - --connect-timeout 10 --max-time 120 \
          -A "$ua" "$url" -o "$out"
    else
      curl -fsSL --connect-timeout 10 --max-time 120 \
        -A "$ua" "$url" -o "$out"
    fi
    return $?
  fi
  if [ -n "$auth" ]; then
    _pw_intel_fetch_php_auth "$url" "$out" "$auth"
    return $?
  fi
  if command -v wget >/dev/null 2>&1; then
    wget -q -T 120 --user-agent="$ua" -O "$out" "$url"
    return $?
  fi
  printf 'PressWarden intel: curl or wget is required for public feeds; authenticated feeds can also use PHP HTTPS streams.\n' >&2
  return 127
}

_pw_intel_json_valid() {
  local file="$1" kind="$2" count
  command -v php >/dev/null 2>&1 || return 1
  case "$kind" in
    cisa)
      php -r '$j=json_decode((string)@file_get_contents($argv[1]),true);exit(is_array($j)&&isset($j["vulnerabilities"])&&is_array($j["vulnerabilities"])?0:1);' "$file" >/dev/null 2>&1
      ;;
    wordfence)
      count=$(php "$PRESSWARDEN_DIR/lib/json-object-stream.php" validate-wordfence "$file" 2>/dev/null) || return 1
      case "$count" in ''|*[!0-9]*) return 1 ;; esac
      [ "$count" -gt 0 ] || return 1
      printf '%s\n' "$count" > "${file}.count"
      chmod 600 "${file}.count" 2>/dev/null || true
      ;;
    *) return 1 ;;
  esac
}

_pw_intel_count_json() {
  local file="$1" kind="$2" countf count
  [ -s "$file" ] || { printf '0'; return; }
  case "$kind" in
    cisa) php -r '$j=json_decode((string)@file_get_contents($argv[1]),true);echo is_array($j["vulnerabilities"]??null)?count($j["vulnerabilities"]):0;' "$file" 2>/dev/null || printf '0' ;;
    wordfence)
      countf="${file}.count"
      if [ -s "$countf" ]; then
        count=$(head -n 1 "$countf" 2>/dev/null || true)
        case "$count" in ''|*[!0-9]*) printf '0' ;; *) printf '%s' "$count" ;; esac
      else
        # Do not parse a potentially 100+ MB feed merely to render status.
        # Running `intel update` validates it once and writes this sidecar.
        printf '0'
      fi
      ;;
    *) printf '0' ;;
  esac
}

_pw_intel_age() {
  local file="$1" now mt age
  [ -e "$file" ] || { printf 'never'; return; }
  now=$(date +%s)
  # GNU/Linux uses `stat -c`; BSD/macOS uses `stat -f`.
  mt=$(stat -c %Y "$file" 2>/dev/null || stat -f %m "$file" 2>/dev/null || printf '0')
  case "$mt" in ''|*[!0-9]*) printf 'unknown'; return ;; esac
  age=$((now-mt))
  [ "$age" -lt 0 ] && { printf 'just now'; return; }
  if [ "$age" -lt 120 ]; then printf '%ss ago' "$age"
  elif [ "$age" -lt 7200 ]; then printf '%sm ago' "$((age/60))"
  elif [ "$age" -lt 172800 ]; then printf '%sh ago' "$((age/3600))"
  else printf '%sd ago' "$((age/86400))"; fi
}

_pw_intel_update_wordfence_feed() {
  local label="$1" endpoint="$2" dest="$3" token="$4" tmp count
  tmp="${dest}.tmp.$$"
  printf '  %-25s ' "$label"
  if _pw_intel_fetch "$endpoint" "$tmp" "Authorization: Bearer $token" && _pw_intel_json_valid "$tmp" wordfence; then
    count=$(head -n 1 "${tmp}.count" 2>/dev/null || printf '0')
    mv -f "$tmp" "$dest"
    mv -f "${tmp}.count" "${dest}.count" 2>/dev/null || true
    chmod 600 "$dest" "${dest}.count" 2>/dev/null || true
    printf '✓ %s records\n' "$count"
    return 0
  fi
  rm -f "$tmp" "${tmp}.count"
  printf '⚠ update failed; existing cache preserved\n'
  return 1
}

pw_intel_status() {
  local dir native campaigns cisa wfscan wfprod ntotal nbehavior ncamp nkev nscan nprod
  dir=$(pw_intel_state_dir); native="$PRESSWARDEN_DIR/intel/native-rules.tsv"; campaigns="$PRESSWARDEN_DIR/intel/campaigns.tsv"
  cisa="$dir/cisa-kev.json"; wfscan="$dir/wordfence-scanner.json"; wfprod="$dir/wordfence-production.json"
  ntotal=$(grep -cvE '^[[:space:]]*(#|$)' "$native" 2>/dev/null || true); ntotal=${ntotal:-0}
  nbehavior=$(awk -F'\t' '$0 !~ /^[[:space:]]*(#|$)/ && $5=="behavior"{n++} END{print n+0}' "$native" 2>/dev/null || printf '0')
  ncamp=$(grep -cvE '^[[:space:]]*(#|$)' "$campaigns" 2>/dev/null || true); ncamp=${ncamp:-0}
  nkev=$(_pw_intel_count_json "$cisa" cisa); nscan=$(_pw_intel_count_json "$wfscan" wordfence); nprod=$(_pw_intel_count_json "$wfprod" wordfence)
  printf 'PressWarden Threat Intelligence v%s\n\n' "${VERSION:-$(cat "$PRESSWARDEN_DIR/VERSION" 2>/dev/null)}"
  printf '  Native behavior rules   %s\n' "$nbehavior"
  printf '  Campaign families       %s\n' "$ncamp"
  printf '  Native rule IDs         %s total\n' "$ntotal"
  printf '  CISA KEV records        %s  (%s)\n' "$nkev" "$(_pw_intel_age "$cisa")"
  if [ -n "${PRESSWARDEN_WORDFENCE_TOKEN:-}" ] || [ -s "$wfscan" ] || [ -s "$wfprod" ]; then
    printf '  Wordfence Scanner       %s  (%s)\n' "$nscan" "$(_pw_intel_age "$wfscan")"
    printf '  Wordfence Production    %s  (%s)\n' "$nprod" "$(_pw_intel_age "$wfprod")"
    if { [ -s "$wfscan" ] && [ ! -s "${wfscan}.count" ]; } || { [ -s "$wfprod" ] && [ ! -s "${wfprod}.count" ]; }; then
      printf '  Wordfence counts        refresh with ./presswarden intel update to build streaming count metadata\n'
    fi
  else
    printf '  Wordfence Intelligence  not configured\n'
  fi
  if [ -n "${PRESSWARDEN_PATCHSTACK_KEY:-}" ]; then printf '  Patchstack API          configured\n'; else printf '  Patchstack API          not configured\n'; fi
  if [ -n "${WPSCAN_API_TOKEN:-}" ]; then printf '  WPScan API              configured\n'; else printf '  WPScan API              not configured\n'; fi
  if [ -n "${PRESSWARDEN_YARA_RULES:-}" ]; then
    if command -v yara >/dev/null 2>&1 && [ -r "$PRESSWARDEN_YARA_RULES" ] && [ -f "$PRESSWARDEN_YARA_RULES" ]; then
      printf '  External YARA rules     configured / ready\n'
    elif command -v yara >/dev/null 2>&1; then
      printf '  External YARA rules     configured / rules unreadable\n'
    else
      printf '  External YARA rules     configured / yara unavailable\n'
    fi
  else
    printf '  External YARA rules     not configured\n'
  fi
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
