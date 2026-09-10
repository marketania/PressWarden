# PressWarden environment, UI primitives, host-agnostic discovery, and discovery cache.
set -uo pipefail

PRESSWARDEN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PRESSWARDEN_PORTABLE="${PRESSWARDEN_PORTABLE:-0}"
[ -f "$PRESSWARDEN_DIR/.presswarden-portable" ] && PRESSWARDEN_PORTABLE=1
if [ "$PRESSWARDEN_PORTABLE" = 1 ]; then
  PRESSWARDEN_CONFIG_FILE="${PRESSWARDEN_CONFIG_FILE:-$PRESSWARDEN_DIR/config/config}"
else
  PRESSWARDEN_CONFIG_FILE="${PRESSWARDEN_CONFIG_FILE:-${XDG_CONFIG_HOME:-$HOME/.config}/presswarden/config}"
fi
PRESSWARDEN_CONFIG_LOADED=0
_presswarden_env_overrides=$(env | grep -E '^(PRESSWARDEN_[A-Za-z0-9_]*|WPSCAN_API_TOKEN|HOSTINGER_API_TOKEN)=' || true)
if [ -r "$PRESSWARDEN_CONFIG_FILE" ]; then
  _presswarden_cfg_mode=$(stat -c %a "$PRESSWARDEN_CONFIG_FILE" 2>/dev/null || printf '')
  case "$_presswarden_cfg_mode" in
    600|400|'') : ;;
    *) printf 'PressWarden warning: config %s has mode %s; use chmod 600 when it contains API keys.\n' "$PRESSWARDEN_CONFIG_FILE" "$_presswarden_cfg_mode" >&2 ;;
  esac
  # shellcheck disable=SC1090
  . "$PRESSWARDEN_CONFIG_FILE"
  PRESSWARDEN_CONFIG_LOADED=1
  unset _presswarden_cfg_mode
fi
if [ -n "$_presswarden_env_overrides" ]; then
  while IFS='=' read -r _presswarden_k _presswarden_v; do
    case "$_presswarden_k" in PRESSWARDEN_*|WPSCAN_API_TOKEN|HOSTINGER_API_TOKEN) printf -v "$_presswarden_k" '%s' "$_presswarden_v"; export "$_presswarden_k" ;; esac
  done <<< "$_presswarden_env_overrides"
fi
unset _presswarden_env_overrides _presswarden_k _presswarden_v 2>/dev/null || true
export PRESSWARDEN_PORTABLE

if [ -n "${ROOT:-}" ]; then
  :
elif [ -n "${PRESSWARDEN_SCAN_ROOT:-}" ]; then
  ROOT="$PRESSWARDEN_SCAN_ROOT"
elif [ "$PRESSWARDEN_PORTABLE" = 1 ]; then
  _presswarden_parent=$(cd "$PRESSWARDEN_DIR/.." 2>/dev/null && pwd -P || dirname "$PRESSWARDEN_DIR")
  if [ -d "$_presswarden_parent/domains" ]; then ROOT="$_presswarden_parent/domains"
  elif [ -d "$_presswarden_parent/public_html" ]; then ROOT="$_presswarden_parent/public_html"
  else ROOT="$_presswarden_parent"
  fi
  unset _presswarden_parent
else
  ROOT="$PWD"
fi

if [ "$PRESSWARDEN_PORTABLE" = 1 ]; then
  PRESSWARDEN_STATE_DIR="${PRESSWARDEN_STATE_DIR:-$PRESSWARDEN_DIR/var}"
  PRESSWARDEN_CACHE_DIR="${PRESSWARDEN_CACHE_DIR:-$PRESSWARDEN_DIR/var/cache}"
else
  PRESSWARDEN_STATE_DIR="${PRESSWARDEN_STATE_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/presswarden}"
  PRESSWARDEN_CACHE_DIR="${PRESSWARDEN_CACHE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/presswarden}"
fi
REPORTS="${REPORTS:-$PRESSWARDEN_STATE_DIR/reports}"
PRESSWARDEN_VERSION="$(cat "$PRESSWARDEN_DIR/VERSION" 2>/dev/null || printf '1.0.4')"
PRESSWARDEN_MAX="${PRESSWARDEN_MAX:-60}"
PRESSWARDEN_INTERACTIVE="${PRESSWARDEN_INTERACTIVE:-1}"
QUARANTINE="${QUARANTINE:-$PRESSWARDEN_STATE_DIR/quarantine}"
PRESSWARDEN_EXCLUDE="${PRESSWARDEN_EXCLUDE:-${PRESSWARDEN_EXCLUDE_DOMAINS:-}}"
# New report directories are private; never chmod existing directories or
# change the caller's umask (which could affect WordPress repair semantics).
(umask 077; mkdir -p "$REPORTS") 2>/dev/null || true
mkdir -p "$PRESSWARDEN_CACHE_DIR" "$QUARANTINE" 2>/dev/null || true
export LC_ALL=C

if { [ -n "${PRESSWARDEN_FORCE_COLOR:-}" ] || [ -t 1 ] || [ -t 2 ]; } && [ -z "${PRESSWARDEN_NOCOLOR:-}" ] && [ "${TERM:-dumb}" != dumb ]; then
  B=$'\033[1m'; D=$'\033[2m'; U=$'\033[4m'; R=$'\033[31m'; G=$'\033[32m'; Y=$'\033[33m'; BL=$'\033[34m'; M=$'\033[35m'; C=$'\033[36m'; WHT=$'\033[37m'; X=$'\033[0m'
else
  B=''; D=''; U=''; R=''; G=''; Y=''; BL=''; M=''; C=''; WHT=''; X=''
fi
_cols=$(tput cols 2>/dev/null || printf '92'); case "$_cols" in ''|*[!0-9]*) _cols=92 ;; esac; [ "$_cols" -lt 68 ] && _cols=68; [ "$_cols" -gt 108 ] && _cols=108; W=$_cols; unset _cols
TOTAL=0; ALERTS=0; REVIEWS=0; DELETED=0; PROTECTED_SKIPPED=0; SECN=0; T0=$(date +%s); SEC_T0=$T0
NAME="${NAME:-check}"; DESC="${DESC:-}"; CURRENT_SECTION=""; SCAN_DOES="${SCAN_DOES:-}"; SCAN_WHY="${SCAN_WHY:-}"

_repeat() { local ch="$1" n="$2" i; for ((i=0; i<n; i++)); do printf '%s' "$ch"; done; }
_rule() { printf '%s' "$D"; _repeat '─' "$W"; printf '%s\n' "$X"; }
human_time() { local s="${1:-0}" m h; h=$((s/3600)); m=$(((s%3600)/60)); s=$((s%60)); if [ "$h" -gt 0 ]; then printf '%dh %02dm %02ds' "$h" "$m" "$s"; elif [ "$m" -gt 0 ]; then printf '%dm %02ds' "$m" "$s"; else printf '%ss' "$s"; fi; }
human_bytes() { local b="${1:-0}"; case "$b" in ''|*[!0-9]*) printf 'n/a'; return ;; esac; if [ "$b" -ge 1073741824 ]; then awk -v b="$b" 'BEGIN{printf "%.2f GB", b/1073741824}'; elif [ "$b" -ge 1048576 ]; then awk -v b="$b" 'BEGIN{printf "%.2f MB", b/1048576}'; elif [ "$b" -ge 1024 ]; then awk -v b="$b" 'BEGIN{printf "%.2f KB", b/1024}'; else printf '%s B' "$b"; fi; }
die() { printf '%s%s✖ ERROR%s  %s\n' "$B" "$R" "$X" "$1" >&2; exit 2; }
tmpf() { mktemp "${TMPDIR:-/tmp}/presswarden.XXXXXX" 2>/dev/null || die "cannot create temp file"; }

SCAN_ROOTS=(); TREE_ROOTS=(); IGNORED_DOMAINS=(); MANUAL_EXCLUDED_DOMAINS=(); MANUAL_EXCLUDED_ROOTS=(); DISCOVERED_DOMAINS=(); NESTED_SITES=()
PRESSWARDEN_DISCOVERY_DEPTH="${PRESSWARDEN_DISCOVERY_DEPTH:-${PRESSWARDEN_WP_DISCOVERY_DEPTH:-8}}"
_is_wordpress_root() { local p="$1"; [ -d "$p" ] || return 1; [ -f "$p/wp-includes/version.php" ] || return 1; [ -f "$p/wp-settings.php" ] || return 1; [ -f "$p/wp-load.php" ] || return 1; [ -d "$p/wp-admin" ] || return 1; [ -d "$p/wp-content" ] || return 1; grep -qE '\$wp_version[[:space:]]*=' "$p/wp-includes/version.php" 2>/dev/null || return 1; }
_rel_from_root() { local p="$1"; if [ "$p" = "$ROOT" ]; then printf ''; else printf '%s' "${p#"$ROOT"/}"; fi; }
site_label_from_root() {
  local p="$1" rel before after base; rel=$(_rel_from_root "$p")
  if [ -z "$rel" ]; then base=$(basename "$ROOT"); case "$base" in public_html|htdocs|httpdocs|www|html) basename "$(dirname "$ROOT")" ;; *) printf '%s' "$base" ;; esac; return; fi
  case "$rel" in
    */public_html) printf '%s' "${rel%/public_html}" ;;
    */public_html/*) before=${rel%%/public_html/*}; after=${rel#*/public_html/}; printf '%s/%s' "$before" "$after" ;;
    public_html) basename "$ROOT" ;;
    public_html/*) printf '%s' "${rel#public_html/}" ;;
    *) printf '%s' "$rel" ;;
  esac
}
site_domain_from_root() { local label; label=$(site_label_from_root "$1"); printf '%s' "${label%%/*}"; }
_is_excluded_site() { local p="$1" label group x;
  # Preserve exclusions resolved under the fleet root when a name narrows ROOT.
  while IFS= read -r x; do [ -n "$x" ] || continue; case "$p" in "$x"|"$x"/*) return 0 ;; esac; done <<< "${_PW_TARGET_EXCLUSIONS:-}"
  label=$(site_label_from_root "$p"); group=${label%%/*}; for x in $PRESSWARDEN_EXCLUDE; do [ "$x" = "$label" ] || [ "$x" = "$group" ] || [ "$x" = "$p" ] || continue; return 0; done; return 1; }
_array_has() { local needle="$1"; shift; local x; for x in "$@"; do [ "$x" = "$needle" ] && return 0; done; return 1; }

_refresh_scan_roots_uncached() {
  local candf rootsf f p label group parent nested depth
  PW_DISCOVERY_FAILED=0
  SCAN_ROOTS=(); TREE_ROOTS=(); IGNORED_DOMAINS=(); MANUAL_EXCLUDED_DOMAINS=(); MANUAL_EXCLUDED_ROOTS=(); DISCOVERED_DOMAINS=(); NESTED_SITES=()
  [ -d "$ROOT" ] || die "scan root does not exist: $ROOT"
  depth="$PRESSWARDEN_DISCOVERY_DEPTH"; case "$depth" in ''|*[!0-9]*) depth=8 ;; esac; [ "$depth" -ge 1 ] || depth=8
  rootsf=$(tmpf); candf=$(tmpf); : > "$rootsf"; : > "$candf"
  if _is_wordpress_root "$ROOT"; then printf '%s\0' "$ROOT" >> "$candf"; fi
  if ! find "$ROOT" -mindepth 1 -maxdepth "$depth" \
    \( -type d \( -name wp-admin -o -name wp-includes -o -name wp-content -o -name vendor -o -name node_modules -o -name .git -o -name .svn -o -name .hg -o -name cache -o -name caches -o -name uploads -o -name backups -o -name backup -o -name logs -o -name tmp -o -name .cache -o -name .local -o -name .npm -o -name .composer \) -prune \) -o \
    \( -type f -name 'wp-settings.php' -print0 \) 2>/dev/null >> "$candf"; then PW_DISCOVERY_FAILED=1; fi
  while IFS= read -r -d '' f; do
    case "$f" in *[[:cntrl:]]*) PW_DISCOVERY_FAILED=1; continue ;; esac
    [ -n "$f" ] || continue; case "$f" in */wp-settings.php) p=${f%/wp-settings.php} ;; *) p="$f" ;; esac; _is_wordpress_root "$p" || continue
    if _is_excluded_site "$p"; then label=$(site_label_from_root "$p"); _array_has "$label" "${MANUAL_EXCLUDED_DOMAINS[@]}" || MANUAL_EXCLUDED_DOMAINS+=("$label"); MANUAL_EXCLUDED_ROOTS+=("$p"); else printf '%s\n' "$p" >> "$rootsf" || PW_DISCOVERY_FAILED=1; fi
  done < "$candf"
  rm -f "$candf"; sort -u "$rootsf" -o "$rootsf" 2>/dev/null || PW_DISCOVERY_FAILED=1
  while IFS= read -r p; do [ -n "$p" ] && SCAN_ROOTS+=("$p"); done < "$rootsf"; rm -f "$rootsf"
  for p in "${SCAN_ROOTS[@]}"; do
    label=$(site_label_from_root "$p"); group=${label%%/*}; _array_has "$group" "${DISCOVERED_DOMAINS[@]}" || DISCOVERED_DOMAINS+=("$group"); nested=0
    for parent in "${TREE_ROOTS[@]}"; do case "$p" in "$parent"/*) nested=1; break ;; esac; done
    if [ "$nested" -eq 1 ]; then NESTED_SITES+=("$label"); else TREE_ROOTS+=("$p"); fi
  done
}
_discovery_cache_key() { printf '%s\n' "$ROOT|$PRESSWARDEN_DISCOVERY_DEPTH|$PRESSWARDEN_EXCLUDE|$PRESSWARDEN_VERSION|${_PW_TARGET_EXCLUSIONS:-}" | cksum | awk '{print $1":"$2}'; }
_discovery_text_safe() {
  local v="$1"
  [ -n "$v" ] || return 1
  [[ "$v" != *[[:cntrl:]]* ]]
}
_discovery_path_safe() {
  local p="$1" rr pr
  _discovery_text_safe "$p" || return 1
  case "$p" in "$ROOT"|"$ROOT"/*) ;; *) return 1 ;; esac
  if command -v realpath >/dev/null 2>&1; then
    rr=$(realpath "$ROOT" 2>/dev/null) || return 1
    pr=$(realpath "$p" 2>/dev/null) || return 1
    case "$pr" in "$rr"|"$rr"/*) ;; *) return 1 ;; esac
  fi
  return 0
}
_discovery_rebuild_derived() {
  local p label group parent nested
  TREE_ROOTS=(); DISCOVERED_DOMAINS=(); NESTED_SITES=(); MANUAL_EXCLUDED_DOMAINS=()
  for p in "${MANUAL_EXCLUDED_ROOTS[@]}"; do
    label=$(site_label_from_root "$p"); _discovery_text_safe "$label" || return 1
    _array_has "$label" "${MANUAL_EXCLUDED_DOMAINS[@]}" || MANUAL_EXCLUDED_DOMAINS+=("$label")
  done
  for p in "${SCAN_ROOTS[@]}"; do
    label=$(site_label_from_root "$p"); _discovery_text_safe "$label" || return 1
    group=${label%%/*}; _discovery_text_safe "$group" || return 1
    _array_has "$group" "${DISCOVERED_DOMAINS[@]}" || DISCOVERED_DOMAINS+=("$group")
    nested=0
    for parent in "${TREE_ROOTS[@]}"; do case "$p" in "$parent"/*) nested=1; break ;; esac; done
    if [ "$nested" -eq 1 ]; then NESTED_SITES+=("$label"); else TREE_ROOTS+=("$p"); fi
  done
  return 0
}
_load_discovery_cache() {
  local ttl="${PRESSWARDEN_DISCOVERY_CACHE_TTL:-300}" cache="$PRESSWARDEN_CACHE_DIR/discovery.tsv" now mt age key type val extra p size lines first=1
  case "$ttl" in ''|*[!0-9]*) ttl=300 ;; esac
  [ "$ttl" -gt 0 ] || return 1
  [ "${PRESSWARDEN_DISCOVERY_REFRESH:-0}" != "1" ] || return 1
  [ -f "$cache" ] && [ ! -L "$cache" ] || return 1
  size=$(wc -c < "$cache" 2>/dev/null | tr -d '[:space:]') || return 1
  lines=$(wc -l < "$cache" 2>/dev/null | tr -d '[:space:]') || return 1
  case "$size:$lines" in *[!0-9:]*|:*|*:) return 1 ;; esac
  [ "$size" -gt 0 ] && [ "$size" -le 4194304 ] && [ "$lines" -le 50000 ] || return 1
  now=$(date +%s); mt=$(stat -c %Y "$cache" 2>/dev/null || printf '0')
  case "$mt" in ''|*[!0-9]*) return 1 ;; esac
  age=$((now-mt)); [ "$age" -ge 0 ] && [ "$age" -le "$ttl" ] || return 1
  key=$(_discovery_cache_key)
  SCAN_ROOTS=(); TREE_ROOTS=(); IGNORED_DOMAINS=(); MANUAL_EXCLUDED_DOMAINS=(); MANUAL_EXCLUDED_ROOTS=(); DISCOVERED_DOMAINS=(); NESTED_SITES=()
  while IFS=$'\t' read -r type val extra || [ -n "$type$val$extra" ]; do
    if [ "$first" -eq 1 ]; then
      [ "$type" = META ] && [ "$val" = "$key" ] && [ -z "$extra" ] || return 1
      first=0; continue
    fi
    [ -z "$extra" ] || return 1
    case "$type" in
      ROOT)
        _discovery_path_safe "$val" || return 1
        _is_wordpress_root "$val" || return 1
        _is_excluded_site "$val" && return 1
        _array_has "$val" "${SCAN_ROOTS[@]}" || SCAN_ROOTS+=("$val")
        [ "${#SCAN_ROOTS[@]}" -le 5000 ] || return 1
        ;;
      EXCLUDED_ROOT)
        _discovery_path_safe "$val" || return 1
        _array_has "$val" "${MANUAL_EXCLUDED_ROOTS[@]}" || MANUAL_EXCLUDED_ROOTS+=("$val")
        ;;
      TREE) _discovery_path_safe "$val" || return 1 ;;
      EXCLUDED_LABEL|DOMAIN|NESTED) _discovery_text_safe "$val" || return 1 ;;
      META|'') return 1 ;;
      *) return 1 ;;
    esac
  done < "$cache"
  [ "$first" -eq 0 ] && [ "${#SCAN_ROOTS[@]}" -gt 0 ] || return 1
  _discovery_rebuild_derived || return 1
  return 0
}
_save_discovery_cache() {
  local cache="$PRESSWARDEN_CACHE_DIR/discovery.tsv" tmp key x
  mkdir -p "$PRESSWARDEN_CACHE_DIR" 2>/dev/null || return 0
  if [ -e "$cache" ] || [ -L "$cache" ]; then [ -f "$cache" ] && [ ! -L "$cache" ] || return 0; fi
  tmp=$( (umask 077; mktemp "$PRESSWARDEN_CACHE_DIR/.discovery.XXXXXX") ) || return 0
  key=$(_discovery_cache_key)
  {
    printf 'META\t%s\n' "$key"
    for x in "${SCAN_ROOTS[@]}"; do printf 'ROOT\t%s\n' "$x"; done
    for x in "${TREE_ROOTS[@]}"; do printf 'TREE\t%s\n' "$x"; done
    for x in "${MANUAL_EXCLUDED_DOMAINS[@]}"; do printf 'EXCLUDED_LABEL\t%s\n' "$x"; done
    for x in "${MANUAL_EXCLUDED_ROOTS[@]}"; do printf 'EXCLUDED_ROOT\t%s\n' "$x"; done
    for x in "${DISCOVERED_DOMAINS[@]}"; do printf 'DOMAIN\t%s\n' "$x"; done
    for x in "${NESTED_SITES[@]}"; do printf 'NESTED\t%s\n' "$x"; done
  } > "$tmp" || { rm -f "$tmp"; return 0; }
  chmod 600 "$tmp" 2>/dev/null || true
  mv -f "$tmp" "$cache" 2>/dev/null || rm -f "$tmp"
}
refresh_scan_roots() { _load_discovery_cache && { PW_DISCOVERY_FAILED=0; return 0; }; _refresh_scan_roots_uncached; [ "${PW_DISCOVERY_FAILED:-0}" -ne 0 ] || _save_discovery_cache; return 0; }

refresh_scan_roots
