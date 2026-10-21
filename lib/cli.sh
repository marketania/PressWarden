# Terminal presentation and argument helpers. No discovery or state writes.
pw_cli_colors() {
  local color=0
  case "${PRESSWARDEN_COLOR:-auto}" in
    always) color=1 ;;
    auto|'')
      if { { [ -n "${PRESSWARDEN_FORCE_COLOR:-}" ] && [ "${PRESSWARDEN_FORCE_COLOR:-}" != 0 ]; } || [ -t 1 ]; } && [ "${TERM:-dumb}" != dumb ]; then color=1; fi
      ;;
    never) : ;;
    *) printf 'Invalid color mode; use auto, always, or never.\n' >&2; return 2 ;;
  esac
  # Explicit accessibility/logging preferences take precedence over forcing.
  if [ -n "${NO_COLOR:-}" ] || [ -n "${PRESSWARDEN_NOCOLOR:-}" ]; then color=0; fi
  if [ "$color" -eq 1 ]; then
    B=$'\033[1m'; D=$'\033[2m'; U=$'\033[4m'; R=$'\033[31m'; G=$'\033[32m'; Y=$'\033[33m'; BL=$'\033[34m'; M=$'\033[35m'; C=$'\033[36m'; WHT=$'\033[37m'; X=$'\033[0m'
  else
    B=''; D=''; U=''; R=''; G=''; Y=''; BL=''; M=''; C=''; WHT=''; X=''
  fi
}

pw_cli_section() { printf '\n%s%s%s%s\n' "$B" "$C" "$1" "$X"; }
pw_cli_row() { printf '  %s%-39s%s %s\n' "$G" "$1" "$X" "$2"; }

# Preserve a missing target versus an explicit empty target. No resolution here.
pw_cli_target_arguments() {
  local target='' selected=0 options=1
  PW_CLI_TARGET_ARGS=()
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --)
        if [ "$options" -eq 1 ]; then options=0; shift; continue; fi
        ;;
      --target)
        if [ "$options" -eq 1 ]; then
          [ "$selected" -eq 0 ] || { printf 'Use one target only; do not combine --target with another target.\n' >&2; return 2; }
          [ "$#" -ge 2 ] && [ -n "$2" ] && [[ "$2" != -* ]] || { printf '%s\n' '--target requires a non-empty website or directory.' >&2; return 2; }
          target="$2"; selected=1; shift 2; continue
        fi
        ;;
      --target=*)
        if [ "$options" -eq 1 ]; then
          [ "$selected" -eq 0 ] || { printf 'Use one target only.\n' >&2; return 2; }
          target=${1#--target=}; selected=1; shift; continue
        fi
        ;;
      -*)
        [ "$options" -eq 0 ] || { printf 'Unknown target option: %s\n' "$1" >&2; return 2; }
        ;;
    esac
    [ "$selected" -eq 0 ] || { printf 'Use one website name, directory, or all.\n' >&2; return 2; }
    target="$1"; selected=1; shift
  done
  if [ "$selected" -eq 1 ]; then
    [ -n "$target" ] || { printf 'Explicit target cannot be empty.\n' >&2; return 2; }
    [[ "$target" != -* ]] || { printf 'A target cannot start with a dash; use ./ for a relative directory.\n' >&2; return 2; }
    PW_CLI_TARGET_ARGS=("$target")
  fi
}

pw_cli_scan_arguments() {
  local mode='' next='' options=1
  local -a targets=()
  PW_CLI_SCAN_SUITE=fast
  PW_CLI_SCAN_KIND=''
  while [ "$#" -gt 0 ]; do
    next=''
    if [ "$options" -eq 1 ]; then
      case "$1" in
        --) options=0; targets+=("--"); shift; continue ;;
        -h|--help) return 3 ;;
        --fast) next=fast ;;
        --full|--deep) next=full ;;
        --incident) next=incident ;;
        -db|--db) next=db ;;
        -php|--php) next=inspect-php ;;
        -js|--js) next=inspect-js ;;
        --runtime) next=inspect-runtime ;;
        --target)
          [ "$#" -ge 2 ] || { printf '%s\n' '--target requires a website or directory.' >&2; return 2; }
          targets+=("$1" "$2"); shift 2; continue
          ;;
        --target=*) targets+=("$1"); shift; continue ;;
        -*) printf 'Unknown scan option: %s\nRun presswarden help scan.\n' "$1" >&2; return 2 ;;
      esac
    fi
    if [ -n "$next" ]; then
      [ -z "$mode" ] || [ "$mode" = "$next" ] || { printf 'Choose one scan mode; omit selectors for the routine security audit.\n' >&2; return 2; }
      mode="$next"
    else
      targets+=("$1")
    fi
    shift
  done
  pw_cli_target_arguments "${targets[@]}" || return 2
  PW_CLI_SCAN_SUITE=${mode:-fast}
  case "$PW_CLI_SCAN_SUITE" in inspect-*) PW_CLI_SCAN_KIND=${PW_CLI_SCAN_SUITE#inspect-}; PW_CLI_SCAN_SUITE=inspect ;; esac
}
