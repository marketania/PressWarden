# Shared transactional wp-config mutation wrapper.
# Callers provide a validated site, display label, allowlisted constant, kind,
# and value. The PHP helper owns backup, serialization, verification and rollback.
pw_config_transaction_set() {
  local site="$1" label="$2" key="$3" kind="$4" value="$5" wp_bin out rc state _ok
  PW_CONFIG_TX_RESULT=''; PW_CONFIG_TX_ID=''
  command -v php >/dev/null 2>&1 || { printf 'CONFIG TRANSACTION: PHP CLI is required.\n' >&2; return 2; }
  wp_bin=$(command -v wp 2>/dev/null) || { printf 'CONFIG TRANSACTION: WP-CLI is required.\n' >&2; return 2; }
  case "$wp_bin" in /*) ;; *) printf 'CONFIG TRANSACTION: could not resolve WP-CLI executable.\n' >&2; return 2 ;; esac
  state="${PRESSWARDEN_STATE_DIR:?PRESSWARDEN_STATE_DIR is not set}"
  out=$(php "$PRESSWARDEN_DIR/lib/config-transaction.php" set "$state" "$site" "$label" "$key" "$kind" "$value" "$wp_bin")
  rc=$?
  [ "$rc" -eq 0 ] || return 2
  IFS=$'\t' read -r _ok PW_CONFIG_TX_RESULT PW_CONFIG_TX_ID <<< "$out"
  [ "$_ok" = OK ] || { printf 'CONFIG TRANSACTION: invalid helper response.\n' >&2; return 2; }
  case "$PW_CONFIG_TX_RESULT" in NOOP|CHANGED) ;; *) printf 'CONFIG TRANSACTION: invalid helper state.\n' >&2; return 2 ;; esac
  export PW_CONFIG_TX_RESULT PW_CONFIG_TX_ID
  return 0
}
