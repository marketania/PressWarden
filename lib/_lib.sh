# Shared PressWarden runtime. Keep modules sourced in this order.
_PRESSWARDEN_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/env-discovery.sh
. "$_PRESSWARDEN_LIB_DIR/env-discovery.sh"
# shellcheck source=lib/reports.sh
. "$_PRESSWARDEN_LIB_DIR/reports.sh"
# shellcheck source=lib/ui.sh
. "$_PRESSWARDEN_LIB_DIR/ui.sh"
# shellcheck source=lib/remediation.sh
. "$_PRESSWARDEN_LIB_DIR/remediation.sh"
# shellcheck source=lib/wp.sh
. "$_PRESSWARDEN_LIB_DIR/wp.sh"
unset _PRESSWARDEN_LIB_DIR
