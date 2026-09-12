#!/usr/bin/env python3
from pathlib import Path
root = Path(__file__).resolve().parents[1]

def read(path): return (root/path).read_text()
def write(path, s): (root/path).write_text(s)
def replace_once(path, old, new):
    s=read(path)
    if old not in s: raise SystemExit(f'anchor not found {path}: {old[:80]!r}')
    write(path, s.replace(old,new,1))
def replace_between(path, start, end, new):
    s=read(path); a=s.find(start)
    if a<0: raise SystemExit(f'start not found {path}: {start[:80]!r}')
    b=s.find(end,a+len(start))
    if b<0: raise SystemExit(f'end not found {path}: {end[:80]!r}')
    write(path, s[:a]+new+s[b:])

replace_between('checks/wp-settings.sh', '_cfg_backup() {', '_policy_set() {', '')
replace_once('checks/wp-settings.sh',
"  local key raw string expected human site label backup root got failed=0 blocker=''\n",
"  local key raw string expected human site label failed=0 blocker='' kind txvalue\n")
replace_between('checks/wp-settings.sh',
'''  require_wp; discover_sites\n  root="$QUARANTINE/wp-settings-$(date -u +%Y%m%dT%H%M%SZ)-$$-$RANDOM"\n''',
'''  [ "$SETTING:$VALUE" != cron:disabled ]''',
'''  require_wp; discover_sites\n  for site in "${WP_SITES[@]}"; do\n    label=$(site_label_from_root "$site")\n    if [ -n "${raw:-}" ]; then kind=bool; txvalue="$raw"; else kind=string; txvalue="$string"; fi\n    if ! pw_config_transaction_set "$site" "$label" "$key" "$kind" "$txvalue"; then\n      printf '✖ %s: wp-config.php transaction failed; verified backup retained when one was created\\n' "$label"\n      failed=1; continue\n    fi\n    blocker=''\n    if [ "$SETTING" = editor ] && wp config is-true DISALLOW_FILE_MODS --type=constant --path="$site" --no-color >/dev/null 2>&1; then blocker='; effective editor remains disabled while file modifications are locked'; fi\n    if [ "$PW_CONFIG_TX_RESULT" = NOOP ]; then\n      printf '✓ %s: %s (already configured)%s\\n' "$label" "$human" "$blocker"\n    else\n      printf '✓ %s: %s%s\\n' "$label" "$human" "$blocker"\n    fi\n  done\n''')

replace_between('checks/wp-auto-updates.sh', '_backup_config() {', '_set_core() {', '')
replace_between('checks/wp-auto-updates.sh', '_set_core() {', '_enabled_names() {', '''_set_core() {\n  local site label desired kind txvalue block fail=0\n  require_wp; discover_sites\n  for site in "${WP_SITES[@]}"; do\n    label=$(site_label_from_root "$site")\n    case "$VALUE" in\n      minor) kind=string; txvalue=minor; desired=MINOR ;;\n      major) kind=bool; txvalue=true; desired=MAJOR ;;\n      disabled) kind=bool; txvalue=false; desired=DISABLED ;;\n    esac\n    if ! pw_config_transaction_set "$site" "$label" WP_AUTO_UPDATE_CORE "$kind" "$txvalue"; then\n      printf '✖ %s: core policy wp-config.php transaction failed; verified backup retained when one was created\\n' "$label"\n      fail=1; continue\n    fi\n    block=$(_blocker "$site")\n    if [ "$PW_CONFIG_TX_RESULT" = NOOP ]; then\n      printf '✓ %s: core auto-updates already %s' "$label" "$desired"\n    else\n      printf '✓ %s: core auto-updates %s' "$label" "$desired"\n    fi\n    [ -z "$block" ] || printf ' (configured, but blocked by %s)' "$block"\n    printf '\\n'\n  done\n  [ "$fail" -eq 0 ] || return 2\n}\n\n''')

replace_between('tests/site-lock.sh', "cat > \"$T/bin/wp\" <<'WP'\n", "WP\nchmod +x \"$T/bin/wp\"", '''cat > "$T/bin/wp" <<'WP'\n#!/usr/bin/env bash\nset -eu\np=''; cfg=''; args=()\nfor a in "$@"; do\n  case "$a" in\n    --path=*) p=${a#--path=} ;;\n    --config-file=*) cfg=${a#--config-file=} ;;\n    --skip-*|--no-color|--type=constant|--format=json|--raw) ;;\n    *) args+=("$a") ;;\n  esac\ndone\nset -- "${args[@]}"\n[ -n "$p" ] || exit 94\n[ -n "$cfg" ] || cfg="$p/wp-config.php"\n[ "$1" = config ] && [ -f "$cfg" ] || exit 95\ncase "$2" in\n  get)\n    grep -q 'DISALLOW_FILE_MODS", true' "$cfg" && echo true || echo false\n    ;;\n  set)\n    value=$4\n    tmp="$cfg.tmp.$$"\n    grep -v 'define("DISALLOW_FILE_MODS"' "$cfg" > "$tmp" || true\n    printf 'define("DISALLOW_FILE_MODS", %s);\\n' "$value" >> "$tmp"\n    mv "$tmp" "$cfg"\n    ;;\n  *) exit 96 ;;\nesac\nWP\nchmod +x "$T/bin/wp"''')
replace_once('tests/site-lock.sh',
"# Existing config backup path remains in use.\nfind \"$T/state/quarantine\" -name wp-config.php | grep -q .\n",
"# Mutations now use the shared verified transaction evidence tree.\nfind \"$T/state/config-transactions\" -name wp-config.php | grep -q .\n")

replace_once('tests/wp-settings.sh', "p=''; args=()\n", "p=''; cfg=''; args=()\n")
replace_once('tests/wp-settings.sh',
'''for a in "$@"; do case "$a" in --path=*) p=${a#--path=} ;; --skip-*|--no-color) ;; *) args+=("$a") ;; esac; done\nset -- "${args[@]}"; [ -n "$p" ] || exit 90\n''',
'''for a in "$@"; do case "$a" in --path=*) p=${a#--path=} ;; --config-file=*) cfg=${a#--config-file=} ;; --skip-*|--no-color|--type=constant|--format=json|--raw) ;; *) args+=("$a") ;; esac; done\nset -- "${args[@]}"; [ -n "$p" ] || exit 90\n[ -n "$cfg" ] || cfg="$p/wp-config.php"\n''')
start=''' config)\n   case "$2" in\n'''
end='''   esac\n   ;;\n *) exit 94 ;;\nesac\nWP\n'''
s=read('tests/wp-settings.sh'); a=s.find(start)
if a<0: raise SystemExit('wp-settings config start missing')
b=s.find(end,a)
if b<0: raise SystemExit('wp-settings config end missing')
config_block=''' config)\n   case "$2" in\n    set)\n      key=$3; value=$4; tmp="$cfg.tmp.$$"\n      grep -v "define(\\\"$key\\\"" "$cfg" > "$tmp" || true\n      case "$key" in\n       WP_ENVIRONMENT_TYPE|WP_DEVELOPMENT_MODE) printf 'define("%s", "%s");\\n' "$key" "$value" >> "$tmp" ;;\n       DISALLOW_FILE_EDIT|DISABLE_WP_CRON|WP_DISABLE_FATAL_ERROR_HANDLER|WP_DEBUG|FORCE_SSL_ADMIN|ALTERNATE_WP_CRON) printf 'define("%s", %s);\\n' "$key" "$value" >> "$tmp" ;;\n       *) rm -f "$tmp"; exit 91 ;;\n      esac\n      mv "$tmp" "$cfg"\n      ;;\n    get)\n      key=$3\n      grep -q "define(\\\"$key\\\"" "$cfg" || exit 92\n      case "$key" in\n       WP_ENVIRONMENT_TYPE|WP_DEVELOPMENT_MODE) sed -n -E "s/.*define\\(\\\"$key\\\", \\\"([^\\\"]*)\\\"\\).*/\\\"\\1\\\"/p" "$cfg" | tail -1 ;;\n       *) grep "define(\\\"$key\\\"" "$cfg" | tail -1 | grep -q ', true)' && echo true || echo false ;;\n      esac\n      ;;\n    is-true) [ "$3" = DISALLOW_FILE_MODS ] && [ "$(cat "$p/.filemods")" = locked ] ;;\n    *) exit 93 ;;\n   esac\n   ;;\n *) exit 94 ;;\nesac\nWP\n'''
write('tests/wp-settings.sh', s[:a]+config_block+s[b+len(end):])
repls={
'''run wp-settings set editor enabled a.com > "$T/set"; grep -q 'effective editor remains disabled' "$T/set"; [ "$(cat "$T/sites/a.com/public_html/.editor")" = enabled ]''':'''run wp-settings set editor enabled a.com > "$T/set"; grep -q 'effective editor remains disabled' "$T/set"; grep -q 'define("DISALLOW_FILE_EDIT", false)' "$T/sites/a.com/public_html/wp-config.php"''',
'''run wp-settings set cron disabled a.com > "$T/set"; grep -q 'external/server cron' "$T/set"; [ "$(cat "$T/sites/a.com/public_html/.cron")" = disabled ]''':'''run wp-settings set cron disabled a.com > "$T/set"; grep -q 'external/server cron' "$T/set"; grep -q 'define("DISABLE_WP_CRON", true)' "$T/sites/a.com/public_html/wp-config.php"''',
'''run wp-settings set recovery disabled a.com > "$T/set"; [ "$(cat "$T/sites/a.com/public_html/.recovery")" = disabled ]''':'''run wp-settings set recovery disabled a.com > "$T/set"; grep -q 'define("WP_DISABLE_FATAL_ERROR_HANDLER", true)' "$T/sites/a.com/public_html/wp-config.php"''',
'''run wp-settings set environment staging a.com > "$T/set"; [ "$(cat "$T/sites/a.com/public_html/.environment")" = staging ]''':'''run wp-settings set environment staging a.com > "$T/set"; grep -q 'define("WP_ENVIRONMENT_TYPE", "staging")' "$T/sites/a.com/public_html/wp-config.php"''',
'''run wp-settings set development theme a.com > "$T/set"; [ "$(cat "$T/sites/a.com/public_html/.development")" = theme ]''':'''run wp-settings set development theme a.com > "$T/set"; grep -q 'define("WP_DEVELOPMENT_MODE", "theme")' "$T/sites/a.com/public_html/wp-config.php"''',
'''run wp-settings set development disabled a.com > "$T/set"; [ "$(cat "$T/sites/a.com/public_html/.development")" = disabled ]''':'''run wp-settings set development disabled a.com > "$T/set"; grep -q 'define("WP_DEVELOPMENT_MODE", "")' "$T/sites/a.com/public_html/wp-config.php"''',
'''run wp-settings set debug enabled a.com > "$T/set"; [ "$(cat "$T/sites/a.com/public_html/.debug")" = enabled ]''':'''run wp-settings set debug enabled a.com > "$T/set"; grep -q 'define("WP_DEBUG", true)' "$T/sites/a.com/public_html/wp-config.php"''',
'''run wp-settings set force-ssl-admin disabled a.com > "$T/set"; [ "$(cat "$T/sites/a.com/public_html/.ssl")" = disabled ]''':'''run wp-settings set force-ssl-admin disabled a.com > "$T/set"; grep -q 'define("FORCE_SSL_ADMIN", false)' "$T/sites/a.com/public_html/wp-config.php"''',
'''run wp-settings set alternate-cron enabled a.com > "$T/set"; grep -q 'compatibility workaround' "$T/set"; [ "$(cat "$T/sites/a.com/public_html/.alternate")" = enabled ]''':'''run wp-settings set alternate-cron enabled a.com > "$T/set"; grep -q 'compatibility workaround' "$T/set"; grep -q 'define("ALTERNATE_WP_CRON", true)' "$T/sites/a.com/public_html/wp-config.php"''',
'''find "$T/state/quarantine" -name wp-config.php | grep -q .''':'''find "$T/state/config-transactions" -name wp-config.php | grep -q .'''
}
for old,new in repls.items(): replace_once('tests/wp-settings.sh',old,new)

replace_once('tests/wp-auto-updates.sh', "p=''; args=(); for a in \"$@\"; do case \"$a\" in --path=*) p=${a#--path=} ;; --skip-*|--no-color) ;; *) args+=(\"$a\") ;; esac; done\nset -- \"${args[@]}\"; [ -n \"$p\" ] || exit 90\n",
"p=''; cfg=''; args=(); for a in \"$@\"; do case \"$a\" in --path=*) p=${a#--path=} ;; --config-file=*) cfg=${a#--config-file=} ;; --skip-*|--no-color|--type=constant|--format=json|--raw) ;; *) args+=(\"$a\") ;; esac; done\nset -- \"${args[@]}\"; [ -n \"$p\" ] || exit 90\n[ -n \"$cfg\" ] || cfg=\"$p/wp-config.php\"\n")
old=''' config)\n   case "$2" in\n    has) case "$3" in WP_AUTO_UPDATE_CORE) exit 0 ;; AUTOMATIC_UPDATER_DISABLED|DISALLOW_FILE_MODS) [ -f "$p/.${3}" ] ;; *) exit 1 ;; esac ;;\n    get) case "$3" in WP_AUTO_UPDATE_CORE) case "$(cat "$p/.core")" in minor) echo '"minor"';; major) echo true;; disabled) echo false;; esac ;; *) exit 1;; esac ;;\n    is-true) [ -f "$p/.${3}" ] ;;\n    set) case "$3" in WP_AUTO_UPDATE_CORE) case "$4" in minor) echo minor > "$p/.core"; printf '<?php define("WP_AUTO_UPDATE_CORE", "minor");\\n' > "$p/wp-config.php" ;; true) echo major > "$p/.core"; printf '<?php define("WP_AUTO_UPDATE_CORE", true);\\n' > "$p/wp-config.php" ;; false) echo disabled > "$p/.core"; printf '<?php define("WP_AUTO_UPDATE_CORE", false);\\n' > "$p/wp-config.php" ;; esac ;; esac ;;\n   esac ;;\n'''
new=''' config)\n   case "$2" in\n    has) case "$3" in WP_AUTO_UPDATE_CORE) grep -q 'define("WP_AUTO_UPDATE_CORE"' "$cfg" ;; AUTOMATIC_UPDATER_DISABLED|DISALLOW_FILE_MODS) [ -f "$p/.${3}" ] ;; *) exit 1 ;; esac ;;\n    get)\n      case "$3" in\n       WP_AUTO_UPDATE_CORE)\n        grep -q 'define("WP_AUTO_UPDATE_CORE"' "$cfg" || exit 1\n        grep -q 'WP_AUTO_UPDATE_CORE", true' "$cfg" && echo true || { grep -q 'WP_AUTO_UPDATE_CORE", false' "$cfg" && echo false || echo '"minor"'; }\n        ;;\n       *) exit 1 ;;\n      esac ;;\n    is-true) [ -f "$p/.${3}" ] ;;\n    set)\n      [ "$3" = WP_AUTO_UPDATE_CORE ] || exit 94\n      value=$4; tmp="$cfg.tmp.$$"; grep -v 'define("WP_AUTO_UPDATE_CORE"' "$cfg" > "$tmp" || true\n      if [ "$value" = true ] || [ "$value" = false ]; then printf 'define("WP_AUTO_UPDATE_CORE", %s);\\n' "$value" >> "$tmp"; else printf 'define("WP_AUTO_UPDATE_CORE", "%s");\\n' "$value" >> "$tmp"; fi\n      mv "$tmp" "$cfg"\n      ;;\n   esac ;;\n'''
replace_once('tests/wp-auto-updates.sh',old,new)
replace_once('tests/wp-auto-updates.sh',
'''run auto-updates core major example.com > "$T/out"; [ "$(cat "$T/sites/example.com/public_html/.core")" = major ]; [ "$(cat "$T/sites/other.com/public_html/.core")" = minor ]''',
'''run auto-updates core major example.com > "$T/out"; grep -q 'WP_AUTO_UPDATE_CORE", true' "$T/sites/example.com/public_html/wp-config.php"; grep -q 'WP_AUTO_UPDATE_CORE", "minor"' "$T/sites/other.com/public_html/wp-config.php"''')
replace_once('tests/wp-auto-updates.sh',
'''run auto-updates core disabled other.com > "$T/out"; [ "$(cat "$T/sites/other.com/public_html/.core")" = disabled ]''',
'''run auto-updates core disabled other.com > "$T/out"; grep -q 'WP_AUTO_UPDATE_CORE", false' "$T/sites/other.com/public_html/wp-config.php"''')
replace_once('tests/wp-auto-updates.sh',
"""find "$T/state/quarantine" -type f | grep -q .\nprintf 'WordPress automatic-update policy: idempotent mixed-state changes, partial status, targeting and backups PASS\\n'""",
"""find "$T/state/config-transactions" -name wp-config.php | grep -q .\nfind "$T/state/quarantine" -type f | grep -q .\nprintf 'WordPress automatic-update policy: idempotent mixed-state changes, partial status, targeting and transactional core backups PASS\\n'""")

(root/'VERSION').write_text('1.1.18\n')
replace_once('README.md','version-1.1.17-2ea44f','version-1.1.18-2ea44f')
replace_once('README.md',
'''Core/plugin/theme automatic-update controls remain under `auto-updates`. See [WordPress policy details](docs/WP-SETTINGS.md).\n''',
'''Core/plugin/theme automatic-update controls remain under `auto-updates`. `lock`/`unlock`, supported `wp-settings set` operations, and core auto-update policy now share a verified staged-copy transaction layer: PressWarden backs up the exact config, mutates and verifies a private copy with WP-CLI, revalidates the live source, then atomically publishes only verified bytes. See [WordPress policy details](docs/WP-SETTINGS.md) and [transaction safety](docs/CONFIG-TRANSACTIONS.md).\n''')
chg=read('CHANGELOG.md')
marker='# Changelog\n\nAll notable changes to PressWarden are documented here.\n\n'
entry='''## 1.1.18 — 2026-09-11\n\nTransactional wp-config mutation hardening.\n\n- Replace three independent wp-config backup/write paths with one shared transaction layer for lock/unlock, supported `wp-settings set` mutations, and core automatic-update policy. Plugin/theme automatic-update preferences remain separate WordPress option state.\n- Prepare changes on a private staged copy through WP-CLI `--config-file`, verify the exact requested value before touching the live config, then revalidate the original live identity/content immediately before same-directory atomic publication.\n- Keep a unique private verified backup and bounded metadata for every real change. Exact no-op mutations succeed without creating a backup. Per-site PHP `flock()` serializes PressWarden config writers without requiring the external `flock` binary.\n- Refuse symlink/hard-linked/oversized configs, owner mismatches where the effective UID can be checked, and any live source that changes during staging. External changes win rather than being overwritten.\n- Verify the published bytes, mode and WordPress constant. Automatic rollback is attempted only while the live file is still exactly the bytes PressWarden published; otherwise the verified backup is retained for manual recovery.\n- Make lock/unlock return INCOMPLETE (2) when any selected site mutation fails while retaining independent successful site changes. Preserve shared-host portability and add PHP 7.4, race, concurrency, privacy and existing command regressions.\n- No malware thresholds, quarantine semantics, baseline/continuation behavior, updater recovery or plugin/theme preference logic changed.\n\n'''
if marker not in chg: raise SystemExit('changelog marker missing')
write('CHANGELOG.md',chg.replace(marker,marker+entry,1))
