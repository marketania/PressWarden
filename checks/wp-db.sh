#!/usr/bin/env bash
# wp-db — database/application state security audit
NAME=wp-db; DESC="database options, grants + credential isolation"
SCAN_DOES="Audits WordPress URL state, registration defaults, database grants, and cross-site credential or salt reuse. Healthy siteurl/home rows are suppressed."
SCAN_WHY="Database tampering and excessive privilege can preserve access or widen a breach beyond the files of a single website."
. "$(cd "$(dirname "$0")/.." && pwd)/lib/_lib.sh"

_hash_text() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 | awk '{print $1}'
  else cksum | awk '{print $1":"$2}'; fi
}

main() {
  require_wp; banner; discover_sites
  local s d home site users role grants bad reg_any=0
  local creds salts cfg dbu dbp dbh h key line group count domains
  local saltfix cachekeys cachefix oc val cache_supported=0 cache_unused=0 cache_missing=0 cache_reused=0
  creds=$(tmpf); salts=$(tmpf); saltfix=$(tmpf); cachekeys=$(tmpf); cachefix=$(tmpf)
  : > "$creds"; : > "$salts"; : > "$saltfix"; : > "$cachekeys"; : > "$cachefix"

  sec "siteurl / home mismatch or off-domain" "only non-OK sites are shown"
  local url_issues=0
  for s in "${WP_SITES[@]}"; do
    d=$(site_domain "$s")
    site=$(wpq "$s" option get siteurl 2>/dev/null || true)
    home=$(wpq "$s" option get home 2>/dev/null || true)
    if [ -z "$site" ] || [ -z "$home" ]; then
      flag "$d" "could not read siteurl/home"; url_issues=$((url_issues+1))
    elif ! printf '%s' "$site" | grep -Fq "$d" || ! printf '%s' "$home" | grep -Fq "$d"; then
      issue "$d" "siteurl=$site home=$home"; url_issues=$((url_issues+1))
    elif [ "$site" != "$home" ]; then
      flag "$d" "siteurl != home" "siteurl=$site\nhome=$home"; url_issues=$((url_issues+1))
    fi
  done
  [ "$url_issues" -gt 0 ] || printf '    %s✓ CLEAN%s  all siteurl/home values match their discovered WordPress site\n' "$G" "$X"

  sec "User registration posture"
  for s in "${WP_SITES[@]}"; do
    d=$(site_domain "$s"); users=$(wpq "$s" option get users_can_register 2>/dev/null || echo 0)
    [ "$users" = "1" ] || continue
    reg_any=1; role=$(wpq "$s" option get default_role 2>/dev/null || echo unknown)
    case "$role" in
      administrator|editor) issue "$d" "registration enabled with privileged default role: $role" ;;
      author) flag "$d" "registration enabled with author default role" ;;
      subscriber|contributor|customer|shop_customer|bbp_participant) printf '    %sℹ REGISTRATION%s %s%s%s  %s›%s  enabled → %s\n' "$C" "$X" "$B$M" "$d" "$X" "$D" "$X" "$role" ;;
      *) flag "$d" "registration enabled with custom/unknown default role: $role" ;;
    esac
  done
  [ "$reg_any" -eq 1 ] || printf '    %s✓ CLEAN%s  public user registration disabled on all sites\n' "$G" "$X"

  if [ "${PRESSWARDEN_SKIP_DB_PRIV_SCOPE:-0}" != "1" ]; then
    sec "Database account privilege scope" "exceptions first • expected host-scoped grants collapse into one summary"
    local grant_ok=0 grant_review=0
    for s in "${WP_SITES[@]}"; do
      d=$(site_domain "$s"); grants=$(wpq "$s" db query 'SHOW GRANTS FOR CURRENT_USER();' --skip-column-names --silent 2>/dev/null || true)
      if [ -z "$grants" ]; then flag "$d" "could not read database grants"; grant_review=$((grant_review+1)); continue; fi
      bad=$(printf '%s\n' "$grants" | grep -E ' ON \*\.\* ' | grep -vE '^GRANT USAGE ON \*\.\* ' || true)
      if [ -n "$bad" ]; then issue "$d" "database user has non-USAGE global privileges" "$bad"; grant_review=$((grant_review+1)); else grant_ok=$((grant_ok+1)); fi
    done
    [ "$grant_ok" -eq 0 ] || printf '    %s✓ CLEAN%s  %s/%s database account(s) have no non-USAGE global privileges\n' "$G" "$X" "$grant_ok" "${#WP_SITES[@]}"
  fi

  if [ "${PRESSWARDEN_SKIP_DB_CRED_REUSE:-0}" != "1" ]; then
    sec "Cross-site DB credential reuse" "hash comparison only • secrets never printed"
    for s in "${WP_SITES[@]}"; do
      d=$(site_domain "$s"); dbu=$(wpq "$s" config get DB_USER --type=constant 2>/dev/null || true); dbp=$(wpq "$s" config get DB_PASSWORD --type=constant 2>/dev/null || true); dbh=$(wpq "$s" config get DB_HOST --type=constant 2>/dev/null || true)
      [ -n "$dbu$dbp$dbh" ] || continue; h=$(printf '%s\0%s\0%s' "$dbu" "$dbp" "$dbh" | _hash_text); printf '%s|%s\n' "$h" "$d" >> "$creds"
    done
    for key in $(cut -d'|' -f1 "$creds" | sort | uniq -d); do
      domains=$(awk -F'|' -v k="$key" '$1==k{print $2}' "$creds" | paste -sd ', ' -); count=$(awk -F'|' -v k="$key" '$1==k{n++}END{print n+0}' "$creds"); issue "credential isolation" "$count sites reuse the same DB username/password/host" "$domains"
    done
    if ! cut -d'|' -f1 "$creds" | sort | uniq -d | grep -q .; then printf '    %s✓ CLEAN%s  no DB credential set is reused across WordPress sites\n' "$G" "$X"; fi
  fi

  sec "Cross-site WordPress salt reuse" "hash comparison only • salts never printed"
  for s in "${WP_SITES[@]}"; do
    d=$(site_domain "$s"); cfg=$(wpq "$s" config list AUTH_KEY SECURE_AUTH_KEY LOGGED_IN_KEY NONCE_KEY AUTH_SALT SECURE_AUTH_SALT LOGGED_IN_SALT NONCE_SALT --strict --fields=key,value --format=csv 2>/dev/null || true)
    [ -n "$cfg" ] || continue; h=$(printf '%s\n' "$cfg" | tail -n +2 | sort | _hash_text); printf '%s|%s|%s\n' "$h" "$d" "$s" >> "$salts"
  done
  for key in $(cut -d'|' -f1 "$salts" | sort | uniq -d); do
    domains=$(awk -F'|' -v k="$key" '$1==k{print $2}' "$salts" | paste -sd ', ' -); count=$(awk -F'|' -v k="$key" '$1==k{n++}END{print n+0}' "$salts"); flag "salt isolation" "$count sites reuse the same WordPress key/salt set" "$domains"; awk -F'|' -v k="$key" '$1==k{print $3}' "$salts" >> "$saltfix"
  done
  sort -u "$saltfix" -o "$saltfix" 2>/dev/null || true
  if [ ! -s "$saltfix" ]; then
    printf '    %s✓ CLEAN%s  no identical WordPress salt/key set found across sites\n' "$G" "$X"
  elif [ "$PRESSWARDEN_INTERACTIVE" != 0 ] && [ -t 0 ]; then
    count=$(grep -c . "$saltfix" 2>/dev/null); count=${count:-0}
    printf '\n    %s%sACTION%s  %s%s%s affected site(s) can receive fresh WordPress authentication keys/salts.\n' "$B" "$BL" "$X" "$B" "$count" "$X"
    printf '    %s⚠ Rotating these salts invalidates existing WordPress login cookies/nonces; administrators will need to log in again.%s\n' "$Y" "$X"
    printf '    %s[r]%s rotate with %swp config shuffle-salts%s   %s[s]%s skip %s(default)%s : ' "$B$Y" "$X" "$C" "$X" "$B$G" "$X" "$D" "$X"
    IFS= read -r ans || ans='s'
    case "$ans" in
      r|R|rotate|ROTATE)
        while IFS= read -r s; do
          [ -n "$s" ] || continue; d=$(site_domain "$s"); bak=$(tmpf)
          if ! cp -p "$s/wp-config.php" "$bak" 2>/dev/null; then printf '    %s✖ FAILED%s   %s%s%s  › could not create temporary wp-config.php safety copy\n' "$R" "$X" "$B$M" "$d" "$X"; rm -f "$bak"; continue; fi
          chmod 600 "$bak" 2>/dev/null || true
          if wp config shuffle-salts --path="$s" --no-color >/dev/null 2>&1; then printf '    %s✓ ROTATED%s  %s%s%s  › WordPress authentication keys/salts refreshed\n' "$G" "$X" "$B$M" "$d" "$X"; rm -f "$bak"; else cp -p "$bak" "$s/wp-config.php" 2>/dev/null || true; rm -f "$bak"; printf '    %s✖ FAILED%s   %s%s%s  › salt rotation failed; original wp-config.php restored\n' "$R" "$X" "$B$M" "$d" "$X"; fi
        done < "$saltfix" ;;
      *) printf '    %s%s↷ SKIPPED%s  WordPress authentication salts were not changed\n' "$B" "$Y" "$X" ;;
    esac
  else printf '    %sℹ%s  non-interactive session — salt rotation not offered\n' "$C" "$X"; fi

  sec "Persistent object-cache namespace isolation" "WP_CACHE_KEY_SALT checked only when the installed drop-in actually uses it"
  for s in "${WP_SITES[@]}"; do
    d=$(site_domain "$s"); oc="$s/wp-content/object-cache.php"; [ -f "$oc" ] || continue
    if ! grep -Fq 'WP_CACHE_KEY_SALT' "$oc" 2>/dev/null; then cache_unused=$((cache_unused+1)); continue; fi
    cache_supported=$((cache_supported+1)); val=$(wp config get WP_CACHE_KEY_SALT --type=constant --path="$s" --no-color 2>/dev/null || true)
    if [ -z "$val" ]; then cache_missing=$((cache_missing+1)); printf '    %s⚠ CACHE SALT%s %s%s%s  %s›%s  WP_CACHE_KEY_SALT missing; this drop-in supports per-site cache namespacing\n' "$Y" "$X" "$B$M" "$d" "$X" "$D" "$X"; printf '%s\n' "$s" >> "$cachefix"; continue; fi
    h=$(printf '%s' "$val" | _hash_text); printf '%s|%s|%s\n' "$h" "$d" "$s" >> "$cachekeys"
  done
  for key in $(cut -d'|' -f1 "$cachekeys" 2>/dev/null | sort | uniq -d); do
    domains=$(awk -F'|' -v k="$key" '$1==k{print $2}' "$cachekeys" | paste -sd ', ' -); count=$(awk -F'|' -v k="$key" '$1==k{n++}END{print n+0}' "$cachekeys"); cache_reused=$((cache_reused+count)); flag "cache namespace" "$count sites reuse the same WP_CACHE_KEY_SALT" "$domains"; awk -F'|' -v k="$key" '$1==k{print $3}' "$cachekeys" >> "$cachefix"
  done
  sort -u "$cachefix" -o "$cachefix" 2>/dev/null || true
  if [ "$cache_supported" -eq 0 ]; then printf '    %s✓ N/A%s    no installed object-cache.php references WP_CACHE_KEY_SALT\n' "$G" "$X"; elif [ ! -s "$cachefix" ]; then printf '    %s✓ CLEAN%s  all %s compatible object-cache drop-in(s) have unique WP_CACHE_KEY_SALT values\n' "$G" "$X" "$cache_supported"; fi
  [ "$cache_unused" -eq 0 ] || note "$cache_unused object-cache.php drop-in(s) do not consume WP_CACHE_KEY_SALT; no cache-salt recommendation was made for them"
  if [ -s "$cachefix" ] && [ "$PRESSWARDEN_INTERACTIVE" != 0 ] && [ -t 0 ]; then
    count=$(grep -c . "$cachefix" 2>/dev/null); count=${count:-0}; printf '\n    %s%sACTION%s  %s%s%s site(s) need a unique cache-key namespace for a drop-in that supports WP_CACHE_KEY_SALT.\n' "$B" "$BL" "$X" "$B" "$count" "$X"
    printf '    %s[c]%s create/rotate with %swp config shuffle-salts WP_CACHE_KEY_SALT --force%s   %s[s]%s skip %s(default)%s : ' "$B$Y" "$X" "$C" "$X" "$B$G" "$X" "$D" "$X"; IFS= read -r ans || ans='s'
    case "$ans" in c|C|cache|CACHE) while IFS= read -r s; do [ -n "$s" ] || continue; d=$(site_domain "$s"); bak=$(tmpf); if ! cp -p "$s/wp-config.php" "$bak" 2>/dev/null; then rm -f "$bak"; continue; fi; chmod 600 "$bak" 2>/dev/null || true; if wp config shuffle-salts WP_CACHE_KEY_SALT --force --path="$s" --no-color >/dev/null 2>&1; then printf '    %s✓ CACHE SALT%s %s%s%s  › unique WP_CACHE_KEY_SALT generated\n' "$G" "$X" "$B$M" "$d" "$X"; rm -f "$bak"; else cp -p "$bak" "$s/wp-config.php" 2>/dev/null || true; rm -f "$bak"; printf '    %s✖ FAILED%s   %s%s%s  › cache salt update failed; original wp-config.php restored\n' "$R" "$X" "$B$M" "$d" "$X"; fi; done < "$cachefix"; note "changing WP_CACHE_KEY_SALT starts a fresh cache namespace; old backend keys are left to expire naturally" ;; *) printf '    %s%s↷ SKIPPED%s  cache-key salts were not changed\n' "$B" "$Y" "$X" ;; esac
  elif [ -s "$cachefix" ]; then printf '    %sℹ%s  non-interactive session — cache-salt remediation not offered\n' "$C" "$X"; fi
  rm -f "$creds" "$salts" "$saltfix" "$cachekeys" "$cachefix"; finish
}
run_logged wp-db
