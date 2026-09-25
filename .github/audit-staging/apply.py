#!/usr/bin/env python3
"""One-time reviewed audit patch generator; not part of distributed applications."""
from pathlib import Path
import hashlib
import re
import shutil
import subprocess
import sys

BASES={'PressWarden':'769bb727456b712d9d4577ca9b3c16cddef0d2b9','PressHarden':'576370d863731c8d219283f11e76f7d4c00606b5','PressGarden':'24ea24cc7ae567d23fd3cc91f9d91c4a789c3acb'}
CHECKOUT='3d3c42e5aac5ba805825da76410c181273ba90b1'
UPLOAD='043fb46d1a93c77aae656e7c1c64a875d1fc6a0a'
ASSET_SHA='b233844db9fa3ba73b9478b3617ca3bcb080988cc2d081faa71523da8d2f4110'
ROOT=Path.cwd()
STAGING=Path(__file__).resolve().parent
product=(ROOT/'PRODUCT').read_text().strip()
assert product in BASES
program=product.lower();short={'PressWarden':'PW','PressHarden':'PH','PressGarden':'PG'}[product]
version='2.0.1' if product=='PressWarden' else '0.1.1'

def replace_once(text,old,new):
    assert text.count(old)==1,(old,text.count(old))
    return text.replace(old,new,1)

def put(path,text):
    path=ROOT/path
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(text)

# Guard the original mutable code and documents against concurrent modifications.
# Local snapshot runs have a synthetic commit but identical BASE tree contents.
if (STAGING/'expected.json').exists():
    import json
    expected=json.loads((STAGING/'expected.json').read_text())[product]
    for path,digest in expected.items():
        assert hashlib.sha256((ROOT/path).read_bytes()).hexdigest()==digest,('source advanced',path)

p=ROOT/program;s=p.read_text()
s=replace_once(s,'unset _'+short+'_TARGET_EXCLUSIONS','unset _'+short+'_TARGET_EXCLUSIONS _'+short+'_FLEET_ROOT')
s=replace_once(s,"  TARGET_NAME=''; TARGET_COUNT=''\n", "  TARGET_NAME=''; TARGET_COUNT=''\n  _"+short+"_FLEET_ROOT=$(resolve_root '') || return 2\n  export _"+short+"_FLEET_ROOT\n")
s=replace_once(s,'    ROOT=$(resolve_root "${1:-}")\n', '    [ "$#" -eq 0 ] || [ -n "$1" ] || { printf \'Explicit target cannot be empty.\\n\' >&2; exit 2; }\n    _'+short+'_FLEET_ROOT=$(resolve_root \'\') || exit 2\n    export _'+short+'_FLEET_ROOT\n    ROOT=$(resolve_root "${1:-}") || exit 2\n')
p.write_text(s)
p=ROOT/'lib/env-discovery.sh';s=p.read_text()
s=replace_once(s,'site_label_from_root() {\n','site_label_from_root() {\n  local ROOT="${2:-$ROOT}"\n')
a=s.index('_is_excluded_site() {');z=s.index('\n_array_has()',a)
exclusion='''_is_excluded_site() {
  local p="$1" label group x fleet_label='' fleet_group=''
  while IFS= read -r x; do
    [ -n "$x" ] || continue
    case "$p" in "$x"|"$x"/*) return 0 ;; esac
  done <<< "${_SHORT_TARGET_EXCLUSIONS:-}"
  label=$(site_label_from_root "$p"); group=${label%%/*}
  # Keep configured exclusions in their original fleet namespace after a
  # directory target narrows ROOT; explicit paths still match directly.
  if [ -n "${_SHORT_FLEET_ROOT:-}" ]; then
    case "$p" in
      "${_SHORT_FLEET_ROOT}"|"${_SHORT_FLEET_ROOT}"/*)
        fleet_label=$(site_label_from_root "$p" "${_SHORT_FLEET_ROOT}")
        fleet_group=${fleet_label%%/*}
        ;;
    esac
  fi
  for x in $PREFIX_EXCLUDE; do
    [ "$x" = "$label" ] || [ "$x" = "$group" ] || [ "$x" = "$p" ] || \\
      [ "$x" = "$fleet_label" ] || [ "$x" = "$fleet_group" ] || continue
    return 0
  done
  return 1
}'''.replace('SHORT',short).replace('PREFIX',product.upper())
s=s[:a]+exclusion+s[z:]
s=replace_once(s,'|${_'+short+'_TARGET_EXCLUSIONS:-}"','|${_'+short+'_TARGET_EXCLUSIONS:-}|${_'+short+'_FLEET_ROOT:-}"')
p.write_text(s)
p=ROOT/'uninstall.sh';s=p.read_text()
guard='''# Do not remove managed code while update/recovery depends on it.
if [ -e "$DIR/.PROGRAM-update.lock" ] || [ -L "$DIR/.PROGRAM-update.lock" ]; then
  echo 'Update/recovery lock is present; resolve the update before uninstalling.' >&2
  exit 2
fi
'''.replace('PROGRAM',program)
s=replace_once(s,'if [ "${1:-}" != --yes ]; then\n',guard+'if [ "${1:-}" != --yes ]; then\n');p.write_text(s)
if product=='PressGarden':
    p=ROOT/'checks/cleanup.sh';s=p.read_text()
    s=replace_once(s,'sites_json=$(php', '# Excluded children are traversal boundaries, never cleanup targets.\nsites_json=$(php')
    s=replace_once(s,'"${WP_SITES[@]}") || exit 2','"${WP_SITES[@]}" "${MANUAL_EXCLUDED_ROOTS[@]}") || exit 2');p.write_text(s)
if product=='PressHarden':
    p=ROOT/'checks/wp-auto-updates.sh';s=p.read_text();a=s.index('_set_items() {');z=s.index('\nmain() {',a);part=s[a:z]
    part=replace_once(part,'  for site in "${WP_SITES[@]}"; do\n','  for site in "${WP_SITES[@]}"; do\n    # Lock the complete snapshot/change/readback/recovery cycle.\n    ph_unlock_site\n    ph_lock_site "$site" || { fail=1; continue; }\n')
    part=replace_once(part,'  [ "$fail" -eq 0 ] || return 2','  ph_unlock_site\n  [ "$fail" -eq 0 ] || return 2');p.write_text(s[:a]+part+s[z:])

p=ROOT/'.codex/config.toml';s=p.read_text();s=replace_once(s,'[models.new_thread]\n','');p.write_text(s)
p=ROOT/'docs/AI-DEVELOPMENT.md';s=p.read_text().replace('[models.new_thread]\n','')
s=s.replace('https://developers.openai.com/docs/config-file/config-basic','https://learn.chatgpt.com/docs/config-file/config-basic')
s=replace_once(s,'Codex loads project','Project defaults use top-level `model` and `model_reasoning_effort`; `[models.new_thread]` belongs to administrator-managed `requirements.toml`, not project configuration.\n\nCodex loads project');p.write_text(s)
for p in (ROOT/'.github/workflows').glob('*.yml'):
    if p.name.startswith('audit-'):continue
    s=p.read_text()
    s=re.sub(r'actions/checkout@(?:v4|11d5960a326750d5838078e36cf38b85af677262)[^\n]*','actions/checkout@'+CHECKOUT+' # v7.0.1',s)
    s=re.sub(r'actions/upload-artifact@(?:v4|ea165f8d65b6e75b540449e92b4886f43607fa02)[^\n]*','actions/upload-artifact@'+UPLOAD+' # v7.0.1',s)
    p.write_text(s)
p=ROOT/'.github/workflows/ci.yml';s=p.read_text()
step='''      - name: ShellCheck error diagnostics
        shell: bash
        run: |
          set -euo pipefail
          shellcheck --version
          mapfile -t files < <(git ls-files '*.sh')
          program=$(tr '[:upper:]' '[:lower:]' < PRODUCT)
          shellcheck --severity=error --shell=bash --format=gcc "$program" "${files[@]}"
'''
s=replace_once(s,'      - name: Independent local syntax and benign-fixture tests\n',step+'      - name: Independent local syntax and benign-fixture tests\n')
matrix='''  php-supported:
    name: PHP ${{ matrix.php }} contracts
    runs-on: ubuntu-latest
    timeout-minutes: 10
    strategy:
      fail-fast: false
      matrix:
        php: ['8.2', '8.3', '8.4', '8.5']
    steps:
      - uses: actions/checkout@CHECKOUT # v7.0.1
        with:
          persist-credentials: false
      - name: Supported PHP syntax and pure contracts
        env:
          PHP_SERIES: ${{ matrix.php }}
        run: |
          docker run --rm --network=none -v "$PWD:/work:ro" -w /work "php:${PHP_SERIES}-cli" bash -c 'set -eu; php -v; for f in lib/*.php; do php -l "$f" >/dev/null; done; for f in tests/*.php; do case "$f" in */db-mysql.php) continue;; esac; php "$f"; done'
'''.replace('CHECKOUT',CHECKOUT)
s=replace_once(s,'  php74:\n',matrix+'  php74:\n');p.write_text(s)
put('.github/dependabot.yml','version: 2\nupdates:\n  - package-ecosystem: github-actions\n    directory: /\n    schedule:\n      interval: weekly\n    open-pull-requests-limit: 5\n')
put('.github/CODEOWNERS','# Review routing only; branch rules must separately require review.\n* @marketania\n')

p=ROOT/'README.md';s=p.read_text();heading='# '+product+'\n\n'
s=replace_once(s,heading,heading+'''<p align="center">
  <img src="docs/assets/press-tool-family.webp" alt="PressWarden blue security shield, PressHarden green policy shield, and PressGarden gold maintenance shield" width="700">
</p>

''')
install='## Install\n' if product=='PressWarden' else '## Install this distribution\n'
s=replace_once(s,install,install+'''
**Production runtime:** use an upstream-supported, security-patched PHP version. PHP 8.2–8.5 are supported at the September 2026 audit date; retained PHP 7.4 syntax tests are not a recommendation to deploy end-of-life PHP.

Read the [public-readiness audit and rollout checklist](docs/PUBLIC-READINESS.md) before fleet-wide use. Start on one staging site, verify recovery, and run as the site owner rather than root.
''');p.write_text(s)
asset=STAGING/'press-tool-family.webp'
assert hashlib.sha256(asset.read_bytes()).hexdigest()==ASSET_SHA
(ROOT/'docs/assets').mkdir(exist_ok=True)
if asset.resolve()!=(ROOT/'docs/assets/press-tool-family.webp').resolve():shutil.copyfile(asset,ROOT/'docs/assets/press-tool-family.webp')
for file in ['public-boundaries.py','public-distribution.py']:
    shutil.copyfile(STAGING/file,ROOT/'tests'/file)

findings='''- Explicitly empty or invalid `sites` directory arguments now stop with exit 2 instead of falling back to fleet inventory.
- Directory targets retain exclusions relative to the original fleet root; discovery cache keys include that scope.
- Uninstall refuses update/recovery markers, including dangling symlinks, before changing managed files.
'''
if product=='PressGarden':findings+='- Cleanup treats excluded nested installations as traversal boundaries, so a selected parent cannot clean an excluded child.\n'
if product=='PressHarden':findings+='- Plugin/theme update-preference mutations now hold the site writer lock across backup, mutation, readback and recovery.\n'
notes=f'''# {product} {version}

Public-readiness fixes and approved README branding.

{findings}
- Add regression tests for public CLI and distribution boundaries.
- Add the approved Press family artwork to the README as a repository-local asset.
- Correct project-local Codex configuration without adding runtime AI.
- Pin Actions dependencies and add supported PHP 8.2–8.5 contracts and ShellCheck error checks.

See `docs/PUBLIC-READINESS.md` for scope, prerequisites and remaining environment-specific checks. This release does not deploy to client servers, authorize production mutations, change WordPress update preferences, or certify recovery of your own data. Existing state and backups remain private.
'''
put('VERSION',version+'\n');put('docs/releases/'+version+'.md',notes)
p=ROOT/'CHANGELOG.md';s=p.read_text();index=s.find('\n## ');assert index>=0
s=s[:index]+'\n## '+version+' — 2026-09-24\n\n'+findings+'\nAdd approved README artwork, distribution regressions, supported-PHP CI, pinned Actions and corrected project Codex defaults.\n'+s[index:];p.write_text(s)
report=f'''# {product} public-readiness audit

Scope: the standalone CLI, targeting, maintenance/policy mutation safeguards, installation/update/uninstall, private-state behavior, documentation, development configuration and CI/release distribution. This is a maintainer audit, not an independent certification or a promise that all bugs are absent.

## Confirmed defects corrected for {version}

{findings}
The new `tests/public-boundaries.py` reproduces these conditions using inert temporary WordPress layouts, a benign mock preference adapter and a real held `flock`. No client website is used. Product-specific cases are skipped in unrelated tools.

## Distribution and brand

The approved three-shield panel is a normal repository-local 700-pixel WebP in `docs/assets/press-tool-family.webp`, shown at the top of the README with alternative text. It is a compressed display derivative of the approved generated image, not replacement artwork or an embedded-data SVG. An offline checksum test protects it from accidental corruption.

Project `.codex/config.toml` uses top-level model settings. The old `[models.new_thread]` table belongs to administrator-managed `requirements.toml`; repository tests previously did not detect this mistake. The CLI still has no runtime OpenAI dependency.

All referenced GitHub actions are pinned to full commit IDs. Dependabot proposes dependency updates but never merges them. CODEOWNERS routes review but does not enforce branch protection. Exact-commit release gates remain intact, and old published tags/assets are not overwritten.

## Validation and evidence

Run `bash tests/run.sh` for bounded local fixture tests and syntax checks. CI adds ShellCheck error diagnostics, PHP 8.2/8.3/8.4/8.5 contracts, retained legacy PHP 7.4 compatibility, and isolated WordPress/MySQL integration. PressGarden additionally has a real disposable-database backup/restore drill. Consult PR and exact-main Actions results for the tested commit and outcomes; a new workflow definition alone is not proof it passed.

The audit began with 48 passing fixture scripts in PressWarden, 22 in PressHarden and 18 in PressGarden. Green baseline tests did not cover the defects above. Regression probes reproduced the failures before fixes and are now included in the test runner.

## Production prerequisites

Use Linux, Bash 4+, the documented GNU utilities, current security-patched supported PHP and the relevant WP-CLI/database clients. PHP 8.2–8.5 are supported at the audit date. PHP 7.4 is end-of-life despite legacy syntax tests; check upstream support before deploying. Web PHP can differ from CLI PHP.

Run as the site owner, keep private configuration/state/backups outside webroots, inspect discovery/exclusions, and begin on one isolated staging site. Retain independent off-host backups and test restoration of your own files and data before risky work. A SQL checksum is not a restore test; selected-table dumps are not complete website backups, and concurrent/nontransactional writes may require host snapshots or quiescence.

Stop other administration before update, uninstall or mutation. Per-product locks are not a distributed cross-product lock. The uninstall marker check does not coordinate every possible external writer. WordPress bootstrap, including MU-plugins, executes trusted PHP; it is not a sandbox. Preserve incident evidence before policy or maintenance work.

Do not schedule unattended mutations until manual staging validation has passed and the target, backup scope, exit codes and logs have been reviewed. Interrupted writes can leave partial effects; inspect current state before retrying. No production website/database, installed server tool, cron job or update preference was changed by this audit.

## Environment-specific acceptance checks

Actual client restore drills, effective web PHP, HTTP cache hits/CDN behavior, credentialed external APIs, hosting permissions/engines/concurrency, and organization branch-protection requirements remain environment-specific. Public use should follow the safeguards above, not a blanket claim of universal production certification.

## References

- [PHP supported versions](https://www.php.net/supported-versions.php)
- [GitHub Actions secure use](https://docs.github.com/en/actions/reference/security/secure-use)
- [Codex configuration reference](https://learn.chatgpt.com/docs/config-file/config-reference)
- [Migration](MIGRATION.md) and [updating/recovery](UPDATING.md)
'''
put('docs/PUBLIC-READINESS.md',report)
print('Prepared',product,version,'public-readiness fixes; runtime behavior changes are scoped to confirmed boundary defects.')
