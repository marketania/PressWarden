# LiteSpeed Cache Management

PressWarden exposes the complete LiteSpeed Cache for WordPress WP-CLI surface through one guarded interface:

```bash
presswarden litespeed <area> <action> [arguments] --target <site|all>
```

Use `presswarden litespeed help` to see the supported areas and actions directly in the terminal.

Omit `--target` to use the configured fleet. Use `--target example.com` for one website. `--site` is accepted as an alias for `--target`.

The existing `presswarden litespeed-db status|optimize [target]` command remains available. Database status and default-blog optimize-all now share the same implementation and reporting across both command styles. `status` is a PressWarden availability check, not an upstream `litespeed-database status` command.

Database maintenance in `db` and `full` also offers the same LiteSpeed cleanup with explicit consent. See [database integration and safety](LITESPEED-DATABASE.md).

## Fleet status

```bash
presswarden litespeed status --target all
```

This checks WordPress/WP-CLI bootstrap, LiteSpeed Cache installation and activation, plugin version, and availability of all eight documented LiteSpeed command families.

## Options

```bash
presswarden litespeed option get cache-priv --target example.com
presswarden litespeed option all --format=json --target example.com
presswarden litespeed option set cache-priv false --target example.com
presswarden litespeed option export --target example.com
presswarden litespeed option export --filename=/tmp/lscache-options.txt --target example.com
presswarden litespeed option import /path/options.txt --target example.com
presswarden litespeed option import-remote https://example.com/options.txt --target example.com
presswarden litespeed option reset --target example.com
```

PressWarden creates a private pre-change option export before option mutations. Fleet exports without `--filename` create separate private files per site. A single explicit `--filename` is refused for multi-site fleet execution to prevent overwriting exports.

Output that appears to contain API keys, tokens, passwords, secrets, credentials, or private/SSL keys is redacted by default. To intentionally display a sensitive `option get` value, set `PRESSWARDEN_LITESPEED_SHOW_SENSITIVE=1` for that invocation.

## Purge

```bash
presswarden litespeed purge network-list --target example.com
presswarden litespeed purge all --target example.com
presswarden litespeed purge url https://example.com/page/ --target example.com
presswarden litespeed purge blog 2 --target example.com
presswarden litespeed purge category 1 3 5 --target example.com
presswarden litespeed purge tag 1 3 5 --target example.com
presswarden litespeed purge post-id 10 20 30 --target example.com
```

On WordPress multisite, LiteSpeed documents `purge all` as purging every site in the network for that WordPress installation.

## Presets

```bash
presswarden litespeed presets backups --target example.com
presswarden litespeed presets apply basic --target example.com
presswarden litespeed presets restore 1667485245 --target example.com
```

PressWarden also takes its own private option backup before applying or restoring a preset.

## Image optimization

```bash
presswarden litespeed image status --target example.com
presswarden litespeed image push --target example.com
presswarden litespeed image pull --target example.com
presswarden litespeed image clean --target example.com
presswarden litespeed image switch optm --target example.com
presswarden litespeed image switch orig --target example.com
presswarden litespeed image remove-backups --target example.com
```

`remove-backups` permanently removes original image backups. Interactive runs require confirmation. Non-interactive execution additionally requires:

```bash
PRESSWARDEN_INTERACTIVE=0 PRESSWARDEN_LITESPEED_DESTRUCTIVE=1 presswarden litespeed image remove-backups --target example.com
```

## QUIC.cloud online services

```bash
presswarden litespeed online init --target example.com
presswarden litespeed online sync --format=json --target example.com
presswarden litespeed online services --format=table --target example.com
presswarden litespeed online nodes --format=table --target example.com
presswarden litespeed online ping img_optm --force --target example.com
presswarden litespeed online cdn-status --target example.com
```

Supported `ping` services are `img_optm`, `ccss`, `ucss`, `lqip`, and `vpi`.

To link a QUIC.cloud account, keep the API key out of shell history:

```bash
export QC_API_KEY='...'
presswarden litespeed online link --email=you@example.com --api-key-env=QC_API_KEY --target example.com
```

To initialize QUIC.cloud CDN with Cloudflare Integration:

```bash
export CF_API_TOKEN='...'
presswarden litespeed online cdn-init --method=cfi --cf-token-env=CF_API_TOKEN --target example.com
```

Other CDN methods are `cname` and `ns`. `--ssl-cert=PATH` and `--ssl-key=PATH` are passed through when supplied.

PressWarden deliberately rejects literal `--api-key=` and `--cf-token=` arguments so credentials are not casually stored in shell history. Command output is redacted for secret-like fields.

## Debug/support report

```bash
presswarden litespeed debug send --target example.com
```

This sends an environment report to LiteSpeed support. Interactive execution requires confirmation. Non-interactive execution requires both:

```bash
PRESSWARDEN_INTERACTIVE=0 PRESSWARDEN_LITESPEED_EXTERNAL=1 presswarden litespeed debug send --target example.com
```

## Crawler

```bash
presswarden litespeed crawler list --target example.com
presswarden litespeed crawler enable 2 --target example.com
presswarden litespeed crawler disable 2 --target example.com
presswarden litespeed crawler run --target example.com
presswarden litespeed crawler reset --target example.com
```

The LiteSpeed crawler must also be permitted at the server level. PressWarden does not modify LiteSpeed Web Server/Apache server configuration to enable the crawler.

## Database

```bash
presswarden litespeed database status --target example.com
presswarden litespeed database clear-posts --target example.com
presswarden litespeed database clear-comments --target example.com
presswarden litespeed database clear-trackbacks --target example.com
presswarden litespeed database clear-transients --target example.com
presswarden litespeed database optimize-tables --target example.com
presswarden litespeed database optimize-all --target example.com
```

For WordPress multisite, specify a blog ID:

```bash
presswarden litespeed database optimize-all --blog=2 --target example.com
```

LiteSpeed documents `litespeed-database` as the exception to its normal WP-CLI behavior: these commands do not accept standard WP-CLI global parameters. PressWarden therefore changes into each WordPress installation and executes the database command without `--path`, `--skip-plugins`, `--skip-themes`, or other global parameters.

## Safety model

Read-only inventory commands do not require confirmation. Mutating commands require confirmation in interactive mode. `PRESSWARDEN_INTERACTIVE=0` is treated as an explicit automation choice, except irreversible image backup removal and support-report upload, which require the additional opt-ins documented above.

Operations are executed sequentially across a fleet to limit database/server load and make per-site failures visible. Sites without active LiteSpeed Cache are skipped. WordPress bootstrap failures or missing LiteSpeed commands are reported as errors rather than successful skips.

### Explicit database blog validation

For database actions with `--blog=ID`, PressWarden requires a positive integer and verifies that it identifies an existing, non-deleted/non-archived/non-spam blog in the targeted multisite installation. Single-site installs and unavailable IDs are refused before cleanup. The target is checked again immediately before dispatch. This guards against LiteSpeed versions that print an invalid-blog error but continue operating on the default blog; unrelated concurrent WordPress changes cannot be made globally transactional.
