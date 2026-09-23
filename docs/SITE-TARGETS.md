# Website names instead of hosting paths

Examples for PressWarden's own responsibilities:

```bash
./presswarden scan example.com
./presswarden full example.com
./presswarden incident example.com
./presswarden inspect js example.com
./presswarden inspect runtime example.com
./presswarden baseline status example.com
./presswarden changes example.com
./presswarden sites
```

A website argument resolves to a **local directory**, not a remote connection. No target, or explicit `all`, uses the configured/default fleet root. A parent target includes discovered nested installations; `example.com/shop` selects that nested directory. Existing discovery limits and exclusions remain in force. Explicit empty, unknown, excluded, ambiguous or invalid targets never fall back to the fleet.

Program updates and configuration advice are not website-targeted operations. Use `sites` to inspect the discovered names and directories before choosing a target.

Security checks may retain account-level scope: a website argument does not turn host cron/SSH investigation into site-only checks. Ordinary scans do not change hardening settings or run routine maintenance. Explicit security remediation has its own authorization requirements.

## Resolution and safety

Name lookup first runs fresh structural discovery beneath the configured/default scan root. It recognizes domain folders in common layouts, including `example.com/public_html`, `example.com/httpdocs`, `example.com/htdocs` and `/var/www/example.com`. Plain domain names are lowercased; nested path case is retained. HTTP(S) URLs and trailing slashes may be pasted, but query strings, credentials, ports and traversal segments are rejected. `www.example.com` is not silently treated as `example.com`.

For otherwise unnamed directories, bounded static token reading can recognize plain literal `WP_HOME` or `WP_SITEURL` definitions in that root's `wp-config.php`. It does not execute includes/expressions, load WordPress, invoke WP-CLI, query a database or contact DNS/the website. These names identify local installations; they do not verify the domain's ownership or effective runtime URL. Dynamic definitions, parent-directory configs, IDNs not supplied as punycode, and sites with URLs only in the database can require an explicit alias.

Unknown names, duplicate names, exclusions, malformed alias files and failed discovery refuse selection with exit 2. There is no fuzzy match, first-match selection or fallback from an unknown website to the fleet. An existing relative folder named `example.com` is still treated as a website name; use `./example.com` to explicitly select it as a filesystem directory. Ordinary absolute/relative paths remain supported. The name resolver requires PHP CLI. Individual operations have their own additional dependencies; resolving a name is not an operation preflight.

`sites` prints names with local directories and marks ambiguous names. It never changes configuration or site contents. A narrowed name preserves discovered exclusions originally expressed relative to the fleet, so excluding `example.com/shop` is not lost when selecting `example.com`.

## Unnamed/custom hosting layouts

Most domain-folder installations need no mapping. For an opaque folder, create a private text file, for example `config/sites`, containing:

```text
example.com=/home/account/public_html
client.example=/var/www/client-project
```

Set its absolute path in private `config/config`:

```bash
PRESSWARDEN_SITE_ALIASES_FILE="/home/account/PressWarden/config/sites"
```

Values are data, not shell commands. The alias must point to an already discovered, non-excluded WordPress installation inside the configured scan root; it cannot broaden scope or bypass exclusions. Multiple aliases can point to one installation, but one alias resolving to multiple installations is refused. The file is limited to 256 KiB and must be a regular non-symlink file. Keep it private and outside served directories. Updating program code preserves private configuration and this untracked mapping file.

## PHP investigation versus configuration

`inspect runtime` inspects local PHP auto-load/remote-include directives as text for persistence evidence. It does not contact a hosting API or establish effective web PHP settings. A directive match may be legitimate, including a WAF, and is not proof of malware.

Detailed PHP configuration and optional provider comparison belong to PressHarden. Locking and policy mutation also belong to PressHarden; cache and routine database/file maintenance belong to PressGarden. See the [migration mapping](MIGRATION.md). Neither sibling is required to run this security tool.
