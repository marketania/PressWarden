# PressWarden Threat Intelligence Sources

PressWarden's native rules are original, behavior-based detections informed by public security research. PressWarden does **not** bundle third-party vulnerability feeds, proprietary malware signature databases, or third-party YARA collections into the MIT-licensed repository.

Source and licensing notes below were rechecked for the v1.1.0 release on 2026-09-06. Provider terms can change; administrators remain responsible for the current terms attached to credentials and data they choose to use.

## Native research references

### Established WordPress malware families

- Wordfence research on WP-VCD: https://www.wordfence.com/blog/2019/11/wp-vcd-the-malware-you-install-on-your-own-sites/
- Sucuri research on SocGholish/NDSW: https://sucuri.net/reports/2023-hacked-website-report/
- Sucuri research on Balada Injector: https://blog.sucuri.net/2023/08/sitecheck-remote-website-scanner-mid-year-2023-report.html
- Sucuri research on Sign1: https://blog.sucuri.net/2024/03/sign1-malware-analysis-campaign-history-indicators-of-compromise.html
- Sucuri research on VexTrio/redirect persistence: https://blog.sucuri.net/2024/04/javascript-malware-switches-to-server-side-redirects-dns-txt-records-tds.html

### Recent behavior informing v1.1 hardening

- Database-backed redirect/reinfector behavior and hexadecimal administrator identities: https://blog.sucuri.net/2024/11/php-reinfector-and-backdoor-malware-target-wordpress-sites.html
- Disguised plugin creating and hiding an `adminbackup` administrator: https://blog.sucuri.net/2025/07/unauthorized-admin-user-created-via-disguised-wordpress-plugin.html
- Database-stored redirect injection hidden in a Google Tag Manager container: https://blog.sucuri.net/2025/07/wordpress-redirect-malware-hidden-in-google-tag-manager-code.html
- Admin-targeted fake browser update plugin using Windows/admin gating and a remote encoded browser payload: https://blog.sucuri.net/2026/01/fake-browser-updates-targeting-wordpress-administrators-via-malicious-plugin.html
- Fake/PBN plugin using database-resident PHP webshell payloads: https://blog.sucuri.net/2026/06/wordpress-pbn-plugin-drops-dual-webshells-via-database-injection.html

Campaign names in PressWarden are hints based on characteristic behavior or documented markers. Unless a rule uses a highly specific marker, output is deliberately phrased as "campaign-like" rather than claiming attribution.

## Optional vulnerability intelligence

### Wordfence Intelligence

When the user supplies `PRESSWARDEN_WORDFENCE_TOKEN`, `./presswarden intel update` downloads both current Wordfence Intelligence V3 feeds into the user's private local intelligence directory:

- **Scanner Feed** — primary installed-version detection dataset.
- **Production Feed** — enrichment for matching vulnerability UUIDs, including CVE/CVSS metadata when available.

PressWarden matches installed core/plugin/theme versions locally against `software` / `affected_versions`. CISA KEV can then elevate a CVE match as known exploited. If the Scanner cache is unavailable but a Production cache exists, Production can be used as a compatibility fallback.

Wordfence documents the V3 vulnerability feed as available for personal and commercial use subject to the Wordfence Intelligence terms. Individual records can contain copyright/attribution metadata. PressWarden keeps feed data local, emits available Defiant/MITRE attribution for displayed matches, and avoids reproducing full third-party descriptions/remediation text in ordinary output.

Documentation: https://www.wordfence.com/help/wordfence-intelligence/v3-accessing-and-consuming-the-vulnerability-data-feed/

### CISA Known Exploited Vulnerabilities

PressWarden can cache CISA's KEV JSON catalog and correlate CVE IDs from vulnerability intelligence. KEV is used as a prioritization signal; it is not a WordPress-specific vulnerability database.

PressWarden first requests CISA's canonical JSON feed and can fall back to CISA's official GitHub mirror. CISA's `kev-data` repository states that the KEV data is distributed under CC0 1.0.

Catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

Official mirror/licensing: https://github.com/cisagov/kev-data

### Patchstack

If the user supplies `PRESSWARDEN_PATCHSTACK_KEY`, PressWarden performs product/version lookups against Patchstack's Threat Intelligence API, deduplicates component/version pairs across the fleet, and maintains a local operational TTL cache to avoid repeated requests during scans.

Patchstack access, plan permissions, rate limits, caching rights, disclosure restrictions, and permitted use are controlled by the user's Patchstack agreement. PressWarden does not bundle, publish, or redistribute Patchstack vulnerability data. The integration should be used only with a plan and terms that permit the administrator's intended operation.

Documentation: https://docs.patchstack.com/api-solutions/threat-intelligence-api/overview/

Terms: https://patchstack.com/terms-and-conditions/

### WPScan

The WPScan integration remains user-token/user-install driven. PressWarden invokes the user's WPScan CLI and does not bundle, export, or cache the WPScan vulnerability database.

WPScan's current API terms state that permanent storage and API-data caching are not permitted and that companies integrating the data into commercial services require an Enterprise account. PressWarden therefore treats WPScan as an optional external service whose license is the responsibility of the token holder.

API terms/documentation: https://wpscan.com/api/

Enterprise terms: https://wpscan.com/terms/

## External YARA support

PressWarden intentionally does not copy third-party YARA rule collections into the MIT repository. Administrators can point `PRESSWARDEN_YARA_RULES` at a rules file they independently maintain or are licensed to use.

External YARA results are review-only inside PressWarden: native severity/confidence guarantees do not apply to third-party signatures, and PressWarden will not automatically quarantine files because an external YARA rule matched.
