# PressWarden Threat Intelligence Sources

PressWarden's native rules are original, behavior-based detections informed by public security research. PressWarden does **not** bundle third-party vulnerability feeds, YARA repositories, or proprietary signature databases.

## Native research references

- Wordfence research on WP-VCD: https://www.wordfence.com/blog/2019/11/wp-vcd-the-malware-you-install-on-your-own-sites/
- Sucuri research on SocGholish/NDSW: https://sucuri.net/reports/2023-hacked-website-report/
- Sucuri research on Balada Injector: https://blog.sucuri.net/2023/08/sitecheck-remote-website-scanner-mid-year-2023-report.html
- Sucuri research on Sign1: https://blog.sucuri.net/2024/03/sign1-malware-analysis-campaign-history-indicators-of-compromise.html
- Sucuri research on WordPress PHP reinfector/redirect persistence, Base64 remote-node options, rogue hexadecimal administrators, and VexTrio redirects: https://blog.sucuri.net/2024/11/php-reinfector-and-backdoor-malware-target-wordpress-sites.html

Campaign names in PressWarden are hints based on characteristic behavior or documented markers. Unless a rule uses a highly specific marker, output is deliberately phrased as "campaign-like" rather than claiming attribution.

## Optional vulnerability intelligence

### Wordfence Intelligence

When the user supplies `PRESSWARDEN_WORDFENCE_TOKEN`, `./presswarden intel update` downloads both Wordfence Intelligence V3 feeds into the user's private local intelligence directory:

- **Scanner Feed** — used as the primary installed-version detection dataset because Wordfence documents it for vulnerability-scanner/detection use.
- **Production Feed** — used to enrich matching vulnerability UUIDs with additional metadata such as CVE/CVSS when available.

Wordfence's current V3 documentation says the vulnerability feed is publicly available free for personal and commercial use, requires token authentication, and defines separate Scanner/Production use cases. It also carries per-record copyright metadata and requires applicable downstream attribution, including MITRE copyright claims when relevant records are displayed.

PressWarden matches installed core/plugin/theme versions locally against the `software` / `affected_versions` data. CISA KEV can then elevate a CVE match as known exploited. If the Scanner cache is unavailable but an older Production cache exists, PressWarden can use Production as a compatibility fallback.

Neither Wordfence feed is bundled or redistributed by PressWarden. Cached feed data stays on the user's system. PressWarden also avoids reproducing third-party vulnerability descriptions/remediation text in its normal match output; it reports operational facts, source references, and available record attribution instead.

Current Wordfence V3 documentation and terms entry point:

https://www.wordfence.com/help/wordfence-intelligence/v3-accessing-and-consuming-the-vulnerability-data-feed/

Administrators and downstream consumers remain responsible for complying with the feed's current terms, copyright notices, source attribution, and any CVE/CNA attribution requirements.

### CISA Known Exploited Vulnerabilities

PressWarden can cache CISA's public KEV JSON catalog and correlate CVE IDs from vulnerability intelligence. KEV is used as a prioritization signal; it is not a WordPress-specific vulnerability database. PressWarden first requests CISA's canonical JSON feed and can fall back to CISA's official GitHub mirror if needed.

CISA's official `cisagov/kev-data` mirror states that the repository data is licensed under **CC0**, allowing universal public-domain use. This makes KEV suitable for PressWarden's local correlation/cache model without importing a proprietary signature database.

https://www.cisa.gov/known-exploited-vulnerabilities-catalog
https://github.com/cisagov/kev-data

### Patchstack

If the user supplies `PRESSWARDEN_PATCHSTACK_KEY`, PressWarden performs deduplicated product/version lookups against Patchstack's documented Threat Intelligence API and keeps local lookup responses only to reduce repeated calls during the configured cache TTL.

Patchstack's current documentation lists the v2 base URL `https://patchstack.com/database/api/v2/`, `PSKey` header authentication, and `GET /product/{type}/{name}/{version}` for product/version matching. Access level, pricing, quota, and endpoint permissions are controlled by Patchstack; current Extended Threat Intelligence access is custom-priced/activated on request, while legacy Standard documentation remains for existing integrations.

PressWarden does not bundle or redistribute Patchstack vulnerability data.

https://docs.patchstack.com/api-solutions/threat-intelligence-api/overview/
https://docs.patchstack.com/api-solutions/threat-intelligence-api/extended/

### WPScan

The optional WPScan integration remains user-token/user-install driven and invokes the user's WPScan CLI at scan time. PressWarden deliberately does **not** build a persistent WPScan vulnerability cache or copy the WPScan database into the repository.

WPScan's current API conditions explicitly state that permanent storage and caching of API vulnerability data are not permitted, that the database data is copyrighted, and that companies integrating the data/services into their own services must use an Enterprise account. Users remain responsible for using an account/token appropriate to their use case.

https://wpscan.com/api/

## External YARA compatibility

PressWarden intentionally does not copy third-party YARA rule collections into the MIT-licensed repository. Administrators may independently run or integrate YARA rules they are licensed to use. Native PressWarden scanning must remain fully functional with zero YARA files and zero external API keys.
