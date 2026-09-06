# PressWarden Threat Intelligence Sources

PressWarden's native rules are original, behavior-based detections informed by public security research. PressWarden does **not** bundle third-party vulnerability feeds, YARA repositories, or proprietary signature databases.

## Native research references

- Wordfence research on WP-VCD: https://www.wordfence.com/blog/2019/11/wp-vcd-the-malware-you-install-on-your-own-sites/
- Sucuri research on SocGholish/NDSW: https://sucuri.net/reports/2023-hacked-website-report/
- Sucuri research on Balada Injector: https://blog.sucuri.net/2023/08/sitecheck-remote-website-scanner-mid-year-2023-report.html
- Sucuri research on Sign1: https://blog.sucuri.net/2024/03/sign1-malware-analysis-campaign-history-indicators-of-compromise.html

Campaign names in PressWarden are hints based on characteristic behavior or documented markers. Unless a rule uses a highly specific marker, output is deliberately phrased as "campaign-like" rather than claiming attribution.

## Optional vulnerability intelligence

### Wordfence Intelligence

When the user supplies `PRESSWARDEN_WORDFENCE_TOKEN`, `./presswarden intel update` downloads both Wordfence Intelligence V3 feeds into the user's private local intelligence directory:

- **Scanner Feed** — used as the primary installed-version detection dataset because Wordfence documents it for vulnerability-scanner/detection use.
- **Production Feed** — used to enrich matching vulnerability UUIDs with additional metadata such as CVE/CVSS when available.

PressWarden matches installed core/plugin/theme versions locally against the `software` / `affected_versions` data. CISA KEV can then elevate a CVE match as known exploited. If the Scanner cache is unavailable but an older Production cache exists, PressWarden can use Production as a compatibility fallback.

Neither Wordfence feed is bundled or redistributed by PressWarden. Cached feed data stays on the user's system. PressWarden also avoids reproducing third-party vulnerability descriptions/remediation text in its normal match output; it reports operational facts and source references instead.

Wordfence's V3 documentation describes token authentication, Scanner/Production feed schemas, copyright metadata, and downstream attribution/licensing requirements:

https://www.wordfence.com/help/wordfence-intelligence/v3-accessing-and-consuming-the-vulnerability-data-feed/

Administrators and downstream consumers remain responsible for complying with the feed's current terms, copyright notices, source attribution, and any CVE/CNA attribution requirements.

### CISA Known Exploited Vulnerabilities

PressWarden can cache CISA's public KEV JSON catalog and correlate CVE IDs from vulnerability intelligence. KEV is used as a prioritization signal; it is not a WordPress-specific vulnerability database. PressWarden first requests CISA's canonical JSON feed and can fall back to CISA's official GitHub mirror if needed.

https://www.cisa.gov/known-exploited-vulnerabilities-catalog

### Patchstack

If the user supplies `PRESSWARDEN_PATCHSTACK_KEY`, PressWarden can perform cached product/version lookups against Patchstack's Threat Intelligence API. Patchstack access, plan permissions, and rate limits are controlled by Patchstack; PressWarden does not bundle or redistribute Patchstack data.

https://docs.patchstack.com/api-solutions/threat-intelligence-api/overview/

### WPScan

The existing optional WPScan integration remains user-token/user-install driven. PressWarden does not redistribute the WPScan vulnerability database.

## External YARA support

PressWarden intentionally does not copy third-party YARA rule collections into the MIT-licensed repository. Future/external YARA execution can point at rules the administrator is independently licensed to use.
