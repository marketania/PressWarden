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

PressWarden can download the Wordfence Intelligence V3 Production Feed when the user supplies `PRESSWARDEN_WORDFENCE_TOKEN`. The feed is not redistributed with PressWarden. Wordfence's current V3 documentation describes token-authenticated Production and Scanner feeds and their usage/licensing requirements:

https://www.wordfence.com/help/wordfence-intelligence/v3-accessing-and-consuming-the-vulnerability-data-feed/

PressWarden stores the downloaded feed only in the user's local runtime/intelligence directory.

### CISA Known Exploited Vulnerabilities

PressWarden can cache CISA's public KEV JSON catalog and correlate CVE IDs from vulnerability intelligence. KEV is used as a prioritization signal; it is not a WordPress-specific vulnerability database.

https://www.cisa.gov/known-exploited-vulnerabilities-catalog

### Patchstack

If the user supplies `PRESSWARDEN_PATCHSTACK_KEY`, PressWarden can perform cached product/version lookups against Patchstack's Threat Intelligence API. Patchstack access and plan limits are controlled by Patchstack; PressWarden does not redistribute Patchstack data.

https://docs.patchstack.com/api-solutions/threat-intelligence-api/overview/

### WPScan

The existing optional WPScan integration remains user-token/user-install driven. PressWarden does not redistribute the WPScan vulnerability database.

## External YARA support

PressWarden intentionally does not copy third-party YARA rule collections into the MIT-licensed repository. Future/external YARA execution can point at rules the administrator is independently licensed to use.
