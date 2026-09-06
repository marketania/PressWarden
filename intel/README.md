# PressWarden Native Threat Intelligence

PressWarden uses an **exception-first behavioral model**. The native intelligence registry describes what a detector means; executable detection logic lives in version-controlled checks/helpers where it can be syntax-checked and regression-tested.

This is intentional. PressWarden does not interpret a large third-party-style regex/signature DSL at runtime, because a loose signature collection would make false-positive controls, portability, and code review harder to reason about on shared hosting.

## Registry

`native-rules.tsv` is the authoritative metadata registry for native rule IDs.

Columns:

| Field | Meaning |
|---|---|
| `id` | Stable PressWarden rule ID. |
| `category` | Primary technical surface such as `php`, `javascript`, `database`, or `campaign`. |
| `family` | Behavioral family or campaign context. |
| `severity` | Operational impact when the rule is satisfied. |
| `confidence` | Confidence in the detection, not certainty of campaign attribution. |
| `type` | `behavior` or `campaign`. |
| `owner` | Check/helper responsible for the executable detector. |
| `date_added` | First date the rule entered the native registry. |
| `date_updated` | Last material rule/metadata update. |
| `source` | `PressWarden native` or the public research source that informed the behavior. |
| `reference` | Repository path or public research URL. |
| `name` | Human-readable rule name. |

`campaigns.tsv` is a smaller knowledge map used to document characteristic families and the evidence that can suggest them. Campaign entries are **context**, not a license to over-attribute a finding.

## Detection policy

A dangerous-looking primitive is not a malware verdict by itself. Native rules should normally require compound evidence such as:

- request input + decode/decrypt + execution sink;
- remote fetch + filesystem write + execution/include behavior;
- packed byte data + XOR/`chr()`/`ord()` reconstruction + browser/network sink;
- decoded JavaScript + dynamic script/iframe insertion;
- suspicious database persistence structure + decoded remote-node behavior;
- highly specific campaign markers with a low expected legitimate collision rate.

Examples that **must not** become malware solely because they occur are `base64_decode()`, `file_get_contents()`, `curl_exec()`, `chmod(0777)`, `wp_enqueue_script()`, `chr()`, and `ord()`.

## Severity vs. confidence

Severity answers: **How bad would this behavior be if the finding is correct?**

Confidence answers: **How strongly does the collected evidence support this finding?**

A campaign hint can therefore be high severity but medium confidence. PressWarden should phrase those findings as `-like`/behavioral unless a highly specific marker or external authoritative source justifies stronger attribution.

## External intelligence

External feeds are not copied into this MIT repository. Wordfence, CISA KEV, Patchstack, and WPScan remain optional integrations governed by their own current terms. See `SOURCES.md`.

PressWarden also does not bundle third-party YARA collections. Administrators may independently use external rule ecosystems under the licenses that apply to those rules; native PressWarden detection remains functional with zero external rule files or API keys.

## Adding a native rule

A new rule should normally include all of the following in the same change:

1. A stable ID and metadata row in `native-rules.tsv`.
2. Executable detector logic in the owning check/helper.
3. A malicious fixture that must trigger.
4. A benign lookalike that must not trigger (or must remain REVIEW when that is the intended boundary).
5. Research/source documentation when behavior was derived from a named public campaign.
6. README/changelog updates when the rule materially changes user-facing coverage.

Rule count is never a release goal. High signal and explainable evidence are.
