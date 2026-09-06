# PressWarden native threat intelligence

PressWarden's native threat-intelligence layer is intentionally small, reviewable, and behavior-first. It is not a bulk signature dump.

## Architecture

The native catalog uses a manifest-plus-detector model:

- `native-rules.tsv` is the stable rule manifest and metadata index.
- `campaigns.tsv` maps campaign names to the durable evidence PressWarden understands.
- `SOURCES.md` records public research and third-party data/licensing boundaries.
- executable detection logic remains in `checks/` and small pure helpers in `lib/`, where compound behavior and false-positive controls can be tested directly.

This is preferable to a generic regex-rule DSL for v1.1 because several high-confidence detections require tokenization, data-flow approximations, WordPress context, database queries, or multi-primitive scoring. A flat text rule that simply lists `base64_decode`, `eval`, `chr`, or `wp_enqueue_script` would be noisier and easier to misuse.

## Rule metadata schema

`native-rules.tsv` columns are:

```text
id
category
severity
confidence
type
name
owner
source
reference
date_added
date_updated
```

Rule IDs are stable public identifiers. Existing IDs should not be repurposed for unrelated behavior.

### Type

- `behavior` — compound technical behavior detected directly by PressWarden.
- `campaign` — a high-specificity marker or a campaign-oriented knowledge mapping.
- `ioc` — reserved for narrowly justified native indicators when a durable IOC is appropriate.

PressWarden generally prefers behavior over IOCs because campaign domains, filenames, and infrastructure rotate quickly.

### Severity

- `critical` — strong evidence of code execution, credential theft, remote payload loading, or similarly dangerous compromise behavior.
- `high` — strong security impact but with less direct execution/exfiltration certainty.
- `review` — potentially malicious persistence or unusual content that requires administrator context before treating it as compromise.

### Confidence

Confidence describes how specifically the observed evidence maps to malicious behavior, not how severe the impact would be.

- `high` — the detector requires a compound chain with a low expected benign match rate.
- `medium` — the behavior is suspicious and research-supported but can overlap legitimate customization or administration.

## Native rule contract

A native PressWarden rule should normally satisfy all of the following:

1. **Compound evidence.** A single PHP/JavaScript function is not malware by itself.
2. **Context.** Prefer execution flow, WordPress location, database field role, or corroborating behavior.
3. **Malicious + benign regressions.** Every new family of logic should include a fixture that must trigger and a lookalike that must stay clean.
4. **Conservative remediation.** Threat-intelligence matches never justify automatic deletion on their own.
5. **Portable runtime.** No runtime Bash process substitution; shared-host restrictions remain a first-class constraint.
6. **No secret dependency.** Native rules work with zero API credentials.
7. **Attribution restraint.** Generic behavior is reported as campaign-like unless a high-specificity marker supports stronger attribution.

## External intelligence

External vulnerability feeds are adapters, not native rule content. Cached provider data lives under the user's runtime tree and is never committed to the repository.

External YARA support follows the same separation: `PRESSWARDEN_YARA_RULES` can point to an administrator-supplied rules file, but PressWarden ships no third-party `.yar`/`.yara` collections. External YARA matches are review-only because their severity, licensing, and false-positive model are outside the native `PW-*` contract.

## Adding a rule

When adding a native rule:

1. add detection logic to the narrowest appropriate `checks/` module or a reusable pure helper in `lib/`;
2. add a stable `PW-*` entry to `native-rules.tsv`;
3. add campaign mapping only when public research supports it;
4. document the source in `SOURCES.md` when external research materially informed the detector;
5. add malicious and benign regression fixtures;
6. run the full GitHub Actions suite before considering the change complete.
