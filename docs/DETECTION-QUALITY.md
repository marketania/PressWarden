# Detection quality and scan completeness

## JavaScript findings

PressWarden 1.1.2 replaces whole-file and proximity-based JavaScript correlations with a bounded, read-only lexical recognizer. It distinguishes executable tokens from comments, quoted examples, regular-expression literals, and template text. It tracks recognized literal decoders, simple aliases, assignment order, reassignment, script objects, and enclosing visitor conditions without evaluating JavaScript or requesting decoded URLs.

An encoded HTTP URL plus visitor targeting is **REVIEW**, not proof of malware or campaign attribution. IP addresses are not automatically malicious. Higher-confidence decoded execution and executable-URI patterns can produce **ALERT**. Neither JavaScript verdict offers the generic delete/quarantine prompt: verify provenance and inspect the evidence before remediation. The native catalog's medium confidence for contextual browser-loader/redirect rules is not a claim that a matched file is infected.

Findings include the stable rule ID, source line, recognized sink, and a hostname when applicable. Decoded URL passwords, query strings, fragments, and payload bodies are not printed. Paths containing terminal control characters are escaped. No Elementor, Wordfence, CodeMirror, LiteSpeed, or other package-name allowlist is used.

### Fleet efficiency

A scan can reuse analysis results for identical file contents through a bounded 512-entry, process-local SHA-256 cache. Each file is read and hashed again; names, modification times, and earlier scans are not trusted. Different bytes or different JavaScript/HTML parsing modes require separate analysis. Cached entries contain findings metadata, not source bodies, and every matched site's own path is still reported. A brief scan line shows unique analyses and reused results.

### Scope and limitations

This is not a complete ECMAScript parser, interpreter, interprocedural taint engine, or a guarantee that a file is safe. It intentionally recognizes a conservative subset: literal decoding and simple same-scope flows, including supported enclosing `if` blocks. Dynamic runtime values, arbitrary custom decoders, cross-function flows, interpolated template expressions, and oversized expressions remain outside that subset. Normal routing, minification, and decoding alone are not findings. A clean result means no recognized high-signal chain in the analyzed scope, not that every possible behavior was evaluated.

JavaScript checks retain a 6 MiB file-size scope and directory pruning. PHP is required; Node.js is not. Missing PHP, read failures, and validator failures produce an incomplete result rather than a clean verdict. The original PHP, WordPress, database, integrity, vulnerability, and campaign checks remain complementary layers.

## Suite exit codes and JSON

- `0`: completed checks have no findings. Deliberately skipped optional checks may still make coverage partial.
- `1`: completed checks contain findings.
- `2`: a check failed, a required check is missing, no sites were discovered, no checks completed, or report generation failed. Findings collected before a failure are retained where available.

`ALL CLEAR` is reserved for suites with completed checks and no skipped or failed checks. Optional skips are shown as `NO FINDINGS IN COMPLETED CHECKS`; failures are shown as `INCOMPLETE`.

Existing JSON fields are retained. The summary adds `coverage_status` (`complete`, `partial`, or `incomplete`), `checks_completed`, `checks_skipped`, and `checks_failed`. Completeness describes execution of the selected checks, not universal malware-detection coverage.

## Validation

Run the offline tests with:

```bash
php -d memory_limit=32M tests/js-flow.php
php -d memory_limit=32M tests/js-memory.php
bash tests/runtime-reliability.sh
```

`bash tests/upstream-corpus.sh` is a separate network integration test. It downloads pinned official WordPress.org packages into a temporary directory, verifies their SHA-256 checksums, reads eligible JavaScript as data, tests both clean files and copies with a synthetic appended injection, and deletes its workspace. It does not install or execute the packages, contact a client site, or bundle third-party code or signature databases into PressWarden. CI fails on download/checksum errors rather than reporting an untested corpus as passing.

The pinned reference corpus uses Elementor 4.2.4, Wordfence 9.0.0, and WordPress 7.1. It contains 1,388 eligible JavaScript files; the 13.4 MB WordPress vips worker is explicitly outside the size scope. These reference-package results do not certify the contents of any live client installation. The injection controls exercise actual upstream Elementor and CodeMirror bundles, not just tiny lookalike examples.

The normal preservation, discovery, White-Engine, PHP/database, incident, fleet, YARA, credential, and Wordfence-streaming regressions remain in the original CI workflow.
