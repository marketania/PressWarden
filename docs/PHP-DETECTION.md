# PHP intelligence: evidence and limitations

PressWarden 1.1.4 replaces proximity/whole-file matching in `php-threat-intel` (PW-PHP-004/005/006) with a native PHP token-based recognizer. This change does not replace `phpquick`, `phpdeep`, the packed-XOR/White-Engine detector, campaign checks, integrity checks or database scanning.

## What is recognized

- **PW-PHP-004 (ALERT):** a request-selected callable reaches a supported direct invocation or `call_user_func`/`call_user_func_array`. Simple aliases are tracked. An explicitly strict literal dispatch allowlist is not arbitrary request-controlled dispatch; that is not a guarantee that its allowed functions are safe.
- **PW-PHP-005 (ALERT):** POST username and password fields reach the same recognized remote request with TLS verification disabled. cURL handle identity, option order, overwritten payloads, restored verification and simple handle aliases matter. Merely handling logins, decoding data and using HTTP elsewhere in a file is insufficient.
- **PW-PHP-006 (REVIEW):** supported enclosing admin/capability/Windows conditions plus a remote response, base64 decoding and an actual raw output or script argument receiving the decoded value. A remote URL alone, an escaped status message, a local file read, a script version argument, or unrelated utility methods do not qualify. This is contextual evidence, not proof of malicious intent or campaign attribution.

The source is passed to PHP's [tokenizer](https://www.php.net/manual/en/function.token-get-all.php) as data, never included or evaluated. No decoded URL is contacted. Comments and quoted examples cannot become code evidence. Function/method scopes, variable case, assignment order and supported reassignments are respected. Conditions do not leak from unrelated functions. Multiple matching rule IDs in one file can be retained.

Findings show the rule ID, source line and recognized behavior. They omit source bodies, payloads, URL values and credentials; control characters in paths are escaped. These three rules never offer the generic delete/quarantine prompt. Confirm provenance and investigate before taking action.

## Coverage is deliberately limited

This is an intraprocedural pattern recognizer, not a complete PHP interpreter, control-flow graph, interprocedural taint engine or syntax checker. It does not prove reachability or exploitability. It recognizes simple expressions and supported positive `if` conditions; arbitrary wrappers, dynamic URLs, reference side effects, closure captures, interpolated strings, heredoc/nowdoc payloads, guard-clause reasoning, branch joins and complex expressions remain outside that subset. Unsupported expressions invalidate or discard facts rather than invent relationships. The complementary scanners still cover other patterns. A clean result means no recognized chain, not a guarantee that PHP is safe.

The 5 MiB file limit and existing directory pruning are retained. PHP CLI and its tokenizer extension are required. No Node.js, Composer package or API key is required. Tokenization uses PHP's native token array, so dense inputs can require substantially more memory than their file size; allocation failures and explicit token/nesting/binding limits must produce INCOMPLETE, never CLEAN. A 4.62 MB comment-heavy fixture is tested under 64 MiB, but that is not a universal maximum-memory guarantee for all PHP inputs.

A bounded 256-entry process-local SHA-256 cache reuses results for identical bytes while keeping every matched site's path. It never trusts a filename, mtime, prior scan or product name. No source text is retained in the result cache.

Read/discovery/dependency/validator and evidence-output failures return exit 2. Findings emitted before a failure are retained where available; no per-rule clean result is printed for an incomplete pass.

## Tests

```bash
php -d memory_limit=64M tests/php-flow.php
php -d memory_limit=64M tests/php-memory.php
bash tests/php-intel-runtime.sh
bash tests/php-upstream.sh   # separate network integration test
```

The upstream test reuses the SHA-256 pins for official Elementor 4.2.4, Wordfence 9.0.0 and WordPress 7.1. It reads PHP as inert data, checks clean reference files, and tests three injected copies of Wordfence's real `wfUtils.php`. Downloads, integrity failures and incomplete analyses fail the test rather than silently skipping it. These results do not certify any live client installation. Third-party packages are temporary test inputs, not bundled with PressWarden.
