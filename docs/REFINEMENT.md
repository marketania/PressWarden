# Refinement checkpoint

Baseline: `d7867965a9b9d759568ef1a2503e394b4baa8e99` (2.0.1).
The local source tree was verified against GitHub tree
`64bc7740b1f17c9955ded49025ede47562f6e6f5` before edits. Its complete local
fixture suite passed 50 scripts with no syntax or test failures on PHP 8.4.23.

## Corrected in this pass

Targeted inert probes showed that the native core verifier could report clean
for a symlinked extra directory, an expected file linked outside the selected
site, or a cached manifest containing a parent traversal. The existing green
suite did not cover these cases.

The native verifier is now a separate, testable PHP module. It validates manifest
paths/digests and file identity, does not follow links, treats directory traversal
errors as incomplete, bounds hashing and enumeration, and refuses to overwrite
result files. Missing and mismatched regular files remain integrity findings;
extra regular files remain review conditions, not proof of malware. Incomplete
sites are excluded from interactive core remediation. No WordPress code or
suspicious PHP is executed by this verifier.

Limits per site: 64 MiB per hashed file, 512 MiB total hashed content, 50,000
core-tree entries, and 32 nested directory levels. Manifests are bounded to
4 MiB and 20,000 entries. Hitting a limit is incomplete, never clean. Official
checksum manifests are validated before cache reuse; MD5 here is the upstream
WordPress integrity contract, not a new cryptographic publisher signature.

## Evidence and release boundary

`tests/core-verification.py` covers clean static inspection, symlinks, hardlinks,
special files, unreadable directories under reduced privileges, traversal,
malformed digests, terminal controls, changed/missing/extra files, oversized
files and exclusive result publication. Attribution tests retain the original
license, provenance, artwork hashes, credit wording and links.

Run `bash tests/run.sh` for the complete local gate. Consult this PR's CI for
actual integration and PHP-matrix results; local tests alone do not establish
all-host readiness. This pass does not publish a release, change tags, alter
branch protection, or touch production sites. Files can change concurrently;
identity checks reduce but do not eliminate filesystem race risks. Investigate
unstable or compromised sites from an isolated snapshot where practical.

## Sources and decisions

- [WP-CLI core checksum verification](https://developer.wordpress.org/cli/commands/core/verify-checksums/): retain static integrity inspection; no WordPress bootstrap.
- [WordPress hardening](https://developer.wordpress.org/advanced-administration/security/hardening/): preserve evidence and recovery, not blanket security guarantees.
- [GitHub Actions secure use](https://docs.github.com/en/actions/reference/security/secure-use): retain pinned actions, read-only PR permissions, and separate release authority.
- [NIST SSDF 1.1, final](https://csrc.nist.gov/pubs/sp/800/218/final): reproducible defects, regression tests and reviewable changes; no certification claim. The consulted SSDF 1.2 page labels it an initial public draft.
