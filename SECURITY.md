# Security policy

`guard` is a deterministic, offline, stdlib-only detector. It has no network surface and no
dependencies, so its attack surface is the detection logic itself.

## Reporting

Report vulnerabilities (e.g. a bypass that hides a real secret/injection/PII from the gate, or
a ReDoS in a pattern) privately via GitHub Security Advisories on this repo, or by email to the
maintainer. Please include a minimal reproducing input.

## Scope / known limits

`guard` is a heuristic first-gate, not a complete guarantee — see "Honest limits" in the README.
Missed detections on **obfuscated/novel** inputs are known trade-offs, not vulnerabilities. A
**bypass of a pattern that should clearly match**, or a pathological-input slowdown, is in scope.
