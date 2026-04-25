# MITRE CWE™ 4.19.1 — PDF catalog (external resource)

This file replaces `cwe_latest.pdf`, the human-readable form of the same
catalog data already shipped as `agents/cwe/cwe_agent/data/cwe_catalog.json`.
The PDF was previously tracked in this repository (~37 MB).

## Source

- **Upstream URL:** https://cwe.mitre.org/data/pdf/cwec_v4.19.1.pdf
- **Version:** CWE 4.19.1
- **License:** [CWE Terms of Use](https://cwe.mitre.org/about/termsofuse.html)
- **Copyright:** © 2006-2025 The MITRE Corporation. All rights reserved.
- **SHA-256:** `6bc9b1244abed043a0e184c90691ebf7ecda8c4c8d3964f7bea3a81860102bc0`

## How to fetch

```bash
curl -fsSL https://cwe.mitre.org/data/pdf/cwec_v4.19.1.pdf -o /tmp/cwe_latest.pdf
sha256sum /tmp/cwe_latest.pdf  # verify against the SHA-256 above
```

## When you need this

You generally don't. The runtime CWE agent reads
`agents/cwe/cwe_agent/data/cwe_catalog.json`, which is committed. The PDF
is only useful if you want to read CWE entries with MITRE's official
formatting and cross-references for human review.

See [NOTICE](../../../NOTICE) and
[THIRD_PARTY_LICENSES.md](../../../THIRD_PARTY_LICENSES.md) for the full
attribution.
