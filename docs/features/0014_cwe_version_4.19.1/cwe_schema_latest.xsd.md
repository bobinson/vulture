# MITRE CWE™ schema XSD (external resource)

This file replaces `cwe_schema_latest.xsd`, MITRE's XML schema definition for
the CWE catalog. The XSD was previously tracked in this repository.

## Source

- **Upstream URL:** https://cwe.mitre.org/data/xsd/cwe_schema_latest.xsd
- **License:** [CWE Terms of Use](https://cwe.mitre.org/about/termsofuse.html)
- **Copyright:** © 2006-2025 The MITRE Corporation. All rights reserved.
- **SHA-256 (at the time of removal):** `ba951edf800cbf83d3b2e66838de9f22852b377f27893dcdd782b8593bc72bfa`

The upstream URL is versionless ("latest") so the SHA-256 above pins the
copy that this repository previously vendored, not future revisions.

## How to fetch

```bash
curl -fsSL https://cwe.mitre.org/data/xsd/cwe_schema_latest.xsd -o /tmp/cwe_schema_latest.xsd
sha256sum /tmp/cwe_schema_latest.xsd  # may differ if MITRE has updated the schema
```

## When you need this

Only when you want to regenerate `cwe_catalog.json` from raw upstream XML
*and* validate the upstream XML against the schema. The committed
`cwe_catalog.json` is the canonical input for the runtime agent and does
not depend on the XSD at all.

See [NOTICE](../../../NOTICE) and
[THIRD_PARTY_LICENSES.md](../../../THIRD_PARTY_LICENSES.md) for the full
attribution.
