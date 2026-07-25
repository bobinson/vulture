# MITRE CWE™ 4.19.1 — XML catalog (external resource)

This file replaces `cwec_v4.19.1.xml`, which was previously tracked in this
repository (~16 MB). The XML is *not* shipped here; download it from MITRE
if you need the raw upstream catalog.

## Source

- **Upstream URL:** https://cwe.mitre.org/data/xml/cwec_v4.19.1.xml.zip
- **Version:** CWE 4.19.1
- **License:** [CWE Terms of Use](https://cwe.mitre.org/about/termsofuse.html)
- **Copyright:** © 2006-2025 The MITRE Corporation. All rights reserved.
- **SHA-256 (uncompressed XML):** `f7d6fae581116795aa3545ce2ab801f81cbb655410d65db703f1343df10ff7b9`

## How to fetch

```bash
curl -fsSL https://cwe.mitre.org/data/xml/cwec_v4.19.1.xml.zip -o /tmp/cwec.zip
unzip /tmp/cwec.zip -d /tmp/cwec
sha256sum /tmp/cwec/cwec_v4.19.1.xml  # verify against the SHA-256 above
```

## What ships in this repo instead

The CWE catalog used at runtime by the `agent-cwe` service is the generated
derivative `agents/cwe/cwe_agent/data/cwe_catalog.json`, which is committed
and is the canonical input format for the agent. You only need this raw
upstream XML if you want to regenerate the JSON or audit the transformation.

## Why this is a pointer instead of the full file

The raw XML is ~16 MB and the corresponding PDF is ~37 MB — together they
accounted for the bulk of the repository's tracked size. They are upstream
content that can be re-downloaded any time; vendoring them inflated clones
for everyone without benefit. See [NOTICE](../../../NOTICE) and
[THIRD_PARTY_LICENSES.md](../../../THIRD_PARTY_LICENSES.md) for the full
attribution.
