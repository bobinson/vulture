# License — CWE catalog data

The file `cwe_catalog.json` in this directory is a derivative work of the
**MITRE CWE™** catalog (Common Weakness Enumeration), version 4.19.1.

- **Original source:** https://cwe.mitre.org/
- **Original license / terms of use:** [CWE Terms of Use](https://cwe.mitre.org/about/termsofuse.html)
- **Original copyright:** © 2006-2025 The MITRE Corporation. All rights reserved.

## Modifications

`cwe_catalog.json` is generated from the upstream `cwec_v4.19.1.xml` by
`scripts/extract_cwe_catalog.py`. The transformation:

- Flattens the XML structure into a JSON lookup keyed by CWE ID.
- Extracts `Observed_Examples` into a structured array per entry.
- Adds a `tech_words` synonym index (used by the agent's keyword matcher).
- Adds taxonomic rollup helpers for Class/Pillar parents.

The textual content of each weakness description is preserved verbatim. No
weakness has been added, removed, or had its meaning altered.

## Attribution

When using or redistributing `cwe_catalog.json` or any derivative, retain the
MITRE copyright notice and the link to https://cwe.mitre.org/about/termsofuse.html.

See the top-level [NOTICE](../../../../NOTICE) and
[THIRD_PARTY_LICENSES.md](../../../../THIRD_PARTY_LICENSES.md) for the
project-wide attribution summary.
