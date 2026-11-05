# Third-party rule set `0xdea`

Vendored verbatim by `plugins/opengrep/tools/vendor_rules.py`; never edit these files
by hand. To bump the set, follow `plugins/opengrep/tools/README.md`.

- Upstream: https://github.com/0xdea/semgrep-rules
- Commit: `60d33a2ab635e529fc7aad9328005c9ba8ac99d3`
- Folders: `rules/c/`
- Rule files: 47 (MIT: 47)
- Licence texts: `LICENSE`

## Notes

- Only rules/c/ is vendored. rules/noisy/ is not: its author marks it too noisy for general use.
- Lineage cross-check: --lineage-corpus was a local clone of opengrep-rules (a fork of semgrep-rules) at f1d2b562b414783763fd02a6ed2736eaed622efa.

## Excluded (2)

| File | Reason |
| --- | --- |
| `rules/c/missing-break-in-switch.yaml` | forbidden licence/provenance marker: returntocorp |
| `rules/c/missing-default-in-switch.yaml` | forbidden licence/provenance marker: returntocorp |
