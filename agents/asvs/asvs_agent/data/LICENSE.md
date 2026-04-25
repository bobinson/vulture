# License — ASVS data files (CC BY-SA 4.0)

> **Important:** the data files in this directory are licensed differently
> from the rest of the Vulture repository. Vulture as a whole is Apache-2.0;
> the four JSON files in this directory inherit **Creative Commons
> Attribution-ShareAlike 4.0 International (CC BY-SA 4.0)** from the upstream
> OWASP ASVS project. Any further derivative of these files must remain
> CC BY-SA 4.0.

## Files governed by this license

- `asvs_source.json` — direct extraction of the upstream ASVS v5.0.0 source.
- `asvs_catalog.json` — reorganized lookup form of the ASVS requirements.
- `asvs_cwe_crosswalk.json` — mapping from each `req_id` to one or more CWE
  IDs. **This is a Vulture-authored derivative**: ASVS v5.0.0 dropped the CWE
  column, so we reconstructed it via LLM-assisted classification followed by
  human review. Its content is treated as a derivative of ASVS content for
  licensing purposes.
- `asvs_detectability.json` — per-requirement classification into `static`,
  `runtime`, or `policy` for use by the ASVS agent's pipeline. Vulture-authored;
  derivative for licensing purposes.

The Python module `_generate_lookup_files.py` in this directory is Vulture
code, licensed under **Apache-2.0** along with the rest of the repository.
The data files it produces are licensed under CC BY-SA 4.0.

## Source

- **Upstream project:** OWASP Application Security Verification Standard (ASVS)
- **Upstream URL:** https://github.com/OWASP/ASVS
- **Upstream version:** ASVS 5.0.0
- **Upstream copyright:** © The OWASP Foundation and contributors
- **Upstream license:** [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/)

## Modifications applied

| File | Modifications |
|---|---|
| `asvs_source.json` | Format conversion only (upstream source → JSON). No textual changes. |
| `asvs_catalog.json` | Reorganized as `{req_id → requirement}` lookup. Per-requirement fields added (chapter index, level, section). Requirement text preserved verbatim. |
| `asvs_cwe_crosswalk.json` | New mapping from `req_id` → `[CWE-id, …]`. LLM-generated; human-reviewed. |
| `asvs_detectability.json` | New classification: each `req_id` tagged with one of `static` / `runtime` / `policy`. LLM-generated; human-reviewed. |

## Your obligations when redistributing

CC BY-SA 4.0 imposes four obligations on every recipient who redistributes
or adapts these files:

1. **Attribution** — credit the OWASP Foundation; link to the upstream URL.
2. **License notice** — include a link to https://creativecommons.org/licenses/by-sa/4.0/.
3. **Indication of changes** — declare any modifications you make.
4. **ShareAlike** — license your derivative under CC BY-SA 4.0 (or a later
   compatible CC version).

## Top-level attribution

See the project's [NOTICE](../../../../NOTICE) and
[THIRD_PARTY_LICENSES.md](../../../../THIRD_PARTY_LICENSES.md).
