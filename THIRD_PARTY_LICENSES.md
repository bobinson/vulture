# Third-Party Licenses

Vulture itself is licensed under the Apache License 2.0 (see [LICENSE](LICENSE)).
This document records every body of third-party content redistributed in this
repository, the upstream license that governs it, and the modifications, if any,
that have been applied. The summary form of these notices is in [NOTICE](NOTICE);
this file is the authoritative long form.

For runtime *dependencies* (Go modules, Python packages, npm packages),
see the dependency manifests:
- Go backend: [`backend/go.mod`](backend/go.mod), [`cli/go.mod`](cli/go.mod)
- Python agents: [`agents/*/pyproject.toml`](agents/)
- Frontend: [`frontend/package.json`](frontend/package.json)

All current runtime dependencies use permissive OSI-approved licenses (Apache-2.0,
MIT, BSD-3-Clause, BSD-2-Clause). No GPL/AGPL/SSPL or non-OSI licenses are pulled
in by the lockfiles as of the v0.1.0 release.

---

## 1. MITRE CWE™ (Common Weakness Enumeration)

**What:** A community-developed list of common software and hardware weakness types,
maintained by The MITRE Corporation.

**Upstream version vendored:** CWE 4.19.1.

**Upstream URL:** https://cwe.mitre.org/

**License / terms:** [CWE Terms of Use](https://cwe.mitre.org/about/termsofuse.html).
Copyright © 2006-2025 The MITRE Corporation. All rights reserved. The CWE Terms of
Use permit redistribution provided that the MITRE copyright notice and attribution
to MITRE are retained and made visible to users of derivative works.

**What we redistribute:**
- `agents/cwe/cwe_agent/data/cwe_catalog.json` — a flat lookup JSON derived from
  the upstream `cwec_v4.19.1.xml`. Field names preserve the upstream attribute
  vocabulary; copyright attribution is preserved at the catalog-file level via
  [`agents/cwe/cwe_agent/data/LICENSE.md`](agents/cwe/cwe_agent/data/LICENSE.md).

**What we do NOT redistribute (replaced by pointer files):**
- The raw upstream XML (`cwec_v4.19.1.xml`).
- The human-readable PDF (`cwec_v4.19.1.pdf`).
- The XSD schema (`cwe_schema_latest.xsd`).

The pointer files under [`docs/features/0014_cwe_version_4.19.1/`](docs/features/0014_cwe_version_4.19.1/)
and [`docs/features/0010_cwe_audit/`](docs/features/0010_cwe_audit/) document the
upstream URLs, versions, and SHA-256 checksums needed to fetch a local copy if you
want to regenerate `cwe_catalog.json` from scratch or audit the transformation.

**Modifications applied:** XML → JSON transformation; `Observed_Examples` extracted
into a structured field; `tech_words` synonym index added; taxonomic rollup helpers
added for Class/Pillar parents. None of the modifications alter, omit, or
contradict the upstream weakness descriptions.

---

## 2. OWASP Application Security Verification Standard (ASVS) v5.0.0

**What:** A list of application security verification requirements maintained by
the OWASP Foundation, organized into 17 chapters and three verification levels.

**Upstream version vendored:** ASVS 5.0.0.

**Upstream URL:** https://github.com/OWASP/ASVS

**License / terms:** Creative Commons Attribution-ShareAlike 4.0 International
([CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/)). Copyright ©
The OWASP Foundation and contributors.

CC BY-SA 4.0 obligations on the redistributed data files:
1. **Attribution** — credit the OWASP Foundation and link to ASVS upstream.
2. **License notice** — provide a link to CC BY-SA 4.0.
3. **Indication of changes** — declare what was modified.
4. **ShareAlike** — derivative works of the ASVS *content* must be licensed under
   CC BY-SA 4.0 (or a later compatible CC version). This applies to the data
   files in `agents/asvs/asvs_agent/data/` only; the rest of Vulture (Apache-2.0
   code) is not a derivative of ASVS content.

**What we redistribute** (under CC BY-SA 4.0; see also
[`agents/asvs/asvs_agent/data/LICENSE.md`](agents/asvs/asvs_agent/data/LICENSE.md)):
- `agents/asvs/asvs_agent/data/asvs_source.json` — direct upstream extraction.
- `agents/asvs/asvs_agent/data/asvs_catalog.json` — reorganized lookup form.
- `agents/asvs/asvs_agent/data/asvs_cwe_crosswalk.json` — LLM-assisted mapping
  from each ASVS req_id to one or more CWE IDs (the upstream v5.0.0 dropped the
  CWE column; this is our reconstruction). Considered a derivative.
- `agents/asvs/asvs_agent/data/asvs_detectability.json` — per-requirement
  classification into `static` / `runtime` / `policy`. Considered a derivative.

**Modifications applied:** transformation to lookup JSON; addition of CWE
crosswalk; addition of detectability classification. The text of each requirement
is preserved verbatim where included.

---

## 3. NIST SP 800-218 — Secure Software Development Framework (SSDF)

**What:** NIST's recommended set of secure software development practices.

**Upstream version vendored:** SSDF v1.1.

**Upstream URL:** https://csrc.nist.gov/Projects/ssdf

**License / terms:** Works of the U.S. federal government are public-domain in
the United States (17 USC §105). NIST publications carry no copyright restriction
on use, reproduction, or redistribution.

**What we redistribute:**
- `agents/ssdf/ssdf_agent/practice_groups/` — the SSDF practice groups (PO, PS,
  PW, RV) and per-practice rules used by the SSDF agent.

**Modifications applied:** the SSDF text is parsed into structured Python
modules; section numbers and identifiers are preserved.

---

## 4. Runtime dependencies (summary)

The full transitive list is generated by the package managers (`go list -m all`,
`pip-licenses`, `npm ls`); a current SBOM may be attached to the GitHub release.

Direct dependencies of note:

**Go backend / CLI:**
- `github.com/google/uuid` — BSD-3-Clause
- `github.com/lib/pq` — MIT
- `golang.org/x/crypto` — BSD-3-Clause
- `modernc.org/sqlite` — BSD-3-Clause

**Python agents (via `agents/shared/pyproject.toml`):**
- `fastapi`, `pydantic`, `openai-agents`, `litellm`, `tiktoken` — MIT
- `uvicorn`, `httpx`, `sse-starlette` — BSD-3-Clause

**Frontend:**
- `react`, `react-dom`, `react-router-dom`, `i18next` — MIT
- `vite`, `vitest`, `@playwright/test` — MIT
- `tailwindcss` — MIT

No copyleft (GPL/AGPL/SSPL) or source-available-with-restrictions (Commons
Clause, BUSL) dependencies are present in the Vulture v0.1.0 lockfiles.
